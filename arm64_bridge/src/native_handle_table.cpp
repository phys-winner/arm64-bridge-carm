#include "native_handle_table.h"

#include "dynarmic_host.h"

#include <condition_variable>
#include <mutex>
#include <unordered_map>

namespace {
DynarmicHost* g_host = nullptr;
std::mutex g_mutex;
std::unordered_map<uint32_t, const void*> g_guest_to_host;
std::unordered_map<const void*, uint32_t> g_host_to_guest;
struct InputQueueHandle {
    const void* queue = nullptr;
    uint64_t generation = 0;
    bool attached = false;
    bool closing = false;
    bool retired = false;
    bool protocol_error = false;
    uint32_t in_flight = 0;
    uint32_t outstanding_events = 0;
    // Event guest handles can be recycled immediately by finish/pre-dispatch.
    // Counts keep a concurrent new event from being erased by the old call's
    // post-dispatch bookkeeping.
    std::unordered_map<uint32_t, uint32_t> events;
};
std::unordered_map<uint32_t, InputQueueHandle> g_input_queues;
std::condition_variable g_input_cv;
constexpr size_t kMaxInputQueueGenerations = 4096;

bool Quiescent(const InputQueueHandle& entry) {
    return entry.closing && !entry.retired && !entry.attached && !entry.in_flight &&
           !entry.outstanding_events && !entry.protocol_error;
}
}

void BindNativeHandleHost(DynarmicHost& host) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_host == &host) return;
    g_host = &host;
    g_guest_to_host.clear();
    g_host_to_guest.clear();
    g_input_queues.clear();
}

uint32_t GuestHandleFor(const void* host_ptr) {
    if (!host_ptr || !g_host) return 0;
    std::lock_guard<std::mutex> lock(g_mutex);
    auto it = g_host_to_guest.find(host_ptr);
    if (it != g_host_to_guest.end()) return it->second;
    const uint32_t handle = g_host->GuestAlloc(4, 4);
    if (!handle) return 0;
    g_host_to_guest.emplace(host_ptr, handle);
    g_guest_to_host.emplace(handle, host_ptr);
    return handle;
}

void* HostPointerFor(uint32_t guest_handle) {
    if (!guest_handle) return nullptr;
    std::lock_guard<std::mutex> lock(g_mutex);
    auto it = g_guest_to_host.find(guest_handle);
    return it == g_guest_to_host.end() ? nullptr : const_cast<void*>(it->second);
}

void ReleaseGuestHandle(const void* host_ptr) {
    if (!host_ptr || !g_host) return;
    std::lock_guard<std::mutex> lock(g_mutex);
    auto it = g_host_to_guest.find(host_ptr);
    if (it == g_host_to_guest.end()) return;
    const uint32_t handle = it->second;
    g_host_to_guest.erase(it);
    g_guest_to_host.erase(handle);
    g_host->GuestFree(handle);
}

uint32_t RegisterInputQueueHandle(const void* queue, uint64_t generation) {
    if (!queue || !generation || !g_host) return 0;
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_input_queues.size() >= kMaxInputQueueGenerations ||
        g_host_to_guest.find(queue) != g_host_to_guest.end()) return 0;
    for (const auto& item : g_input_queues) {
        if (!item.second.retired && item.second.queue == queue) return 0;
    }
    // Keep queue tokens outside GuestHandleFor's 32-byte heap class and never
    // free them: neither a stale generic handle nor an old queue token can
    // resolve to a later queue when native addresses are recycled.
    const uint32_t handle = g_host->GuestAlloc(4, 64);
    if (!handle || g_guest_to_host.find(handle) != g_guest_to_host.end() ||
        g_input_queues.find(handle) != g_input_queues.end()) return 0;
    g_guest_to_host.emplace(handle, queue);
    g_input_queues.emplace(handle, InputQueueHandle{queue, generation});
    return handle;
}

bool CloseInputQueueHandle(uint32_t guest_handle) {
    std::lock_guard<std::mutex> lock(g_mutex);
    const auto it = g_input_queues.find(guest_handle);
    if (it == g_input_queues.end() || it->second.retired) return false;
    it->second.closing = true;
    g_input_cv.notify_all();
    return true;
}

InputQueueAccess BeginInputQueueOperation(uint32_t guest_handle, InputQueueOperation operation) {
    std::lock_guard<std::mutex> lock(g_mutex);
    const auto it = g_input_queues.find(guest_handle);
    if (it == g_input_queues.end()) return InputQueueAccess::Untracked;
    InputQueueHandle& entry = it->second;
    if (entry.retired || (entry.closing &&
        (operation == InputQueueOperation::Attach || operation == InputQueueOperation::GetEvent)))
        return InputQueueAccess::Denied;
    ++entry.in_flight;
    return InputQueueAccess::Allowed;
}

void EndInputQueueOperation(uint32_t guest_handle, InputQueueOperation operation,
                            uint32_t result, uint32_t event_handle, bool target_valid) {
    std::lock_guard<std::mutex> lock(g_mutex);
    const auto it = g_input_queues.find(guest_handle);
    if (it == g_input_queues.end() || !it->second.in_flight) return;
    InputQueueHandle& entry = it->second;
    switch (operation) {
        case InputQueueOperation::Attach:
            if (target_valid && result == 0) entry.attached = true;
            else entry.protocol_error = true;
            break;
        case InputQueueOperation::Detach:
            if (target_valid && result == 0) entry.attached = false;
            else entry.protocol_error = true;
            break;
        case InputQueueOperation::GetEvent:
            if (static_cast<int32_t>(result) >= 0) {
                if (event_handle) {
                    ++entry.events[event_handle];
                    ++entry.outstanding_events;
                }
                else entry.protocol_error = true;
            }
            break;
        case InputQueueOperation::PreDispatchEvent:
            if (!target_valid || result > 1) {
                entry.protocol_error = true;
            } else if (result && event_handle) {
                auto event = entry.events.find(event_handle);
                if (event != entry.events.end() && event->second) {
                    if (!--event->second) entry.events.erase(event);
                    --entry.outstanding_events;
                } else entry.protocol_error = true;
            }
            break;
        case InputQueueOperation::FinishEvent:
            if (!target_valid) {
                entry.protocol_error = true;
            } else if (result == 0 && event_handle) {
                auto event = entry.events.find(event_handle);
                if (event != entry.events.end() && event->second) {
                    if (!--event->second) entry.events.erase(event);
                    --entry.outstanding_events;
                } else entry.protocol_error = true;
            }
            break;
    }
    --entry.in_flight;
    g_input_cv.notify_all();
}

InputQueueHandleStatus GetInputQueueHandleStatus(uint32_t guest_handle) {
    std::lock_guard<std::mutex> lock(g_mutex);
    const auto it = g_input_queues.find(guest_handle);
    if (it == g_input_queues.end()) return {};
    const InputQueueHandle& entry = it->second;
    return {true, entry.attached, entry.closing, entry.retired,
            entry.protocol_error, entry.in_flight,
            entry.outstanding_events, entry.generation};
}

bool WaitInputQueueQuiescent(uint32_t guest_handle,
                             std::chrono::steady_clock::time_point deadline) {
    std::unique_lock<std::mutex> lock(g_mutex);
    if (std::chrono::steady_clock::now() > deadline) return false;
    return g_input_cv.wait_until(lock, deadline, [guest_handle] {
        const auto it = g_input_queues.find(guest_handle);
        return it != g_input_queues.end() && Quiescent(it->second);
    }) && std::chrono::steady_clock::now() <= deadline;
}

bool RetireInputQueueHandle(uint32_t guest_handle) {
    std::lock_guard<std::mutex> lock(g_mutex);
    const auto it = g_input_queues.find(guest_handle);
    if (it == g_input_queues.end() || !Quiescent(it->second)) return false;
    g_guest_to_host.erase(guest_handle);
    it->second.queue = nullptr;
    it->second.retired = true;
    g_input_cv.notify_all();
    return true;
}
