#pragma once

#include <chrono>
#include <cstdint>

class DynarmicHost;

void BindNativeHandleHost(DynarmicHost& host);
uint32_t GuestHandleFor(const void* host_ptr);
void* HostPointerFor(uint32_t guest_handle);
void ReleaseGuestHandle(const void* host_ptr);

// Input queues are owned by NativeActivity, not by the handle table. Their
// guest tokens must be generation-specific and must never alias a later queue.
enum class InputQueueOperation : uint8_t {
    Attach, Detach, GetEvent, PreDispatchEvent, FinishEvent
};
enum class InputQueueAccess : uint8_t { Untracked, Allowed, Denied };
struct InputQueueHandleStatus {
    bool known = false;
    bool attached = false;
    bool closing = false;
    bool retired = false;
    bool protocol_error = false;
    uint32_t in_flight = 0;
    uint32_t outstanding_events = 0;
    uint64_t generation = 0;
};

uint32_t RegisterInputQueueHandle(const void* queue, uint64_t generation);
bool CloseInputQueueHandle(uint32_t guest_handle);
InputQueueAccess BeginInputQueueOperation(uint32_t guest_handle, InputQueueOperation operation);
void EndInputQueueOperation(uint32_t guest_handle, InputQueueOperation operation,
                            uint32_t result, uint32_t event_handle, bool target_valid);
InputQueueHandleStatus GetInputQueueHandleStatus(uint32_t guest_handle);
bool WaitInputQueueQuiescent(uint32_t guest_handle,
                             std::chrono::steady_clock::time_point deadline);
bool RetireInputQueueHandle(uint32_t guest_handle);
