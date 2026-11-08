#include "dynarmic_host.h"
#include "native_handle_table.h"

#include <chrono>
#include <cstdint>
#include <cstdlib>

#define CHECK(condition) do { if (!(condition)) std::abort(); } while (false)

// Standalone Android component test. Link with the same BRIDGE_SOURCES and
// libraries as bridge_regression; no device execution is part of this change.
int main() {
    DynarmicHost host;
    CHECK(host.Initialize());

    int generic_storage = 0;
    const uint32_t retired_generic = GuestHandleFor(&generic_storage);
    CHECK(retired_generic);
    ReleaseGuestHandle(&generic_storage);
    CHECK(HostPointerFor(retired_generic) == nullptr);

    int queue_storage = 0;
    const auto ready_deadline = [] {
        return std::chrono::steady_clock::now() + std::chrono::seconds(1);
    };
    const auto blocked_deadline = [] {
        return std::chrono::steady_clock::now() + std::chrono::milliseconds(10);
    };
    const uint32_t first = RegisterInputQueueHandle(&queue_storage, 1);
    CHECK(first && first != retired_generic && HostPointerFor(first) == &queue_storage);
    CHECK(BeginInputQueueOperation(first, InputQueueOperation::Attach) ==
           InputQueueAccess::Allowed);
    EndInputQueueOperation(first, InputQueueOperation::Attach, 0, 0, true);
    CHECK(GetInputQueueHandleStatus(first).attached);

    constexpr uint32_t event = 0x12340000u;
    for (int i = 0; i < 2; ++i) {
        CHECK(BeginInputQueueOperation(first, InputQueueOperation::GetEvent) ==
               InputQueueAccess::Allowed);
        EndInputQueueOperation(first, InputQueueOperation::GetEvent, 0, event, true);
    }
    CHECK(GetInputQueueHandleStatus(first).outstanding_events == 2);
    CHECK(CloseInputQueueHandle(first));
    CHECK(BeginInputQueueOperation(first, InputQueueOperation::GetEvent) ==
           InputQueueAccess::Denied);
    CHECK(BeginInputQueueOperation(first, InputQueueOperation::Attach) ==
           InputQueueAccess::Denied);
    for (int remaining = 1; remaining >= 0; --remaining) {
        CHECK(BeginInputQueueOperation(first, InputQueueOperation::FinishEvent) ==
               InputQueueAccess::Allowed);
        EndInputQueueOperation(first, InputQueueOperation::FinishEvent, 0, event, true);
        CHECK(GetInputQueueHandleStatus(first).outstanding_events ==
               static_cast<uint32_t>(remaining));
    }
    CHECK(!WaitInputQueueQuiescent(first, blocked_deadline()));  // Still attached.
    CHECK(BeginInputQueueOperation(first, InputQueueOperation::Detach) ==
           InputQueueAccess::Allowed);
    EndInputQueueOperation(first, InputQueueOperation::Detach, 0, 0, true);
    CHECK(WaitInputQueueQuiescent(first, ready_deadline()));
    CHECK(RetireInputQueueHandle(first));
    CHECK(!RetireInputQueueHandle(first));
    CHECK(HostPointerFor(first) == nullptr);
    CHECK(BeginInputQueueOperation(first, InputQueueOperation::FinishEvent) ==
           InputQueueAccess::Denied);

    // Reuse the exact native address: neither the guest token nor its mapping
    // may alias the retired generation.
    const uint32_t second = RegisterInputQueueHandle(&queue_storage, 2);
    CHECK(second && second != first && HostPointerFor(second) == &queue_storage);
    CHECK(HostPointerFor(first) == nullptr);
    CHECK(GetInputQueueHandleStatus(second).generation == 2);
    CHECK(BeginInputQueueOperation(second, InputQueueOperation::Attach) ==
           InputQueueAccess::Allowed);
    EndInputQueueOperation(second, InputQueueOperation::Attach, 0, 0, true);
    CHECK(BeginInputQueueOperation(second, InputQueueOperation::GetEvent) ==
           InputQueueAccess::Allowed);
    CHECK(CloseInputQueueHandle(second));
    CHECK(BeginInputQueueOperation(second, InputQueueOperation::GetEvent) ==
           InputQueueAccess::Denied);
    CHECK(BeginInputQueueOperation(second, InputQueueOperation::Detach) ==
           InputQueueAccess::Allowed);
    EndInputQueueOperation(second, InputQueueOperation::Detach, 0, 0, true);
    CHECK(!WaitInputQueueQuiescent(second, blocked_deadline()));  // GetEvent still in flight.
    EndInputQueueOperation(second, InputQueueOperation::GetEvent, uint32_t(-1), 0, true);
    CHECK(WaitInputQueueQuiescent(second, ready_deadline()));
    CHECK(RetireInputQueueHandle(second));
    return 0;
}
