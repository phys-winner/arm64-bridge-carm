#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <array>
#include <atomic>
#include <memory>
#include <mutex>

namespace Dynarmic::A32 {
    class Jit;
}

class DynarmicHost;

using ThunkHandler = std::function<void(Dynarmic::A32::Jit& jit, DynarmicHost& host)>;

void RegisterAndroidThunks(class ThunkManager& manager);
void SnapshotGotShadow(class DynarmicHost& host);
void W418GotHealNow_public();
void W432PltHardenTick();  // W418: early GOT poison heal (public wrapper)  // W418 (run556): early GOT poison heal, callable outside the 5s tick
void RegisterEglThunks(class ThunkManager& manager);
void RegisterGles1Thunks(class ThunkManager& manager);
void RegisterLibcExtraThunks(class ThunkManager& manager, DynarmicHost& host);

class ThunkManager {
public:
    ThunkManager(DynarmicHost& host);
    ~ThunkManager();

    void RegisterAllThunks();
    // Returns the guest address of this thunk's trampoline.
    uint32_t RegisterThunk(const std::string& name, ThunkHandler handler);
    void RegisterSymbol(const std::string& name, uint32_t address);

    uint32_t GetOrCreateThunkAddress(const std::string& name);
    void DispatchThunk(uint32_t thunk_id, Dynarmic::A32::Jit& jit);
    uint32_t GetThunkSvcId(const std::string& name) const;

    uint32_t FindRegisteredSymbol(const std::string& name) const;
    std::unordered_map<std::string, uint32_t> GetThunkSymbolTable() const {
        std::lock_guard lock(m_registry_mutex);
        return m_symbol_to_address;
    }

    static uint32_t s_screenWidth;
    static uint32_t s_screenHeight;
    // Virtual screen size reported to the guest for UI scaling; 0 = report the real one.
    static uint32_t s_virtualWidth;
    static uint32_t s_virtualHeight;
    static uint32_t s_forced_dpi;
    static uint32_t s_ui_inset;

private:
    void RegisterGLThunks();
    void RegisterLibcThunks();
    void RegisterZlibThunks();
    DynarmicHost& m_host;
    // The old 0x10000 page was shared with guest mmap/zero-fill activity and
    // static probes. Keep SVC trampolines in a dedicated bridge-owned arena.
    static constexpr uint32_t kThunkBase = 0x8F100000u;
    uint32_t m_next_thunk_addr = kThunkBase;
    std::unordered_map<std::string, uint32_t> m_symbol_to_address;
    static constexpr size_t kMaxThunks = 0x10000u / 8u;
    static_assert(kThunkBase + kMaxThunks * 8u == 0x8F110000u,
                  "SVC trampoline arena must end where fixed veneers begin");
    struct ThunkEntry { std::string name; ThunkHandler handler; };
    // Immutable entries stay alive across replacement and concurrent callbacks.
    std::array<std::atomic<const ThunkEntry*>, kMaxThunks> m_dispatch{};
    std::vector<std::unique_ptr<ThunkEntry>> m_entries;
    std::unordered_map<std::string, uint32_t> m_function_ids;
    mutable std::mutex m_registry_mutex;
};

struct GuestThreadWorker {
    uint32_t start_func;
    uint32_t arg;
};

const std::vector<GuestThreadWorker>& GetGuestThreadWorkers();
void AddGuestThreadWorker(uint32_t start_func, uint32_t arg);

// Device probes the guest usually wants (thunk_manager.cpp). Kept generic: no
// game class is consulted, only android.os / Resources / system properties.
std::string QueryDeviceLanguage();
std::string QueryDeviceCountryCode();
uint32_t QueryDeviceDensity();
uint32_t QueryDeviceIsPad();

// Asset overriding from <externalFilesDir>/... (thunks_libc.cpp).
// Technique: the engine's own archive->archive->plain-file lookup chain is left
// alone; the first source is simply made to miss for any file the user dropped
// into the override root, so the engine's existing fallback does the work.
void SetAssetOverrideRoot(const std::string& root);
bool HasAssetOverride(const char* entry_name);
// plt_slot: the guest PLT entry of the archive-open function to divert.
// real_symbol: that same function's name, resolved in the guest for the tail call.
void InstallAssetOverrideHook(DynarmicHost& host, uint32_t plt_slot, const char* real_symbol);
