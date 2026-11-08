#pragma once

#include <cstdint>
#include <array>
#include <cstddef>
#include <functional>
#include <memory>
#include <vector>
#include <string>
#include <optional>
#include <mutex>
#include <unordered_map>
#include <atomic>
#include <dynarmic/interface/A32/a32.h>
#include <dynarmic/interface/A32/config.h>
#include <dynarmic/interface/exclusive_monitor.h>
// W440: true once the ELF .init_array constructor walk has completed; the
// pump must not dispatch guest calls (handle_cmd/write_cmd/SetPaused)
// concurrently with the constructor walk -- they double-take the guest's
// log lock and wedge the constructors mid-init.
bool DynarmicInitDone();
void MarkCtorWalkThread();  // W444: exempt the calling thread from ctor-walk parking

class ElfLoader;
class ThunkManager;

class DynarmicHost : public Dynarmic::A32::UserCallbacks {
public:
    // The full 32-bit guest address space. Mapping all of it means fastmem can resolve any
    // guest address as base + zext32(vaddr) without ever faulting.
    static constexpr size_t GUEST_ADDRESS_SPACE = 0x100000000ULL; // 4 GiB
    // Keep the main image at the historical address, but leave non-overlapping 2 MiB slots
    // for the FMOD images. The main image is 0x008C9000 bytes, so the old 0x40400000
    // slot overlapped it and corrupted libfmodex's relocation table before relocation.
    static constexpr uint32_t kGuestGameBase = 0x40000000;
    static constexpr uint32_t kGuestFmodexBase = 0x41000000;
    static constexpr uint32_t kGuestFmodexLBase = 0x41200000;
    static constexpr uint32_t kGuestFmodeventBase = 0x41400000;
    static constexpr uint32_t kGuestFmodeventLBase = 0x41600000;

    // Fallback if the 4 GiB reservation is refused: no fastmem, bounds-checked callbacks.
    static constexpr size_t GUEST_FALLBACK_SIZE = 0x80000000ULL;  // 2 GiB

    DynarmicHost();
    ~DynarmicHost() override;

    bool Initialize();
    bool LoadGame(const std::string& elf_path);
    bool LoadGameFromMemory(const uint8_t* data, size_t size);

    bool LoadLibraries(const std::string& fmodex_path, const std::string& fmodevent_path, const std::string& game_path);
    bool LoadLibrariesFromMemory(const uint8_t* fmodex_data, size_t fmodex_size,
                                 const uint8_t* fmodevent_data, size_t fmodevent_size,
                                 const uint8_t* game_data, size_t game_size);
    bool LoadAllLibrariesFromMemory(const uint8_t* fmodex_data, size_t fmodex_size,
                                    const uint8_t* fmodex_l_data, size_t fmodex_l_size,
                                    const uint8_t* fmodevent_data, size_t fmodevent_size,
                                    const uint8_t* fmodevent_l_data, size_t fmodevent_l_size,
                                    const uint8_t* game_data, size_t game_size);

    Dynarmic::A32::Jit& CurrentJit();
    // The optional flag reports a normal exit-trap halt, not callback protocol success.
    uint32_t RunFunction(uint32_t target_pc, const std::vector<uint32_t>& args = {},
                         bool* reached_exit_trap = nullptr);
    // W325 (run431): resolve libc DATA symbols the guest imports but the
    // bridge never registered (_ctype_, __sF, __stack_chk_guard). Without
    // this they resolve to 0 and every ctype/stdio/canary access reads the
    // trap page.
    uint32_t ResolveLibcDataSymbol(const std::string& name);
    // Start a guest pthread on a host thread with its own Dynarmic JIT.
    void SpawnGuestThread(uint32_t start_func, uint32_t arg);

    // W11: detached host thread with a large stack (64 MiB). Dynarmic's block
    // translation and IR-walk recursion run on the executing thread; bionic's
    // ~1 MiB pthread default overflowed during heavy guest texture loading
    // (run35: SIGSEGV stack overflow in IR::Value::IsImmediate on a worker).
    // Returns false when the host worker could not be created.
    static bool SpawnLargeStackThread(const char* name, std::function<void()> body);
    // A thunk cannot re-enter its currently running JIT. Execute a guest
    // initializer on an isolated JIT and wait for it to return.
    bool RunGuestInitializer(uint32_t entry);
    // Runs calls that were made from inside a thunk (i.e. from inside Jit::Run, where the JIT
    // is not re-entrant). Call once per frame from a point known to be outside the JIT.
    void DrainDeferred();

    uint8_t* GetGuestMemoryBase() const { return m_memory; }
    size_t GetGuestMemorySize() const { return m_memory_size; }
    ElfLoader& GetElfLoader() { return *m_elf_loader; }
    // Find the unwind table belonging to the guest image that contains pc.
    bool GetExidxRangeForPc(uint32_t pc, uint32_t& start, uint32_t& end) const;
    // W3 diagnostic: reads the luaD_throw scratch block (magic-cleared after
    // read). Empty when no new throw was dumped.
    std::string DiagReadLuaThrow();
    // W7 diagnostic: reads the Android_fopen path snapshot written by the
    // entry trampoline. Empty when no new open was dumped.
    std::string DiagReadFopenPath();
    // W7 diagnostic: reads the __cxa_throw snapshot (throw site, exception
    // object, type name). Empty when no new throw was dumped.
    std::string DiagReadCxaThrow();
    // W10 diagnostic: reads the __throw_length_error snapshot (message string
    // + throw site). Empty when no new throw was dumped.
    std::string DiagReadThrowLengthError();
    // W16b diagnostic: full register state of every thread parked in the
    // bridge page (pc <= 0x40, excluding the exit traps) plus a hex dump of
    // the low guest page the stuck control flow executes.
    std::string DiagDumpStuckThreads();
    ElfLoader* GetFmodExLoader() { return m_fmodex_loader.get(); }
    ElfLoader* GetFmodExLLoader() { return m_fmodex_l_loader.get(); }
    ElfLoader* GetFmodEventLoader() { return m_fmodevent_loader.get(); }
    ElfLoader* GetFmodEventLLoader() { return m_fmodevent_l_loader.get(); }
    ThunkManager& GetThunkManager() { return *m_thunk_manager; }
    std::recursive_mutex& GetMutex() { return m_mutex; }
    uint32_t FindSymbol(const std::string& name);
    // Drop any cached translation of a guest range that was just rewritten.
    void InvalidateGuestCode(uint32_t addr, size_t size);
    uint32_t GuestAlloc(size_t size, size_t alignment = 8);
    void GuestFree(uint32_t addr);
    // Payload size of a live GuestAlloc block, 0 if addr did not come from here.
    uint32_t GuestAllocSize(uint32_t addr);
    // Address space for whole-file mappings (the mmap thunk), deliberately outside the
    // malloc heap: one expansion file can be hundreds of megabytes and would otherwise eat
    // the arena permanently -- a 345 MB .obb mapped twice is how "GuestAlloc out of guest
    // heap" showed up right after loading started. Bump-only, never freed: these mappings
    // live for the process and the address is never reused.
    uint32_t GuestAllocMapping(size_t size, size_t alignment);

    // Runaway-PC containment. The loaded modules and the trampoline page are
    // covered automatically; register anything else that legitimately holds guest
    // code (hand-built veneers, JIT-ed guest stubs) so it is not trapped.
    void AddExecutableRange(uint32_t base, uint32_t size);

    // D1 diagnostic-only: snapshot the guest PC of every registered JIT (one per
    // guest thread). A JIT mid-Run on its own thread may yield a torn value; the
    // histogram consumer tolerates that noise. Registered JITs are held by
    // weak_ptr because a guest thread destroys its own JIT on exit.
    std::vector<uint32_t> SampleGuestPcs();
    void InvalidateGuestCodeAll(uint32_t addr, size_t size);
    struct GuestThreadPc { uint32_t tid; uint32_t pc; uint32_t lr; uint32_t r4; uint32_t r5; uint32_t sp; uint32_t r0; uint32_t r1; uint32_t r2; uint32_t r3; };
    std::vector<GuestThreadPc> SampleGuestThreadPcs();

    // C1 diagnostic-only: check the trailing canary of every live guest-heap
    // block and return a bounded report (empty string = no violation). Called by
    // the diag writer thread every dump cycle; a violation means something wrote
    // past a live allocation and the report names the block.
    std::string DiagCheckHeapCanaries();

    // N1 diagnostic-only: dump the gDynamic_vb_map Rb_tree header (root/begin/
    // rightmost/size), the neighbouring VB globals, and a bounded __tree_next
    // walk printing per-node {addr parent left right key value}. Pure guest
    // memory reads on the diag writer thread; every step is bounded so a cyclic
    // or broken tree can only shorten the report, never hang or fault it.
    std::string DiagWalkDynamicVbMap();

    // W146 diagnostic-only: poll the boot-critical guest data-segment globals
    // (startup pause flag, LLMem default alignment) and the head of the LLMem
    // pool-descriptor pointer table every diag dump; count/stride fields never
    // legitimately mutate after pool creation, so a change line timestamps the
    // corrupting write. Read-only, races the guest like the C1 canary pass.
    std::string DiagW146Sentinels();

  private:
    // N1: one canonical __tree_increment step, bounds-checked.
    uint32_t DiagVbTreeNext(uint32_t x, uint32_t header);

  public:

    // Dynarmic UserCallbacks interface
    std::optional<std::uint32_t> MemoryReadCode(std::uint32_t vaddr) override;

    std::uint8_t MemoryRead8(std::uint32_t vaddr) override;
    std::uint16_t MemoryRead16(std::uint32_t vaddr) override;
    std::uint32_t MemoryRead32(std::uint32_t vaddr) override;
    std::uint64_t MemoryRead64(std::uint32_t vaddr) override;

    void MemoryWrite8(std::uint32_t vaddr, std::uint8_t value) override;
    void MemoryWrite16(std::uint32_t vaddr, std::uint16_t value) override;
    void MemoryWrite32(std::uint32_t vaddr, std::uint32_t value) override;
    void MemoryWrite64(std::uint32_t vaddr, std::uint64_t value) override;

    // Needed now that global_monitor is set: the base-class defaults return false, which makes
    // every guest STREX report failure and spin its retry loop forever.
    bool MemoryWriteExclusive8(std::uint32_t vaddr, std::uint8_t value, std::uint8_t expected) override;
    bool MemoryWriteExclusive16(std::uint32_t vaddr, std::uint16_t value, std::uint16_t expected) override;
    bool MemoryWriteExclusive32(std::uint32_t vaddr, std::uint32_t value, std::uint32_t expected) override;
    bool MemoryWriteExclusive64(std::uint32_t vaddr, std::uint64_t value, std::uint64_t expected) override;

    void InterpreterFallback(std::uint32_t pc, std::size_t num_instructions) override;
    void CallSVC(std::uint32_t swi) override;
    void ExceptionRaised(std::uint32_t pc, Dynarmic::A32::Exception exception) override;

    void AddTicks(std::uint64_t ticks) override;
    std::uint64_t GetTicksRemaining() override;

    // W108: top of the loaded guest image (base + largest segment end),
    // rounded up to a page. Bridge-owned stub/counter windows must live
    // above this -- the ELF data expanded into the old 0x65Cxxx window.
    uint32_t GuestImageEnd() const;

    // W130: one-line bridge-heap state (bump position, live blocks, live
    // bytes, top-3 blocks) for the W40PCS diag line.
    std::string DiagHeapState();

    // W198: sample the live guest PC of every live JIT context (the game
    // thread included). Racy by design -- diagnostic only.
    std::string DiagSamplePCs();

    bool IsJitRunning() const;

private:
    uint8_t* m_memory = nullptr;
    size_t m_memory_size = 0;
    std::unique_ptr<Dynarmic::ExclusiveMonitor> m_monitor;
    std::shared_ptr<Dynarmic::A32::Jit> m_jit;
    Dynarmic::A32::UserConfig m_jit_config;
    std::mutex m_jit_list_mutex;
    // weak_ptr: each guest thread owns its JIT via t_owned_jit; the list only
    // wants to observe live instances (D1 PC sampling), never keep them alive.
    struct GuestJitEntry {
        std::weak_ptr<Dynarmic::A32::Jit> jit;
        uint32_t owner_tid = 0;  // host tid that created this JIT (W12 diag)
    };
    std::vector<GuestJitEntry> m_jits;
    static constexpr uint32_t kMaxGuestCores = 64;
    std::array<uint32_t, kMaxGuestCores> m_thread_stacks{};
    std::unique_ptr<ElfLoader> m_fmodex_loader;
    std::unique_ptr<ElfLoader> m_fmodex_l_loader;
    std::unique_ptr<ElfLoader> m_fmodevent_loader;
    std::unique_ptr<ElfLoader> m_fmodevent_l_loader;
    std::unique_ptr<ElfLoader> m_elf_loader;
    std::unique_ptr<ThunkManager> m_thunk_manager;
    // Attach, detach, get, pre-dispatch, finish. All guest AInputQueue calls
    // pass through CallSVC, so its wrapper can hold a lease across each thunk.
    std::array<uint32_t, 5> m_input_queue_thunk_ids{};
    std::recursive_mutex m_mutex;
    bool m_is_running_jit = false;

    std::vector<std::pair<uint32_t, std::vector<uint32_t>>> m_deferred;
    std::vector<std::pair<uint32_t, uint32_t>> m_code_ranges;   // [base, end)

    // Guest heap: bump pointer for fresh memory, free lists for reuse. Requests up
    // to kMaxClassSize round to a power-of-two size class; anything larger (asset
    // payloads, thread stacks) is sized exactly and recycled by exact capacity, so
    // repeated 8 MB stacks do not round up to 16 MB.
    static constexpr uint32_t kHeapBase  = 0x50000000;
    static constexpr uint32_t kHeapLimit = 0x7E000000;   // guest stacks live above this
    // File mappings sit above both guest stacks and below the kuser helper page.
    static constexpr uint32_t kMapBase   = 0xA0000000;
    static constexpr uint32_t kMapLimit  = 0xF0000000;
    static constexpr int kMinClassShift = 5;                        // 32 B smallest block
    static constexpr uint32_t kMaxClassSize = 1u << 20;             // 1 MB largest class
    static constexpr int kNumSizeClasses = 20 - kMinClassShift + 1;
    void HeapSelfCheck();
    std::mutex m_heap_mutex;
    std::vector<uint32_t> m_free_small[kNumSizeClasses];             // class -> block bases
    std::unordered_map<uint32_t, std::vector<uint32_t>> m_free_huge; // capacity -> block bases
    uint32_t m_heap_current = kHeapBase;                             // guarded by m_heap_mutex
    uint32_t m_map_current  = kMapBase;                              // guarded by m_heap_mutex

    // C1 diagnostic-only: live-block registry for the periodic canary pass.
    struct HeapBlock { uint32_t base; uint32_t size; uint32_t capacity; };
    std::unordered_map<uint32_t, HeapBlock> m_live_blocks;           // payload -> block, m_heap_mutex

    // N2 diagnostic-only: freed blocks are filled with a pattern and remembered
    // until reuse; when a block comes back, the region beyond the freshly
    // zeroed payload is verified against the pattern, so any guest write into
    // the freed block between free and reuse is reported (pool-level
    // double-management detector).
    struct FreedFill { uint32_t payload; uint32_t fill_len; };
    std::unordered_map<uint32_t, FreedFill> m_freed_fills;           // base -> fill info, m_heap_mutex

    uint32_t m_stack_top    = 0x7F000000;
    std::uint64_t m_ticks_remaining = 0;
};
