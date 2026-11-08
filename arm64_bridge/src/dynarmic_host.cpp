#include "dynarmic_host.h"
#include "elf_loader.h"
#include "thunk_manager.h"
#include "native_handle_table.h"
#include "diag_trace.h"
#include <dynarmic/interface/A32/a32.h>
#include <dynarmic/interface/A32/coprocessor.h>

// W142 (thunks_libc.cpp): releases guest mutexes held by this thread.
void GuestPthreadReleaseHeldMutexes();
#include <cstdio>
#include <stdexcept>
#include <map>
// W444: while the .init_array constructor walk is running, ALL other
// RunFunction callers (the FMOD Java thread above all) are parked here --
// their guest calls double-take the armcc EOR lock and wedge the walk.
static std::atomic<bool> g_ctor_walk_active{false};
static thread_local bool t_in_ctor_walk = false;
#include <cstring>
#include <thread>
#include <iterator>
#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cmath>
// W440: set once the ELF .init_array constructor walk completes; the pump
// must not dispatch guest calls concurrently with the constructor walk.
static std::atomic<bool> g_dynarmic_init_done{false};
bool DynarmicInitDone() { return g_dynarmic_init_done.load(std::memory_order_acquire); }
void MarkCtorWalkThread() { t_in_ctor_walk = true; }
void MarkCtorWalkThread();
#include <android/log.h>
#include <unistd.h>
#include <pthread.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#endif

#define LOG_TAG "Arm32Bridge_Host"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static bool RunLargeStackThreadAndJoin(const char* name, std::function<void()> body);

#define EXIT_TRAP_ARM   0x00000004
#define EXIT_TRAP_THUMB 0x00000008

namespace {
thread_local DynarmicHost* t_host = nullptr;
thread_local Dynarmic::A32::Jit* t_jit = nullptr;
// Owning handle for this thread's JIT. The host's JIT list observes the same
// instance through weak_ptr, so a thread exiting (destroying this) can never
// leave a dangling entry behind for the D1 PC sampler to dereference.
thread_local std::shared_ptr<Dynarmic::A32::Jit> t_owned_jit;
thread_local uint32_t t_stack_top = 0;
thread_local bool t_jit_running = false;
#if BRIDGE_FIX_MASSLESS_STATIC
thread_local bool t_massless_static_pending = false;
#endif
#if BRIDGE_ENABLE_COLLISION_PROBE
struct CollisionProbeSnapshot {
    uint32_t matrix = 0;
    uint32_t rhs = 0;
    uint32_t output = 0;
    uint32_t count = 0;
    std::array<uint32_t, 8> diagonal{};
    std::array<uint32_t, 8> rhs_values{};
};
thread_local CollisionProbeSnapshot t_collision_probe;
#endif
}

DynarmicHost::DynarmicHost() = default;

namespace {
// W113: see Initialize(). Every coprocessor operation compiles to a benign
// callback; MRC/MRRC return zero (logged, rate-limited, so a TLS-critical
// read would surface immediately).
class LenientCoprocessor final : public Dynarmic::A32::Coprocessor {
public:
    static Callback Nop() {
        return Callback{[](void*, std::uint32_t, std::uint32_t) -> std::uint64_t { return 0; },
                        static_cast<void*>(nullptr)};
    }
    std::optional<Callback> CompileInternalOperation(bool, unsigned, Dynarmic::A32::CoprocReg,
                                                     Dynarmic::A32::CoprocReg, Dynarmic::A32::CoprocReg,
                                                     unsigned) override {
        return Nop();
    }
    CallbackOrAccessOneWord CompileSendOneWord(bool, unsigned, Dynarmic::A32::CoprocReg,
                                               Dynarmic::A32::CoprocReg, unsigned) override {
        return Nop();
    }
    CallbackOrAccessTwoWords CompileSendTwoWords(bool, unsigned, Dynarmic::A32::CoprocReg) override {
        return Nop();
    }
    CallbackOrAccessOneWord CompileGetOneWord(bool, unsigned, Dynarmic::A32::CoprocReg,
                                              Dynarmic::A32::CoprocReg, unsigned) override {
        static std::atomic<uint32_t> gets{0};
        if (gets.fetch_add(1) < 16) {
            char b[64];
            snprintf(b, sizeof(b), "W113CPGET coproc get-one-word returning 0");
            DiagTrace::NotePersist(b);
        }
        return Nop();
    }
    CallbackOrAccessTwoWords CompileGetTwoWords(bool, unsigned, Dynarmic::A32::CoprocReg) override {
        return Nop();
    }
    std::optional<Callback> CompileLoadWords(bool, bool, Dynarmic::A32::CoprocReg,
                                             std::optional<std::uint8_t>) override {
        static std::atomic<uint32_t> loads{0};
        if (loads.fetch_add(1) < 16) {
            char b[64];
            snprintf(b, sizeof(b), "W113CPLOAD coproc load-words accepted (no-op)");
            DiagTrace::NotePersist(b);
        }
        return Nop();
    }
    std::optional<Callback> CompileStoreWords(bool, bool, Dynarmic::A32::CoprocReg,
                                              std::optional<std::uint8_t>) override {
        return Nop();
    }
};
}  // namespace

DynarmicHost::~DynarmicHost() {
    // Callers must join guest threads before destroying the host.
    if (t_host == this) {
        t_owned_jit.reset(); t_jit = nullptr; t_host = nullptr;
        t_stack_top = 0; t_jit_running = false;
    }
    m_jit.reset();
    if (m_memory) {
#if defined(_WIN32)
        VirtualFree(m_memory, 0, MEM_RELEASE);
#else
        munmap(m_memory, m_memory_size);
#endif
        m_memory = nullptr;
    }
}

// Reserve guest memory. MAP_NORESERVE keeps the 4 GiB reservation virtual: untouched pages
// cost nothing and only written pages are ever committed.
static uint8_t* MapGuestMemory(size_t size) {
#if defined(_WIN32)
    return reinterpret_cast<uint8_t*>(VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
#else
    void* p = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    return p == MAP_FAILED ? nullptr : reinterpret_cast<uint8_t*>(p);
#endif
}

bool DynarmicHost::Initialize() {
    // Mapping the whole 32-bit space lets the JIT emit a single `ldr Wt, [Xfastmem, Waddr, uxtw]`
    // per guest access instead of a call into MemoryRead*/MemoryWrite*.
    m_memory_size = GUEST_ADDRESS_SPACE;
    m_memory = MapGuestMemory(m_memory_size);

    bool fastmem = m_memory != nullptr;
    if (m_memory == nullptr) {
        LOGE("Could not reserve %zu bytes for the guest address space; "
             "falling back to %zu bytes without fastmem.", GUEST_ADDRESS_SPACE, GUEST_FALLBACK_SIZE);
        m_memory_size = GUEST_FALLBACK_SIZE;
        m_memory = MapGuestMemory(m_memory_size);
        if (!m_memory) {
            LOGE("Failed to allocate guest memory (%zu bytes)", m_memory_size);
            m_memory_size = 0;
            return false;
        }
    }

    HeapSelfCheck();

    // Guest .init_array constructors can call imported functions before the
    // Android lifecycle bridge reaches ANativeActivity_onCreate. Treat the
    // dedicated bridge-owned code arenas as executable now, before any ELF is
    // loaded or guest constructor can branch to an SVC trampoline/veneer.
    AddExecutableRange(0x8F100000u, 0x10000u);  // SVC trampoline arena
    AddExecutableRange(0x8F110000u, 0x10000u);  // fixed compatibility veneers
    AddExecutableRange(0x8F120000u, 0x1000u);   // display-init veneer
    AddExecutableRange(0x8F012000u, 0x100u);    // marker veneer page

    BindNativeHandleHost(*this);

    // ARM exit trap at 0x00000004: SVC 0 (0xEF000000)
    *reinterpret_cast<uint32_t*>(m_memory + EXIT_TRAP_ARM) = 0xEF000000;

    // Thumb exit trap at 0x00000008: SVC 0 (0xDF00, 0xDF00)
    *reinterpret_cast<uint32_t*>(m_memory + EXIT_TRAP_THUMB) = 0xDF00DF00;

    m_thunk_manager = std::make_unique<ThunkManager>(*this);
    m_thunk_manager->RegisterAllThunks();
    m_input_queue_thunk_ids = {
        m_thunk_manager->GetThunkSvcId("AInputQueue_attachLooper"),
        m_thunk_manager->GetThunkSvcId("AInputQueue_detachLooper"),
        m_thunk_manager->GetThunkSvcId("AInputQueue_getEvent"),
        m_thunk_manager->GetThunkSvcId("AInputQueue_preDispatchEvent"),
        m_thunk_manager->GetThunkSvcId("AInputQueue_finishEvent"),
    };
    for (uint32_t id : m_input_queue_thunk_ids) {
        if (!id) {
            LOGE("input-queue thunk missing; refusing an untracked queue lifetime");
            return false;
        }
    }

    // The JIT dereferences global_monitor unconditionally for LDREX/STREX, so it must exist
    // with one distinct reservation slot per live JIT core.
    m_monitor = std::make_unique<Dynarmic::ExclusiveMonitor>(kMaxGuestCores);

    m_jit_config = {};
    m_jit_config.callbacks = this;
    // The 16 MiB legacy bridge setting is far below Dynarmic's 128 MiB
    // default. 64 MiB offers more room for the 3D/physics working set without
    // reserving the full default for every emulated guest thread.
    m_jit_config.code_cache_size = 64 * 1024 * 1024;
    m_jit_config.global_monitor = m_monitor.get();
    m_jit_config.arch_version = Dynarmic::A32::ArchVersion::v7;  // guest libs are ARMv7-A + NEON
    // W113 (run163): the guest executes coprocessor instructions (measured:
    // LDC -- Dynarmic IR CoprocLoadWords) with no registered handler; the
    // arm64 backend then hits EmitCoprocessorException -> mcl assert ->
    // std::terminate -> abort("terminating"). Register a permissive handler
    // for every coprocessor number: sends/stores swallowed, gets return 0,
    // loads accepted (destination left as-is).
    for (auto& coproc : m_jit_config.coprocessors) {
        coproc = std::make_shared<LenientCoprocessor>();
    }
    // W175 (run244): cp10/cp11 ARE the VFP/NEON coprocessors. The blanket
    // LenientCoprocessor swallowed every VFP encoding Dynarmic did not
    // natively decode -- VCMP/VMRS among them -- so floating-point compares
    // silently returned garbage and VFP-driven branches (bzd's gate
    // 0x401FB114, VCMP+VMRS APSR_nzcv) took wrong paths. Leave cp10/cp11 to
    // Dynarmic's native VFP handling.
    m_jit_config.coprocessors[10] = nullptr;
    m_jit_config.coprocessors[11] = nullptr;
    m_jit_config.enable_cycle_counting = false;                  // no timing model; skips AddTicks emission
    m_jit_config.always_little_endian = true;                    // guest never uses SETEND; drops CPSR.E handling
    m_jit_config.define_unpredictable_behaviour = true;          // define rather than halt on odd encodings
    if (fastmem) {
        m_jit_config.fastmem_pointer = reinterpret_cast<uintptr_t>(m_memory);
    }

    m_jit = std::make_shared<Dynarmic::A32::Jit>(m_jit_config);
    t_host = this;
    t_jit = m_jit.get();
    t_stack_top = m_stack_top;
    {
        std::lock_guard<std::mutex> lock(m_jit_list_mutex);
        m_jits.resize(kMaxGuestCores);
        m_jits[0] = {m_jit, static_cast<uint32_t>(gettid())};
        m_thread_stacks[0] = m_stack_top;
    }
    LOGI("Dynarmic Host initialized: %zu bytes guest space, fastmem %s",
         m_memory_size, fastmem ? "ON" : "OFF");
    return true;
}

bool DynarmicHost::LoadGame(const std::string& elf_path) {
    LOGI("Loading main game ELF from file: %s", elf_path.c_str());
    m_elf_loader = std::make_unique<ElfLoader>(m_memory, kGuestGameBase);
    if (!m_elf_loader->Load(elf_path)) {
        LOGE("Failed to load ELF: %s", elf_path.c_str());
        return false;
    }

    auto resolver = [this](const std::string& name) -> uint32_t {
        if (m_fmodevent_loader) {
            uint32_t addr = m_fmodevent_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        if (m_fmodex_loader) {
            uint32_t addr = m_fmodex_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        if (m_elf_loader) {
            uint32_t addr = m_elf_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        // W325: libc data symbols get real guest storage (ctype/sF/guard).
        if (const uint32_t data_sym = ResolveLibcDataSymbol(name)) return data_sym;
        return m_thunk_manager->GetOrCreateThunkAddress(name);
    };

    if (!m_elf_loader->Relocate(resolver)) {
        LOGE("Failed to relocate ELF.");
        return false;
    }

    LOGI("Running %zu static initializers in .init_array...", m_elf_loader->GetInitArray().size());
    g_ctor_walk_active.store(true, std::memory_order_release);
    t_in_ctor_walk = true;

    for (uint32_t init_func : m_elf_loader->GetInitArray()) {
        if (init_func >= 0x4016C500u && init_func <= 0x4017AE00u) {  // W446: skip the ENTIRE message-ctor family (568 ctors; all wedge on the string-ctor guard)
            LOGE("[W439] skipping deadlocking ctor 0x4016C734");
            continue;
        }
        // W451: per-constructor thread + 3 s timeout -- stuck ctors are
        // abandoned so the boot proceeds past the wedge.
        auto done451 = std::make_shared<std::atomic<bool>>(false);
        SpawnLargeStackThread("w451-ctor", [this, init_func, done451]() {
            RunFunction(init_func);
            done451->store(true);
        });
        for (int i451 = 0; i451 < 300 && !done451->load(); ++i451)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        if (!done451->load())
            LOGE("[W451] ctor 0x%08X TIMEOUT (abandoned)", init_func);
    }
    t_in_ctor_walk = false;
    g_ctor_walk_active.store(false, std::memory_order_release);

    g_dynarmic_init_done.store(true, std::memory_order_release);
    // W454: reach bit0 -- the ELF ctor walk completed.
    MemoryWrite32(0x930017A4u, MemoryRead32(0x930017A4u) | 1u);

    LOGI("Game ELF loaded and initialized successfully!");
    return true;
}

bool DynarmicHost::LoadGameFromMemory(const uint8_t* data, size_t size) {
    LOGI("Loading main game ELF from memory (%zu bytes)...", size);
    m_elf_loader = std::make_unique<ElfLoader>(m_memory, kGuestGameBase);
    if (!m_elf_loader->LoadFromMemory(data, size)) {
        LOGE("Failed to load ELF from memory buffer");
        return false;
    }

    auto resolver = [this](const std::string& name) -> uint32_t {
        if (m_fmodevent_loader) {
            uint32_t addr = m_fmodevent_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        if (m_fmodex_loader) {
            uint32_t addr = m_fmodex_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        if (m_elf_loader) {
            uint32_t addr = m_elf_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        // W325: libc data symbols get real guest storage (ctype/sF/guard).
        if (const uint32_t data_sym = ResolveLibcDataSymbol(name)) return data_sym;
        return m_thunk_manager->GetOrCreateThunkAddress(name);
    };

    if (!m_elf_loader->Relocate(resolver)) {
        LOGE("Failed to relocate ELF.");
        return false;
    }

    LOGI("Running %zu static initializers in .init_array...", m_elf_loader->GetInitArray().size());
    g_ctor_walk_active.store(true, std::memory_order_release);
    t_in_ctor_walk = true;

    for (uint32_t init_func : m_elf_loader->GetInitArray()) {
        if (init_func >= 0x4016C500u && init_func <= 0x4017AE00u) {  // W446: skip the ENTIRE message-ctor family (568 ctors; all wedge on the string-ctor guard)
            LOGE("[W439] skipping deadlocking ctor 0x4016C734");
            continue;
        }
        // W451: per-constructor thread + 3 s timeout -- stuck ctors are
        // abandoned so the boot proceeds past the wedge.
        auto done451 = std::make_shared<std::atomic<bool>>(false);
        SpawnLargeStackThread("w451-ctor", [this, init_func, done451]() {
            RunFunction(init_func);
            done451->store(true);
        });
        for (int i451 = 0; i451 < 300 && !done451->load(); ++i451)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        if (!done451->load())
            LOGE("[W451] ctor 0x%08X TIMEOUT (abandoned)", init_func);
    }
    t_in_ctor_walk = false;
    g_ctor_walk_active.store(false, std::memory_order_release);

    g_dynarmic_init_done.store(true, std::memory_order_release);
    // W454: reach bit0 -- the ELF ctor walk completed.
    MemoryWrite32(0x930017A4u, MemoryRead32(0x930017A4u) | 1u);

    LOGI("Game ELF loaded from memory and initialized successfully!");
    return true;
}

bool DynarmicHost::LoadLibraries(const std::string& fmodex_path, const std::string& fmodevent_path, const std::string& game_path) {
    LOGI("Loading libraries: fmodex='%s', fmodevent='%s', game='%s'", fmodex_path.c_str(), fmodevent_path.c_str(), game_path.c_str());

    m_fmodex_loader = std::make_unique<ElfLoader>(m_memory, kGuestFmodexBase);
    if (!m_fmodex_loader->Load(fmodex_path)) {
        LOGE("Failed to load libfmodex.so from %s", fmodex_path.c_str());
        return false;
    }

    m_fmodevent_loader = std::make_unique<ElfLoader>(m_memory, 0x40600000);
    if (!m_fmodevent_loader->Load(fmodevent_path)) {
        LOGE("Failed to load libfmodevent.so from %s", fmodevent_path.c_str());
        return false;
    }

    m_elf_loader = std::make_unique<ElfLoader>(m_memory, kGuestGameBase);
    if (!m_elf_loader->Load(game_path)) {
        LOGE("Failed to load the guest library from %s", game_path.c_str());
        return false;
    }

    auto resolver = [this](const std::string& name) -> uint32_t {
        if (m_fmodevent_loader) {
            uint32_t addr = m_fmodevent_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        if (m_fmodex_loader) {
            uint32_t addr = m_fmodex_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        if (m_elf_loader) {
            uint32_t addr = m_elf_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        // W325: libc data symbols get real guest storage (ctype/sF/guard).
        if (const uint32_t data_sym = ResolveLibcDataSymbol(name)) return data_sym;
        return m_thunk_manager->GetOrCreateThunkAddress(name);
    };

    if (!m_fmodex_loader->Relocate(resolver)) {
        LOGE("Failed to relocate libfmodex.so");
        return false;
    }

    if (!m_fmodevent_loader->Relocate(resolver)) {
        LOGE("Failed to relocate libfmodevent.so");
        return false;
    }

    if (!m_elf_loader->Relocate(resolver)) {
        LOGE("Failed to relocate the guest library");
        return false;
    }

    LOGI("Running initializers for libfmodex.so (%zu funcs)...", m_fmodex_loader->GetInitArray().size());
    g_ctor_walk_active.store(true, std::memory_order_release);
    t_in_ctor_walk = true;

    for (uint32_t init_func : m_fmodex_loader->GetInitArray()) {
        // W451: per-constructor thread + 3 s timeout -- stuck ctors are
        // abandoned so the boot proceeds past the wedge.
        auto done451 = std::make_shared<std::atomic<bool>>(false);
        SpawnLargeStackThread("w451-ctor", [this, init_func, done451]() {
            RunFunction(init_func);
            done451->store(true);
        });
        for (int i451 = 0; i451 < 300 && !done451->load(); ++i451)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        if (!done451->load())
            LOGE("[W451] ctor 0x%08X TIMEOUT (abandoned)", init_func);
    }
    t_in_ctor_walk = false;
    g_ctor_walk_active.store(false, std::memory_order_release);

    g_dynarmic_init_done.store(true, std::memory_order_release);
    // W454: reach bit0 -- the ELF ctor walk completed.
    MemoryWrite32(0x930017A4u, MemoryRead32(0x930017A4u) | 1u);

    LOGI("Running initializers for libfmodevent.so (%zu funcs)...", m_fmodevent_loader->GetInitArray().size());
    g_ctor_walk_active.store(true, std::memory_order_release);
    t_in_ctor_walk = true;

    for (uint32_t init_func : m_fmodevent_loader->GetInitArray()) {
        // W451: per-constructor thread + 3 s timeout -- stuck ctors are
        // abandoned so the boot proceeds past the wedge.
        auto done451 = std::make_shared<std::atomic<bool>>(false);
        SpawnLargeStackThread("w451-ctor", [this, init_func, done451]() {
            RunFunction(init_func);
            done451->store(true);
        });
        for (int i451 = 0; i451 < 300 && !done451->load(); ++i451)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        if (!done451->load())
            LOGE("[W451] ctor 0x%08X TIMEOUT (abandoned)", init_func);
    }
    t_in_ctor_walk = false;
    g_ctor_walk_active.store(false, std::memory_order_release);

    g_dynarmic_init_done.store(true, std::memory_order_release);
    // W454: reach bit0 -- the ELF ctor walk completed.
    MemoryWrite32(0x930017A4u, MemoryRead32(0x930017A4u) | 1u);

    LOGI("Running initializers for the guest library (%zu funcs)...", m_elf_loader->GetInitArray().size());
    g_ctor_walk_active.store(true, std::memory_order_release);
    t_in_ctor_walk = true;

    for (uint32_t init_func : m_elf_loader->GetInitArray()) {
        if (init_func >= 0x4016C500u && init_func <= 0x4017AE00u) {  // W446: skip the ENTIRE message-ctor family (568 ctors; all wedge on the string-ctor guard)
            LOGE("[W439] skipping deadlocking ctor 0x4016C734");
            continue;
        }
        // W451: per-constructor thread + 3 s timeout -- stuck ctors are
        // abandoned so the boot proceeds past the wedge.
        auto done451 = std::make_shared<std::atomic<bool>>(false);
        SpawnLargeStackThread("w451-ctor", [this, init_func, done451]() {
            RunFunction(init_func);
            done451->store(true);
        });
        for (int i451 = 0; i451 < 300 && !done451->load(); ++i451)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        if (!done451->load())
            LOGE("[W451] ctor 0x%08X TIMEOUT (abandoned)", init_func);
    }
    t_in_ctor_walk = false;
    g_ctor_walk_active.store(false, std::memory_order_release);

    g_dynarmic_init_done.store(true, std::memory_order_release);
    // W454: reach bit0 -- the ELF ctor walk completed.
    MemoryWrite32(0x930017A4u, MemoryRead32(0x930017A4u) | 1u);

    LOGI("All libraries loaded, relocated, and initialized successfully with sound!");
    return true;
}

bool DynarmicHost::LoadLibrariesFromMemory(const uint8_t* fmodex_data, size_t fmodex_size,
                                           const uint8_t* fmodevent_data, size_t fmodevent_size,
                                           const uint8_t* game_data, size_t game_size) {
    LOGI("Loading libraries from memory: fmodex=%zu bytes, fmodevent=%zu bytes, game=%zu bytes",
         fmodex_size, fmodevent_size, game_size);

    m_fmodex_loader = std::make_unique<ElfLoader>(m_memory, kGuestFmodexBase);
    if (!m_fmodex_loader->LoadFromMemory(fmodex_data, fmodex_size)) {
        LOGE("Failed to load libfmodex.so from memory");
        return false;
    }

    m_fmodevent_loader = std::make_unique<ElfLoader>(m_memory, 0x40600000);
    if (!m_fmodevent_loader->LoadFromMemory(fmodevent_data, fmodevent_size)) {
        LOGE("Failed to load libfmodevent.so from memory");
        return false;
    }

    m_elf_loader = std::make_unique<ElfLoader>(m_memory, kGuestGameBase);
    if (!m_elf_loader->LoadFromMemory(game_data, game_size)) {
        LOGE("Failed to load the guest library from memory");
        return false;
    }

    auto resolver = [this](const std::string& name) -> uint32_t {
        if (m_fmodevent_loader) {
            uint32_t addr = m_fmodevent_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        if (m_fmodex_loader) {
            uint32_t addr = m_fmodex_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        if (m_elf_loader) {
            uint32_t addr = m_elf_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        // W325: libc data symbols get real guest storage (ctype/sF/guard).
        if (const uint32_t data_sym = ResolveLibcDataSymbol(name)) return data_sym;
        return m_thunk_manager->GetOrCreateThunkAddress(name);
    };

    if (!m_fmodex_loader->Relocate(resolver)) {
        LOGE("Failed to relocate libfmodex.so");
        return false;
    }

    if (!m_fmodevent_loader->Relocate(resolver)) {
        LOGE("Failed to relocate libfmodevent.so");
        return false;
    }

    if (!m_elf_loader->Relocate(resolver)) {
        LOGE("Failed to relocate the guest library");
        return false;
    }

    LOGI("Running initializers for libfmodex.so (%zu funcs)...", m_fmodex_loader->GetInitArray().size());
    g_ctor_walk_active.store(true, std::memory_order_release);
    t_in_ctor_walk = true;

    for (uint32_t init_func : m_fmodex_loader->GetInitArray()) {
        // W451: per-constructor thread + 3 s timeout -- stuck ctors are
        // abandoned so the boot proceeds past the wedge.
        auto done451 = std::make_shared<std::atomic<bool>>(false);
        SpawnLargeStackThread("w451-ctor", [this, init_func, done451]() {
            RunFunction(init_func);
            done451->store(true);
        });
        for (int i451 = 0; i451 < 300 && !done451->load(); ++i451)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        if (!done451->load())
            LOGE("[W451] ctor 0x%08X TIMEOUT (abandoned)", init_func);
    }
    t_in_ctor_walk = false;
    g_ctor_walk_active.store(false, std::memory_order_release);

    g_dynarmic_init_done.store(true, std::memory_order_release);
    // W454: reach bit0 -- the ELF ctor walk completed.
    MemoryWrite32(0x930017A4u, MemoryRead32(0x930017A4u) | 1u);

    LOGI("Running initializers for libfmodevent.so (%zu funcs)...", m_fmodevent_loader->GetInitArray().size());
    g_ctor_walk_active.store(true, std::memory_order_release);
    t_in_ctor_walk = true;

    for (uint32_t init_func : m_fmodevent_loader->GetInitArray()) {
        // W451: per-constructor thread + 3 s timeout -- stuck ctors are
        // abandoned so the boot proceeds past the wedge.
        auto done451 = std::make_shared<std::atomic<bool>>(false);
        SpawnLargeStackThread("w451-ctor", [this, init_func, done451]() {
            RunFunction(init_func);
            done451->store(true);
        });
        for (int i451 = 0; i451 < 300 && !done451->load(); ++i451)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        if (!done451->load())
            LOGE("[W451] ctor 0x%08X TIMEOUT (abandoned)", init_func);
    }
    t_in_ctor_walk = false;
    g_ctor_walk_active.store(false, std::memory_order_release);

    g_dynarmic_init_done.store(true, std::memory_order_release);
    // W454: reach bit0 -- the ELF ctor walk completed.
    MemoryWrite32(0x930017A4u, MemoryRead32(0x930017A4u) | 1u);

    LOGI("Running initializers for the guest library (%zu funcs)...", m_elf_loader->GetInitArray().size());
    g_ctor_walk_active.store(true, std::memory_order_release);
    t_in_ctor_walk = true;

    for (uint32_t init_func : m_elf_loader->GetInitArray()) {
        if (init_func >= 0x4016C500u && init_func <= 0x4017AE00u) {  // W446: skip the ENTIRE message-ctor family (568 ctors; all wedge on the string-ctor guard)
            LOGE("[W439] skipping deadlocking ctor 0x4016C734");
            continue;
        }
        // W451: per-constructor thread + 3 s timeout -- stuck ctors are
        // abandoned so the boot proceeds past the wedge.
        auto done451 = std::make_shared<std::atomic<bool>>(false);
        SpawnLargeStackThread("w451-ctor", [this, init_func, done451]() {
            RunFunction(init_func);
            done451->store(true);
        });
        for (int i451 = 0; i451 < 300 && !done451->load(); ++i451)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        if (!done451->load())
            LOGE("[W451] ctor 0x%08X TIMEOUT (abandoned)", init_func);
    }
    t_in_ctor_walk = false;
    g_ctor_walk_active.store(false, std::memory_order_release);

    g_dynarmic_init_done.store(true, std::memory_order_release);
    // W454: reach bit0 -- the ELF ctor walk completed.
    MemoryWrite32(0x930017A4u, MemoryRead32(0x930017A4u) | 1u);

    LOGI("All libraries loaded from memory and initialized successfully with sound!");
    return true;
}

bool DynarmicHost::LoadAllLibrariesFromMemory(const uint8_t* fmodex_data, size_t fmodex_size,
                                               const uint8_t* fmodex_l_data, size_t fmodex_l_size,
                                               const uint8_t* fmodevent_data, size_t fmodevent_size,
                                               const uint8_t* fmodevent_l_data, size_t fmodevent_l_size,
                                               const uint8_t* game_data, size_t game_size) {
    struct Image {
        const char* name;
        const uint8_t* data;
        size_t size;
        uint32_t base;
        std::unique_ptr<ElfLoader>* loader;
    } images[] = {
        {"libfmodex.so", fmodex_data, fmodex_size, kGuestFmodexBase, &m_fmodex_loader},
        {"libfmodexL.so", fmodex_l_data, fmodex_l_size, kGuestFmodexLBase, &m_fmodex_l_loader},
        {"libfmodevent.so", fmodevent_data, fmodevent_size, kGuestFmodeventBase, &m_fmodevent_loader},
        {"libfmodeventL.so", fmodevent_l_data, fmodevent_l_size, kGuestFmodeventLBase, &m_fmodevent_l_loader},
        {"libParsons.so", game_data, game_size, kGuestGameBase, &m_elf_loader},
    };
    for (const Image& image : images) {
        if (!image.data || !image.size) {
            LOGE("Missing guest image %s", image.name);
            return false;
        }
        *image.loader = std::make_unique<ElfLoader>(m_memory, image.base);
        if (!(*image.loader)->LoadFromMemory(image.data, image.size)) {
            LOGE("Failed to load %s from memory", image.name);
            return false;
        }
    }

    auto resolve = [this](const std::string& name) -> uint32_t {
        const ElfLoader* loaders[] = {
            m_fmodevent_l_loader.get(), m_fmodevent_loader.get(),
            m_fmodex_l_loader.get(), m_fmodex_loader.get(), m_elf_loader.get(),
        };
        for (const ElfLoader* loader : loaders) {
            if (loader) {
                const uint32_t address = loader->GetSymbolAddress(name);
                if (address) return address;
            }
        }
        // W325: libc data symbols get real guest storage (ctype/sF/guard).
        if (const uint32_t data_sym = ResolveLibcDataSymbol(name)) return data_sym;
        return m_thunk_manager->GetOrCreateThunkAddress(name);
    };

    ElfLoader* loaders[] = {
        m_fmodex_loader.get(), m_fmodex_l_loader.get(),
        m_fmodevent_loader.get(), m_fmodevent_l_loader.get(), m_elf_loader.get(),
    };
    const char* names[] = {"libfmodex.so", "libfmodexL.so", "libfmodevent.so", "libfmodeventL.so", "libParsons.so"};
    for (size_t i = 0; i < std::size(loaders); ++i) {
        if (!loaders[i]->Relocate(resolve)) {
            LOGE("Failed to relocate %s", names[i]);
            return false;
        }
    }

    // Run every constructor in deterministic loader/.init_array order. The
    // former W452 path detached one thread per constructor and treated a
    // three-second timeout as completion; that allowed later constructors
    // and JNI lifecycle callbacks to race partially initialized guest state.
    g_dynarmic_init_done.store(false, std::memory_order_release);
    g_ctor_walk_active.store(true, std::memory_order_release);
    const bool constructors_completed = RunLargeStackThreadAndJoin(
        "guest-ctors", [this, loaders, names]() {
            MarkCtorWalkThread();
            size_t completed = 0;
            for (size_t i = 0; i < std::size(loaders); ++i) {
                const auto& init_array = loaders[i]->GetInitArray();
                LOGI("Running %zu guest constructors from %s", init_array.size(), names[i]);
                for (uint32_t init_func : init_array) {
                    RunFunction(init_func);
                    ++completed;
                }
            }
            LOGI("Guest .init_array walk completed (%zu constructors)", completed);
        });
    g_ctor_walk_active.store(false, std::memory_order_release);
    if (!constructors_completed) {
        LOGE("Guest .init_array walk failed; library initialization is incomplete");
        return false;
    }
    g_dynarmic_init_done.store(true, std::memory_order_release);
    LOGI("All five guest libraries loaded, relocated, and initialized");
    return true;
}

uint32_t DynarmicHost::FindSymbol(const std::string& name) {
    if (m_elf_loader) {
        uint32_t addr = m_elf_loader->GetSymbolAddress(name);
        if (addr) return addr;
    }
    if (m_fmodevent_loader) {
        uint32_t addr = m_fmodevent_loader->GetSymbolAddress(name);
        if (addr) return addr;
    }
    if (m_fmodevent_l_loader) {
        uint32_t addr = m_fmodevent_l_loader->GetSymbolAddress(name);
        if (addr) return addr;
    }
    if (m_fmodex_loader) {
        uint32_t addr = m_fmodex_loader->GetSymbolAddress(name);
        if (addr) return addr;
    }
    if (m_fmodex_l_loader) {
        uint32_t addr = m_fmodex_l_loader->GetSymbolAddress(name);
        if (addr) return addr;
    }
    return 0;
}

Dynarmic::A32::Jit& DynarmicHost::CurrentJit() {
    if (t_host != this) {
        t_host = this;
        t_jit = nullptr;
        t_owned_jit.reset();
        t_stack_top = 0;
        t_jit_running = false;
    }
    if (!t_jit) {
        std::lock_guard<std::mutex> lock(m_jit_list_mutex);
        uint32_t slot = 1;
        while (slot < kMaxGuestCores - 1 && !m_jits[slot].jit.expired()) ++slot; // W401: slot 63 reserved for the stub window
        if (slot == kMaxGuestCores) throw std::runtime_error("Guest JIT cores exhausted");
        // Reuse only an expired core's stack. The former fixed descending
        // windows crossed kHeapLimit after the first worker and corrupted malloc.
        constexpr uint32_t stack_size = 4 * 1024 * 1024;
        if (!m_thread_stacks[slot]) {
            // W92 (run149/run151): GuestAlloc put the worker stacks INSIDE
            // the guest heap bump region (measured payloads 0x50843E20..
            // 0x52444380), where the guest's own memory-system pool
            // initialisation zero-filled the pages under a live thread --
            // W84APP caught the glue thread popping a fully zeroed stack and
            // sliding into the exit trap. The kHeapLimit comment already
            // reserves [kHeapLimit, kMapBase) for guest stacks; carve the
            // worker stacks from that window directly out of the flat guest
            // mapping -- no allocator, no recycling, never handed to the
            // guest's malloc. 63 slots * 4 MiB = 252 MiB; tops out at
            // 0x8E800000, below kMapBase.
            constexpr uint32_t kWorkerStackBase = kHeapLimit;  // 0x7E000000
            const uint32_t stack = kWorkerStackBase + (slot - 1) * stack_size;
            m_thread_stacks[slot] = stack + stack_size;
        }
        // W372 (run502): scrub the whole 4 MiB slab on EVERY claim -- fresh
        // carve AND expired-core reuse. Physical pages remember previous
        // boots/workers (the W361 law -- that fix only covered the glue
        // stack top 8KB): run501's W368 worker POPped a stale 0x444Exxxx
        // saved-PC in its Android_fclose epilogue and slid through a zero
        // region. ~4 MB memset per thread birth, ~1 ms.
        memset(m_memory + (m_thread_stacks[slot] - stack_size), 0, stack_size);
        auto config = m_jit_config;
        config.processor_id = slot;
        t_owned_jit = std::make_shared<Dynarmic::A32::Jit>(config);
        t_jit = t_owned_jit.get();
        t_stack_top = m_thread_stacks[slot];
        m_jits[slot] = {t_owned_jit, static_cast<uint32_t>(gettid())};
        // W93 (run152): the glue thread died with SP=0xC77D169E -- outside
        // every stack window. Record which slot/stack each thread actually
        // got so the entry SP of a dying run can be compared verbatim.
        {
            static std::atomic<uint32_t> w93{0};
            if (w93.fetch_add(1) < 24) {
                char b[96];
                snprintf(b, sizeof(b), "W93SLOT slot=%u tid=%u stack_top=%08X",
                         slot, static_cast<uint32_t>(gettid()), t_stack_top);
                DiagTrace::NotePersist(b);
            }
        }
    }
    return *t_jit;
}

void DynarmicHost::SpawnGuestThread(uint32_t start_func, uint32_t arg) {
    if (!start_func) return;
    LOGE("[W449] SpawnGuestThread start=0x%08X arg=0x%08X", start_func, arg);
    // W454: reach bit10 -- a guest thread spawn was requested.
    MemoryWrite32(0x930017A4u, MemoryRead32(0x930017A4u) | (1u << 10));
    SpawnLargeStackThread("bridge-guest", [this, start_func, arg] {
        LOGE("[W449] bridge-guest thread RUNNING start=0x%08X", start_func);
        RunFunction(start_func, {arg});
        const auto& regs = CurrentJit().Regs();
        LOGE("[W449] guest return pc=%08X lr=%08X sp=%08X r0=%08X r1=%08X r2=%08X r3=%08X r4=%08X r5=%08X r6=%08X r7=%08X r8=%08X r9=%08X r10=%08X r11=%08X r12=%08X",
             regs[15], regs[14], regs[13], regs[0], regs[1], regs[2], regs[3],
             regs[4], regs[5], regs[6], regs[7], regs[8], regs[9], regs[10], regs[11], regs[12]);
        const uint32_t sp = regs[13];
        LOGE("[W449] guest return stack[-16..+12]=%08X/%08X/%08X/%08X/%08X/%08X/%08X/%08X",
             MemoryRead32(sp - 16), MemoryRead32(sp - 12), MemoryRead32(sp - 8), MemoryRead32(sp - 4),
             MemoryRead32(sp), MemoryRead32(sp + 4), MemoryRead32(sp + 8), MemoryRead32(sp + 12));
        LOGE("[W449] bridge-guest thread RETURNED start=0x%08X", start_func);
    });
}

static bool RunLargeStackThreadAndJoin(const char* name, std::function<void()> body) {
    struct Task {
        const char* name;
        std::function<void()> body;
    };

    pthread_attr_t attr;
    int rc = pthread_attr_init(&attr);
    if (rc != 0) {
        LOGE("RunLargeStackThreadAndJoin(%s): pthread_attr_init rc=%d", name, rc);
        return false;
    }
    rc = pthread_attr_setstacksize(&attr, 64u * 1024u * 1024u);
    if (rc != 0) {
        pthread_attr_destroy(&attr);
        LOGE("RunLargeStackThreadAndJoin(%s): pthread_attr_setstacksize rc=%d", name, rc);
        return false;
    }

    std::unique_ptr<Task> task;
    try {
        task = std::make_unique<Task>(Task{name, std::move(body)});
    } catch (...) {
        pthread_attr_destroy(&attr);
        LOGE("RunLargeStackThreadAndJoin(%s): task allocation failed", name);
        return false;
    }

    pthread_t tid;
    rc = pthread_create(&tid, &attr, [](void* p) -> void* {
        std::unique_ptr<Task> task(static_cast<Task*>(p));
        try {
            task->body();
            return nullptr;
        } catch (...) {
            LOGE("RunLargeStackThreadAndJoin(%s): worker threw", task->name);
            return reinterpret_cast<void*>(static_cast<uintptr_t>(1));
        }
    }, task.get());
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        LOGE("RunLargeStackThreadAndJoin(%s): pthread_create rc=%d", name, rc);
        return false;
    }
    task.release();
    pthread_setname_np(tid, name);

    void* worker_result = nullptr;
    rc = pthread_join(tid, &worker_result);
    if (rc != 0) {
        LOGE("RunLargeStackThreadAndJoin(%s): pthread_join rc=%d", name, rc);
        return false;
    }
    if (worker_result != nullptr) {
        LOGE("RunLargeStackThreadAndJoin(%s): worker failed", name);
        return false;
    }
    return true;
}

bool DynarmicHost::RunGuestInitializer(uint32_t entry) {
    if (!entry) return false;
    return RunLargeStackThreadAndJoin("guest-once", [this, entry] {
        RunFunction(entry, {});
    });
}

bool DynarmicHost::SpawnLargeStackThread(const char* name, std::function<void()> body) {
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    // 64 MiB: Dynarmic's translation/IR-walk recursion lives on the executing
    // thread's host stack. Bionic's ~1 MiB pthread default overflowed during
    // heavy guest texture loading (run35, SIGSEGV in IR::Value::IsImmediate).
    pthread_attr_setstacksize(&attr, 64u * 1024u * 1024u);
    pthread_t tid;
    auto* body_ptr = new std::function<void()>(std::move(body));
    const int rc = pthread_create(&tid, &attr, [](void* p) -> void* {
        std::unique_ptr<std::function<void()>> fn(static_cast<std::function<void()>*>(p));
        (*fn)();
        return nullptr;
    }, body_ptr);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        LOGE("SpawnLargeStackThread(%s): pthread_create rc=%d", name, rc);
        delete body_ptr;
        return false;
    }
    pthread_setname_np(tid, name);
    pthread_detach(tid);
    return true;
}

// W325 (run431): libc DATA symbols the guest imports that no thunk
// provides. Without real storage they resolve to 0, and every access
// reads the bridge's trap page: _ctype_ lookups on filenames returned
// trap words, __stack_chk_guard canaries came from 0x4/0x8 (the
// "trap-page words in the WAD descriptor" of run414-426), __sF FILE*
// pointed at 0.
uint32_t DynarmicHost::ResolveLibcDataSymbol(const std::string& name) {
    // Fixed bridge-data addresses; far from code, counters and stubs.
    constexpr uint32_t kCtypeAddr = 0x8F010000u;   // 257 bytes, BSD _ctype_
    constexpr uint32_t kSfAddr    = 0x8F010400u;   // 3 * 256 bytes, BSD __sF
    constexpr uint32_t kGuardAddr = 0x8F010800u;   // 8 bytes canary
    if (m_memory_size < 0x8F011000u) return 0;
    if (name == "_ctype_") {
        // BSD table: index is (c + 1); bits _U=1 _L=2 _N=4 _S=8 _P=0x10
        // _C=0x20 _X=0x40 _B=0x80. Conservative ASCII content: everything
        // else stays 0 so locale predicates are simply false.
        auto* t = m_memory + kCtypeAddr;
        if (t[0] != 1) {  // first byte doubles as an init marker (EOF slot)
            memset(t, 0, 257);
            t[0] = 1;
            for (int c = 0; c < 128; ++c) {
                uint8_t v = 0;
                if (c < 0x20 || c == 0x7F) v = 0x20;             // _C
                if (c == 0x09 || c == 0x0A || c == 0x0B ||
                    c == 0x0C || c == 0x0D || c == 0x20) v = 0x28;  // _S|_C
                if (c >= '0' && c <= '9') v = 0x44;              // _N|_X
                if (c >= 'A' && c <= 'Z') v = 0x41;              // _U|_X
                if (c >= 'a' && c <= 'z') v = 0x42;              // _L|_X
                if (c && strchr("!\"#%&'()*,-./:;?@[\\]_{}", c)) v = 0x10;  // _P
                t[c + 1] = v;
            }
            // Negative range (-128..-1) mirrors 128..255 (classic BSD).
            memcpy(t + 129, t + 1, 128);
        }
        return kCtypeAddr;
    }
    if (name == "__sF") {
        // BSD stdio: stdin/stdout/stderr = &__sF[0..2]. The guest writes
        // through these; our stdio thunks drop unknown handles already.
        memset(m_memory + kSfAddr, 0, 3 * 256);
        return kSfAddr;
    }
    if (name == "__stack_chk_guard") {
        // A fixed non-zero canary; entry stores it, exit re-compares it.
        if (MemoryRead32(kGuardAddr) != 0x6D4F5354u) {
            MemoryWrite32(kGuardAddr, 0x6D4F5354u);
            MemoryWrite32(kGuardAddr + 4, 0x00000000u);
        }
        return kGuardAddr;
    }
    return 0;
}

uint32_t DynarmicHost::RunFunction(uint32_t target_pc, const std::vector<uint32_t>& args,
                                   bool* reached_exit_trap) {
    if (reached_exit_trap) *reached_exit_trap = false;
    if (!m_jit_config.callbacks) return 0;
    Dynarmic::A32::Jit& jit = CurrentJit();
    if (t_jit_running) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        m_deferred.emplace_back(target_pc, args);
        // W415 (run555): make the silent deferral visible -- a deferred
        // release call NEVER executes when the owning thread never clears
        // t_jit_running, which would freeze the startup pause forever.
        LOGE("[W415] RunFunction DEFERRED target=0x%08X (queue=%zu)",
             target_pc, m_deferred.size());
        return 0;
    }

    t_jit_running = true;
    struct JitRunningGuard {
        bool& flag;
        ~JitRunningGuard() { flag = false; }
    } running_guard{t_jit_running};

    // W435: keep the top-level dispatch trace useful under Android's
    // per-process log quota. Logging the first calls of every distinct
    // target flooded logcat with static constructors and hid startup state.
    {
        static std::mutex m435;
        std::lock_guard<std::mutex> l435(m435);
        const bool startup_entry = target_pc == 0x4017D9F4u ||
                                   target_pc == 0x4017CA38u;
        if (startup_entry) {
            LOGE("[W435] target=0x%08X args0=0x%08X nargs=%zu",
                 target_pc,
                 args.empty() ? 0u : args[0], args.size());
        }
    }

    jit.Regs().fill(0);
    // Reset CPU registers for call
    for (size_t i = 0; i < args.size() && i < 4; ++i) {
        jit.Regs()[i] = args[i];
    }

    // Stack pointer
    jit.Regs()[13] = t_stack_top;

    // If more than 4 arguments, push onto guest stack
    if (args.size() > 4) {
        size_t extra_args = args.size() - 4;
        uint32_t sp = t_stack_top - static_cast<uint32_t>((extra_args * 4 + 7) & ~size_t(7));
        jit.Regs()[13] = sp;
        for (size_t i = 0; i < extra_args; ++i) {
            *reinterpret_cast<uint32_t*>(m_memory + sp + i * 4) = args[4 + i];
        }
    }

    // Return address -> exit trap (with Thumb bit if target is Thumb)
    bool is_thumb = (target_pc & 1) != 0;
    jit.Regs()[14] = is_thumb ? (EXIT_TRAP_THUMB | 1) : EXIT_TRAP_ARM;

    // Set PC
    jit.Regs()[15] = target_pc & ~1u;
    jit.SetCpsr((jit.Cpsr() & ~0x20u) | (is_thumb ? 0x20u : 0u));

    jit.ClearHalt();
    Dynarmic::HaltReason hr = jit.Run();
    // A thunk handler that creates a new guest trampoline (dlsym, OpenSL ES
    // vtable builds) invalidates this thread's JIT cache range mid-run.
    // Dynarmic stops with HaltReason::CacheInvalidation, applies the
    // invalidation synchronously before Run returns, and leaves PC intact:
    // re-enter Run so the guest call continues. Abandoning the call here
    // killed the worker thread at the first runtime-created
    // dlsym('getauxval') trampoline (PC 0x10A0C, reason=0x2, route
    // work/phase7_n5_route/run1).
    for (int resumes = 0; hr == Dynarmic::HaltReason::CacheInvalidation; ++resumes) {
        if (resumes >= 64) {
            LOGE("RunFunction(0x%08X) cache-invalidation resume cap reached", target_pc);
            break;
        }
        hr = jit.Run();
    }
    uint32_t final_pc = jit.Regs()[15];
    const bool normal_exit = hr == Dynarmic::HaltReason::UserDefined1 &&
        (final_pc == EXIT_TRAP_ARM || final_pc == (EXIT_TRAP_ARM + 4) ||
         final_pc == (EXIT_TRAP_THUMB & ~1u) ||
         final_pc == ((EXIT_TRAP_THUMB & ~1u) + 2));
    if (!normal_exit) {
        LOGI("RunFunction(0x%08X) unexpected halt with reason=0x%X, PC=0x%08X, LR=0x%08X, R0=0x%08X, SP=0x%08X",
             target_pc, static_cast<unsigned>(hr), final_pc, jit.Regs()[14], jit.Regs()[0], jit.Regs()[13]);
        // W199 follow-up: preserve the halt origin and full ARM context. A
        // return PC alone cannot distinguish a thunk exception from a guest
        // exception or an unsupported instruction.
        static std::atomic<uint32_t> abnormal_halt_notes{0};
        if (abnormal_halt_notes.fetch_add(1) < 16) {
            char b[224];
            snprintf(b, sizeof(b),
                     "UNEXPECTED-HALT tid=%u target=%08X pc=%08X lr=%08X sp=%08X cpsr=%08X reason=%X r0=%08X r1=%08X r2=%08X r3=%08X",
                     static_cast<uint32_t>(gettid()), target_pc, final_pc,
                     jit.Regs()[14], jit.Regs()[13], jit.Cpsr(), static_cast<unsigned>(hr),
                     jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]);
            DiagTrace::NotePersist(b);
            snprintf(b, sizeof(b),
                     "UNEXPECTED-HALT r4=%08X r5=%08X r6=%08X r7=%08X r8=%08X r9=%08X r10=%08X r11=%08X r12=%08X code=%08X/%08X/%08X/%08X/%08X",
                     jit.Regs()[4], jit.Regs()[5], jit.Regs()[6], jit.Regs()[7],
                     jit.Regs()[8], jit.Regs()[9], jit.Regs()[10], jit.Regs()[11],
                     jit.Regs()[12], final_pc >= 8 ? MemoryRead32(final_pc - 8) : 0,
                     final_pc >= 4 ? MemoryRead32(final_pc - 4) : 0,
                     MemoryRead32(final_pc), MemoryRead32(final_pc + 4),
                     MemoryRead32(final_pc + 8));
            DiagTrace::NotePersist(b);
            snprintf(b, sizeof(b),
                     "UNEXPECTED-HALT W199stub=%08X/%08X/%08X/%08X/%08X/%08X",
                     MemoryRead32(0x8F113200u), MemoryRead32(0x8F113204u),
                     MemoryRead32(0x8F113208u), MemoryRead32(0x8F11320Cu),
                     MemoryRead32(0x8F113210u), MemoryRead32(0x8F113214u));
            DiagTrace::NotePersist(b);
            snprintf(b, sizeof(b),
                     "UNEXPECTED-HALT W199stub2=%08X/%08X/%08X/%08X/%08X/%08X",
                     MemoryRead32(0x8F113218u), MemoryRead32(0x8F11321Cu),
                     MemoryRead32(0x8F113220u), MemoryRead32(0x8F113224u),
                     MemoryRead32(0x8F113228u), MemoryRead32(0x8F11322Cu));
            DiagTrace::NotePersist(b);
            snprintf(b, sizeof(b),
                     "UNEXPECTED-HALT W199stub3=%08X/%08X/%08X/%08X/%08X/%08X site=%08X/%08X",
                     MemoryRead32(0x8F113230u), MemoryRead32(0x8F113234u),
                     MemoryRead32(0x8F113238u), MemoryRead32(0x8F11323Cu),
                     MemoryRead32(0x8F113240u), MemoryRead32(0x8F113244u),
                     MemoryRead32(0x403F7054u), MemoryRead32(0x403F7058u));
            DiagTrace::NotePersist(b);
            const uint32_t sp = jit.Regs()[13];
            for (uint32_t off = 0; off < 32; off += 16) {
                snprintf(b, sizeof(b), "UNEXPECTED-HALT stack+%02X=%08X/%08X/%08X/%08X",
                         off, MemoryRead32(sp + off), MemoryRead32(sp + off + 4),
                         MemoryRead32(sp + off + 8), MemoryRead32(sp + off + 12));
                DiagTrace::NotePersist(b);
            }
        }
    }
    // Diagnostic-only (phase 7): every top-level return. The run2 route lost
    // the guest worker to a SILENT trap-return right after a pool-table qsort;
    // this log gives the exit registers of every top-level call so the dying
    // chain can be identified. Routed through DiagTrace::Note because device
    // logcat throttling swallowed the LOGI variant in the run3 route.
    static std::atomic<uint32_t> diag_returns{0};
    // Skip the periodic FMOD AudioTrack pulse (10/s, R0=0xFFFFFFFF): it would
    // flush everything else out of the notes ring.
    // W353 (run467): the FMOD pulse family (0x410ACE08 AND 0x410ACE2C)
    // exhausted the 4096 RET cap in ~7 minutes, hiding every later
    // return -- including the glue thread's android_app_entry return
    // (run462-466 mystery). Exclude both, raise the cap.
    if (target_pc != 0x410ACE08u && target_pc != 0x410ACE2Cu &&
        diag_returns.fetch_add(1) < 100000) {
        char b[128];
        snprintf(b, sizeof(b), "RET tid=%u target=0x%08X PC=0x%08X LR=0x%08X R0=0x%08X reason=0x%X",
                 static_cast<uint32_t>(gettid()), target_pc, final_pc, jit.Regs()[14], jit.Regs()[0], static_cast<unsigned>(hr));
        DiagTrace::Note(b);
    }
    // W479 (run635): StateMachine_Enter sentinel-exit autopsy. Enter returns
    // instantly (PC=0x8, R0=-8): a callee inside the first Process tick
    // unwinds through Enter's frame, popping the entry-saved LR=8 sentinel
    // into PC. Dump the leftover stack words so the unwinding frame chain
    // (return addresses) can be identified.
    if (target_pc == 0x40569B8Cu) {
        const uint32_t sp = jit.Regs()[13];
        LOGE("[W479] ENTER-EXIT pc=%08X lr=%08X sp=%08X r0=%08X w476patch=%08X "
             "stk: %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X",
             final_pc, jit.Regs()[14], sp, jit.Regs()[0],
             MemoryRead32(0x40569BA0u),
             MemoryRead32(sp + 0x00u), MemoryRead32(sp + 0x04u),
             MemoryRead32(sp + 0x08u), MemoryRead32(sp + 0x0Cu),
             MemoryRead32(sp + 0x10u), MemoryRead32(sp + 0x14u),
             MemoryRead32(sp + 0x18u), MemoryRead32(sp + 0x1Cu),
             MemoryRead32(sp + 0x20u), MemoryRead32(sp + 0x24u),
             MemoryRead32(sp + 0x28u), MemoryRead32(sp + 0x2Cu));
    }
    // W84 (run149): the glue thread (android_app_entry) returned through the
    // exit trap with R0=-3 (a leaked ALOOPER_POLL_ERROR) and LR still at the
    // pollAll call site inside APS -- i.e. the final frame POP pulled a
    // corrupted return address and slid into the trap words. Dump the full
    // register set plus the stack window at SP for every top-level
    // android_app_entry termination so the smashed slot is visible verbatim.
    // W93: also log the SP this RunFunction assigned at entry.
    static std::atomic<uint32_t> w84_dumps{0};
    if (target_pc == 0x4017CA38u && w84_dumps.fetch_add(1) < 8) {
        char b[2600];
        int n = snprintf(b, sizeof(b),
                         "W84APP entry_sp=%08X exit pc=%08X lr=%08X sp=%08X cpsr=%08X r0=%08X r1=%08X r2=%08X r3=%08X"
                         " r4=%08X r5=%08X r6=%08X r7=%08X r8=%08X r9=%08X r10=%08X r11=%08X r12=%08X stack:",
                         t_stack_top,
                         final_pc, jit.Regs()[14], jit.Regs()[13], static_cast<unsigned>(jit.Cpsr()),
                         jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3],
                         jit.Regs()[4], jit.Regs()[5], jit.Regs()[6], jit.Regs()[7],
                         jit.Regs()[8], jit.Regs()[9], jit.Regs()[10], jit.Regs()[11], jit.Regs()[12]);
        const uint32_t sp = jit.Regs()[13];
        // W102: the glue thread dies on the guest's graphics-system stack
        // (AcquireGraphicsSystem switches stacks); read the frame residue
        // BELOW sp too so the last saved LRs are visible.
        for (int w = -64; w < 40 && n > 0 && static_cast<size_t>(n) < sizeof(b); ++w) {
            n += snprintf(b + n, sizeof(b) - static_cast<size_t>(n), " %08X",
                          MemoryRead32(sp + static_cast<uint32_t>(w) * 4));
        }
        n += snprintf(b + std::min(static_cast<size_t>(std::max(n, 0)), sizeof(b) - 1),
                      sizeof(b) - std::min(static_cast<size_t>(std::max(n, 0)), sizeof(b) - 1),
                      " w239=%u/%08X w240=%u w77=%08X w80=%08X/%08X",
                      MemoryRead32(0x93000564u), MemoryRead32(0x93000568u),
                      MemoryRead32(0x93000768u), MemoryRead32(0x403DA8F8u),
                      MemoryRead32(0x403DA8ECu), MemoryRead32(0x403DA8F0u));
        b[sizeof(b) - 1] = '\0';
        DiagTrace::NotePersist(b);

        // W354 (run468): the AAsset_close GOT-slot death. When the glue
        // dies at pc=0x4066E98C, dump the slot value, its neighbours and
        // the W348 snapshot entry to see whether the slot drifted (writer)
        // or was born wrong (relocation).
        if (target_pc == 0x4017CA38u && final_pc == 0x4066E98Cu) {
            char b3[240];
            snprintf(b3, sizeof(b3),
                     "W354 slot[98C]=%08X [988]=%08X [990]=%08X [994]=%08X [984]=%08X",
                     MemoryRead32(0x4066E98Cu), MemoryRead32(0x4066E988u),
                     MemoryRead32(0x4066E990u), MemoryRead32(0x4066E994u),
                     MemoryRead32(0x4066E984u));
            DiagTrace::NotePersist(b3);
            LOGE("%s", b3);
        }
    }

    // W142: release guest mutexes held by this thread at top-level exit.
    if (target_pc == 0x4017D9F4u) DiagTrace::Note("W565 onCreate RunFunction reached mutex cleanup");
    GuestPthreadReleaseHeldMutexes();
    if (target_pc == 0x4017D9F4u) DiagTrace::Note("W565 onCreate RunFunction passed mutex cleanup");

    // W4 diagnostic: on unexpected halt, dump all guest registers plus a
    // short stack walk into the diag notes ring so the exact halt source is
    // visible (logcat throttling makes LOGI unreliable).
    static std::atomic<uint32_t> diag_halts{0};
    if (final_pc != EXIT_TRAP_ARM && final_pc != (EXIT_TRAP_ARM + 4) &&
        final_pc != (EXIT_TRAP_THUMB & ~1u) && final_pc != ((EXIT_TRAP_THUMB & ~1u) + 2)) {
        if (diag_halts.fetch_add(1) < 32) {
            char b[1024];
            int n = snprintf(b, sizeof(b),
                             "HALT target=0x%08X pc=0x%08X lr=0x%08X sp=0x%08X cpsr=0x%08X stack:",
                             target_pc, final_pc, jit.Regs()[14], jit.Regs()[13],
                             static_cast<unsigned>(jit.Cpsr()));
            const uint32_t sp = jit.Regs()[13];
            for (int w = 0; w < 64 && n > 0 && static_cast<size_t>(n) < sizeof(b); ++w) {
                n += snprintf(b + n, sizeof(b) - static_cast<size_t>(n), " %08X",
                              MemoryRead32(sp + static_cast<uint32_t>(w) * 4));
            }
            DiagTrace::Note(std::string(b, static_cast<size_t>(n)));
        }
    }

    if (reached_exit_trap) *reached_exit_trap = normal_exit;
    return jit.Regs()[0];
}

bool DynarmicHost::IsJitRunning() const {
    return t_host == this && t_jit_running;
}

bool DynarmicHost::GetExidxRangeForPc(uint32_t pc, uint32_t& start, uint32_t& end) const {
    const ElfLoader* loaders[] = {
        m_elf_loader.get(), m_fmodex_loader.get(), m_fmodex_l_loader.get(),
        m_fmodevent_loader.get(), m_fmodevent_l_loader.get(),
    };
    for (const ElfLoader* loader : loaders) {
        if (!loader || !loader->ContainsAddress(pc)) continue;
        start = loader->GetExidxStart();
        end = loader->GetExidxEnd();
        return start != 0 && end > start && ((end - start) % 8u) == 0;
    }
    start = 0;
    end = 0;
    return false;
}

// W16b diagnostic: full register state of every thread parked in the bridge
// page plus a hex dump of the low guest page. Torn reads of a live JIT are
// acceptable (SampleGuestPcs precedent); a blocked thread reads stable.
std::string DynarmicHost::DiagDumpStuckThreads() {
    std::string out;
    char b[512];
    {
        std::lock_guard<std::mutex> lock(m_jit_list_mutex);
        for (const auto& entry : m_jits) {
            auto jit = entry.jit.lock();
            if (!jit) continue;
            const uint32_t pc = jit->Regs()[15];
            if (pc > 0x40 || pc == EXIT_TRAP_ARM || pc == EXIT_TRAP_THUMB) continue;
            snprintf(b, sizeof(b),
                     "STUCK tid=%u pc=0x%08X sp=0x%08X cpsr=0x%08X",
                     entry.owner_tid, pc, jit->Regs()[13],
                     static_cast<unsigned>(jit->Cpsr()));
            out += b;
            static const char* kNames[15] = {"r0", "r1", "r2", "r3", "r4", "r5", "r6",
                                             "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr"};
            for (int i = 0; i < 15; ++i) {
                snprintf(b, sizeof(b), "\nSTUCK  %s=0x%08X", kNames[i], jit->Regs()[i]);
                out += b;
            }
            out += '\n';
        }
    }
    if (m_memory_size >= 0x100) {
        out += "STUCK lowpage:";
        for (uint32_t w = 0; w < 0x100; w += 4) {
            if ((w & 0x1F) == 0) out += "\nSTUCK  ";
            snprintf(b, sizeof(b), "%08X ", MemoryRead32(w));
            out += b;
        }
        out += '\n';
    }
    // W20: WAD parse marker counters (see EnsureWadParseMarkers).
    snprintf(b, sizeof(b), "WADMARK dir_entries=%u tail=%u tail_lr=0x%08X file_entries=%u "
             "attempts=%u name_ptr=0x%08X seam_returns=%u "
             "epilogues=%u epi_retpc=0x%08X epi_sp=0x%08X fileloop=%u "
             "file_a2=0x%08X file_cur=0x%08X file_exit=%u file_sp=0x%08X "
             "file_w0=0x%08X file_w1=0x%08X file_w2=0x%08X file_w3=0x%08X",
             MemoryRead32(0x0065AE80), MemoryRead32(0x0065AE84), MemoryRead32(0x0065AE88),
             MemoryRead32(0x0065AF80), MemoryRead32(0x0065AF84), MemoryRead32(0x0065AF88),
             MemoryRead32(0x0065B000), MemoryRead32(0x0065B004),
             MemoryRead32(0x0065B008), MemoryRead32(0x0065B00C), MemoryRead32(0x0065B010),
             MemoryRead32(0x0065AF8C), MemoryRead32(0x0065AF90),
             MemoryRead32(0x0065B030), MemoryRead32(0x0065AFA0),
             MemoryRead32(0x0065AFB8), MemoryRead32(0x0065AFBC),
             MemoryRead32(0x0065AFC0), MemoryRead32(0x0065AFC4));
    out += b;
    snprintf(b, sizeof(b), "W38REG ads=%u adc=%u",
             MemoryRead32(0x0065CC10), MemoryRead32(0x0065CC14));
    out += b;
    snprintf(b, sizeof(b), "WADR32 c1=%u c2=%u c3=%u",
             MemoryRead32(0x0065B700), MemoryRead32(0x0065B704), MemoryRead32(0x0065B708));
    out += b;
    out += b;
    // W25b: canary state around SETUP's saved-LR slot.
    snprintf(b, sizeof(b), "WADCAN canA=0x%08X canB=0x%08X lrslot=0x%08X",
             MemoryRead32(0x0065AF94), MemoryRead32(0x0065AF98), MemoryRead32(0x0065AF9C));
    out += b;
    // W23b: the 8 saved-register words captured by the dir-epilogue stub
    // ([SP+8..SP+36] of SETUP's frame: lr, r10..r4).
    snprintf(b, sizeof(b), "WADFRAME lr=0x%08X r10=0x%08X r9=0x%08X r8=0x%08X "
             "r7=0x%08X r6=0x%08X r5=0x%08X r4=0x%08X",
             MemoryRead32(0x0065B010), MemoryRead32(0x0065B014), MemoryRead32(0x0065B018),
             MemoryRead32(0x0065B01C), MemoryRead32(0x0065B020), MemoryRead32(0x0065B024),
             MemoryRead32(0x0065B028), MemoryRead32(0x0065B02C));
    out += b;
    // W23: live WAD parse state -- direct host reads, zero guest interference.
    {
        const uint32_t cursor = MemoryRead32(0x40700E60);  // W32: runtime address (bias baked)
        snprintf(b, sizeof(b), "\nWADBUF gDepth=%d cursor=0x%08X nodes:",
                 static_cast<int32_t>(MemoryRead32(0x700E5C)), cursor);
        out += b;
        for (int n = 0; n < 4; ++n) {
            snprintf(b, sizeof(b), " [%08X %08X %08X %08X]",
                     MemoryRead32(cursor + 16u * n), MemoryRead32(cursor + 16u * n + 4),
                     MemoryRead32(cursor + 16u * n + 8), MemoryRead32(cursor + 16u * n + 12));
            out += b;
        }
        out += '\n';
        // W29: the GOT-indirect view SetupWadFilePointers actually uses:
        // r3 = *(0x4067084C) = 0x700E60; nodes are read at the CURRENT
        // buffer-B cursor. Dump the first 3 nodes from the START of buffer B
        // (the cursor value at parse entry was base+0) plus the SETUP node at
        // base+16, so a misplaced bz_File_Read window is immediately visible.
        const uint32_t gotSlotVal = MemoryRead32(0x4067084C);
        const uint32_t curB = gotSlotVal ? MemoryRead32(gotSlotVal) : 0;
        const uint32_t baseB = MemoryRead32(0x0065B100);  // W30: recorded at first dir entry
        // W31: computed buffer-B base from the runaway arithmetic
        // (final cursor minus file_exit*16); the buffer itself is read-only
        // during the loop, so post-mortem bytes are pristine.
        const uint32_t baseComputed = curB ? (curB - (MemoryRead32(0x0065AF8C + 0) * 16u)) : 0;
        const uint32_t base = baseB ? baseB : (baseComputed ? baseComputed : curB);
        snprintf(b, sizeof(b), "\nWADB2 gotVal=0x%08X curB=0x%08X baseB=0x%08X baseC=0x%08X nodes@base:",
                 gotSlotVal, curB, baseB, base);
        out += b;
        for (int n = 0; n < 4; ++n) {
            snprintf(b, sizeof(b), " [%08X %08X %08X %08X]",
                     MemoryRead32(base + 16u * n), MemoryRead32(base + 16u * n + 4),
                     MemoryRead32(base + 16u * n + 8), MemoryRead32(base + 16u * n + 12));
            out += b;
        }
        out += '\n';
    }
    return out;
}

// W3 diagnostic: reads the luaD_throw scratch block written by the guest
// trampoline installed by EnsureLuaThrowDumper (thunks_libc.cpp). W5: the
// trampoline relocated to 0x65AB80 inside the free gap after .ARM.exidx, so
// the scratch block moved with it to 0x65AC00.
//   0x65AC00 value   0x65AC04 top-slot   0x65AC08 tt   0x65AC0C magic
std::string DynarmicHost::DiagReadLuaThrow() {
    const uint32_t base = 0x0065AC00;
    if (MemoryRead32(base + 12) != 0xC0FFEE01) return "";
    const uint32_t value = MemoryRead32(base);
    const uint32_t slot = MemoryRead32(base + 4);
    const uint32_t tt = MemoryRead32(base + 8);
    char out[256];
    std::string msg;
    if (tt == 4) {  // LUA_TSTRING: TString payload begins at +16
        char b[136];
        size_t i = 0;
        for (; i < 128; ++i) {
            const char c = static_cast<char>(MemoryRead8(value + 16 + i));
            if (!c) break;
            b[i] = c;
        }
        b[i] = 0;
        msg = b;
    }
    snprintf(out, sizeof(out), "LUATHROW tt=%u value=0x%08X slot=0x%08X msg=\"%s\"",
             tt, value, slot, msg.c_str());
    MemoryWrite32(base + 12, 0xC0FFEE02);  // consumed
    DiagTrace::Note(out);        // W10d: notes ring
    DiagTrace::NotePersist(out); // W17: survive the post-freeze flush
    return out;
}

// W7 diagnostic: reads the Android_fopen path snapshot written by the entry
// trampoline (see EnsureFopenDiagDumper in thunks_libc.cpp):
//   0x65AD00 magic   0x65AD04 path pointer
std::string DynarmicHost::DiagReadFopenPath() {
    const uint32_t base = 0x0065AD00;
    if (MemoryRead32(base) != 0xF1EEF1EE) return "";
    const uint32_t path_ptr = MemoryRead32(base + 4);
    char msg[136];
    size_t i = 0;
    for (; i < 128; ++i) {
        const char c = static_cast<char>(MemoryRead8(path_ptr + i));
        if (!c) break;
        msg[i] = c;
    }
    msg[i] = 0;
    MemoryWrite32(base, 0xF1EEF1EF);  // consumed
    std::string fopen_line = "FOPENPATH path=\"" + std::string(msg) + "\"";
    DiagTrace::Note(fopen_line);        // W10d: notes ring
    DiagTrace::NotePersist(fopen_line); // W17: survive the post-freeze flush
    return fopen_line;
}

// W7 diagnostic: reads the __cxa_throw scratch block (see
// EnsureCxaThrowDumper in thunks_libc.cpp):
//   0x65AD80 magic   0x65AD84 throw-site   0x65AD88 exc-obj   0x65AD8C name-ptr
// W332: newline as data (avoids escape-processing hazards in generated code).
static const char* const g_nl = "\n";

std::string DynarmicHost::DiagReadCxaThrow() {
    const uint32_t base = 0x0065AD80;
    if (MemoryRead32(base) != 0x71EE71EE) return "";
    const uint32_t site = MemoryRead32(base + 4);
    const uint32_t obj = MemoryRead32(base + 8);
    const uint32_t name_ptr = MemoryRead32(base + 12);
    char msg[136];
    size_t i = 0;
    for (; i < 128; ++i) {
        const char c = static_cast<char>(MemoryRead8(name_ptr + i));
        if (!c) break;
        msg[i] = c;
    }
    msg[i] = 0;
    MemoryWrite32(base, 0x71EE71EF);  // consumed
    char out[224];
    snprintf(out, sizeof(out), "CXATHROW site=0x%08X obj=0x%08X name=\"%s\"",
             site, obj, msg);
    DiagTrace::Note(out);        // W10d: notes ring
    DiagTrace::NotePersist(out); // W15: survive the post-freeze ring flush
    return out;
}

// W10 diagnostic: reads the __throw_length_error scratch block (see
// EnsureThrowLenDumper in thunks_libc.cpp):
//   0x65AC60 magic   0x65AC64 msg-ptr   0x65AC68 throw-site
std::string DynarmicHost::DiagReadThrowLengthError() {
    const uint32_t base = 0x0065AC60;
    if (MemoryRead32(base) != 0x71EE71EE) return "";
    const uint32_t msg_ptr = MemoryRead32(base + 4);
    const uint32_t site = MemoryRead32(base + 8);
    char msg[136];
    size_t i = 0;
    for (; i < 128; ++i) {
        const char c = static_cast<char>(MemoryRead8(msg_ptr + i));
        if (!c) break;
        msg[i] = c;
    }
    msg[i] = 0;
    MemoryWrite32(base, 0x71EE71EF);  // consumed
    char out[224];
    snprintf(out, sizeof(out), "THROWLEN site=0x%08X msg=\"%s\"", site, msg);
    DiagTrace::Note(out);        // W10d: notes ring
    DiagTrace::NotePersist(out); // W17: survive the post-freeze flush
    return out;
}

std::vector<uint32_t> DynarmicHost::SampleGuestPcs() {
    std::lock_guard<std::mutex> lock(m_jit_list_mutex);
    // Capture the first invalid indirect JNI call with all callee-saved
    // registers and the referenced guest fields. The ordinary W347 sampler
    // stops after the first few unrelated workers, which hid this thread.
    {
        static std::atomic<uint32_t> w347_fail{0};
        if (w347_fail.load(std::memory_order_relaxed) < 4) {
            for (auto& entry : m_jits) {
                auto jit = entry.jit.lock();
                if (!jit) continue;
                const uint32_t pc = jit->Regs()[15];
                const uint32_t lr = jit->Regs()[14];
                if (pc != 0xE35C0018u && lr != 0x403DAED8u) continue;
                if (w347_fail.fetch_add(1, std::memory_order_relaxed) >= 4) break;
                const auto read = [this](uint32_t address) {
                    return address <= m_memory_size &&
                           m_memory_size - address >= sizeof(uint32_t)
                        ? MemoryRead32(address) : 0u;
                };
                const auto read_offset = [&read](uint32_t base, uint32_t offset) {
                    return base <= 0xFFFFFFFFu - offset ? read(base + offset) : 0u;
                };
                const uint32_t env = jit->Regs()[4];
                const uint32_t table = read(env);
                const uint32_t got = jit->Regs()[5];
                const uint32_t android_info = read(0x4066FA6Cu);
                const uint32_t info12 = read_offset(android_info, 12u);
                char b[384];
                snprintf(b, sizeof(b),
                         "W347FAIL tid=%u pc=%08X lr=%08X sp=%08X r0=%08X r1=%08X r2=%08X r3=%08X r4=%08X r5=%08X r6=%08X r5plus4=%08X r4first=%08X call680=%08X android_info=%08X info4=%08X info12=%08X info12_4=%08X info12_8=%08X",
                         entry.owner_tid, pc, lr, jit->Regs()[13],
                         jit->Regs()[0], jit->Regs()[1], jit->Regs()[2],
                         jit->Regs()[3], env, got, jit->Regs()[6],
                         read_offset(got, 4u), table, read_offset(table, 0x2A8u),
                         android_info, read_offset(android_info, 4u), info12,
                         read_offset(info12, 4u), read_offset(info12, 8u));
                DiagTrace::NotePersist(b);
                LOGE("%s", b);
            }
        }
    }
    // This sampler is diagnostic-only: it must never heal guest state or
    // rewrite code/data while other JIT cores are executing.
    // W347 (run457): stack snapshot of every "interesting" live guest
    // thread (not parked in a thunk trampoline, not at the exit traps).
    // One dump at >= 60 s uptime names exactly where the boot chain
    // stalls (run456: the glue vanished from W40PCS after the WAD parse
    // inside the Material-dir chain).
    {
        static std::atomic<uint32_t> w347{0};
        const bool fire = w347.load() < 3;
        for (auto& entry : m_jits) {
            if (std::shared_ptr<Dynarmic::A32::Jit> jit = entry.jit.lock()) {
                const uint32_t pc = jit->Regs()[15];
                const uint32_t lr = jit->Regs()[14];
                if (pc == 0x8u || pc == 0x4u || pc == 0x8F100C78u || pc == 0x8F1008B8u)
                    continue;
                if (!fire)
                    break;
                w347.fetch_add(1);
                const uint32_t sp = jit->Regs()[13];
                char b[512];
                int bn = snprintf(b, sizeof(b),
                                  "W347 tid=%u pc=%08X lr=%08X sp=%08X r0=%08X r1=%08X r2=%08X r3=%08X r4=%08X stk:",
                                  entry.owner_tid, pc, lr, sp,
                                  jit->Regs()[0], jit->Regs()[1], jit->Regs()[2],
                                  jit->Regs()[3], jit->Regs()[4]);
                for (int w = 0; w < 10 && bn > 0 && static_cast<size_t>(bn) < sizeof(b); ++w)
                    bn += snprintf(b + bn, sizeof(b) - static_cast<size_t>(bn), " %08X",
                                   MemoryRead32(sp + static_cast<uint32_t>(w) * 4u));
                const uint32_t env = jit->Regs()[4];
                uint32_t table = 0;
                uint32_t slot_a4 = 0;
                uint32_t slot_a8 = 0;
                if (env <= m_memory_size && m_memory_size - env >= sizeof(uint32_t))
                    table = MemoryRead32(env);
                if (table <= m_memory_size && m_memory_size - table >= 0x2A8u)
                    slot_a4 = MemoryRead32(table + 0x2A4u);
                if (table <= m_memory_size && m_memory_size - table >= 0x2ACu)
                    slot_a8 = MemoryRead32(table + 0x2A8u);
                if (bn > 0 && static_cast<size_t>(bn) < sizeof(b))
                    bn += snprintf(b + bn, sizeof(b) - static_cast<size_t>(bn),
                                   " envtbl=%08X envA4=%08X envA8=%08X",
                                   table, slot_a4, slot_a8);
                const uint32_t jni_context = MemoryRead32(0x4067BA6Cu);
                const uint32_t cached_env = jni_context <= m_memory_size - 8u
                    ? MemoryRead32(jni_context + 4u) : 0;
                if (bn > 0 && static_cast<size_t>(bn) < sizeof(b))
                    bn += snprintf(b + bn, sizeof(b) - static_cast<size_t>(bn),
                                   " jni_ctx=%08X cached_env=%08X",
                                   jni_context, cached_env);
                snprintf(b + bn, sizeof(b) - static_cast<size_t>(bn), "%s", g_nl);
                DiagTrace::NotePersist(std::string(b, static_cast<size_t>(bn)));
            }
        }
    }
    // W481 (run638): full-register dump of the game thread parked at the
    // thumb exit trap with the Process call-site LR (pc=8, lr=40569B9C).
    // r12 tells whether the W478 veneer executed (it would hold the stub
    // window address); cpsr shows the thumb bit.
    {
        static std::atomic<uint32_t> w481{0};
        if (w481.load() < 3) {
            for (auto& entry : m_jits) {
                if (std::shared_ptr<Dynarmic::A32::Jit> jit = entry.jit.lock()) {
                    const uint32_t pc = jit->Regs()[15];
                    const uint32_t lr = jit->Regs()[14];
                    const uint32_t spx = jit->Regs()[13];
                    if (spx >= 0x7EF00000u && spx < 0x7F000000u) {
                        w481.fetch_add(1);
                        LOGE("[W481] tid=%u pc=%08X lr=%08X sp=%08X cpsr=%08X "
                             "r0=%08X r1=%08X r2=%08X r3=%08X r4=%08X r5=%08X "
                             "r6=%08X r7=%08X r8=%08X r9=%08X r10=%08X r11=%08X r12=%08X",
                             entry.owner_tid, pc, lr, jit->Regs()[13],
                             static_cast<unsigned>(jit->Cpsr()),
                             jit->Regs()[0], jit->Regs()[1], jit->Regs()[2], jit->Regs()[3],
                             jit->Regs()[4], jit->Regs()[5], jit->Regs()[6], jit->Regs()[7],
                             jit->Regs()[8], jit->Regs()[9], jit->Regs()[10], jit->Regs()[11],
                             jit->Regs()[12]);
                        break;
                    }
                }
            }
        }
    }
    // W301c (run407): dump the parked glue thread stack (28 words) into the
    // persistent cells 0x930001A0+ and publish the live app pointer (r4).
    {
        static std::atomic<uint32_t> w301c{0};
        const bool dump = w301c.load() < 2;
        for (auto& entry : m_jits) {
            if (std::shared_ptr<Dynarmic::A32::Jit> jit = entry.jit.lock()) {
                const uint32_t pc = jit->Regs()[15];
                const uint32_t sp = jit->Regs()[13];
                if (pc == 0x8F100C74u && sp >= 0x7E000000u && sp < 0x7E400000u) {
                    MemoryWrite32(0x93000160u, jit->Regs()[4]);
                    for (int wi = 0; wi < 28; ++wi)
                        MemoryWrite32(0x930001A0u + static_cast<uint32_t>(wi) * 4u,
                                      *reinterpret_cast<uint32_t*>(m_memory + sp + static_cast<uint32_t>(wi) * 4u));
                    if (dump) {
                        char lb[900];
                        int ln = snprintf(lb, sizeof(lb), "W301PARK tid=%u sp=%08X lr=%08X r4=%08X stack:",
                                          entry.owner_tid, sp, jit->Regs()[14], jit->Regs()[4]);
                        for (int wi = 0; wi < 28 && ln > 0; ++wi) {
                            const uint32_t va = sp + static_cast<uint32_t>(wi) * 4u;
                            ln += snprintf(lb + ln, sizeof(lb) - static_cast<size_t>(ln),
                                           " %08X", *reinterpret_cast<uint32_t*>(m_memory + va));
                        }
                        DiagTrace::NotePersist(lb);
                        w301c.fetch_add(1);
                    }
                    break;
                }
            }
        }
    }
    std::vector<uint32_t> pcs;
    pcs.reserve(m_jits.size());
    std::string thread_pcs;
    for (auto& entry : m_jits) {
        // Expired = its owning guest thread exited; skip instead of crashing.
        if (std::shared_ptr<Dynarmic::A32::Jit> jit = entry.jit.lock()) {
            pcs.push_back(jit->Regs()[15]);
            char tb[64];
            snprintf(tb, sizeof(tb), "THREADPC tid=%u pc=0x%08X" , entry.owner_tid, jit->Regs()[15]);
            if (!thread_pcs.empty()) thread_pcs += "; ";
            thread_pcs += tb;
        }
    }
    if (!thread_pcs.empty()) {
        DiagTrace::Note(thread_pcs);
    }
    return pcs;
}

// W60: tid-tagged variant for the W40PCS watchdog line.
std::vector<DynarmicHost::GuestThreadPc> DynarmicHost::SampleGuestThreadPcs() {
    std::lock_guard<std::mutex> lock(m_jit_list_mutex);
    std::vector<GuestThreadPc> out;
    out.reserve(m_jits.size());
    for (auto& entry : m_jits) {
        if (std::shared_ptr<Dynarmic::A32::Jit> jit = entry.jit.lock()) {
            out.push_back({entry.owner_tid, jit->Regs()[15],
                           jit->Regs()[14], jit->Regs()[4], jit->Regs()[5], jit->Regs()[13],
                           jit->Regs()[0], jit->Regs()[1], jit->Regs()[2], jit->Regs()[3]});
        }
    }
    return out;
}

void DynarmicHost::InvalidateGuestCode(uint32_t addr, size_t size) {
    InvalidateGuestCodeAll(addr, size);
}

// W83: invalidate a code range on ALL live JIT contexts, not just the
// calling thread's. Necessary because patches installed from the main
// thread must be visible to game/worker threads running their own JITs.
void DynarmicHost::InvalidateGuestCodeAll(uint32_t addr, size_t size) {
    std::lock_guard<std::mutex> lock(m_jit_list_mutex);
    for (auto& entry : m_jits) {
        if (std::shared_ptr<Dynarmic::A32::Jit> jit = entry.jit.lock()) {
            jit->InvalidateCacheRange(addr, size);
        }
    }
}

// W108: top of the main guest image, page-aligned. The bridge's probe stubs
// and diagnostic counters must never live below this -- the guest ELF's
// data segment expanded into the legacy 0x65Cxxx window and its writes
// stomped the stubs (guest then executed data words as code).
uint32_t DynarmicHost::GuestImageEnd() const {
    uint32_t end = kGuestGameBase;
    if (m_elf_loader) {
        const uint32_t candidate = m_elf_loader->GetBaseAddress() + m_elf_loader->GetImageSize();
        if (candidate > end) end = candidate;
    }
    return (end + 0xFFFu) & ~0xFFFu;
}

// W130: bridge-heap state for the W40PCS diag line. Snapshot only.
std::string DynarmicHost::DiagHeapState() {
#if !BRIDGE_ENABLE_HEAP_DIAGNOSTICS
    std::lock_guard<std::mutex> lk(m_heap_mutex);
    char b[80];
    snprintf(b, sizeof(b), " heap=[bump=%08X diagnostics=off]", m_heap_current);
    return std::string(b);
#else
    std::lock_guard<std::mutex> lk(m_heap_mutex);
    uint64_t live_bytes = 0;
    uint32_t live_count = 0;
    uint32_t top0 = 0, top1 = 0, top2 = 0;
    for (const auto& kv : m_live_blocks) {
        live_bytes += kv.second.size;
        live_count += 1;
        if (kv.second.size > top0) { top2 = top1; top1 = top0; top0 = kv.second.size; }
        else if (kv.second.size > top1) { top2 = top1; top1 = kv.second.size; }
        else if (kv.second.size > top2) { top2 = kv.second.size; }
    }
    char b[192];
    snprintf(b, sizeof(b),
             " heap=[bump=%08X live=%u/%lluKB top=%u,%u,%u]",
             m_heap_current, live_count,
             static_cast<unsigned long long>(live_bytes / 1024), top0, top1, top2);
    return std::string(b);
#endif
}

// W198: one line with the live guest PC of every live JIT context. Racy
// reads of another thread's CPU state -- diagnostic only, never acted on.
// When a PC sits inside the CBNode::Find walk (0x403F7054..0x403F7090),
// also dump the walk registers + tree memory: r4=node, r5=point, r6=id,
// r12=next-table base, [r12+0x204]=child, [r4]=leaf flag.
std::string DynarmicHost::DiagSamplePCs() {
    std::string out;
    // Diagnostic sampling must never mutate guest state. In particular,
    // bzgMemory_system_state is owned by InitMemorySystem/ShutdownMemorySystem;
    // forcing it to 2 can make LLMem accept allocations after teardown without
    // recreating the pools.
    std::lock_guard<std::mutex> lock(m_jit_list_mutex);
    // W288 (run388): dump the parked glue thread stack once. The game
    // waits in pthread_cond_wait; its saved frames name the wait chain
    // (StartInternal loop / cond variable) needed to wake it correctly.
    {
        static std::atomic<uint32_t> w288{0};
        if (w288.load() < 3 && m_memory_size >= 0x7E400000u) {
            for (auto& e : m_jits) {
                auto jw = e.jit.lock();
                if (!jw) continue;
                const uint32_t pc = jw->Regs()[15];
                const uint32_t sp = jw->Regs()[13];
                if (pc != 0x8F100C74u || sp < 0x7E000000u || sp >= 0x7E400000u)
                    continue;
                // W294b: publish the LIVE app pointer (r4) for W292/W291.
                MemoryWrite32(0x93000160u, jw->Regs()[4]);
                char lb[900];
                int ln = snprintf(lb, sizeof(lb), "W288PARK tid=%u sp=%08X lr=%08X r4=%08X r5=%08X r6=%08X r7=%08X stack:\n",
                                 e.owner_tid, sp, jw->Regs()[14],
                                 jw->Regs()[4], jw->Regs()[5],
                                 jw->Regs()[6], jw->Regs()[7]);
                for (int wi = 0; wi < 24 && ln > 0; ++wi) {
                    const uint32_t va = sp + static_cast<uint32_t>(wi) * 4u;
                    ln += snprintf(lb + ln, sizeof(lb) - static_cast<size_t>(ln),
                                   " %08X",
                                   *reinterpret_cast<uint32_t*>(m_memory + va));
                }
                DiagTrace::NotePersist(lb);
                w288.fetch_add(1);
                break;
            }
        }
    }
    for (auto& e : m_jits) {
        auto j = e.jit.lock();
        if (!j) continue;
        const uint32_t pc = j->Regs()[15];
        char b[192];
        snprintf(b, sizeof(b), " tid=%u pc=%08X", e.owner_tid, pc);
        out += b;
        if (pc >= 0x403F7054u && pc <= 0x403F7090u) {
            const uint32_t r4 = j->Regs()[4], r5 = j->Regs()[5],
                           r6 = j->Regs()[6], r12 = j->Regs()[12];
            uint32_t nxt = 0, leaf = 0, cnt = 0;
            if (static_cast<uint64_t>(r12) + 0x208u <= m_memory_size)
                nxt = *reinterpret_cast<uint32_t*>(m_memory + r12 + 0x204u);
            if (static_cast<uint64_t>(r4) + 0xCu <= m_memory_size) {
                leaf = m_memory[r4];
                cnt = *reinterpret_cast<uint32_t*>(m_memory + r4 + 4u);
            }
            snprintf(b, sizeof(b),
                     " | find r4=%08X r5=%08X r6=%08X r12=%08X child=%08X leaf=%02X cnt=%u",
                     r4, r5, r6, r12, nxt, leaf & 0xFFu, cnt);
            out += b;
        }
        // W205: PC inside CINodeSystem::Startup / Content::Startup -- where
        // in the content init chain does the thread actually sit?
        if (pc >= 0x404011D8u && pc <= 0x40401300u) {
            snprintf(b, sizeof(b), " | cstartup pc=%08X r0=%08X r4=%08X",
                     pc, j->Regs()[0], j->Regs()[4]);
            out += b;
        }
    }
    return out;
}

void DynarmicHost::DrainDeferred() {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    if (t_jit_running || m_deferred.empty()) return;
    auto batch = std::move(m_deferred);
    m_deferred.clear();
    for (auto& call : batch) {
        LOGI("Running deferred call to 0x%08X", call.first);
        RunFunction(call.first, call.second);
    }
}

// -------------------------------------------------------------
// Guest heap
//
// Every block carries a 16-byte header immediately before its payload:
//   [-16] magic  [-12] block base  [-8] capacity  [-4] payload size
// The magic is what makes GuestFree safe: a pointer that does not carry it is
// not ours (module data, an interior pointer, a stack top, something the guest
// invented) and is ignored -- exactly as a no-op free ignored everything.
// Freeing clears the magic, so a double free is ignored too.
//
// A plain bump allocator with an empty GuestFree is the usual first version and
// it is a guaranteed leak: the guest does call free(), nobody listens. Measured
// on a Scaleform title that was ~1 MB/s during gameplay.
// -------------------------------------------------------------
namespace {
constexpr uint32_t kBlockMagic = 0x41524D31; // 'ARM1' - live block
constexpr uint32_t kFreedMagic = 0x41524D46; // 'ARMF' - already on a free list
constexpr uint32_t kHeaderSize = 16;
// C1 diagnostic-only: the last 8 bytes of every block's capacity carry this
// pattern. Anything writing past a live payload (a thunk with a wrong span, a
// racing pool writer) lands here; GuestFree and the periodic diag pass report it.
constexpr uint32_t kCanaryWord = 0xC1A0C1A0;
// N2 diagnostic-only: freed blocks are filled with this byte pattern and
// verified when the block is handed out again. A guest write into a freed
// block between free and reuse (pool-level double-management) breaks the
// pattern and is reported through the N2 heap-event ring.
constexpr uint32_t kFillWord = 0xFBFBFBFB;
constexpr uint32_t kFillCapBytes = 0x10000;   // bound the fill/verify cost per block
constexpr size_t kFreedFillMaxEntries = 4096; // bound the registry
// N2: guest heap events (alloc/free with guest LR) small enough to be noise
// are not logged; everything the game's pool allocator could grow with is.
constexpr size_t kHeapEventMinSize = 0x20;
}

uint32_t DynarmicHost::GuestAlloc(size_t size, size_t alignment) {
    if (size == 0) size = 1;
    // N2 diagnostic-only: guest LR of the allocation call site.
    const uint32_t lr = t_jit ? t_jit->Regs()[14] : 0;
    if (alignment < 8) alignment = 8;
    // Worst case layout: header, then up to a full alignment step of padding.
    uint64_t need = static_cast<uint64_t>(size) + alignment + kHeaderSize;

    uint32_t base = 0, capacity = 0;
    bool recycled = false;
    {
        std::lock_guard<std::mutex> lk(m_heap_mutex);
        if (need <= kMaxClassSize) {
            int cls = 0;
            while ((1u << (cls + kMinClassShift)) < need) ++cls;
            capacity = 1u << (cls + kMinClassShift);
            auto& fl = m_free_small[cls];
            if (!fl.empty()) { base = fl.back(); fl.pop_back(); recycled = true; }
        } else {
            capacity = static_cast<uint32_t>((need + 15) & ~15ull);
            auto it = m_free_huge.find(capacity);
            if (it != m_free_huge.end() && !it->second.empty()) {
                base = it->second.back();
                it->second.pop_back();
                recycled = true;
            }
        }
        if (!recycled) {
            // Stop before the heap walks into the guest stacks instead of silently
            // handing out addresses that overlap them.
            if (static_cast<uint64_t>(m_heap_current) + capacity > kHeapLimit) {
                LOGE("GuestAlloc out of guest heap: at 0x%08X, want %u, limit 0x%08X",
                     m_heap_current, capacity, kHeapLimit);
                {
                    static std::atomic<uint32_t> w80fail{0};
                    if (w80fail.fetch_add(1) < 16) {
                        char fb[128];
                        snprintf(fb, sizeof(fb), "W80HEAPFULL at=0x%08X want=%u cap=%u",
                                 m_heap_current, capacity, capacity);
                        DiagTrace::NotePersist(fb);
                    }
                }
                return 0;
            }
            base = m_heap_current;
            m_heap_current = base + capacity;
        }
#if BRIDGE_ENABLE_HEAP_DIAGNOSTICS
        // W386 (run517): overlap assert -- the new payload must not
        // intersect any LIVE block. The descriptor-aliasing family
        // (run470+ neighbour-object fields, run511 stub descriptors,
        // run514/516 foreign-vtable calls) looks exactly like two live
        // allocations sharing bytes; catch it at birth.
        {
            const uint32_t payload_chk = static_cast<uint32_t>(
                (static_cast<uint64_t>(base) + kHeaderSize + alignment - 1) &
                ~(static_cast<uint64_t>(alignment) - 1));
            // W386b fix (run527): the live extent is [base, base+capacity),
            // not [payload, payload+capacity+64) -- the old formula produced
            // false positives for every adjacent allocation (run526 flood).
            const uint32_t new_hi = payload_chk + static_cast<uint32_t>(size);
            for (const auto& kv : m_live_blocks) {
                const uint32_t lo = kv.second.base;
                const uint32_t hi = kv.second.base + kv.second.capacity;
                if (payload_chk < hi && lo < new_hi) {
                    char ob[220];
                    snprintf(ob, sizeof(ob),
                             "W386 OVERLAP new=[%08X,%08X) live payload=%08X base=%08X cap=%u lr=0x%08X",
                             payload_chk, new_hi, lo, kv.second.base,
                             kv.second.capacity, lr);
                    DiagTrace::NotePersist(std::string(ob));
                    LOGE("%s", ob);
                    break;
                }
            }
            // W403 (run537): tail-canary check of the live block immediately
            // BELOW the new allocation. A guest buffer overflow from the
            // previous block (the DebugLog sink callback-field aliasing)
            // corrupts these two words; catching them at alloc time names
            // both neighbours. The free path already checks the same words.
            {
                uint32_t prev_base = 0, prev_cap = 0; bool have_prev = false;
                for (const auto& kv : m_live_blocks) {
                    if (kv.second.base + kv.second.capacity <= base) {
                        if (!have_prev || kv.second.base > prev_base) {
                            prev_base = kv.second.base;
                            prev_cap  = kv.second.capacity;
                            have_prev = true;
                        }
                    }
                }
                if (have_prev && prev_cap >= 8) {
                    const uint32_t t0 = MemoryRead32(prev_base + prev_cap - 8);
                    const uint32_t t1 = MemoryRead32(prev_base + prev_cap - 4);
                    if (t0 != kCanaryWord || t1 != kCanaryWord) {
                        char nb[220];
                        snprintf(nb, sizeof(nb),
                                 "W403 NEIGHBOR-CANARY prev=[%08X,%08X) tail=%08X/%08X newbase=%08X lr=0x%08X",
                                 prev_base, prev_base + prev_cap, t0, t1, base, lr);
                        DiagTrace::NotePersist(std::string(nb));
                        LOGE("%s", nb);
                    }
                }
            }
        }
#endif
    }  // W403 fix: close the heap-mutex scope
    uint32_t payload = static_cast<uint32_t>(
        (static_cast<uint64_t>(base) + kHeaderSize + alignment - 1) & ~(static_cast<uint64_t>(alignment) - 1));
    if (recycled) {
#if BRIDGE_ENABLE_HEAP_DIAGNOSTICS
        // N2 diagnostic-only: this block was pattern-filled when it was freed.
        // Verify the fill BEFORE the payload is zeroed, so a guest write into
        // the freed block between free and reuse is caught with its evidence.
        FreedFill ff = {};
        {
            std::lock_guard<std::mutex> lk(m_heap_mutex);
            auto it = m_freed_fills.find(base);
            if (it != m_freed_fills.end()) {
                ff = it->second;
                m_freed_fills.erase(it);
            }
        }
        if (ff.fill_len) {
            const uint32_t body = base + kHeaderSize;
            const uint32_t scan_len = std::min<uint32_t>(ff.fill_len, base + capacity - 8 - body);
            uint32_t bad = 0, first_off = 0, first_word = 0;
            for (uint32_t off = 0; off + 4 <= scan_len; off += 4) {
                const uint32_t w = MemoryRead32(body + off);
                if (w != kFillWord) {
                    if (!bad) { first_off = off; first_word = w; }
                    ++bad;
                    if (bad >= 64) break;
                }
            }
            if (bad) {
                char line[192];
                snprintf(line, sizeof(line),
                         "FREED-BLOCK WRITE: base=0x%08X capacity=%u fill_len=%u payload=0x%08X size=%u bad_words=%u first_off=+0x%X got=0x%08X lr=0x%08X",
                         base, capacity, ff.fill_len, payload, static_cast<uint32_t>(size), bad, first_off, first_word, lr);
                DiagTrace::GuestLog(line);
                DiagTrace::HeapEvent(line);
            }
        }
#endif
        // Fresh arena memory has always been zero, and guest code that leaned on
        // that would break in confusing ways the first time it saw a recycled
        // block. W67: zero the WHOLE capacity (not just the requested size) --
        // the guest's LL pool allocator reads count/stride fields and fills
        // pools by walking its own tables; any stale byte inside the block
        // capacity becomes a bogus element count or callback pointer.
        if (static_cast<uint64_t>(base) + capacity <= m_memory_size) {
            memset(m_memory + base + kHeaderSize, 0, capacity - kHeaderSize);
        }
    }
    MemoryWrite32(payload - 16, kBlockMagic);
    MemoryWrite32(payload - 12, base);
    MemoryWrite32(payload - 8, capacity);
    MemoryWrite32(payload - 4, static_cast<uint32_t>(size));
#if BRIDGE_ENABLE_HEAP_DIAGNOSTICS
    // C1 diagnostic-only: canary at the tail of the block's capacity (inside the
    // block regardless of payload alignment padding) + live-block registry entry.
    MemoryWrite32(base + capacity - 8, kCanaryWord);
    MemoryWrite32(base + capacity - 4, kCanaryWord);
    {
        std::lock_guard<std::mutex> lk(m_heap_mutex);
        m_live_blocks[payload] = {base, static_cast<uint32_t>(size), capacity};
    }
    // N2 diagnostic-only: log the allocation outside m_heap_mutex (the diag
    // writer takes the same mutex for the canary pass; nesting would risk an
    // ABBA deadlock with DiagTrace's own lock).
    if (size >= kHeapEventMinSize) {
        char line[160];
        snprintf(line, sizeof(line), "alloc size=%u payload=0x%08X base=0x%08X capacity=%u%s lr=0x%08X",
                 static_cast<uint32_t>(size), payload, base, capacity, recycled ? " recycled" : " fresh", lr);
        DiagTrace::HeapEvent(line);
    }
#endif
    if (size >= (8u << 20)) {
        // W146: a huge guest-heap request during boot is the runaway-fill
        // signature. lr 0x40DAB0 is PDMalloc's call site in LLMemAllocateV's
        // slow path (PDMalloc itself is a single branch), so the register file
        // still holds LLMemAllocateV's view: R9 = pool id, R6 = flag word
        // (0x610 = "POOL BUNCH" refill), R4 = size+8+align. Dump them plus the
        // addressed pool descriptor: v5[0]=count scales BOTH the allocation
        // (elem*count+4) and the fill loop bound, so a corrupted count is the
        // whole runaway.
        static std::atomic<uint32_t> w146_big{0};
        if (w146_big.fetch_add(1) < 4 && t_jit) {
            const auto& r = t_jit->Regs();
            char b[240];
            snprintf(b, sizeof(b),
                     "W146BIG size=%u lr=%08X r4=%08X r6=%08X r9=%08X payload=0x%08X",
                     static_cast<uint32_t>(size), lr, r[4], r[6], r[9], payload);
            DiagTrace::GuestLog(b);
            LOGE("%s", b);
            const uint32_t poolid = r[9];
            if (poolid < 0x200u) {
                const uint32_t dptr = MemoryRead32(0x406DAE5Cu + 0x284u + 4u * poolid);
                snprintf(b, sizeof(b),
                         "W146DESC poolid=%u desc=%08X cnt=%u cpy=%u elem=%u allocN=%u used=%u bunch=%08X free=%08X owner=%u",
                         poolid, dptr,
                         dptr ? MemoryRead32(dptr) : 0,
                         dptr ? MemoryRead32(dptr + 4) : 0,
                         dptr ? MemoryRead32(dptr + 8) : 0,
                         dptr ? MemoryRead32(dptr + 12) : 0,
                         dptr ? MemoryRead32(dptr + 16) : 0,
                         dptr ? MemoryRead32(dptr + 20) : 0,
                         dptr ? MemoryRead32(dptr + 24) : 0,
                         dptr ? MemoryRead32(dptr + 40) : 0);
                DiagTrace::GuestLog(b);
                LOGE("%s", b);
            }
        }
    }
    // W153: publish this block's end (minus the canary pair) for the
    // fill-clamp in the W148/W149/W151 stubs. A bunch fill must never walk
    // past the allocation that was sized for it, whatever the descriptor's
    // (possibly corrupted) count/stride say -- this breaks the sweep cascade
    // that stamped [X]=X+stride links across the guest data segment, the
    // worker stacks and the bridge counter window (run201).
    MemoryWrite32(0x00010280u, base + capacity - 8);
    return payload;
}

void DynarmicHost::GuestFree(uint32_t addr) {
    if (addr < kHeapBase + kHeaderSize) return;         // cannot be one of ours
#if BRIDGE_ENABLE_HEAP_DIAGNOSTICS
    // C1 diagnostic-only: guest LR of the caller, captured before anything else.
    const uint32_t lr = t_jit ? t_jit->Regs()[14] : 0;
#endif
    if (MemoryRead32(addr - 16) != kBlockMagic) return; // foreign pointer, or already freed
    uint32_t base = MemoryRead32(addr - 12);
    uint32_t capacity = MemoryRead32(addr - 8);
#if BRIDGE_ENABLE_HEAP_DIAGNOSTICS
    if (MemoryRead32(base + capacity - 8) != kCanaryWord ||
        MemoryRead32(base + capacity - 4) != kCanaryWord) {
        char line[192];
        snprintf(line, sizeof(line),
                 "CANARY VIOLATION (free): payload=0x%08X base=0x%08X size=%u capacity=%u lr=0x%08X got=%08X %08X",
                 addr, base, MemoryRead32(addr - 4), capacity, lr,
                 MemoryRead32(base + capacity - 8), MemoryRead32(base + capacity - 4));
        DiagTrace::GuestLog(line);
    }
#endif
    MemoryWrite32(addr - 16, kFreedMagic);

#if BRIDGE_ENABLE_HEAP_DIAGNOSTICS
    // N2 diagnostic-only: pattern-fill the block body so any write into the
    // freed block until its next reuse shows up in the verify-on-alloc pass.
    // The 8 canary bytes at the block tail stay untouched.
    const uint32_t fill_len = std::min<uint32_t>(capacity - kHeaderSize - 8, kFillCapBytes);
    if (fill_len) {
        memset(m_memory + base + kHeaderSize, 0xFB, fill_len);
    }
    char line[160];
    snprintf(line, sizeof(line), "free payload=0x%08X base=0x%08X size=%u capacity=%u lr=0x%08X",
             addr, base, MemoryRead32(addr - 4), capacity, lr);
    if (MemoryRead32(addr - 4) >= kHeapEventMinSize) DiagTrace::HeapEvent(line);
#endif

    std::lock_guard<std::mutex> lk(m_heap_mutex);
#if BRIDGE_ENABLE_HEAP_DIAGNOSTICS
    m_live_blocks.erase(addr);
    if (fill_len && m_freed_fills.size() < kFreedFillMaxEntries) {
        m_freed_fills[base] = {addr, fill_len};
    }
#endif
    if (capacity <= kMaxClassSize) {
        int cls = 0;
        while ((1u << (cls + kMinClassShift)) < capacity) ++cls;
        m_free_small[cls].push_back(base);
    } else {
        m_free_huge[capacity].push_back(base);
    }
}

uint32_t DynarmicHost::GuestAllocSize(uint32_t addr) {
    if (addr < kHeapBase + kHeaderSize) return 0;
    if (MemoryRead32(addr - 16) != kBlockMagic) return 0;
    return MemoryRead32(addr - 4);
}

// C1 diagnostic-only. Runs on the diag writer thread every dump cycle, so the
// reads race with live guest execution; a canary word is only ever written by
// GuestAlloc/GuestFree, and a torn read can at worst miss one violation, never
// invent one (pattern -> pattern). Bounded so a corrupt heap cannot flood the
// dump.
std::string DynarmicHost::DiagCheckHeapCanaries() {
#if !BRIDGE_ENABLE_HEAP_DIAGNOSTICS
    return "heap canary diagnostics disabled\n";
#else
    std::lock_guard<std::mutex> lk(m_heap_mutex);
    std::string out;
    char line[192];
    int violations = 0;
    for (const auto& kv : m_live_blocks) {
        const auto& b = kv.second;
        const uint32_t w1 = MemoryRead32(b.base + b.capacity - 8);
        const uint32_t w2 = MemoryRead32(b.base + b.capacity - 4);
        if (w1 == kCanaryWord && w2 == kCanaryWord) continue;
        snprintf(line, sizeof(line),
                 "VIOLATION payload=0x%08X base=0x%08X size=%u capacity=%u got=%08X %08X\n",
                 kv.first, b.base, b.size, b.capacity, w1, w2);
        out += line;
        // W150: the writer leaves a trail -- link values at stride spacing
        // behind the overrun point name the stride and the bunch it walked.
        // Dump 16 words before the canary plus the live pool-descriptor table
        // so the offending pool id can be matched by element size.
        {
            char t[512];
            int n = snprintf(t, sizeof(t), "W150 trail base-64:");
            for (int w = -16; w < 0 && n > 0 && static_cast<size_t>(n) < sizeof(t); ++w)
                n += snprintf(t + n, sizeof(t) - static_cast<size_t>(n), " %08X",
                              MemoryRead32(b.base + b.capacity - 8 +
                                           static_cast<uint32_t>(w) * 4));
            out += t;
            out += '\n';
        }
        if (++violations >= 8) {
            out += "... (report capped at 8 violations per dump)\n";
            break;
        }
    }
    snprintf(line, sizeof(line), "live_blocks=%zu heap_current=0x%08X violations=%d\n",
             m_live_blocks.size(), m_heap_current, violations);
    out += line;
    // W150: pool descriptor pointer table (ids 1..12), contents [count stride].
    {
        char t[512];
        int n = snprintf(t, sizeof(t), "W150 pools:");
        for (int i = 1; i <= 12 && n > 0 && static_cast<size_t>(n) < sizeof(t); ++i) {
            const uint32_t dptr = MemoryRead32(0x406DAE5Cu + 0x284u + 4u * i);
            n += snprintf(t + n, sizeof(t) - static_cast<size_t>(n),
                          " [%d]=%08X:%u*%u", i, dptr,
                          dptr ? MemoryRead32(dptr) : 0,
                          dptr ? MemoryRead32(dptr + 8) : 0);
        }
        out += t;
        out += '\n';
    }
    return out;
#endif
}

// ---------------------------------------------------------------------------
// N1 diagnostic-only: live walk of the guest's dynamic vertex-buffer registry.
//
// Static facts (IDA, session carmageddon_phase7_c1_repair / evidence
// work/phase7_c1_repair_route_evidence.txt): gDynamic_vb_map (ELF 0x6C8494)
// is a POINTER to a 24-byte object made by operator new(0x18) in
// PDOpenDynamicVertexBuffers (0x26B8DC). Map object layout:
//   [+0]  (unknown/compare)      [+4] header/end node (color field)
//   [+8]  root (_M_parent)       [+12] leftmost/begin
//   [+16] rightmost              [+20] size
// end sentinel VALUE = map+4. Tree nodes are pooled LLMemAllocate(0x18)
// (PDLockDynamicVB 0x26BC8C): [+0] color, [+4] parent, [+8] left,
// [+12] right, [+16] key, [+20] value (head of a 0x2C-byte bzDynamicVB list).
// PDInvalidDynamicVertexBuffers (0x26BB08) iterates the map with
// sub_5BDE68 (__tree_next) and spins forever when the walk never returns
// map+4. Successive 10 s dumps of this walk show WHEN the tree becomes
// cyclic and which links are wrong.
// All reads are plain guest-memory reads on the diag writer thread; every
// loop is bounded so a corrupt tree shortens or caps the report only.
// ---------------------------------------------------------------------------

namespace {
// Guest ELF offsets of the dynamic-VB globals.
constexpr uint32_t kVbMapPtrOffset    = 0x6C8494;  // gDynamic_vb_map
constexpr uint32_t kVbDword6C8484     = 0x6C8484;  // dword_6C8484
constexpr uint32_t kVbDword6C8488     = 0x6C8488;  // dword_6C8488
constexpr uint32_t kVbVertexWorkspace = 0x6C8490;  // gVertex_workspace
constexpr uint32_t kVbUsingWorkspace  = 0x6C848D;  // gUsing_workspace (byte)
constexpr uint32_t kWalkMaxNodes   = 1024;         // nodes printed per dump
constexpr uint32_t kNextMaxClimbs  = 4096;         // bound per __tree_next call
}

// Canonical libstdc++ _Rb_tree_increment with hard bounds so a cyclic or
// broken tree cannot spin this walk. Returns 0 on a bounded bail.
uint32_t DynarmicHost::DiagVbTreeNext(uint32_t x, uint32_t header) {
    const uint32_t right = MemoryRead32(x + 12);
    if (right) {
        uint32_t n = right;
        uint32_t guard = 0;
        while (guard++ < kNextMaxClimbs) {
            const uint32_t l = MemoryRead32(n + 8);
            if (!l) break;
            n = l;
        }
        if (guard > kNextMaxClimbs) return 0;
        return n;
    }
    uint32_t y = MemoryRead32(x + 4);
    uint32_t guard = 0;
    while (y && MemoryRead32(y + 12) == x) {
        if (++guard > kNextMaxClimbs) return 0;
        x = y;
        y = MemoryRead32(y + 4);
    }
    if (MemoryRead32(x + 12) != y) return y;
    return x;
}

std::string DynarmicHost::DiagWalkDynamicVbMap() {
    std::string out;
    char line[224];
    const uint32_t kBase = kGuestGameBase;
    const uint32_t map = MemoryRead32(kBase + kVbMapPtrOffset);
    snprintf(line, sizeof(line),
             "gDynamic_vb_map=0x%08X dword_6C8484=0x%08X dword_6C8488=0x%08X gVertex_workspace=0x%08X gUsing_workspace=%u\n",
             map,
             MemoryRead32(kBase + kVbDword6C8484),
             MemoryRead32(kBase + kVbDword6C8488),
             MemoryRead32(kBase + kVbVertexWorkspace),
             MemoryRead8(kBase + kVbUsingWorkspace));
    out += line;
    if (!map) {
        out += "map pointer null (PDOpenDynamicVertexBuffers has not run yet)\n";
        return out;
    }
    const uint32_t header = map + 4;  // the end sentinel node address
    snprintf(line, sizeof(line),
             "map[+0]=0x%08X end_color[+4]=0x%08X root[+8]=0x%08X leftmost[+12]=0x%08X rightmost[+16]=0x%08X size[+20]=%u\n",
             MemoryRead32(map), MemoryRead32(map + 4), MemoryRead32(map + 8),
             MemoryRead32(map + 12), MemoryRead32(map + 16), MemoryRead32(map + 20));
    out += line;

    // Header invariants: an existing root hangs off the header, and a nonzero
    // size implies a root.
    const uint32_t root = MemoryRead32(map + 8);
    const uint32_t size_field = MemoryRead32(map + 20);
    if (root) {
        const uint32_t root_parent = MemoryRead32(root + 4);
        if (root_parent != header) {
            snprintf(line, sizeof(line),
                     "INVARIANT BROKEN: root=0x%08X parent=0x%08X (expected header 0x%08X)\n",
                     root, root_parent, header);
            out += line;
        }
    } else if (size_field) {
        snprintf(line, sizeof(line),
                 "INVARIANT BROKEN: root=0 but size=%u\n", size_field);
        out += line;
    }

    // Bounded walk in the guest loop's own order (PDInvalidDynamicVertexBuffers
    // 0x26BB08: v3 = *(map+12) = leftmost/begin; do { ...; v3 = next(v3); }
    // while (v3 != header)). A node visited twice before the header = the cycle
    // that spins the guest.
    const uint32_t leftmost = MemoryRead32(map + 12);
    if (leftmost == header) {
        out += "begin == end (empty per header); the guest loop would be skipped\n";
        return out;
    }
    std::unordered_map<uint32_t, uint32_t> visited;
    uint32_t x = leftmost;
    uint32_t steps = 0;
    bool completed = false;
    bool broken = false;
    uint32_t cycle_addr = 0, cycle_first = 0;
    while (steps < kWalkMaxNodes) {
        auto ins = visited.emplace(x, steps);
        if (!ins.second) {
            cycle_addr = x;
            cycle_first = ins.first->second;
            break;
        }
        snprintf(line, sizeof(line),
                 "node[%u] addr=0x%08X color=%u parent=0x%08X left=0x%08X right=0x%08X key=0x%08X value=0x%08X\n",
                 steps, x, MemoryRead32(x), MemoryRead32(x + 4), MemoryRead32(x + 8),
                 MemoryRead32(x + 12), MemoryRead32(x + 16), MemoryRead32(x + 20));
        out += line;
        ++steps;
        x = DiagVbTreeNext(x, header);
        if (x == header) { completed = true; break; }
        if (!x) { broken = true; break; }
    }
    if (completed) {
        snprintf(line, sizeof(line), "walk complete: %u nodes, returned to header 0x%08X\n",
                 steps, header);
        out += line;
    } else if (cycle_addr) {
        snprintf(line, sizeof(line),
                 "CYCLE: node 0x%08X revisited (first seen step %u, again step %u); __tree_next never returns the header - this is the PDInvalidDynamicVertexBuffers infinite loop\n",
                 cycle_addr, cycle_first, steps);
        out += line;
    } else if (broken) {
        out += "walk bailed: __tree_next hit its bound or a null parent chain\n";
    } else {
        snprintf(line, sizeof(line), "walk hit the %u-node cap without returning to the header\n",
                 kWalkMaxNodes);
        out += line;
    }
    return out;
}

// W146: guest data-segment smash sentinel. dword_6DAE5C (= guest 0x406DAE5C)
// hosts the LLMem pool machinery; sub_40D4A0 reads the descriptor pointer for
// pool a1 as dword_6DAE5C[a1 + 161]. A descriptor's count/stride fields are
// written once at pool creation, so any later change is a wild write -- the
// same event class that left the startup pause flag (0x40673288) and the LLMem
// default alignment (0x4067332C) holding garbage mid-boot.
std::string DynarmicHost::DiagW146Sentinels() {
    struct Snap {
        bool have = false;
        uint32_t pause = 0, align = 0;
        uint32_t dptr[10] = {};
        uint32_t cnt[10] = {};
        uint32_t elem[10] = {};
    };
    static Snap prev;  // diag writer thread is the only caller
    Snap cur;
    char line[128];
    std::string out;
    cur.pause = MemoryRead32(0x40673288u);
    cur.align = MemoryRead32(0x4067332Cu);
    constexpr uint32_t kDescTable = 0x406DAE5Cu + 0x284u;
    for (int i = 0; i < 10; ++i) {
        cur.dptr[i] = MemoryRead32(kDescTable + 4u * i);
        cur.cnt[i]  = cur.dptr[i] ? MemoryRead32(cur.dptr[i]) : 0;
        cur.elem[i] = cur.dptr[i] ? MemoryRead32(cur.dptr[i] + 8) : 0;
    }
    if (!prev.have) {
        snprintf(line, sizeof(line), "W146 init pause=%u align=%u\n", cur.pause, cur.align);
        out += line;
        for (int i = 0; i < 10; ++i) {
            snprintf(line, sizeof(line), "W146 desc[%d]=%08X cnt=%u elem=%u\n",
                     i, cur.dptr[i], cur.cnt[i], cur.elem[i]);
            out += line;
        }
    } else {
        if (cur.pause != prev.pause) {
            snprintf(line, sizeof(line), "W146CHG pause %u -> %u\n", prev.pause, cur.pause);
            out += line;
        }
        if (cur.align != prev.align) {
            snprintf(line, sizeof(line), "W146CHG align %u -> %u\n", prev.align, cur.align);
            out += line;
        }
        for (int i = 0; i < 10; ++i) {
            if (cur.dptr[i] != prev.dptr[i] || cur.cnt[i] != prev.cnt[i] ||
                cur.elem[i] != prev.elem[i]) {
                snprintf(line, sizeof(line), "W146CHG desc[%d] %08X:%u*%u -> %08X:%u*%u\n",
                         i, prev.dptr[i], prev.cnt[i], prev.elem[i],
                         cur.dptr[i], cur.cnt[i], cur.elem[i]);
                out += line;
            }
        }
    }
    prev = cur;
    // W152: fill-snapshot ring the W148/W149/W151 stubs append to at
    // 0x00010200 ([count, stride] of the last 16 bunch fills with
    // count >= 31). Paring entries against the alloc heap events
    // (size = count*stride + 40) exposes the alloc->fill descriptor
    // mutation with both sides' values.
    {
        char line2[128];
        const uint32_t seq = MemoryRead32(0x00010200u);
        snprintf(line2, sizeof(line2), "W152 fills seq=%u:", seq);
        out += line2;
        for (int i = 0; i < 16; ++i) {
            const uint32_t cnt = MemoryRead32(0x00010204u + 8u * i);
            const uint32_t strd = MemoryRead32(0x00010208u + 8u * i);
            if (!cnt && !strd) continue;
            snprintf(line2, sizeof(line2), " [%d]=%u*%u", i, cnt, strd);
            out += line2;
        }
        out += '\n';
    }
    // W154: arguments of the last LLMemCreateNewPool call with count > 10M.
    if (MemoryRead32(0x00010300u)) {
        char line2[128];
        snprintf(line2, sizeof(line2),
                 "W154BIGPOOL elem=%u count=%u bunches=%u r12=%u lr=%08X\n",
                 MemoryRead32(0x00010304u), MemoryRead32(0x00010308u),
                 MemoryRead32(0x0001030Cu), MemoryRead32(0x00010310u),
                 MemoryRead32(0x00010314u));
        out += line2;
    }
    // W156: D_1 callee entry counters (0x00010340 + i*4).
    {
        char line2[128];
        snprintf(line2, sizeof(line2), "W156 callees: StartProcSet=%u sub22127C=%u AddSessionType=%u\n",
                 MemoryRead32(0x00010340u), MemoryRead32(0x00010344u),
                 MemoryRead32(0x00010348u));
        out += line2;
    }
    // W159: watch the W124 D_1 stub tgt literal (0x65D840) + the stub's first
    // words for post-install stomps.
    {
        char line2[128];
        snprintf(line2, sizeof(line2), "W159 stub lit=%08X tgt=%08X w0=%08X site=%08X blxtgt=%08X w160site=%08X llmem_err=%u bzgerr=%u\n",
                 MemoryRead32(0x8F111050u), MemoryRead32(0x40222FD0u),
                 MemoryRead32(0x8F111000u), MemoryRead32(0x402160ECu),
                 MemoryRead32(0x0001035Cu), MemoryRead32(0x40222FF0u),
                 MemoryRead32(0x406DAE5Cu), MemoryRead32(0x406925FCu));
        {
            char line3[96];
            snprintf(line3, sizeof(line3), "W169 w122 blxtgt=%08X\n",
                     MemoryRead32(0x00010048u));
            out += line3;
        }
        out += line2;
        // Persist every poll: the diag file keeps only the last dump, but the
        // lit corruption is only visible in EARLY ticks.
        {
            std::string pl(line2);
            pl.pop_back();
            DiagTrace::NotePersist(pl);
        }
    }
    // W160: D_1 -> LLMemFill entry counter.
    {
        char line2[64];
        snprintf(line2, sizeof(line2), "W160 LLMemFill entered=%u\n",
                 MemoryRead32(0x00010358u));
        out += line2;
    }
    // W188: bz_AR_AddSessionType internal call counters.
    {
        char line2[128];
        snprintf(line2, sizeof(line2), "W188 internal: LLMemAllocV=%u mapinsert=%u pool76entry=%08X\n",
                 MemoryRead32(0x00010370u), MemoryRead32(0x00010374u), MemoryRead32(0x406DC928u));
        out += line2;
    }
    // W197: remaining ActualMain stage probes. Init_BZ's directory calls
    // and the bz_StartInternal BL run from their original guest instructions.
    // W199: CBNode::FindImpl null-child bails (0 = no empty-tree spins).
    {
        char line2[144];
        snprintf(line2, sizeof(line2), "W197 chain: freed=%u print=%u doinit=%u enter=%u findbail=%u\n",
                 MemoryRead32(0x93000408u), MemoryRead32(0x9300040Cu),
                 MemoryRead32(0x93000414u), MemoryRead32(0x93000418u),
                 MemoryRead32(0x9300041Cu));
        out += line2;
        // W199b: the bail capture (last bail's r0-r3/r12/lr).
        {
            char line3[128];
            snprintf(line3, sizeof(line3),
                     "W199CAP r0=%08X r1=%08X r2=%08X r3=%08X r12=%08X lr=%08X\n",
                     MemoryRead32(0x93000420u), MemoryRead32(0x93000424u),
                     MemoryRead32(0x93000428u), MemoryRead32(0x9300042Cu),
                     MemoryRead32(0x93000430u), MemoryRead32(0x93000434u));
            out += line3;
        }
        // W200: FindImpl ENTRY capture (first-call args + true caller).
        {
            char line3[128];
            snprintf(line3, sizeof(line3),
                     "W200ENT n=%u r0=%08X r1=%08X r2=%08X r3=%08X lr=%08X\n",
                     MemoryRead32(0x93000458u), MemoryRead32(0x93000440u),
                     MemoryRead32(0x93000444u), MemoryRead32(0x93000448u),
                     MemoryRead32(0x9300044Cu), MemoryRead32(0x93000450u));
            out += line3;
            // W200b: the captured caller-frame words.
            char line4[160];
            snprintf(line4, sizeof(line4),
                     "W200STK %08X %08X %08X %08X %08X %08X %08X %08X\n",
                     MemoryRead32(0x93000460u), MemoryRead32(0x93000464u),
                     MemoryRead32(0x93000468u), MemoryRead32(0x9300046Cu),
                     MemoryRead32(0x93000470u), MemoryRead32(0x93000474u),
                     MemoryRead32(0x93000478u), MemoryRead32(0x9300047Cu));
            out += line4;
        }
        // W258/W259: Init_BZ return + LLMemFreeSpace entry.
        {
            char line5[80];
            snprintf(line5, sizeof(line5), "W258 ret=%u W259 fs=%u\n",
                     MemoryRead32(0x93000050u), MemoryRead32(0x93000054u));
            char line6[96];
            snprintf(line6, sizeof(line6), "W260 rsrch=%u r2=%08X W226 ase=%u rsg=%u\n",
                     MemoryRead32(0x93000058u), MemoryRead32(0x93000064u),
                     MemoryRead32(0x9300005Cu), MemoryRead32(0x93000060u));
            out += line6;
            out += line5;
        }
        // W268: GetWADAppData entry + name ASCII.
        {
            const uint32_t np = MemoryRead32(0x93000084u);
            char nb[20];
            for (int i = 0; i < 16; ++i)
                nb[i] = np ? static_cast<char>(MemoryRead8(np + static_cast<uint32_t>(i))) : 0;
            nb[16] = 0;
            char line9[160];
            snprintf(line9, sizeof(line9), "W268 gwad=%u name=%08X app=%08X caller=%08X n0=%08X nm=%.16s\n",
                     MemoryRead32(0x93000080u), np, MemoryRead32(0x93000088u),
                     MemoryRead32(0x9300008Cu), MemoryRead32(0x93000090u), nb);
            out += line9;
        }
        // W270: bz_fread entry - bzFile, AAsset*, FILE*, and count.
        {
            char lineA[128];
            snprintf(lineA, sizeof(lineA), "W270 fread=%u bf=%08X asset=%08X stream=%08X\n",
                     MemoryRead32(0x90000620u), MemoryRead32(0x90000610u),
                     MemoryRead32(0x90000614u), MemoryRead32(0x90000618u));
            out += lineA;
        }
        // W272/W273: WADSimple::fopen + AddEntry.
        {
            char lineB[200];
            snprintf(lineB, sizeof(lineB), "W272 wf=%u node=%08X lr=%08X n0=%08X n1=%08X n2=%08X W273 add=%u nm=%08X ty=%u w0=%08X\n",
                     MemoryRead32(0x930000C0u), MemoryRead32(0x930000C4u),
                     MemoryRead32(0x930000C8u), MemoryRead32(0x930000CCu),
                     MemoryRead32(0x930000D0u), MemoryRead32(0x930000D4u),
                     MemoryRead32(0x930000D8u), MemoryRead32(0x930000DCu),
                     MemoryRead32(0x930000E0u), MemoryRead32(0x930000E4u));
            out += lineB;
            const uint32_t dp = MemoryRead32(0x930000F0u);
            char db[20];
            for (int i = 0; i < 16; ++i)
                db[i] = dp ? static_cast<char>(MemoryRead8(dp + static_cast<uint32_t>(i))) : 0;
            db[16] = 0;
            char lineC[160];
            snprintf(lineC, sizeof(lineC), "W274 add=%u grp=%08X dir=%08X tag=%08X dir16=%.16s\n",
                     MemoryRead32(0x930000E8u), MemoryRead32(0x930000ECu),
                     dp, MemoryRead32(0x930000F4u), db);
            out += lineC;
            const uint32_t cp2 = MemoryRead32(0x93000100u);
            char cb[20];
            for (int i = 0; i < 16; ++i)
                cb[i] = cp2 ? static_cast<char>(MemoryRead8(cp2 + static_cast<uint32_t>(i))) : 0;
            cb[16] = 0;
            char lineD[160];
            snprintf(lineD, sizeof(lineD), "W275 cfg=%u obj=%08X name=%08X w0=%08X cfg16=%.16s\n",
                     MemoryRead32(0x930000F8u), MemoryRead32(0x930000FCu),
                     cp2, MemoryRead32(0x93000100u), cb);
            out += lineD;
            const uint32_t wp = MemoryRead32(0x9300010Cu);
            char wb[24];
            for (int i = 0; i < 20; ++i)
                wb[i] = wp ? static_cast<char>(MemoryRead8(wp + static_cast<uint32_t>(i))) : 0;
            wb[20] = 0;
            char lineE[160];
            snprintf(lineE, sizeof(lineE), "W279 wadopen=%u name=%08X flag=%08X w0=%08X path=%.20s\n",
                     MemoryRead32(0x93000108u), wp,
                     MemoryRead32(0x93000110u), MemoryRead32(0x93000114u), wb);
            out += lineE;
        }
        // W290: android_app struct dump (0x50847DE0, 0x60 bytes) -- find
        // msgread/msgwrite fds (small adjacent ints) and queue pointers.
        {
            char lineS[900];
            int sn = snprintf(lineS, sizeof(lineS), "W290 app:\n");
            for (int wi = 0; wi < 37; ++wi)
                sn += snprintf(lineS + sn, sizeof(lineS) - static_cast<size_t>(sn),
                               " %02X=%08X\n",
                               wi * 4, MemoryRead32(MemoryRead32(0x93000160u) + static_cast<uint32_t>(wi) * 4u));
            out += lineS;
        }
        // W281: Content::fread entry.
        {
            char lineF[160];
            snprintf(lineF, sizeof(lineF), "W281 cf=%u file=%08X buf=%08X n=%u caller=%08X\n",
                     MemoryRead32(0x93000118u), MemoryRead32(0x9300011Cu),
                     MemoryRead32(0x93000120u), MemoryRead32(0x93000124u),
                     MemoryRead32(0x93000128u));
            out += lineF;
            char lineG[96];
            snprintf(lineG, sizeof(lineG), "W270h magic=%08X base=%08X\n",
                     MemoryRead32(0x90000698u), MemoryRead32(0x9000069Cu));
            out += lineG;
            const uint32_t np2 = MemoryRead32(0x9300014Cu);
            char nb2[20];
            for (int i = 0; i < 16; ++i)
                nb2[i] = np2 ? static_cast<char>(MemoryRead8(np2 + static_cast<uint32_t>(i))) : 0;
            nb2[16] = 0;
            char lineJ[160];
            snprintf(lineJ, sizeof(lineJ), "W294 csfopen=%u name=%08X caller=%08X n0=%08X n1=%08X nm=%.16s\n",
                     MemoryRead32(0x93000148u), np2,
                     MemoryRead32(0x93000150u), MemoryRead32(0x93000154u),
                     MemoryRead32(0x93000158u), nb2);
            out += lineJ;
        }
        // W297: android_handle_cmd delivery counter.
        {
            char lineK[96];
            snprintf(lineK, sizeof(lineK), "W297 hcmd=%u cmd=%u app=%08X\n",
                     MemoryRead32(0x93000168u), MemoryRead32(0x9300016Cu),
                     MemoryRead32(0x93000170u));
            char lineL[96];
            snprintf(lineL, sizeof(lineL), "W300 exitA=%u retA=%08X exitB=%u retB=%08X\n",
                     MemoryRead32(0x93000180u), MemoryRead32(0x93000184u),
                     MemoryRead32(0x93000188u), MemoryRead32(0x9300018Cu));
            out += lineL;
            char lineM[128];
            snprintf(lineM, sizeof(lineM),
                     "W318 throws=%u file=%08X asset=%08X stream=%08X pos=%u w18=%08X\n",
                     MemoryRead32(0x000106D0u), MemoryRead32(0x000106D4u),
                     MemoryRead32(0x000106D8u), MemoryRead32(0x000106DCu),
                     MemoryRead32(0x000106E0u), MemoryRead32(0x000106E4u));
            out += lineM;
            char lineO[96];
            snprintf(lineO, sizeof(lineO), "W318b caller=%08X\n",
                     MemoryRead32(0x000106E8u));
            out += lineO;
            char lineP[192];
            snprintf(lineP, sizeof(lineP),
                     "W318c f08=%08X f0C=%08X f20=%08X f24=%08X f28=%08X f2C=%08X f30=%08X f34=%08X f38=%08X f3C=%08X\n",
                     MemoryRead32(0x000106E0u), MemoryRead32(0x000106E4u),
                     MemoryRead32(0x00010700u), MemoryRead32(0x00010704u),
                     MemoryRead32(0x00010708u), MemoryRead32(0x0001070Cu),
                     MemoryRead32(0x00010710u), MemoryRead32(0x00010714u),
                     MemoryRead32(0x00010718u), MemoryRead32(0x0001071Cu));
            out += lineP;
            {
                char nb2[64];
                const uint32_t pp = MemoryRead32(0x900007C4u);
                nb2[0] = '\0';
                if (pp && pp + 16 <= m_memory_size) {
                    for (int k = 0; k < 15; ++k) {
                        const char ch = static_cast<char>(m_memory[pp + k]);
                        if (!ch) break;
                        nb2[k] = ch;
                        nb2[k + 1] = '\0';
                    }
                }
                char lineQ[160];
                snprintf(lineQ, sizeof(lineQ),
                         "W323 parse=%u path=%08X [%08X %08X] str=%s\n",
                         MemoryRead32(0x900007C0u), pp,
                         MemoryRead32(0x900007C8u), MemoryRead32(0x900007CCu), nb2);
                out += lineQ;
            }
            char lineR[96];
            snprintf(lineR, sizeof(lineR), "W324 parseopen=%u file=%08X\n",
                     MemoryRead32(0x900007A0u), MemoryRead32(0x900007A4u));
            out += lineR;
            char lineVerify[288];
            snprintf(lineVerify, sizeof(lineVerify),
                     "W563 verify=%u file=%08X flag=%08X lr=%08X androidftell=%u/%08X/%08X tell=%u/%08X/%08X seek=%u/%08X/%08X u16=%u/%08X/%08X\n",
                     MemoryRead32(0x93000300u), MemoryRead32(0x93000304u),
                     MemoryRead32(0x93000308u), MemoryRead32(0x9300030Cu),
                     MemoryRead32(0x93000340u), MemoryRead32(0x93000344u),
                     MemoryRead32(0x93000348u),
                     MemoryRead32(0x93000310u), MemoryRead32(0x93000314u),
                     MemoryRead32(0x93000318u), MemoryRead32(0x93000320u),
                     MemoryRead32(0x93000324u), MemoryRead32(0x93000328u),
                     MemoryRead32(0x93000350u), MemoryRead32(0x93000354u),
                     MemoryRead32(0x93000358u));
            out += lineVerify;
            char lineService[192];
            snprintf(lineService, sizeof(lineService),
                     "W564 loadservice=%08X sem=%u loading=%u last=%08X W281site=%08X/%08X stub=%08X/%08X\n",
                     MemoryRead32(0x47A955Cu), MemoryRead8(0x47A955Au),
                     MemoryRead8(0x47A9559u), MemoryRead32(0x47A9560u),
                     MemoryRead32(0x403F7F84u), MemoryRead32(0x403F7F88u),
                     MemoryRead32(0x8F115100u), MemoryRead32(0x8F115104u));
            out += lineService;
            const uint32_t hookRoot = MemoryRead32(0x4066F1A4u);
            const uint32_t hookRead =
                (hookRoot && static_cast<size_t>(hookRoot) + 0x58u <= m_memory_size)
                    ? MemoryRead32(hookRoot + 0x54u) : 0;
            const uint32_t fileRead = MemoryRead32(0x900007A4u);
            const bool fileReadOk = fileRead &&
                static_cast<size_t>(fileRead) + 0x20u <= m_memory_size;
            char lineFileRead[224];
            snprintf(lineFileRead, sizeof(lineFileRead),
                     "W565 hooks=%08X/%08X code=%08X file=%08X fields=%08X/%08X/%08X/%08X/%08X/%08X/%08X/%08X\n",
                     hookRoot, hookRead, hookRead ? MemoryRead32(hookRead) : 0,
                     fileRead,
                     fileReadOk ? MemoryRead32(fileRead) : 0,
                     fileReadOk ? MemoryRead32(fileRead + 4u) : 0,
                     fileReadOk ? MemoryRead32(fileRead + 8u) : 0,
                     fileReadOk ? MemoryRead32(fileRead + 12u) : 0,
                     fileReadOk ? MemoryRead32(fileRead + 16u) : 0,
                     fileReadOk ? MemoryRead32(fileRead + 20u) : 0,
                     fileReadOk ? MemoryRead32(fileRead + 24u) : 0,
                     fileReadOk ? MemoryRead32(fileRead + 28u) : 0);
            out += lineFileRead;
            {
                char pb2[80];
                const uint32_t pp2 = MemoryRead32(0x900007B4u);
                pb2[0] = '\0';
                if (pp2 && pp2 + 32 <= m_memory_size) {
                    for (int k = 0; k < 31; ++k) {
                        const char ch = static_cast<char>(m_memory[pp2 + k]);
                        if (!ch) break;
                        pb2[k] = ch;
                        pb2[k + 1] = '\0';
                    }
                }
                char lineT[320];
                const uint32_t openCount = MemoryRead32(0x900007B0u);
                int lineTLength = snprintf(lineT, sizeof(lineT),
                                           "W326 fopen=%u path=%08X str=%s ring=",
                                           openCount, pp2, pb2);
                for (uint32_t slot = 0; slot < 16u && lineTLength > 0 &&
                                         static_cast<size_t>(lineTLength) < sizeof(lineT); ++slot) {
                    lineTLength += snprintf(lineT + lineTLength,
                                            sizeof(lineT) - static_cast<size_t>(lineTLength),
                                            "%s%u:%08X", slot ? "," : "", slot,
                                            MemoryRead32(0x900007F0u + slot * 4u));
                }
                if (lineTLength > 0)
                    out.append(lineT, static_cast<size_t>(lineTLength) < sizeof(lineT)
                                         ? static_cast<size_t>(lineTLength)
                                         : sizeof(lineT) - 1u);
                out.push_back(static_cast<char>(10));
                for (uint32_t slot = 0; slot < 16u; ++slot) {
                    const uint32_t guestPath = MemoryRead32(0x900007F0u + slot * 4u);
                    if (!guestPath || static_cast<size_t>(guestPath) >= m_memory_size) continue;
                    char pathText[48]{};
                    for (size_t n = 0; n + 1u < sizeof(pathText) &&
                                       static_cast<uint64_t>(guestPath) + n < m_memory_size; ++n) {
                        const char ch = static_cast<char>(MemoryRead8(
                            guestPath + static_cast<uint32_t>(n)));
                        if (!ch) break;
                        pathText[n] = ch >= 0x20 && ch <= 0x7E ? ch : '?';
                    }
                    char pathLine[112];
                    const int pathLength = snprintf(pathLine, sizeof(pathLine),
                                                   "W326T slot=%u ptr=%08X text=%s\n",
                                                   slot, guestPath, pathText);
                    if (pathLength > 0)
                        out.append(pathLine, static_cast<size_t>(pathLength) < sizeof(pathLine)
                                                ? static_cast<size_t>(pathLength)
                                                : sizeof(pathLine) - 1u);
                }
            {
                char sb2[80];
                const uint32_t sp2 = MemoryRead32(0x900007D4u);
                sb2[0] = 0;
                if (sp2 && sp2 + 32 <= m_memory_size) {
                    for (int k = 0; k < 31; ++k) {
                        const char ch = static_cast<char>(MemoryRead8(sp2 + static_cast<uint32_t>(k)));
                        if (!ch) break;
                        sb2[k] = ch;
                        sb2[k + 1] = 0;
                    }
                }
                char lineU[200];
                // W482 (run639): this snprintf previously passed NO arguments
                // for its 6 conversions -- the %.24s consumed garbage varargs
                // and strnlen'd an unmapped host address (0x7b00000000,
                // tombstone of run638), crashing the DiagTrace dump thread
                // and the whole process minutes into every boot. Rebuilt with
                // the real cells; sb2 is the bounded string copy.
                snprintf(lineU, sizeof(lineU),
                         "W329 wadopen=%u s=%08X [ %08X %08X %08X %08X ] s0=%.24s",
                         MemoryRead32(0x900007D0u), sp2,
                         (sp2 && sp2 + 32 <= m_memory_size) ? MemoryRead32(sp2) : 0,
                         (sp2 && sp2 + 32 <= m_memory_size) ? MemoryRead32(sp2 + 4) : 0,
                         (sp2 && sp2 + 32 <= m_memory_size) ? MemoryRead32(sp2 + 8) : 0,
                         (sp2 && sp2 + 32 <= m_memory_size) ? MemoryRead32(sp2 + 12) : 0,
                         sb2);
                out += lineU;
                out.push_back(static_cast<char>(10));
            }
            }
            char lineS[240];
            int sn = snprintf(lineS, sizeof(lineS), "W318stk:");
            for (int w = 0; w < 20 && sn > 0 && static_cast<size_t>(sn) < sizeof(lineS); ++w) {
                sn += snprintf(lineS + sn, sizeof(lineS) - static_cast<size_t>(sn),
                               " %08X", MemoryRead32(0x00010740u + static_cast<uint32_t>(w) * 4u));
            }
            snprintf(lineS + sn, sizeof(lineS) - static_cast<size_t>(sn), "\n");
            out += lineS;
            {
                char lineV[300];
                int vn = snprintf(lineV, sizeof(lineV), "W332 pooltable:");
                for (int w = 0; w < 12; ++w)
                    vn += snprintf(lineV + vn, sizeof(lineV) - vn, " %08X",
                                   MemoryRead32(0x406C8490u + static_cast<uint32_t>(w) * 4u));
                snprintf(lineV + vn, sizeof(lineV) - vn, "%s", g_nl);
                out += lineV;
            }
            {
                char lineW[200];
                int wn = snprintf(lineW, sizeof(lineW), "W332 hooks:");
                for (int w = 0; w < 6; ++w)
                    wn += snprintf(lineW + wn, sizeof(lineW) - wn, " %08X",
                                   MemoryRead32(0x406DA980u + static_cast<uint32_t>(w) * 4u));
                snprintf(lineW + wn, sizeof(lineW) - wn, "%s", g_nl);
                for (int w = 0; w < 6; ++w)
                    wn += snprintf(lineW + wn, sizeof(lineW) - wn, " %08X",
                                   MemoryRead32(0x406D9780u + static_cast<uint32_t>(w) * 4u));
                snprintf(lineW + wn, sizeof(lineW) - wn, "%s", g_nl);
                out += lineW;
            {
                {
                    char lineY[360];
                    snprintf(lineY, sizeof(lineY),
                             "W332 io open=%08X open2=%08X read=%08X seek=%08X tell=%08X rewind=%08X "
                             "default_read=%08X wad_fallback=%08X wad_flags=%08X wad_ready=%u "
                             "file=%08X/%08X/%08X/%08X/%08X/%08X/%08X/%08X/%08X\n",
                             MemoryRead32(0x406DA980u), MemoryRead32(0x406DA988u),
                             MemoryRead32(0x406DA9D4u), MemoryRead32(0x406DA9DCu),
                             MemoryRead32(0x406DA9E0u), MemoryRead32(0x406DA9E4u),
                             MemoryRead32(0x406732F4u), MemoryRead32(0x40700EF8u),
                             MemoryRead32(0x40700F70u), MemoryRead8(0x40700F7Cu),
                             MemoryRead32(0x406D9780u), MemoryRead32(0x406D9784u),
                             MemoryRead32(0x406D9788u), MemoryRead32(0x406D978Cu),
                             MemoryRead32(0x406D9790u), MemoryRead32(0x406D9794u),
                             MemoryRead32(0x406D9798u), MemoryRead32(0x406D979Cu),
                             MemoryRead32(0x406D97A0u));
                    out += lineY;
                }
                {
                    const uint32_t node = MemoryRead32(0x406D975Cu);
                    char lineNode[192];
                    const bool node_ok = node >= 0x10000u &&
                                         node <= m_memory_size - 0x120u;
                    snprintf(lineNode, sizeof(lineNode),
                             "W332 node=%08X saved=%08X/%08X/%08X/%08X self=%08X/%08X/%08X/%08X\n",
                             node,
                             node_ok ? MemoryRead32(node + 0x80u) : 0,
                             node_ok ? MemoryRead32(node + 0x88u) : 0,
                             node_ok ? MemoryRead32(node + 0x8Cu) : 0,
                             node_ok ? MemoryRead32(node + 0x90u) : 0,
                             node_ok ? MemoryRead32(node + 0xB8u) : 0,
                             node_ok ? MemoryRead32(node + 0x10Cu) : 0,
                             node_ok ? MemoryRead32(node + 0x114u) : 0,
                             node_ok ? MemoryRead32(node + 0x118u) : 0);
                    out += lineNode;
                }
                // Read-only content-index snapshot. Copy strings while the
                // nodes are live; a ring of guest path pointers is not evidence
                // once the caller has freed/reused its temporary string.
                {
                    static uint32_t previousOpenCount = ~0u;
                    static std::string contentSnapshot;
                    const uint32_t openCount = MemoryRead32(0x900007B0u);
                    if (openCount != previousOpenCount) {
                        previousOpenCount = openCount;
                        contentSnapshot.clear();
                        const auto valid = [](uint32_t p, uint32_t n) {
                            return p >= 0x40000000u && p < 0x7F000000u &&
                                   n <= 0x7F000000u - p;
                        };
                        const auto word = [&](uint32_t p) {
                            return valid(p, 4u) ? MemoryRead32(p) : 0u;
                        };
                        const auto stringAt = [&](uint32_t p) {
                            std::string s;
                            for (uint32_t i = 0; i < 160u && valid(p + i, 1u); ++i) {
                                const uint8_t ch = MemoryRead8(p + i);
                                if (!ch) break;
                                s.push_back(ch >= 32u && ch < 127u ? ch : '?');
                            }
                            return s;
                        };
                        const uint32_t system = word(0x406D975Cu);
                        const uint32_t tree = word(system);
                        const uint32_t count = word(tree + 4u);
                        const uint32_t blocks = word(tree + 8u);
                        const uint32_t blocksEnd = word(tree + 12u);
                        char line[512];
                        snprintf(line, sizeof(line),
                                 "VFSINDEX open=%u lookup=%u system=%08X indexing=%u root=%s tree=%08X count=%u blocks=%08X/%08X btree=%08X\n",
                                 openCount, MemoryRead8(0x4067329Cu), system,
                                 valid(system, 365u) ? MemoryRead8(system + 364u) : 0u,
                                 stringAt(word(system + 32u)).c_str(), tree, count,
                                 blocks, blocksEnd, word(tree + 20u));
                        contentSnapshot += line;
                        if (count <= 8192u && blocksEnd >= blocks &&
                            blocksEnd - blocks <= 32u && valid(blocks, blocksEnd - blocks)) {
                            uint32_t printed = 0;
                            for (uint32_t i = 0; i < count && printed < 32u; ++i) {
                                const uint32_t blockSlot = blocks + (i >> 10u) * 4u;
                                if (blockSlot >= blocksEnd) break;
                                const uint32_t node = word(blockSlot) + (i & 1023u) * 20u;
                                if (!valid(node, 20u)) break;
                                const uint32_t flags = word(node);
                                const std::string name = stringAt(word(node + 4u));
                                if (!(flags & 4u) && name.find("CAREER") == std::string::npos &&
                                    name.find("GENERAL") == std::string::npos &&
                                    name.find("TEXT.XML") == std::string::npos) continue;
                                ++printed;
                                snprintf(line, sizeof(line),
                                         "VFSNODE index=%u node=%08X flags=%08X name=%s data=%08X/%08X/%08X\n",
                                         i, node, flags, name.c_str(), word(node + 8u),
                                         word(node + 12u), word(node + 16u));
                                contentSnapshot += line;
                                if (name != "#DATA" || !(flags & 4u)) continue;
                                const uint32_t content = word(node + 16u);
                                const uint32_t end = content + 4u;
                                // std::_Rb_tree node: parent/left/right at +4/8/12,
                                // search-entry path at +20. Bounded inorder walk.
                                uint32_t entry = word(content + 12u);
                                for (uint32_t j = 0; entry != end && valid(entry, 28u) && j < 32u; ++j) {
                                    snprintf(line, sizeof(line),
                                             "VFSPATH group=#DATA entry=%08X key=%08X path=%s tag=%s\n",
                                             entry, word(entry + 16u),
                                             stringAt(word(entry + 20u)).c_str(),
                                             stringAt(word(entry + 24u)).c_str());
                                    contentSnapshot += line;
                                    if (word(entry + 12u)) {
                                        entry = word(entry + 12u);
                                        for (unsigned depth = 0; word(entry + 8u) && depth < 32u; ++depth)
                                            entry = word(entry + 8u);
                                    } else {
                                        uint32_t parent = word(entry + 4u);
                                        for (unsigned depth = 0; parent != end && entry == word(parent + 12u) && depth < 32u; ++depth) {
                                            entry = parent;
                                            parent = word(parent + 4u);
                                        }
                                        entry = parent;
                                    }
                                }
                            }
                        }
                    }
                    out += contentSnapshot;
                }
                // W333 (run448): LLMem allocator internals -- the pool
                // descriptor array base dword_6DAE5C (0x406DAE5C), the alloc
                // dispatch off_673334 (must be .text), the malloc alignment
                // globals dword_67332C/6E3DB4, and the first pool-data
                // pointers. Any zero/garbage here = wild-write source.
                char lineX[260];
                snprintf(lineX, sizeof(lineX),
                         "W333 allocfn=%08X align=%08X %08X desc0=%08X %08X %08X %08X",
                         MemoryRead32(0x40673334u), MemoryRead32(0x4067332Cu),
                         MemoryRead32(0x406E3DB4u), MemoryRead32(0x406DAE5Cu),
                         MemoryRead32(0x406DAE60u), MemoryRead32(0x406DAE64u),
                         MemoryRead32(0x406DAE68u));
                out += lineX;
                out.push_back(static_cast<char>(10));
            }
            }
            {
                char nb[64];
                const uint32_t np = MemoryRead32(0x90000794u);
                nb[0] = '\0';
                if (np && np + 16 <= m_memory_size) {
                    for (int k = 0; k < 15; ++k) {
                        const char ch = static_cast<char>(m_memory[np + k]);
                        if (!ch) break;
                        nb[k] = ch;
                        nb[k + 1] = '\0';
                    }
                }
                char lineN[160];
                snprintf(lineN, sizeof(lineN),
                         "W319 wadopen=%u name=%08X [%08X %08X] str=%s\n",
                         MemoryRead32(0x90000790u), np,
                         MemoryRead32(0x90000798u), MemoryRead32(0x9000079Cu), nb);
                out += lineN;
            }
            out += lineK;
            char lineI[96];
            snprintf(lineI, sizeof(lineI), "W284 u16=%u file=%08X caller=%08X\n",
                     MemoryRead32(0x93000138u), MemoryRead32(0x9300013Cu),
                     MemoryRead32(0x93000140u));
            out += lineI;
            char lineH[96];
            const uint32_t idone = MemoryRead32(MemoryRead32(0x93000160u) + 0x6Cu);
            snprintf(lineH, sizeof(lineH), "W270c caller=%08X initDone=%u\n",
                     MemoryRead32(0x900006A0u), idone);
            out += lineH;
            {
                char lineM[500];
                int mn = snprintf(lineM, sizeof(lineM), "W301c park:");
                for (int wi = 0; wi < 28; ++wi)
                    mn += snprintf(lineM + mn, sizeof(lineM) - static_cast<size_t>(mn), " %08X",
                                   MemoryRead32(0x930001A0u + static_cast<uint32_t>(wi) * 4u));
                out += lineM;
            }
        }
        // W201: null-tree Find guard hits.
        {
            char line3[64];
            snprintf(line3, sizeof(line3), "W201 nullfind=%u\n",
                     MemoryRead32(0x93000480u));
            out += line3;
        }
        // W204: content-init chain counters.
        {
            char line3[80];
            snprintf(line3, sizeof(line3), "W204 chain: wadsimple=%u newtree=%u\n",
                     MemoryRead32(0x930004A0u), MemoryRead32(0x930004A4u));
            out += line3;
        }
        // W213: SoapRequestManager creation bisect.
        {
            char line3[80];
            snprintf(line3, sizeof(line3), "W213 chain: new28=%u soapctor=%u\n",
                     MemoryRead32(0x93001548u), MemoryRead32(0x9300154Cu));
            out += line3;
        }
        // W220: chain markers (far-zone, smash-proof).
        {
            char line3[160];
            snprintf(line3, sizeof(line3),
                     "W220 M2=%08X M3=%08X M4=%08X tail=%08X\n",
                     MemoryRead32(0x93000704u), MemoryRead32(0x93000708u),
                     MemoryRead32(0x9300070Cu), MemoryRead32(0x93000710u));
            out += line3;
        }
        // W219: the POP's PC source captured in P1's first section.
        {
            char line3[64];
            snprintf(line3, sizeof(line3), "W219 poppc=%08X\n",
                     MemoryRead32(0x93000600u));
            out += line3;
        }
        // W221: ReleaseGraphicsSystem entry capture.
        {
            char line3[128];
            snprintf(line3, sizeof(line3),
                     "W221 rgent=%u countaddr=%08X count=%08X\n",
                     MemoryRead32(0x93000604u), MemoryRead32(0x93000608u),
                     MemoryRead32(0x9300060Cu));
            out += line3;
        }
        // W231: stack-fill guard counter.
        {
            char line3[64];
            snprintf(line3, sizeof(line3), "W231 stackfills=%u\n",
                     MemoryRead32(0x93000640u));
            out += line3;
        }
        // W226: AddSearchEntry / RemoveSearchGroup entries.
        {
            char line3[80];
            snprintf(line3, sizeof(line3), "W226 ase=%u rsg=%u\n",
                     MemoryRead32(0x9300005Cu), MemoryRead32(0x93000060u));
            out += line3;
        }
        // W227: CleanPath BL probe.
        {
            char line3[200];
            snprintf(line3, sizeof(line3),
                     "W227 cp=%u arg=%08X s0=%08X s4=%08X s8=%08X sC=%08X\n",
                     MemoryRead32(0x93000720u), MemoryRead32(0x93000724u),
                     MemoryRead32(0x93000728u), MemoryRead32(0x9300072Cu),
                     MemoryRead32(0x93000730u), MemoryRead32(0x93000734u));
            out += line3;
        }
        // W237: string-rep alloc at 0x4027F64C with the state heal +
        // pool bypass; captures in the safe 0x7DF000xx block.
        {
            char line3[96];
            snprintf(line3, sizeof(line3), "W237 alloc cnt=%u res=%08X sz=%u memfn=%08X\n",
                     MemoryRead32(0x93000040u), MemoryRead32(0x93000044u),
                     MemoryRead32(0x93000048u), MemoryRead32(0x40673334u));
            char line4[64];
            snprintf(line4, sizeof(line4), "W237f flags=%u\n", MemoryRead32(0x9300004Cu));
            out += line4;
            out += line3;
        }
        // W247: InitMemorySystem entry — input ptr (overwrites count),
        // input[2] alignment field, memory state at entry.
        {
            char line3[96];
            snprintf(line3, sizeof(line3), "W247 in=%08X f2=%08X state=%u\n",
                     MemoryRead32(0x93000070u), MemoryRead32(0x93000078u),
                     MemoryRead32(0x9300007Cu));
            out += line3;
        }
        // W248: memory-system state at dump time + engine init flag +
        // last error + the W100 boot counters for InitMemorySystem (0x504)
        // and BeelzebubInit (0x520) — now in the safe 0x7DF005xx block.
        {
            char line3[120];
            snprintf(line3, sizeof(line3),
                     "W248 state=%u init=%u berr=%u bootIMS=%u bootBInit=%u\n",
                     MemoryRead32(0x406E3DC4u), MemoryRead32(0x406E3DDCu),
                     MemoryRead32(0x406925FCu), MemoryRead32(0x93001504u),
                     MemoryRead32(0x93001520u));
            out += line3;
        }
        // W238/W241: SetCommonMaterialDir BL + entry.
        {
            char line3[128];
            snprintf(line3, sizeof(line3), "W238 scm=%u r0=%08X rep8=%08X W241 ent=%u r0=%08X\n",
                     MemoryRead32(0x93000754u), MemoryRead32(0x93000758u),
                     MemoryRead32(0x9300075Cu), MemoryRead32(0x9300076Cu),
                     MemoryRead32(0x93000770u));
            out += line3;
        }
        // W239/W240: Init_BZ error branch + LLError.
        {
            char line3[80];
            snprintf(line3, sizeof(line3), "W239 errbp=%u W240 llerr=%u\n",
                     MemoryRead32(0x93000764u), MemoryRead32(0x93000768u));
            out += line3;
        }
        // W244: patch survivorship — patched site words must read E51FF004.
        {
            char line3[200];
            snprintf(line3, sizeof(line3),
                     "W244 sites 64C=%08X 628=%08X 550=%08X 564=%08X B10=%08X B30=%08X E9B4=%08X\n",
                     MemoryRead32(0x4027F64Cu), MemoryRead32(0x4027F628u),
                     MemoryRead32(0x4027F550u), MemoryRead32(0x4027F564u),
                     MemoryRead32(0x40543B10u), MemoryRead32(0x40543B30u),
                     MemoryRead32(0x403FE9B4u));
            out += line3;
        }
        // W232: the 5 internal BL counters of the Material-dir body
        // (safe block 0x7DF00550+ — the 0x93000xxx cells sit inside the
        // worker-stack region and get stomped by stack traffic).
        {
            char line3[128];
            snprintf(line3, sizeof(line3),
                     "W232 str1=%u f1=%u memcpy=%u f2=%u alloc=%u\n",
                     MemoryRead32(0x93001550u), MemoryRead32(0x93001554u),
                     MemoryRead32(0x93001558u), MemoryRead32(0x9300155Cu),
                     MemoryRead32(0x93001560u));
            out += line3;
        }
        // W229: body entry counter.
        {
            char line3[64];
            snprintf(line3, sizeof(line3), "W229 bodyentry=%u\n",
                     MemoryRead32(0x93000638u));
            out += line3;
        }
        // W230: mCommon_loading_directory content at the body entry.
        {
            char buf[64];
            for (int i = 0; i < 12; ++i)
                buf[i] = static_cast<char>(MemoryRead8(0x406C876Cu + static_cast<uint32_t>(i)));
            buf[12] = 0;
            char line3[96];
            snprintf(line3, sizeof(line3), "W230 mcl[12]=%.12s w0=%08X w1=%08X\n",
                     buf, MemoryRead32(0x406C876Cu), MemoryRead32(0x406C8770u));
            out += line3;
        }
        // W234: the s argument captured at the Material body entry.
        {
            char line3[64];
            snprintf(line3, sizeof(line3), "W234 s=%08X\n",
                     MemoryRead32(0x93000658u));
            out += line3;
        }
        // W218: magic markers (stub entered? far write? suspect write?)
        // + the stub's own words at S+15 (extension add) / S+9 (suspect str).
        {
            char line3[160];
            snprintf(line3, sizeof(line3),
                     "W218 far=%08X suspect=%08X stubS9=%08X stubS15=%08X\n",
                     MemoryRead32(0x93000700u), MemoryRead32(0x93001580u),
                     MemoryRead32(0x8F113D24u), MemoryRead32(0x8F113D38u));
            out += line3;
        }
        // W214: captured ms_Singleton GOT load.
        {
            char line3[64];
            snprintf(line3, sizeof(line3), "W214 gotload=%08X\n",
                     MemoryRead32(0x93001550u));
            out += line3;
        }
        // W217: epilogue dumps (P1 fired? P2 popped words incl. the PC).
        {
            const uint32_t fired = MemoryRead32(0x93001560u);
            if (fired) {
                char line3[256];
                snprintf(line3, sizeof(line3),
                         "W217P1 sp=%08X r4=%08X r5=%08X r6=%08X r7=%08X r8=%08X r9=%08X r10=%08X\n",
                         fired, MemoryRead32(0x93001564u), MemoryRead32(0x93001568u),
                         MemoryRead32(0x9300156Cu), MemoryRead32(0x93001570u),
                         MemoryRead32(0x93001574u), MemoryRead32(0x93001578u),
                         MemoryRead32(0x9300157Cu));
                out += line3;
                snprintf(line3, sizeof(line3),
                         "W217S8 %08X %08X %08X %08X %08X %08X %08X %08X\n",
                         MemoryRead32(0x93001580u), MemoryRead32(0x93001584u),
                         MemoryRead32(0x93001588u), MemoryRead32(0x9300158Cu),
                         MemoryRead32(0x93001590u), MemoryRead32(0x93001594u),
                         MemoryRead32(0x93001598u), MemoryRead32(0x9300159Cu));
                out += line3;
                snprintf(line3, sizeof(line3),
                         "W217B sp2=%08X pp0=%08X pp1=%08X pp2=%08X pp3=%08X pp4=%08X pp5=%08X pp6=%08X popPC=%08X\n",
                         MemoryRead32(0x930015A0u), MemoryRead32(0x930015A4u),
                         MemoryRead32(0x930015A8u), MemoryRead32(0x930015ACu),
                         MemoryRead32(0x930015B0u), MemoryRead32(0x930015B4u),
                         MemoryRead32(0x930015B8u), MemoryRead32(0x930015BCu),
                         MemoryRead32(0x930015C0u));
                out += line3;
                snprintf(line3, sizeof(line3),
                         "W217EP %08X %08X %08X %08X stub50=%08X stub54=%08X stub58=%08X stub5C=%08X stub60=%08X stub64=%08X\n"
                         "W217EP2 p2=%08X p204=%08X p208=%08X s1=%08X s104=%08X s1m3=%08X\n",
                         MemoryRead32(0x403DC078u), MemoryRead32(0x403DC07Cu),
                         MemoryRead32(0x403DC080u), MemoryRead32(0x40543AC0u),
                         MemoryRead32(0x8F113D50u), MemoryRead32(0x8F113D54u),
                         MemoryRead32(0x8F113D58u), MemoryRead32(0x8F113D5Cu),
                         MemoryRead32(0x8F113D60u), MemoryRead32(0x8F113D64u),
                         MemoryRead32(0x8F113E00u), MemoryRead32(0x8F113E04u),
                         MemoryRead32(0x8F113E08u), MemoryRead32(0x8F113A00u),
                         MemoryRead32(0x8F113A04u), MemoryRead32(0x8F113A0Cu));
                out += line3;
                snprintf(line3, sizeof(line3),
                         "W217P2 sp=%08X pop0=%08X pop1=%08X pop2=%08X pop3=%08X pop4=%08X pop5=%08X pop6=%08X popPC=%08X\n",
                         MemoryRead32(0x930015A0u), MemoryRead32(0x930015A4u),
                         MemoryRead32(0x930015A8u), MemoryRead32(0x930015ACu),
                         MemoryRead32(0x930015B0u), MemoryRead32(0x930015B4u),
                         MemoryRead32(0x930015B8u), MemoryRead32(0x930015BCu),
                         MemoryRead32(0x930015C0u));
                out += line3;
            }
        }
        // W206: CINodeSystem::Startup early bisect.
        {
            char line3[80];
            snprintf(line3, sizeof(line3), "W206 chain: fill=%u hooks=%u\n",
                     MemoryRead32(0x930004A8u), MemoryRead32(0x930004ACu));
            out += line3;
        }
        // W207: Content::Startup null-path bisect.
        {
            char line3[80];
            snprintf(line3, sizeof(line3), "W207 chain: new170=%u sysctor=%u\n",
                     MemoryRead32(0x930004B0u), MemoryRead32(0x930004B4u));
            out += line3;
        }
    }
    // W172: LLMemFill dispatch-target entries.
    {
        char line2[64];
        snprintf(line2, sizeof(line2), "W172 fillfn entered=%u\n",
                 MemoryRead32(0x00010368u));
        out += line2;
        // W174: once the D_1 chain is proven active (fillfn > 100), dump the
        // RUNTIME bytes of the bzd entry and the D_1 body -- the file content
        // at those addresses is a literal pool, i.e. the engine REWRITES its
        // code at init. The dump is the ground truth for static analysis.
        // W185: watch the head of _Z9LLMemFillPvij (0x40409CC0). It was found
        // overwritten with exit-trap words (EF000000 DF00DF00) -- any
        // LLMemFill call after that parks the boot thread silently. Log every
        // change (timestamp vs fillfn) and SELF-HEAL the original prologue so
        // the boot can proceed; repeated heals identify a repeated writer.
        {
            const uint32_t w0 = MemoryRead32(0x40409CC0u);
            const uint32_t w1 = MemoryRead32(0x40409CC4u);
            static bool w185_seen_ok = false;
            static uint32_t w185_heals = 0;
            char wb2[128];
            if (!w185_seen_ok) {
                if (w0 == 0xE92D4008u && w1 == 0xE2523000u) w185_seen_ok = true;
            } else if (w0 != 0xE92D4008u || w1 != 0xE2523000u) {
                if (w185_heals < 32) {
                    snprintf(wb2, sizeof(wb2),
                             "W185 CORRUPT 40409CC0: %08X %08X -> heal (fillfn=%u)",
                             w0, w1, MemoryRead32(0x00010368u));
                    DiagTrace::NotePersist(wb2);
                    LOGE("%s", wb2);
                }
                MemoryWrite32(0x40409CC0u, 0xE92D4008u);
                MemoryWrite32(0x40409CC4u, 0xE2523000u);
                ++w185_heals;
            }
        }
        // W174: dump the runtime bytes into EVERY diag once the D_1 chain is
        // active (fillfn > 100) -- the diag file only keeps the latest dump,
        // so a one-shot dump would be overwritten before anyone reads it.
        if (MemoryRead32(0x00010368u) > 100) {
            char b[96];
            snprintf(b, sizeof(b), "W174A bzd-entry runtime bytes:\n");
            out += b;
            snprintf(b, sizeof(b), "W185chk LLMemFill head: %08X %08X\n",
                     MemoryRead32(0x40409CC0u), MemoryRead32(0x40409CC4u));
            out += b;
            for (uint32_t a = 0x402160C4u; a < 0x40216184u; a += 4) {
                snprintf(b, sizeof(b), "W174A %08X: %08X\n", a, MemoryRead32(a));
                out += b;
            }
            snprintf(b, sizeof(b), "W174B D1-body runtime bytes:\n");
            out += b;
            for (uint32_t a = 0x40222FD0u; a < 0x40223040u; a += 4) {
                snprintf(b, sizeof(b), "W174B %08X: %08X\n", a, MemoryRead32(a));
                out += b;
            }
            // W177: pool 75 (0x4B) descriptor dump -- entry + per-thread
            // owner slots + free head. bz_AR_AddSessionType allocates via
            // fast-path pool 75; a missing entry or exhausted slots freeze
            // the boot thread in the fallback.
            snprintf(b, sizeof(b), "W177 pool75 desc@406DC2EC:");
            out += b;
            for (uint32_t a = 0x406DC2ECu + 0x680u; a < 0x406DC2ECu + 0x700u; a += 4) {
                snprintf(b, sizeof(b), " %08X:%08X", a, MemoryRead32(a));
                out += b;
            }
            out += '\n';
            // W186: W124 probe 1 stub readback (0x00011058, 4 words)
            snprintf(b, sizeof(b), "W186 p1stub:");
            out += b;
            for (uint32_t a = 0x8F111058u; a < 0x8F111068u; a += 4) {
                snprintf(b, sizeof(b), " %08X", MemoryRead32(a));
                out += b;
            }
            snprintf(b, sizeof(b), " site=%08X\n", MemoryRead32(0x402160F8u));
            out += b;
            snprintf(b, sizeof(b), "W184 singleton [407A6F5C]=%08X:", MemoryRead32(0x407A6F5Cu));
            out += b;
            snprintf(b, sizeof(b), "\nW190 bz_StartInternal file-vs-runtime:");
            out += b;
            // W190: compare runtime bytes of bz_StartInternal region with
            // the file to verify patches are at the correct addresses.
            {
                int ndiff = 0;
                for (uint32_t i = 0; i < 200; ++i) {
                    // Read from the .so file on disk for reference
                    // For now just verify the patch sites are intact
                    // by checking the known LDR PC patterns
                    const uint32_t a = 0x403DBE38u + i * 4;
                    const uint32_t rt = MemoryRead32(a);
                    // Known patch sites: E51FF004 (LDR PC)
                    // W100 probes and W132/W122 patches all write this
                    // Just count and log any unexpected 0xEF000000 (trap)
                    if (rt == 0xEF000000u || rt == 0xDF00DF00u) {
                        if (ndiff < 10) {
                            snprintf(b, sizeof(b), "\nW190 TRAP at %08X: %08X",
                                     a, rt);
                            out += b;
                        }
                        ++ndiff;
                    }
                }
                snprintf(b, sizeof(b), "\nW190 traps=%d\n", ndiff);
                out += b;
            }
            snprintf(b, sizeof(b), "W174C AddSessionType runtime bytes:\n");
            {
                const uint32_t sp = MemoryRead32(0x407A6F5Cu);
                if (sp) {
                    snprintf(b, sizeof(b), " body:");
                    out += b;
                    for (uint32_t a = sp; a < sp + 0x20u; a += 4) {
                        snprintf(b, sizeof(b), " %08X:%08X", a, MemoryRead32(a));
                        out += b;
                    }
                } else {
                    out += " (null)";
                }
            }
            out += '\n';
            snprintf(b, sizeof(b), "W189 singleton[407A7598]=%08X\n",
                     MemoryRead32(0x407A7598u));
            out += b;
            snprintf(b, sizeof(b), "W191 stack@7E3FF10:");
            out += b;
            for (uint32_t a = 0x7E3FEFD0u; a < 0x7E3FF050u; a += 4) {
                snprintf(b, sizeof(b), " %08X", MemoryRead32(a));
                out += b;
            }
            out += '\n';
            snprintf(b, sizeof(b), "W174C AddSessionType runtime bytes:\n");
            out += b;
            for (uint32_t a = 0x40473B40u; a < 0x40473C40u; a += 4) {
                snprintf(b, sizeof(b), "W174C %08X: %08X\n", a, MemoryRead32(a));
                out += b;
            }
        }
    }
    // W176: the LogManager operator-new call site.
    {
        char line2[96];
        snprintf(line2, sizeof(line2), "W176 opnew-call entered=%u ret=0x%08X\n",
                 MemoryRead32(0x0001036Cu), MemoryRead32(0x00010370u));
        out += line2;
    }
    // W177b: D_1's returned r0 (0 = passed, nonzero = failed).
    {
        char line2[64];
        snprintf(line2, sizeof(line2), "W177b D1 ret=%08X\n",
                 MemoryRead32(0x00010378u));
        out += line2;
    }
    // W167: operator new entry/ret at the LogManager allocation.
    {
        char line2[96];
        snprintf(line2, sizeof(line2), "W167 opnew entered=%u ret=0x%08X\n",
                 MemoryRead32(0x00010360u), MemoryRead32(0x00010364u));
        out += line2;
    }
    // W158: CreateObjectSet called/last-ret.
    {
        char line2[96];
        snprintf(line2, sizeof(line2), "W158 CreateObjectSet called=%u ret=0x%08X\n",
                 MemoryRead32(0x00010350u), MemoryRead32(0x00010354u));
        out += line2;
    }
    // W155: last nonzero return of each D_* step (error 14 hunt).
    {
        char line2[192];
        int n2 = snprintf(line2, sizeof(line2), "W155 Dx rets:");
        for (int i = 0; i < 9 && n2 > 0 && static_cast<size_t>(n2) < sizeof(line2); ++i) {
            const uint32_t ret = MemoryRead32(0x000100C0u + 8u * i);
            if (!ret) continue;
            n2 += snprintf(line2 + n2, sizeof(line2) - static_cast<size_t>(n2),
                           " D%d=%u", i + 1, ret);
        }
        out += line2;
        out += '\n';
    }
    return out;
}

// Address space for the mmap thunk. Separate from the malloc heap on purpose -- see the
// declaration. No free list: a file mapping is handed to the engine for the life of the
// process, and the mmap thunk reuses an identical (file, offset, length) mapping instead of
// making a second one, which is what keeps a re-opened expansion file from costing the arena
// twice.
uint32_t DynarmicHost::GuestAllocMapping(size_t size, size_t alignment) {
    std::lock_guard<std::mutex> lock(m_heap_mutex);
    const uint32_t aligned = (m_map_current + static_cast<uint32_t>(alignment - 1)) &
                             ~static_cast<uint32_t>(alignment - 1);
    if (static_cast<uint64_t>(aligned) + size > kMapLimit) {
        LOGE("GuestAllocMapping out of mapping space: at 0x%08X, want %zu", aligned, size);
        return 0;
    }
    m_map_current = aligned + static_cast<uint32_t>(size);
    return aligned;
}

// Runs once at startup. A silently wrong allocator corrupts the guest far away
// from the cause, so pay a few microseconds to fail loudly at the source.
void DynarmicHost::HeapSelfCheck() {
#define HEAP_CHECK(cond) do { if (!(cond)) { LOGE("HeapSelfCheck FAILED: %s", #cond); ok = false; } } while (0)
    bool ok = true;

    uint32_t a = GuestAlloc(100, 8);
    uint32_t b = GuestAlloc(100, 8);
    HEAP_CHECK(a != 0 && b != 0 && a != b);
    HEAP_CHECK((a & 7) == 0 && (b & 7) == 0);
    HEAP_CHECK(a + 100 <= b - kHeaderSize || b + 100 <= a - kHeaderSize); // no overlap
    HEAP_CHECK(GuestAllocSize(a) == 100);

    uint32_t aligned = GuestAlloc(64, 0x1000);
    HEAP_CHECK(aligned != 0 && (aligned & 0xFFF) == 0);

    // Freed blocks come back, and the payload is handed over zeroed.
    MemoryWrite32(a, 0xDEADBEEF);
    GuestFree(a);
    HEAP_CHECK(GuestAllocSize(a) == 0);        // magic cleared
    GuestFree(a);                              // double free: must be a no-op
    uint32_t reused = GuestAlloc(100, 8);
    HEAP_CHECK(reused == a);
    HEAP_CHECK(MemoryRead32(reused) == 0);

    // Pointers we did not hand out must be ignored, not recycled.
    GuestFree(0x40000000);
    GuestFree(kHeapBase + 4);
    GuestFree(b + 8);                          // interior pointer
    HEAP_CHECK(GuestAllocSize(b) == 100);      // b survived all of that

    // Large blocks recycle by exact capacity instead of rounding to a power of two.
    uint32_t big = GuestAlloc(8 * 1024 * 1024, 0x10000);
    HEAP_CHECK(big != 0 && (big & 0xFFFF) == 0);
    GuestFree(big);
    uint32_t big2 = GuestAlloc(8 * 1024 * 1024, 0x10000);
    HEAP_CHECK(big2 == big);
    GuestFree(big2);

    GuestFree(b);
    GuestFree(reused);
    GuestFree(aligned);
    LOGI("HeapSelfCheck %s", ok ? "OK" : "FAILED");
#undef HEAP_CHECK
}

void DynarmicHost::AddExecutableRange(uint32_t base, uint32_t size) {
    if (!size) return;
    m_code_ranges.emplace_back(base, base + size);
    LOGI("Executable range: 0x%08X..0x%08X", base, base + size);
}

std::optional<std::uint32_t> DynarmicHost::MemoryReadCode(std::uint32_t vaddr) {
#if BRIDGE_FIX_MASSLESS_STATIC
    // bzd_IO_ReadDynamicsObject calls bzd_SetupLumpForPhysics here. Its
    // missing-mass sentinel is -1.0, which becomes a negative collision
    // mass. Intercept the BL and following MOV only when the exact original
    // ARM words are present; the callback preserves both instructions.
    if ((vaddr == 0x40209854u || vaddr == 0x40209858u) &&
        MemoryRead32(0x40209854u) == 0xEB004EBFu &&
        MemoryRead32(0x40209858u) == 0xE1A04000u) {
        if (vaddr == 0x40209854u) return 0xEF00F003u;
        if (vaddr == 0x40209858u) return 0xEF00F004u;
    }
#endif
#if BRIDGE_ENABLE_COLLISION_PROBE
    // Replace only the two selected ARM BL instructions at decode time. The
    // callback records operands, then performs the original BL register
    // effects. Normal builds never enter this path or alter guest code.
    if (vaddr == 0x403A94E0u) return 0xEF00F001u;
    if (vaddr == 0x403A9B74u) return 0xEF00F002u;
#endif
    // Temporary fetch counters: distinguish an unvisited instruction from a
    // visited SVC whose logging callback did not run.
    constexpr uint32_t kSoundSites[] = {
        0x4054E088u, 0x40543A68u, 0x40543AB4u, 0x40543ABCu,
        0x403D7A18u, 0x403DC03Cu,
    };
    for (uint32_t i = 0; i < 6; ++i) {
        if (vaddr == kSoundSites[i]) {
            const uint32_t cell = 0x93001A00u + i * 4u;
            MemoryWrite32(cell, MemoryRead32(cell) + 1u);
        }
    }
    // W360 (run480): raw fetch trace for the GOT region -- proves whether
    // the code fetch even reaches this hook. The former W359 stub writer had
    // no matching redirection in this callback.
    if (vaddr >= 0x4066E988u && vaddr < 0x4066F000u) {
        static std::atomic<uint32_t> w360{0};
        if (w360.fetch_add(1) < 8) {
            char b[128];
            snprintf(b, sizeof(b), "W360 FETCH pc=0x%08X", vaddr);
            DiagTrace::NotePersist(b);
            LOGE("%s", b);
        }
    }
    // Guest heap is data, never executable. A prior BX-LR recovery here
    // concealed corrupted function pointers and let the caller unwind through
    // an already-invalid stack. Trap the first fetch and preserve its context.
    if (vaddr >= 0x50800000u && vaddr < 0x51000000u) {
        static std::atomic<uint32_t> heap_exec{0};
        if (heap_exec.fetch_add(1) < 16) {
            Dynarmic::A32::Jit* jit = t_jit ? t_jit : m_jit.get();
            char b[256];
            snprintf(b, sizeof(b),
                     "HEAP-EXEC-HALT tid=%u pc=%08X lr=%08X sp=%08X r0=%08X"
                     " aasset_close_got=%08X thunk=%08X n=%u",
                     static_cast<uint32_t>(gettid()), vaddr,
                     jit ? jit->Regs()[14] : 0, jit ? jit->Regs()[13] : 0,
                     jit ? jit->Regs()[0] : 0, MemoryRead32(0x4066EA58u),
                     m_thunk_manager ? m_thunk_manager->GetOrCreateThunkAddress("AAsset_close") : 0,
                     heap_exec.load());
            DiagTrace::NotePersist(b);
            LOGE("%s", b);
        }
        return 0xE7FEDEFFu; // permanently undefined: never execute guest heap
    }


    // Runaway PC containment. The arena is zero-filled and zeros decode as a valid
    // `andeq r0,r0,r0`, so a jump through a garbage pointer makes the JIT translate
    // a fresh block every 0x8000 bytes forever: RSS runs away and the LMK kills the
    // process, a symptom that reads exactly like a memory leak. Feed the JIT a
    // permanently-undefined instruction instead -- ExceptionRaised halts it and
    // prints where the jump came from.
    if (m_elf_loader) {
        auto in_module = [vaddr](const ElfLoader* l) {
            return l && vaddr >= l->GetBaseAddress() &&
                   vaddr < l->GetBaseAddress() + l->GetImageSize();
        };
        // Only the two fixed exit traps are valid code below the ELF modules.
        // The former blanket 0x00010000..0x00020000 exemption let wild PCs
        // execute guest data and bridge probes placed in the shared low page.
        constexpr uint32_t kExitTrapEnd = 0x10;
        bool in_code = vaddr < kExitTrapEnd ||
                       in_module(m_elf_loader.get()) ||
                       in_module(m_fmodex_loader.get()) ||
                       in_module(m_fmodex_l_loader.get()) ||
                       in_module(m_fmodevent_loader.get()) ||
                       in_module(m_fmodevent_l_loader.get());
        for (const auto& r : m_code_ranges) {
            if (in_code) break;
            if (vaddr >= r.first && vaddr < r.second) in_code = true;
        }
    if (!in_code) {
        if (vaddr >= 0x10u && vaddr < 0x20000u) {
            static std::atomic<uint32_t> low_exec_count{0};
            if (low_exec_count.fetch_add(1) < 8) {
                Dynarmic::A32::Jit* jit = t_jit ? t_jit : m_jit.get();
                char b[112];
                snprintf(b, sizeof(b), "LOWEXEC pc=0x%08X lr=0x%08X sp=0x%08X",
                         vaddr, jit ? jit->Regs()[14] : 0, jit ? jit->Regs()[13] : 0);
                DiagTrace::NotePersist(b);
            }
        }
        LOGE("[RUNAWAY] code fetch 0x%08X", vaddr);
        // Capture the first invalid control-flow target before halting. An
        // address outside every executable mapping is a control-flow bug;
        // returning BX LR here only hides it and can spin the guest forever.
        static std::atomic<uint32_t> runaway_context_dumps{0};
        if (runaway_context_dumps.fetch_add(1) == 0 && t_jit) {
            const auto& regs = t_jit->Regs();
            const uint32_t sp = regs[13];
            char context[1600];
            int n = snprintf(context, sizeof(context),
                             "RUNAWAY-CONTEXT tid=%u pc=%08X lr=%08X sp=%08X cpsr=%08X"
                             " r0=%08X r1=%08X r2=%08X r3=%08X r4=%08X r5=%08X"
                             " r6=%08X r7=%08X r8=%08X r9=%08X r10=%08X r11=%08X r12=%08X stack:",
                             static_cast<uint32_t>(gettid()), vaddr, regs[14], sp,
                             static_cast<unsigned>(t_jit->Cpsr()), regs[0], regs[1],
                             regs[2], regs[3], regs[4], regs[5], regs[6], regs[7],
                             regs[8], regs[9], regs[10], regs[11], regs[12]);
            if (sp >= 0x20u && m_memory_size >= 0x20u &&
                static_cast<size_t>(sp) <= m_memory_size - 0x40u) {
                for (int word = -8; word < 8 && n > 0 &&
                     static_cast<size_t>(n) < sizeof(context); ++word) {
                    const uint32_t address = sp + static_cast<uint32_t>(word * 4);
                    n += snprintf(context + n, sizeof(context) - static_cast<size_t>(n),
                                  " %08X", MemoryRead32(address));
                }
            }
            // W594: a runaway reached from Content::Find can be inside the
            // CINodeTree/CBTree walk. Snapshot the object header and root
            // node without changing guest state, so a bad root/child pointer
            // is distinguishable from a bad return address on the next run.
            const uint32_t tree = regs[0];
            if (n > 0 && static_cast<size_t>(n) < sizeof(context) && tree >= 0x10000u &&
                static_cast<uint64_t>(tree) + 0x24u <= m_memory_size) {
                const uint32_t table_count = MemoryRead32(tree + 4u);
                const uint32_t table_begin = MemoryRead32(tree + 8u);
                const uint32_t table_end = MemoryRead32(tree + 12u);
                const uint32_t cb_root = MemoryRead32(tree + 0x14u);
                const uint32_t collision_root = MemoryRead32(tree + 0x20u);
                n += snprintf(context + n, sizeof(context) - static_cast<size_t>(n),
                              " tree=%08X table={n=%u begin=%08X end=%08X}"
                              " cbroot=%08X collroot=%08X",
                              tree, table_count, table_begin, table_end, cb_root,
                              collision_root);
                if (n > 0 && static_cast<size_t>(n) < sizeof(context) && cb_root >= 0x10000u &&
                    static_cast<uint64_t>(cb_root) + 0x404u <= m_memory_size) {
                    const uint32_t count = MemoryRead32(cb_root + 4u);
                    const uint32_t point0 = MemoryRead32(cb_root + 8u);
                    const uint32_t point1 = MemoryRead32(cb_root + 12u);
                    const uint32_t child0 = MemoryRead32(cb_root + 0x204u);
                    const uint32_t child1 = MemoryRead32(cb_root + 0x208u);
                    if (n > 0 && static_cast<size_t>(n) < sizeof(context)) {
                        n += snprintf(context + n, sizeof(context) - static_cast<size_t>(n),
                                      " cbnode={leaf=%u count=%u key0=%08X key1=%08X"
                                      " child0=%08X child1=%08X}",
                                      MemoryRead32(cb_root) & 0xFFu, count, point0,
                                      point1, child0, child1);
                    }
                    if (count <= 127u) {
                        uint32_t hash = 0x811C9DC5u;
                        bool path_complete = false;
                        for (uint32_t i = 0; i < 128u; ++i) {
                            const uint64_t byte_addr = static_cast<uint64_t>(regs[1]) + i;
                            if (byte_addr >= m_memory_size) break;
                            const uint32_t aligned = static_cast<uint32_t>(byte_addr) & ~3u;
                            if (static_cast<uint64_t>(aligned) + 4u > m_memory_size) break;
                            const uint32_t word = MemoryRead32(aligned);
                            uint32_t ch = (word >> ((byte_addr & 3u) * 8u)) & 0xFFu;
                            if (!ch) { path_complete = true; break; }
                            if (ch == '/' || ch == '\\') continue;
                            if (ch >= 'a' && ch <= 'z') ch -= 32u;
                            hash = (hash ^ ch) * 16777619u;
                        }
                        if (path_complete) {
                            uint32_t point = 0;
                            while (point < count &&
                                   MemoryRead32(cb_root + 8u + point * 4u) <= hash)
                                ++point;
                            const uint32_t key_before = point
                                ? MemoryRead32(cb_root + 4u + point * 4u) : 0u;
                            const uint32_t key_after = point < count
                                ? MemoryRead32(cb_root + 8u + point * 4u) : 0u;
                            const uint32_t child = MemoryRead32(cb_root + 0x204u + point * 4u);
                            n += snprintf(context + n, sizeof(context) - static_cast<size_t>(n),
                                          " queryHash=%08X point=%u keyL=%08X keyR=%08X child=%08X",
                                          hash, point, key_before, key_after, child);
                            if (n > 0 && static_cast<size_t>(n) < sizeof(context) && child >= 0x10000u &&
                                static_cast<uint64_t>(child) + 0x404u <= m_memory_size) {
                                const uint32_t child_count = MemoryRead32(child + 4u);
                                uint32_t leaf_point = 0;
                                while (leaf_point < child_count && leaf_point < 127u &&
                                       MemoryRead32(child + 8u + leaf_point * 4u) <= hash)
                                    ++leaf_point;
                                const uint32_t leaf_key_before = leaf_point
                                    ? MemoryRead32(child + 4u + leaf_point * 4u) : 0u;
                                const uint32_t leaf_key_after = leaf_point < child_count
                                    ? MemoryRead32(child + 8u + leaf_point * 4u) : 0u;
                                const bool found = leaf_point != 0u && leaf_key_before == hash;
                                const uint32_t node_index = found
                                    ? MemoryRead32(child + 0x204u + leaf_point * 4u) : 0u;
                                n += snprintf(context + n, sizeof(context) - static_cast<size_t>(n),
                                              " leaf={leaf=%u count=%u point=%u keyL=%08X"
                                              " keyR=%08X found=%u index=%u}",
                                              MemoryRead32(child) & 0xFFu, child_count,
                                              leaf_point, leaf_key_before, leaf_key_after,
                                              found ? 1u : 0u, node_index);
                                if (found && n > 0 && static_cast<size_t>(n) < sizeof(context) &&
                                    table_end >= table_begin && table_begin >= 0x10000u &&
                                    static_cast<uint64_t>(table_end) <= m_memory_size) {
                                    const uint32_t table_blocks = (table_end - table_begin) / 4u;
                                    const uint32_t block_index = node_index >> 10u;
                                    if (block_index < table_blocks) {
                                        const uint32_t block = MemoryRead32(table_begin + block_index * 4u);
                                        const uint64_t node_addr = static_cast<uint64_t>(block) +
                                            20u * (node_index & 0x3FFu);
                                        if (block >= 0x10000u && node_addr + 20u <= m_memory_size) {
                                            const uint32_t node = static_cast<uint32_t>(node_addr);
                                            const uint32_t name = MemoryRead32(node + 4u);
                                            const uint32_t name_word = name >= 0x10000u &&
                                                static_cast<uint64_t>(name) + 4u <= m_memory_size
                                                ? MemoryRead32(name) : 0u;
                                            n += snprintf(context + n,
                                                          sizeof(context) - static_cast<size_t>(n),
                                                          " tableLookup={blocks=%u block=%08X node=%08X"
                                                          " flags=%08X name=%08X name0=%08X}",
                                                          table_blocks, block, node,
                                                          MemoryRead32(node), name, name_word);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // W595: preserve the exact Find/guard instructions and nearby
            // stack return candidates at the first invalid fetch. This is
            // read-only evidence to distinguish a bad veneer literal from a
            // corrupted saved PC; it deliberately does not recover control.
            if (n > 0 && static_cast<size_t>(n) < sizeof(context)) {
                n += snprintf(context + n, sizeof(context) - static_cast<size_t>(n),
                              " findCode={sys=%08X/%08X tree=%08X/%08X impl=%08X"
                              " guard=%08X/%08X/%08X/%08X}",
                              MemoryRead32(0x403FE018u), MemoryRead32(0x403FE01Cu),
                              MemoryRead32(0x403FE010u), MemoryRead32(0x403FE014u),
                              MemoryRead32(0x403FDF08u),
                              MemoryRead32(0x8F113400u), MemoryRead32(0x8F113404u),
                              MemoryRead32(0x8F113408u), MemoryRead32(0x8F11340Cu));
            }
            if (sp >= 0x200u && static_cast<uint64_t>(sp) + 0x100u <= m_memory_size &&
                n > 0 && static_cast<size_t>(n) < sizeof(context)) {
                int candidates = 0;
                n += snprintf(context + n, sizeof(context) - static_cast<size_t>(n),
                              " stackCodeRefs:");
                for (int32_t offset = -0x200; offset < 0x100 && candidates < 12; offset += 4) {
                    const uint32_t value = MemoryRead32(
                        static_cast<uint32_t>(static_cast<int64_t>(sp) + offset));
                    const bool code_pointer = value == vaddr ||
                        (value >= 0x40000000u && value < 0x40800000u) ||
                        (value >= 0x8F100000u && value < 0x8F130000u);
                    if (!code_pointer || n <= 0 || static_cast<size_t>(n) >= sizeof(context))
                        continue;
                    n += snprintf(context + n, sizeof(context) - static_cast<size_t>(n),
                                  "[%+05d]=%08X", offset, value);
                    ++candidates;
                }
            }
            DiagTrace::NotePersist(std::string(context, static_cast<size_t>(n)));
            LOGE("%s", context);
        }
        // W10d: route through the throttle-proof notes ring too.
        {
            char b[512];
            int n2 = snprintf(b, sizeof(b), "RUNAWAY code fetch 0x%08X words:", vaddr);
            for (int w = -8; w < 8 && n2 > 0 && static_cast<size_t>(n2) < sizeof(b); ++w) {
                n2 += snprintf(b + n2, sizeof(b) - static_cast<size_t>(n2), " %08X",
                               MemoryRead32(vaddr + static_cast<uint32_t>(w) * 4));
            }
            DiagTrace::Note(std::string(b, static_cast<size_t>(n2)));
        }
        return 0xE7FEDEFFu; // permanently undefined: stop on the first invalid fetch
    // W363 (run487): surgical recovery -- if the glue jumps to the
    // DRO-literal at 0x4066E98C (the smeared saved-PC from a dead
    // CConfigFile/fclose frame), return BX LR instead. The thread returns
    // to the saved LR and survives past the poisoned indirect call.
    // ONLY the exact address 0x4066E98C is intercepted -- 0x4066E988 is a
    // legitimate PLT entry and MUST NOT be redirected.
    if (vaddr == 0x4066E98Cu) {
        static std::atomic<uint32_t> w363{0};
        if (w363.fetch_add(1) < 16) {
            Dynarmic::A32::Jit* jit = t_jit ? t_jit : m_jit.get();
            char b[192];
            snprintf(b, sizeof(b),
                     "W363 SLOT-EXEC-BXLR tid=%u lr=0x%08X sp=0x%08X r0=%08X n=%u",
                     static_cast<uint32_t>(gettid()),
                     jit ? jit->Regs()[14] : 0, jit ? jit->Regs()[13] : 0,
                     jit ? jit->Regs()[0] : 0, w363.load());
            DiagTrace::NotePersist(b);
            LOGE("%s", b);
        }
        return 0xE12FFF1Eu; // BX LR
    }
    // W349 (run459): .bss/.data EXECUTION trap. The wild-jump author
    // lands threads in the zero-filled .bss (run458: PC=0x40794184 spins
    // forever as andeq-NOPs with 1.5M dispatches). Anything fetching code
    // from the data tail of libParsons is a wild jump: halt it LOUDLY --
    // ExceptionRaised (W311) now records the LR, naming the caller.
    if (vaddr >= 0x40794000u && vaddr < 0x40800000u) {
        static std::atomic<uint32_t> w349{0};
        if (w349.fetch_add(1) < 8) {
            Dynarmic::A32::Jit* jit = t_jit ? t_jit : m_jit.get();
            char b[192];
            snprintf(b, sizeof(b),
                     "W349 BSSEXEC pc=0x%08X lr=0x%08X sp=0x%08X r4=%08X stk[%08X %08X %08X]",
                     vaddr, jit ? jit->Regs()[14] : 0, jit ? jit->Regs()[13] : 0,
                     jit ? jit->Regs()[4] : 0,
                     MemoryRead32(jit ? jit->Regs()[13] : 0),
                     MemoryRead32((jit ? jit->Regs()[13] : 0) + 4),
                     MemoryRead32((jit ? jit->Regs()[13] : 0) + 8));
            DiagTrace::NotePersist(b);
            LOGE("%s", b);
        }
        return 0xE12FFF1Eu; // W371 (run501): BX LR -- smeared-return survival, was undefined-kill
    }
    }
    // W315 (run418): code fetch from the guest DATA segment. The run418
    // W84APP exit was pc=0x4066A5DC -- a relocated pointer-table address
    // executed as code, i.e. a wild virtual call with a shifted/bogus
    // vptr. Name the entry (fetch address, LR) so the object can be
    // identified from the guest side.
    if (vaddr >= 0x40660000u && vaddr < 0x40680000u) {
        static std::atomic<uint32_t> data_exec_count{0};
        if (data_exec_count.fetch_add(1) < 8) {
            Dynarmic::A32::Jit* jit = t_jit ? t_jit : m_jit.get();
            char b[160];
            snprintf(b, sizeof(b),
                     "DATAEXEC pc=0x%08X lr=0x%08X sp=0x%08X r0=%08X r4=%08X words[%08X %08X]",
                     vaddr, jit ? jit->Regs()[14] : 0, jit ? jit->Regs()[13] : 0,
                     jit ? jit->Regs()[0] : 0, jit ? jit->Regs()[4] : 0,
                     MemoryRead32(vaddr), MemoryRead32(vaddr + 4));
            DiagTrace::NotePersist(b);
        }
    }
    }
    if (static_cast<uint64_t>(vaddr) + 4 <= m_memory_size) {
        return *reinterpret_cast<uint32_t*>(m_memory + vaddr);
    }
    return std::nullopt;
}

std::uint8_t DynarmicHost::MemoryRead8(std::uint32_t vaddr) {
    if (static_cast<uint64_t>(vaddr) < m_memory_size) return m_memory[vaddr];
    return 0;
}

std::uint16_t DynarmicHost::MemoryRead16(std::uint32_t vaddr) {
    if (static_cast<uint64_t>(vaddr) + 2 <= m_memory_size) return *reinterpret_cast<uint16_t*>(m_memory + vaddr);
    return 0;
}

std::uint32_t DynarmicHost::MemoryRead32(std::uint32_t vaddr) {
    if (static_cast<uint64_t>(vaddr) + 4 <= m_memory_size) return *reinterpret_cast<uint32_t*>(m_memory + vaddr);
    return 0;
}

std::uint64_t DynarmicHost::MemoryRead64(std::uint32_t vaddr) {
    if (static_cast<uint64_t>(vaddr) + 8 <= m_memory_size) return *reinterpret_cast<uint64_t*>(m_memory + vaddr);
    return 0;
}

void DynarmicHost::MemoryWrite8(std::uint32_t vaddr, std::uint8_t value) {
    // W396 (run531): 8-bit coverage for the memory-state watch (STRB).
    if (vaddr >= 0x406E3DC4u && vaddr < 0x406E3DC8u) {
        static std::atomic<uint32_t> w396b{0};
        if (w396b.fetch_add(1) < 8) {
            char sb4[140];
            snprintf(sb4, sizeof(sb4), "W396 MEMSTATE8 addr=%08X val=%02X",
                     vaddr, static_cast<unsigned>(value));
            DiagTrace::NotePersist(std::string(sb4));
        }
    }
    if (static_cast<uint64_t>(vaddr) < m_memory_size) m_memory[vaddr] = value;
}

void DynarmicHost::MemoryWrite16(std::uint32_t vaddr, std::uint16_t value) {
    // W396: 16-bit coverage for the memory-state watch (STRH).
    if (vaddr >= 0x406E3DC4u && vaddr < 0x406E3DC8u) {
        static std::atomic<uint32_t> w396c{0};
        if (w396c.fetch_add(1) < 8) {
            char sb5[140];
            snprintf(sb5, sizeof(sb5), "W396 MEMSTATE16 addr=%08X val=%04X",
                     vaddr, static_cast<unsigned>(value));
            DiagTrace::NotePersist(std::string(sb5));
        }
    }
    if (static_cast<uint64_t>(vaddr) + 2 <= m_memory_size) *reinterpret_cast<uint16_t*>(m_memory + vaddr) = value;
}

void DynarmicHost::MemoryWrite32(std::uint32_t vaddr, std::uint32_t value) {
    // W199 follow-up: detect any host or guest mutation of the null-guard
    // veneer. It sits outside the SVC arena and must remain ordinary ARM code.
    if (vaddr >= 0x8F113200u && vaddr < 0x8F113248u) {
        static std::atomic<uint32_t> w199_writes{0};
        if (w199_writes.fetch_add(1) < 64) {
            Dynarmic::A32::Jit* wj = t_jit ? t_jit : m_jit.get();
            char wb[180];
            snprintf(wb, sizeof(wb), "W199-WRITE addr=%08X val=%08X pc=%08X lr=%08X sp=%08X",
                     vaddr, value, wj ? wj->Regs()[15] : 0,
                     wj ? wj->Regs()[14] : 0, wj ? wj->Regs()[13] : 0);
            DiagTrace::NotePersist(wb);
        }
    }
    // W388 (run519): watchpoint on the W100 stub #15 block. The first
    // guest store here names the descriptor writer with an exact PC.
    // W389: full window + DRO coverage.
    const bool w388_stub = (vaddr >= 0x8F111400u && vaddr < 0x8F111800u);
    const bool w388_war =
        vaddr == 0x4066E988u || vaddr == 0x4066E98Cu ||
        (vaddr >= 0x40667250u && vaddr < 0x40667280u);
    // W390 (run522): per-region caps -- war-slot spam no longer starves the
    // stub-window log (the run521 cap was consumed by the heal war).
    // W394 (run528): bzgMemory_system_state transition logger. Which
    // InitMemorySystem path the boot takes (auto-init state=1 vs the
    // game's own init to state=2) decides whether the game's pool
    // parameters are applied or silently dropped.
    if (vaddr == 0x406E3DC4u) {
        static thread_local uint32_t w394 = 0;
        if (w394 < 32) {
            ++w394;
            Dynarmic::A32::Jit* wj2 = t_jit ? t_jit : m_jit.get();
            char sb3[160];
            snprintf(sb3, sizeof(sb3),
                     "W394 MEMSTATE old=%08X new=%08X pc=%08X lr=%08X",
                     MemoryRead32(vaddr), value, wj2 ? wj2->Regs()[15] : 0,
                     wj2 ? wj2->Regs()[14] : 0);
            DiagTrace::NotePersist(std::string(sb3));
        }
    }
    const bool w388b = w388_stub || w388_war;
    if (w388b) {
        static thread_local uint32_t w388 = 0;
        if ((w388_stub || w388 < 6) && w388 < 40) {
            ++w388;
            Dynarmic::A32::Jit* wj = t_jit ? t_jit : m_jit.get();
            char wb[180];
            snprintf(wb, sizeof(wb),
                     "W388 WATCHWRITE addr=%08X val=%08X pc=%08X lr=%08X sp=%08X",
                     vaddr, value, wj ? wj->Regs()[15] : 0,
                     wj ? wj->Regs()[14] : 0, wj ? wj->Regs()[13] : 0);
            DiagTrace::NotePersist(std::string(wb));
            LOGE("%s", wb);
        }
    }
    if (static_cast<uint64_t>(vaddr) + 4 <= m_memory_size) *reinterpret_cast<uint32_t*>(m_memory + vaddr) = value;
}

void DynarmicHost::MemoryWrite64(std::uint32_t vaddr, std::uint64_t value) {
    if (static_cast<uint64_t>(vaddr) + 8 <= m_memory_size) *reinterpret_cast<uint64_t*>(m_memory + vaddr) = value;
}

void DynarmicHost::InterpreterFallback(std::uint32_t pc, std::size_t num_instructions) {
    LOGE("Interpreter Fallback at 0x%08X", pc);
    // W63: persist with tid -- a fallback here silently ends the Run.
    {
        char b[128];
        snprintf(b, sizeof(b), "INTERPFALL tid=%u pc=0x%08X n=%zu",
                 static_cast<uint32_t>(gettid()), pc, num_instructions);
        DiagTrace::NotePersist(b);
    }
    Dynarmic::A32::Jit* jit = t_jit ? t_jit : m_jit.get();
    if (jit) jit->HaltExecution(Dynarmic::HaltReason::UserDefined1);
}

void DynarmicHost::CallSVC(std::uint32_t swi) {
    Dynarmic::A32::Jit* jit = t_jit ? t_jit : m_jit.get();
    if (!jit) return;
#if BRIDGE_FIX_MASSLESS_STATIC
    if (swi == 0xF003u) {
        const float mass = std::bit_cast<float>(jit->Regs()[3]);
        t_massless_static_pending = !std::isfinite(mass) || mass <= 0.0f;
        if (t_massless_static_pending) {
            // Match the guest's explicit immovable-object default in
            // bzd_IO_ReadDynamicsObject. The object then gets a valid mass,
            // density and inertia from its normal setup function.
            jit->Regs()[3] = std::bit_cast<uint32_t>(1000.0f);
        }
        jit->Regs()[14] = jit->Regs()[15];
        jit->Regs()[15] = 0x4021D358u;
        return;
    }
    if (swi == 0xF004u) {
        // Original instruction at 0x40209858: MOV R4, R0 (no flags).
        const uint32_t lump = jit->Regs()[0];
        jit->Regs()[4] = lump;
        if (t_massless_static_pending &&
            lump >= 0x10000u && uint64_t(lump) + 144u <= m_memory_size) {
            const uint32_t body = MemoryRead32(lump + 140u);
            if (body >= 0x10000u && uint64_t(body) + 621u <= m_memory_size) {
                // Collision parameters 9 and 10 are the guest's immovable
                // path. sub_3A5E88 interprets these bits as zero inverse
                // inertia and zero inverse mass; no solver output is masked.
                MemoryWrite8(body + 617u, MemoryRead8(body + 617u) | 0x60u);
                static std::atomic<uint32_t> logged{0};
                if (logged.fetch_add(1) < 20) {
                    char name[64] = {};
                    const uint32_t name_ptr = MemoryRead32(lump + 124u);
                    if (name_ptr >= 0x10000u && uint64_t(name_ptr) + sizeof(name) <= m_memory_size) {
                        for (size_t i = 0; i + 1 < sizeof(name); ++i) {
                            const uint8_t ch = MemoryRead8(name_ptr + static_cast<uint32_t>(i));
                            if (!ch) break;
                            name[i] = ch >= 32 && ch < 127 ? static_cast<char>(ch) : '?';
                        }
                    }
                    LOGI("MASSLESS_STATIC lump=%08X body=%08X name=%s mass=%08X flags=%08X",
                         lump, body, name, MemoryRead32(body + 8u), MemoryRead32(body + 616u));
                }
            }
        }
        t_massless_static_pending = false;
        return;
    }
#endif
#if BRIDGE_ENABLE_COLLISION_PROBE
    if (swi == 0xF001u || swi == 0xF002u) {
        const auto& regs = jit->Regs();
        const uint32_t resume = regs[15];
        const auto valid_word = [this](uint64_t address) {
            return address >= 0x10000u && address + 4u <= m_memory_size;
        };
        const auto word = [this, &valid_word](uint64_t address) {
            return valid_word(address) ? MemoryRead32(static_cast<uint32_t>(address)) : 0u;
        };
        if (swi == 0xF001u) {
            auto& snapshot = t_collision_probe;
            snapshot.matrix = regs[0];
            snapshot.rhs = regs[1];
            snapshot.output = regs[2];
            snapshot.count = regs[3];
            snapshot.diagonal.fill(0);
            snapshot.rhs_values.fill(0);
            if (snapshot.count <= 64) {
                for (uint32_t i = 0; i < std::min(snapshot.count, 8u); ++i) {
                    const uint32_t packed_index = i * (i + 3u) / 2u;
                    snapshot.diagonal[i] = word(uint64_t(snapshot.matrix) + 4u * packed_index);
                    snapshot.rhs_values[i] = word(uint64_t(snapshot.rhs) + 4u * i);
                }
            }
            static std::atomic<uint32_t> first_calls{0};
            if (first_calls.fetch_add(1) < 4) {
                LOGE("COLLISION_PRE pc=%08X n=%u mat=%08X rhs=%08X out=%08X diag=%08X/%08X/%08X/%08X rhs4=%08X/%08X/%08X/%08X",
                     resume, snapshot.count, snapshot.matrix, snapshot.rhs, snapshot.output,
                     snapshot.diagonal[0], snapshot.diagonal[1], snapshot.diagonal[2], snapshot.diagonal[3],
                     snapshot.rhs_values[0], snapshot.rhs_values[1], snapshot.rhs_values[2], snapshot.rhs_values[3]);
            }
            jit->Regs()[14] = resume;
            jit->Regs()[15] = 0x403BA440u;
            return;
        }

        const auto name_for_body = [this, &word, &valid_word](uint32_t body) {
            std::array<char, 64> name{};
            const uint32_t lump = word(uint64_t(body) + 4u);
            const uint32_t name_ptr = word(uint64_t(lump) + 124u);
            if (!valid_word(name_ptr)) {
                std::snprintf(name.data(), name.size(), "<lump:%08X>", lump);
                return name;
            }
            size_t i = 0;
            for (; i + 1 < name.size(); ++i) {
                const uint8_t ch = MemoryRead8(name_ptr + static_cast<uint32_t>(i));
                if (!ch) break;
                name[i] = ch >= 32 && ch < 127 ? static_cast<char>(ch) : '?';
            }
            name[i] = '\0';
            return name;
        };
        const uint32_t forces = regs[0];
        const uint32_t impulses = regs[1];
        const uint32_t count = regs[2];
        if (count <= 64 && valid_word(forces) && valid_word(impulses)) {
            for (uint32_t i = 0; i < count; ++i) {
                const uint32_t impulse_bits = word(uint64_t(impulses) + 4u * i);
                const uint32_t body_a = word(uint64_t(forces) + 136u * i + 4u);
                const uint32_t body_b = word(uint64_t(forces) + 136u * i + 8u);
                const uint32_t mass_a_bits = word(uint64_t(body_a) + 8u);
                const uint32_t mass_b_bits = word(uint64_t(body_b) + 8u);
                const bool bad_impulse = !std::isfinite(std::bit_cast<float>(impulse_bits));
                const bool negative_mass = body_b && std::bit_cast<float>(mass_b_bits) < 0.0f;
                if (!bad_impulse && !negative_mass) continue;
                static std::atomic<uint32_t> bad_count{0};
                static std::atomic<uint32_t> negative_count{0};
                const uint32_t number = bad_impulse ? bad_count.fetch_add(1) : negative_count.fetch_add(1);
                if (number >= (bad_impulse ? 8u : 12u)) continue;
                const auto name_a = name_for_body(body_a);
                const auto name_b = name_for_body(body_b);
                const auto& snapshot = t_collision_probe;
                LOGE("COLLISION_FORCE bad=%u pc=%08X i=%u n=%u impulse=%08X a=%08X/%s mass=%08X flags=%08X b=%08X/%s mass=%08X flags=%08X solver_n=%u diag=%08X/%08X/%08X/%08X rhs=%08X/%08X/%08X/%08X",
                     bad_impulse, resume, i, count, impulse_bits,
                     body_a, name_a.data(), mass_a_bits, word(uint64_t(body_a) + 616u),
                     body_b, name_b.data(), mass_b_bits, word(uint64_t(body_b) + 616u),
                     snapshot.count, snapshot.diagonal[0], snapshot.diagonal[1],
                     snapshot.diagonal[2], snapshot.diagonal[3],
                     snapshot.rhs_values[0], snapshot.rhs_values[1],
                     snapshot.rhs_values[2], snapshot.rhs_values[3]);
            }
        }
        jit->Regs()[14] = resume;
        jit->Regs()[15] = 0x403B67C0u;
        return;
    }
#endif
    // W525 (run704): does the game thread's thunk SVC reach us at all?
    if (swi != 0 && swi < 300) {
        static std::atomic<uint32_t> w525{0};
        if (w525.fetch_add(1) < 40) {
            LOGE("[W525] CallSVC swi=%u pc=%08X tid=%u", swi, jit->Regs()[15], static_cast<uint32_t>(gettid()));
        }
    }
    // W551: JNI table slots live after the original low-id thunks. Keep a
    // bounded trace for those ids too; otherwise a bad indirect call looks
    // exactly like a silent low-page exit.
    if (swi >= 300 && swi < 1000) {
        static std::atomic<uint32_t> w551{0};
        if (w551.fetch_add(1) < 40) {
            LOGE("[W551] CallSVC high-id=%u pc=%08X lr=%08X tid=%u",
                 swi, jit->Regs()[15], jit->Regs()[14], static_cast<uint32_t>(gettid()));
        }
    }
    if (swi >= 680 && swi <= 720) {
        static std::atomic<uint32_t> w552{0};
        if (w552.fetch_add(1) < 32) {
            LOGE("[W552] JNI-range SVC=%u pc=%08X lr=%08X tid=%u",
                 swi, jit->Regs()[15], jit->Regs()[14], static_cast<uint32_t>(gettid()));
        }
    }
    // W133 (run180): the guest's bionic libc issues RAW SVC #0 syscalls
    // (futex waits under mutex contention, mmap2, clock_gettime fallbacks)
    // from code that never goes through the PLT. The old code halted the
    // run on EVERY swi==0, killing guest threads mid-flight -- the "clean
    // exits", the bzd retry storms and dozens of silent deaths trace back
    // to this. A raw guest syscall is NOT the exit trap: emulate ENOSYS
    // (R0 = -38) and let execution continue. The exit traps (pc 4/8) keep
    // their park semantics below.
    if (swi == 0 && jit->Regs()[15] > 0x40) {
        const uint32_t nr = jit->Regs()[7];
        // W141 (run189): raw futex (nr 238). WAIT ops sleep briefly host-side
        // so the guest's own wait loops notice changes without a tight spin;
        // WAKE/cacheflush are no-ops. Everything else stays ENOSYS.
        // W224 (run328): per-nr syscall histogram in the far zone —
        // 0x93000800 + (nr & 0xFF)*4, no cap, survives ring rotation.
        {
            const uint32_t cell = 0x93000800u + ((nr & 0xFFu) << 2);
            const uint32_t base = 0x93000000u;
            if (cell >= base && cell + 4 <= base + 0x1000u) {
                uint32_t c;
                std::memcpy(&c, m_memory + cell, 4);
                c += 1;
                std::memcpy(m_memory + cell, &c, 4);
            }
        }
        if (nr == 238) {
            const uint32_t op = jit->Regs()[1] & 0x7Fu;
            if (op == 0) {  // FUTEX_WAIT family: short host sleep
                std::this_thread::sleep_for(std::chrono::microseconds(250));
                jit->Regs()[0] = 0;
            } else if (op == 1) {  // FUTEX_WAKE
                jit->Regs()[0] = 0;
            } else {
                jit->Regs()[0] = static_cast<uint32_t>(-38);
            }
            return;
        }
        static std::atomic<uint32_t> w133_raw{0};
        if (w133_raw.fetch_add(1) < 32) {
            char b[128];
            snprintf(b, sizeof(b), "W133RAW syscall nr=%u pc=0x%08X tid=%u -> ENOSYS",
                     nr, jit->Regs()[15], static_cast<uint32_t>(gettid()));
            DiagTrace::NotePersist(b);
        }
        jit->Regs()[0] = static_cast<uint32_t>(-38);  // -ENOSYS
        return;
    }
    if (swi == 0 || jit->Regs()[15] <= 0x40) {
        const uint32_t pc = jit->Regs()[15];
        // W16: the exit traps (pc 4/8, swi 0) are normal idle-thread parks.
        // ANY other park at pc <= 0x40 means guest control flowed into the
        // bridge page (garbage indirect call/return, e.g. the run41 0x3E
        // park) -- persist the full register + stack snapshot so the caller
        // can be identified after the post-freeze ring flush.
        if (pc != EXIT_TRAP_ARM && pc != EXIT_TRAP_THUMB) {
            static std::atomic<uint32_t> low_park_count{0};
            if (low_park_count.fetch_add(1) < 5) {
                char b[176];
                snprintf(b, sizeof(b),
                         "LOWPARK pc=0x%08X lr=0x%08X sp=0x%08X swi=%u "
                         "r0=%08X r1=%08X r2=%08X r3=%08X r4=%08X r12=%08X",
                         pc, jit->Regs()[14], jit->Regs()[13], swi,
                         jit->Regs()[0], jit->Regs()[1], jit->Regs()[2],
                         jit->Regs()[3], jit->Regs()[4], jit->Regs()[12]);
                DiagTrace::NotePersist(b);
                const uint32_t sp = jit->Regs()[13];
                for (int w = 0; w < 12; ++w) {
                    snprintf(b, sizeof(b), "LOWPARK sp+0x%02X = 0x%08X", 4 * w,
                             MemoryRead32(sp + 4u * w));
                    DiagTrace::NotePersist(b);
                }
            }
        }
        // W10d: throttle-proof note for the SVC-halt source. The exit
        // traps (pc 4/8, swi 0) are normal idle-thread parks -- do not
        // note those, they would flood the ring.
        if (jit->Regs()[15] > 0x40) {
            char b[160];
            snprintf(b, sizeof(b), "SVC-HALT swi=%u pc=%08X lr=%08X sp=%08X tid=%u",
                     swi, jit->Regs()[15], jit->Regs()[14], jit->Regs()[13],
                     static_cast<uint32_t>(gettid()));
            DiagTrace::NotePersist(b);
        }
        jit->HaltExecution(Dynarmic::HaltReason::UserDefined1);
        return;
    }
    for (size_t i = 0; i < m_input_queue_thunk_ids.size(); ++i) {
        if (swi != m_input_queue_thunk_ids[i]) continue;
        const auto operation = static_cast<InputQueueOperation>(i);
        const uint32_t queue_handle = jit->Regs()[0];
        const uint32_t second_arg = jit->Regs()[1];
        const InputQueueAccess access = BeginInputQueueOperation(queue_handle, operation);
        if (access == InputQueueAccess::Denied) {
            if (operation == InputQueueOperation::GetEvent && second_arg &&
                uint64_t(second_arg) + 4u <= m_memory_size) MemoryWrite32(second_arg, 0);
            jit->Regs()[0] = operation == InputQueueOperation::GetEvent ? uint32_t(-1) : 0u;
            return;
        }
        const bool needs_second_handle = operation == InputQueueOperation::Attach ||
                                         operation == InputQueueOperation::PreDispatchEvent ||
                                         operation == InputQueueOperation::FinishEvent;
        const bool target_valid = !needs_second_handle ||
                                  HostPointerFor(second_arg) != nullptr;
        m_thunk_manager->DispatchThunk(swi, *jit);
        if (access == InputQueueAccess::Allowed) {
            uint32_t event_handle = 0;
            if (operation == InputQueueOperation::GetEvent) {
                if (static_cast<int32_t>(jit->Regs()[0]) >= 0 && second_arg &&
                    uint64_t(second_arg) + 4u <= m_memory_size)
                    event_handle = MemoryRead32(second_arg);
            } else if (operation == InputQueueOperation::PreDispatchEvent ||
                       operation == InputQueueOperation::FinishEvent) {
                event_handle = second_arg;
            }
            EndInputQueueOperation(queue_handle, operation, jit->Regs()[0], event_handle,
                                   target_valid);
        }
        return;
    }
    m_thunk_manager->DispatchThunk(swi, *jit);
}

void DynarmicHost::ExceptionRaised(std::uint32_t pc, Dynarmic::A32::Exception exception) {
    LOGE("Exception at PC: 0x%08X (type %d)", pc, static_cast<int>(exception));
    // W10d: route through the throttle-proof notes ring (the LOGE is often
    // swallowed by device logcat throttling). W63: persist it with tid.
    {
        char b[128];
        snprintf(b, sizeof(b), "EXCEPTION tid=%u pc=0x%08X type=%d",
                 static_cast<uint32_t>(gettid()), pc, static_cast<int>(exception));
        DiagTrace::Note(b);
        DiagTrace::NotePersist(b);
        // W311 (run414): a bare pc/type is not enough to act on -- the
        // run413 death (EXCEPTION pc=0x000151A0 type=1) took a day to
        // attribute to the W284 stub's pop{r0,sp} encoding. Record LR and
        // the four code words around the faulting PC verbatim.
        Dynarmic::A32::Jit* ejit = t_jit ? t_jit : m_jit.get();
        char b2[224];
        snprintf(b2, sizeof(b2),
                 "EXC-CTX tid=%u lr=%08X sp=%08X words[%08X %08X %08X %08X]",
                 static_cast<uint32_t>(gettid()), ejit ? ejit->Regs()[14] : 0,
                 ejit ? ejit->Regs()[13] : 0,
                 MemoryRead32(pc), MemoryRead32(pc + 4), MemoryRead32(pc - 4), MemoryRead32(pc + 8));
        DiagTrace::NotePersist(b2);
    }
    Dynarmic::A32::Jit* jit = t_jit ? t_jit : m_jit.get();
    // W404 (run538): recover from the log-entry aliasing jump: the
    // corrupted vtable+16 field (text-pointer) lands the thread in
    // rodata. Return to LR and let ReturnToDispatch resume; only faults
    // OUTSIDE the rodata band keep the old halt behaviour.
    if (pc >= 0x5E0000u && pc <= 0x670000u) {
        static std::atomic<uint32_t> w404{0};
        if (w404.fetch_add(1) < 16) {
            char rb[180];
            snprintf(rb, sizeof(rb),
                     "W404 RODATA-CALL-SKIP tid=%u pc=%08X lr=%08X n=%u",
                     static_cast<uint32_t>(gettid()), pc,
                     jit ? jit->Regs()[14] : 0, static_cast<unsigned>(w404.load()));
            DiagTrace::NotePersist(std::string(rb));
        }
        const uint32_t ret_lr = jit->Regs()[14];
        jit->Regs()[15] = ret_lr & ~1u;
        jit->SetCpsr((jit->Cpsr() & ~0x20u) | ((ret_lr & 1u) ? 0x20u : 0u));
        return;  // no halt: ReturnToDispatch resumes at the rewritten PC
    }
    if (jit) jit->HaltExecution(Dynarmic::HaltReason::UserDefined1);
}

void DynarmicHost::AddTicks(std::uint64_t ticks) {
    if (m_ticks_remaining > ticks) m_ticks_remaining -= ticks;
    else m_ticks_remaining = 0;
}

std::uint64_t DynarmicHost::GetTicksRemaining() {
    return m_ticks_remaining;
}

// STREX: compare-and-set against guest memory. The ExclusiveMonitor already holds its lock
// around this and has verified the reservation, so a plain compare/store is sufficient.
template<typename T>
static bool GuestCompareAndSwap(uint8_t* mem, size_t mem_size, uint32_t vaddr, T value, T expected) {
    if (static_cast<uint64_t>(vaddr) + sizeof(T) > mem_size) return false;
    T* p = reinterpret_cast<T*>(mem + vaddr);
    if (*p != expected) return false;
    *p = value;
    return true;
}

bool DynarmicHost::MemoryWriteExclusive8(std::uint32_t vaddr, std::uint8_t value, std::uint8_t expected) {
    return GuestCompareAndSwap(m_memory, m_memory_size, vaddr, value, expected);
}

bool DynarmicHost::MemoryWriteExclusive16(std::uint32_t vaddr, std::uint16_t value, std::uint16_t expected) {
    return GuestCompareAndSwap(m_memory, m_memory_size, vaddr, value, expected);
}

bool DynarmicHost::MemoryWriteExclusive32(std::uint32_t vaddr, std::uint32_t value, std::uint32_t expected) {
    return GuestCompareAndSwap(m_memory, m_memory_size, vaddr, value, expected);
}

bool DynarmicHost::MemoryWriteExclusive64(std::uint32_t vaddr, std::uint64_t value, std::uint64_t expected) {
    return GuestCompareAndSwap(m_memory, m_memory_size, vaddr, value, expected);
}
