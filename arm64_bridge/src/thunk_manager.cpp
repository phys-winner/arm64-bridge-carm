#include "thunk_manager.h"
#include <stdexcept>
#include "diag_trace.h"
#include "native_handle_table.h"
struct ANativeWindow;
ANativeWindow* BridgeCurrentSurfaceWindow();
#include "dynarmic_host.h"
#include "elf_loader.h"
#include "thunk_types.h"
#include <android/log.h>
#include <android/native_window.h>
#include <atomic>
#include <chrono>
#include <map>
#include <mutex>
#include <unordered_map>
#include <thread>
#include <unistd.h>
#include <vector>

#define LOG_TAG "Arm32Bridge_Thunks"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

uint32_t ThunkManager::s_screenWidth = 1213;
uint32_t ThunkManager::s_screenHeight = 540;
uint32_t ThunkManager::s_virtualWidth = 0;
uint32_t ThunkManager::s_virtualHeight = 0;
uint32_t ThunkManager::s_forced_dpi = 0;
uint32_t ThunkManager::s_ui_inset = 0;

// W100: bz_StartInternal progress counters, defined in thunks_libc.cpp.
extern uint32_t g_w100_counter_addr;
// W124: bzd D_* step counters, defined in thunks_libc.cpp.
extern uint32_t g_w124_counter_addr;
// W122: bzd called/ret counter pair, defined in thunks_libc.cpp.
extern uint32_t g_w122_counter_addr;
// W128: pool-creator trace block (cnt+20 = last LLMemAllocate result).
extern uint32_t g_w128_counter_addr;
// W125: bzd entry counter, defined in thunks_libc.cpp.
extern uint32_t g_w125_counter_addr;

ThunkManager::ThunkManager(DynarmicHost& host) : m_host(host) {}

ThunkManager::~ThunkManager() = default;

#include "thunks_opensles.h"

void ThunkManager::RegisterAllThunks() {
    RegisterGLThunks();
    RegisterGles1Thunks(*this);
    RegisterEglThunks(*this);
    RegisterAndroidThunks(*this);
    RegisterOpenSLESThunks(*this, m_host);
    RegisterLibcThunks();
    RegisterZlibThunks();
    RegisterLibcExtraThunks(*this, m_host);
    // The guest-visible JNIEnv/JavaVM tables live in FakeJniEnv; jni_bridge.cpp
    // calls FakeJniEnv::Instance().Init(host) once the host JavaVM is known.
}

#include <jni.h>
#include <sys/system_properties.h>
#include <cmath>
#include <cctype>
#include <cstring>

JavaVM* GetHostJavaVM();

std::string QueryDeviceLanguage() {
    std::string lang = "en";
    JavaVM* jvm = GetHostJavaVM();
    if (jvm) {
        JNIEnv* env = nullptr;
        bool attached = false;
        if (jvm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
            if (jvm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
                attached = true;
            }
        }
        if (env) {
            jclass locCls = env->FindClass("java/util/Locale");
            if (locCls) {
                jmethodID getDefault = env->GetStaticMethodID(locCls, "getDefault", "()Ljava/util/Locale;");
                if (getDefault) {
                    jobject locObj = env->CallStaticObjectMethod(locCls, getDefault);
                    if (locObj) {
                        jmethodID getLang = env->GetMethodID(locCls, "getLanguage", "()Ljava/lang/String;");
                        if (getLang) {
                            jstring jStr = (jstring)env->CallObjectMethod(locObj, getLang);
                            if (jStr) {
                                const char* utf = env->GetStringUTFChars(jStr, nullptr);
                                if (utf && strlen(utf) > 0) {
                                    lang = utf;
                                }
                                if (utf) env->ReleaseStringUTFChars(jStr, utf);
                            }
                        }
                    }
                }
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (attached) jvm->DetachCurrentThread();
        }
    }
    if (lang.empty() || lang == "en") {
        char prop[PROP_VALUE_MAX] = {0};
        if (__system_property_get("persist.sys.locale", prop) > 0 ||
            __system_property_get("ro.product.locale", prop) > 0 ||
            __system_property_get("persist.sys.language", prop) > 0) {
            char* dash = strchr(prop, '-');
            if (dash) *dash = '\0';
            char* under = strchr(prop, '_');
            if (under) *under = '\0';
            if (strlen(prop) > 0) lang = prop;
        }
    }
    for (char& c : lang) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    return lang;
}

std::string QueryDeviceCountryCode() {
    std::string country = "US";
    JavaVM* jvm = GetHostJavaVM();
    if (jvm) {
        JNIEnv* env = nullptr;
        bool attached = false;
        if (jvm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
            if (jvm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
                attached = true;
            }
        }
        if (env) {
            jclass locCls = env->FindClass("java/util/Locale");
            if (locCls) {
                jmethodID getDefault = env->GetStaticMethodID(locCls, "getDefault", "()Ljava/util/Locale;");
                if (getDefault) {
                    jobject locObj = env->CallStaticObjectMethod(locCls, getDefault);
                    if (locObj) {
                        jmethodID getCountry = env->GetMethodID(locCls, "getCountry", "()Ljava/lang/String;");
                        if (getCountry) {
                            jstring jStr = (jstring)env->CallObjectMethod(locObj, getCountry);
                            if (jStr) {
                                const char* utf = env->GetStringUTFChars(jStr, nullptr);
                                if (utf && strlen(utf) > 0) {
                                    country = utf;
                                }
                                if (utf) env->ReleaseStringUTFChars(jStr, utf);
                            }
                        }
                    }
                }
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (attached) jvm->DetachCurrentThread();
        }
    }
    if (country.empty() || country == "US") {
        char prop[PROP_VALUE_MAX] = {0};
        if (__system_property_get("persist.sys.country", prop) > 0 ||
            __system_property_get("ro.product.locale.region", prop) > 0) {
            if (strlen(prop) > 0) country = prop;
        } else if (__system_property_get("persist.sys.locale", prop) > 0 ||
                   __system_property_get("ro.product.locale", prop) > 0) {
            char* dash = strchr(prop, '-');
            if (dash && strlen(dash + 1) >= 2) {
                country = std::string(dash + 1, 2);
            } else {
                char* under = strchr(prop, '_');
                if (under && strlen(under + 1) >= 2) {
                    country = std::string(under + 1, 2);
                }
            }
        }
    }
    for (char& c : country) c = static_cast<char>(toupper(static_cast<unsigned char>(c)));
    return country;
}

uint32_t QueryDeviceDensity() {
    if (ThunkManager::s_forced_dpi > 0) {
        return ThunkManager::s_forced_dpi;
    }
    uint32_t density = 0;
    JavaVM* jvm = GetHostJavaVM();
    if (jvm) {
        JNIEnv* env = nullptr;
        bool attached = false;
        if (jvm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
            if (jvm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
                attached = true;
            }
        }
        if (env) {
            jclass resCls = env->FindClass("android/content/res/Resources");
            if (resCls) {
                jmethodID getSys = env->GetStaticMethodID(resCls, "getSystem", "()Landroid/content/res/Resources;");
                if (getSys) {
                    jobject resObj = env->CallStaticObjectMethod(resCls, getSys);
                    if (resObj) {
                        jmethodID getDM = env->GetMethodID(resCls, "getDisplayMetrics", "()Landroid/util/DisplayMetrics;");
                        if (getDM) {
                            jobject dmObj = env->CallObjectMethod(resObj, getDM);
                            if (dmObj) {
                                jclass dmCls = env->FindClass("android/util/DisplayMetrics");
                                jfieldID fid = env->GetFieldID(dmCls, "densityDpi", "I");
                                if (fid) {
                                    density = static_cast<uint32_t>(env->GetIntField(dmObj, fid));
                                }
                            }
                        }
                    }
                }
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (attached) jvm->DetachCurrentThread();
        }
    }
    if (density == 0) {
        char prop[PROP_VALUE_MAX] = {0};
        if (__system_property_get("ro.sf.lcd_density", prop) > 0 ||
            __system_property_get("qemu.sf.lcd_density", prop) > 0) {
            density = static_cast<uint32_t>(atoi(prop));
        }
    }
    if (density == 0) {
        density = 320;
    }
    return density;
}

uint32_t QueryDeviceIsPad() {
    JavaVM* jvm = GetHostJavaVM();
    if (jvm) {
        JNIEnv* env = nullptr;
        bool attached = false;
        if (jvm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
            if (jvm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
                attached = true;
            }
        }
        if (env) {
            // Configuration.screenLayout is the platform answer; the diagonal
            // fallback below covers devices that report it wrong.
            jclass resCls = env->FindClass("android/content/res/Resources");
            if (resCls) {
                jmethodID getSys = env->GetStaticMethodID(resCls, "getSystem", "()Landroid/content/res/Resources;");
                if (getSys) {
                    jobject resObj = env->CallStaticObjectMethod(resCls, getSys);
                    if (resObj) {
                        jmethodID getCfg = env->GetMethodID(resCls, "getConfiguration", "()Landroid/content/res/Configuration;");
                        if (getCfg) {
                            jobject cfgObj = env->CallObjectMethod(resObj, getCfg);
                            if (cfgObj) {
                                jclass cfgCls = env->FindClass("android/content/res/Configuration");
                                jfieldID slFid = env->GetFieldID(cfgCls, "screenLayout", "I");
                                if (slFid) {
                                    jint screenLayout = env->GetIntField(cfgObj, slFid);
                                    if ((screenLayout & 0x0F) >= 3) { // SCREENLAYOUT_SIZE_LARGE or XLARGE
                                        if (env->ExceptionCheck()) env->ExceptionClear();
                                        if (attached) jvm->DetachCurrentThread();
                                        return 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (attached) jvm->DetachCurrentThread();
        }
    }

    uint32_t w = ThunkManager::s_screenWidth;
    uint32_t h = ThunkManager::s_screenHeight;
    uint32_t dpi = QueryDeviceDensity();
    if (w > 0 && h > 0 && dpi > 0) {
        double w_in = static_cast<double>(w) / static_cast<double>(dpi);
        double h_in = static_cast<double>(h) / static_cast<double>(dpi);
        double diag = sqrt(w_in * w_in + h_in * h_in);
        if (diag >= 6.5) return 1;
    }
    return 0;
}


uint32_t ThunkManager::RegisterThunk(const std::string& name, ThunkHandler handler) {
    uint32_t address;
    bool created = false;
    {
        std::lock_guard lock(m_registry_mutex);
        if (name.empty() || !handler) throw std::invalid_argument("Invalid thunk registration");
        auto existing = m_function_ids.find(name);
        uint32_t id;
        if (existing != m_function_ids.end()) {
            id = existing->second;
            address = m_symbol_to_address.at(name);
        } else {
            if (m_symbol_to_address.contains(name)) throw std::logic_error("Cannot replace data with a function: " + name);
            if (m_function_ids.size() >= kMaxThunks) throw std::overflow_error("Guest trampoline page exhausted");
            id = static_cast<uint32_t>(m_function_ids.size() + 1);
            address = m_next_thunk_addr;
            m_next_thunk_addr += 8;
            m_host.MemoryWrite32(address, 0xEF000000 | id);
            m_host.MemoryWrite32(address + 4, 0xE12FFF1E);
            m_symbol_to_address.emplace(name, address);
            m_function_ids.emplace(name, id);
            created = true;
        }
        auto entry = std::make_unique<ThunkEntry>(ThunkEntry{name, std::move(handler)});
        const auto* published = entry.get();
        m_entries.push_back(std::move(entry));
        m_dispatch[id - 1].store(published, std::memory_order_release);
    }
    if (created) {
        m_host.InvalidateGuestCode(address, 8);
    }
    return address;
}

void ThunkManager::RegisterSymbol(const std::string& name, uint32_t address) {
    std::lock_guard lock(m_registry_mutex);
    if (name.empty() || !address || address >= m_host.GetGuestMemorySize() || m_function_ids.contains(name))
        throw std::invalid_argument("Invalid guest data symbol: " + name);
    m_symbol_to_address[name] = address;
}

uint32_t ThunkManager::FindRegisteredSymbol(const std::string& name) const {
    std::lock_guard lock(m_registry_mutex);
    auto it = m_symbol_to_address.find(name);
    return it == m_symbol_to_address.end() ? 0 : it->second;
}
uint32_t ThunkManager::GetOrCreateThunkAddress(const std::string& name) {
    return FindRegisteredSymbol(name);
}
uint32_t ThunkManager::GetThunkSvcId(const std::string& name) const {
    std::lock_guard lock(m_registry_mutex);
    auto it = m_function_ids.find(name);
    return it == m_function_ids.end() ? 0 : it->second;
}

// W40 watchdog: track in-flight thunk dispatches per host thread and report
// any dispatch parked longer than 3 s. This names the exact blocking thunk
// (with the guest PC/LR of the SVC site) no matter which call it is.
namespace {
struct W40Dispatch {
    std::string name;
    uint32_t pc;
    uint32_t lr;
    std::chrono::steady_clock::time_point t0;
};
static uint32_t w347b_dump_count = 0;
static bool g_got_snapshotted = false;
static uint32_t g_got_base = 0;
static std::vector<uint32_t> g_got_shadow;
static std::vector<uint32_t> g_dro_shadow;
static bool g_dro_snapshotted = false;

// W335 (run449): called from the boot sequence BEFORE any guest code runs,
// so the shadow holds the pristine relocation-time GOT and the wild-writer's
// early poison is detected (and reverted) on the first watchdog tick.
void SnapshotGotShadowImpl(DynarmicHost& host) {
    LOGI("[W335] SnapshotGotShadowImpl entered (snapshotted=%d)", (int)g_got_snapshotted);
    if (g_got_snapshotted) return;
    g_got_snapshotted = true;
    g_got_base = host.GetElfLoader().GetGotVaddr() + 12u;
    const uint32_t entries = host.GetElfLoader().GetPltRelSize() / 4u;
    g_got_shadow.resize(entries);
    for (uint32_t gi = 0; gi < entries; ++gi)
        g_got_shadow[gi] = host.MemoryRead32(g_got_base + gi * 4u);
    DiagTrace::NotePersist("W335 GOT snapshot (boot): base=" + std::to_string(g_got_base) + " entries=" + std::to_string(entries));
    g_dro_shadow.resize(0x2400u);  // 0x4066A000..0x40669000? -> 0x2400 words = 0x9000 bytes
    for (uint32_t gi = 0; gi < g_dro_shadow.size(); ++gi)
        g_dro_shadow[gi] = host.MemoryRead32(0x4066A000u + gi * 4u);
    LOGE("[W336] DRO shadow: %u words from 0x4066A000", (unsigned)g_dro_shadow.size());
    LOGE("[W335] GOT snapshot (boot): base=%u entries=%u", g_got_base, entries);
    // W468 (run613): NOP the armcc dispatch-wait BNE at 0x4058DF5C. The
    // waiter (LDREX/EOR/CMP/BNE loop) spins while a flag held by the armcc
    // dispatch iframe is set; under the bridge that flag never clears
    // (the iframe's pending-init queue is re-fed by pump registrations),
    // so EVERY message ctor in the .init_array walk wedged there. Our W444
    // serialization already makes the ctor walk single-threaded, so the
    // mutual exclusion is unnecessary -- pass through the wait.
    {
        // W469: veneer the iframe's dispatch boundary [0x4058DF2C,+8]
        // (ADD r11,sp,#0 + BLX r0): count dispatches and capture the last
        // dispatched target into guest cells (rotation-proof).
        {
            const uint32_t w469site = 0x4058DF2Cu;
            const uint32_t w469stub = 0x8F117900u;
            const uint32_t code[12] = {
                0xE300C7A8u,  // MOVW r12,#0x17A8
                0xE349C300u,  // MOVT r12,#0x9300
                0xE59C3000u,  // LDR r3,[r12]
                0xE2833001u,  // ADD r3,r3,#1
                0xE58C3000u,  // STR r3,[r12]
                0xE300C7ACu,  // MOVW r12,#0x17AC
                0xE349C300u,  // MOVT r12,#0x9300
                0xE58C0000u,  // STR r0,[r12]   (last dispatched target)
                0xE28DB000u,  // ADD r11,sp,#0  (displaced)
                0xE12FFF30u,  // BLX r0         (displaced)
                0xE51FF004u,  // LDR PC,[PC,#-4]
                0x4058DF34u}; // resume
            for (size_t ci = 0; ci < sizeof(code)/sizeof(code[0]); ++ci)
                host.MemoryWrite32(w469stub + static_cast<uint32_t>(ci * 4), code[ci]);
            host.InvalidateGuestCode(w469stub, sizeof(code));
            host.MemoryWrite32(w469site, 0xE51FF004u);       // ldr pc,[pc,#-4]
            host.MemoryWrite32(w469site + 4u, w469stub);
            host.InvalidateGuestCode(w469site, 8);
        }
        const uint32_t w468 = 0x4058DF5Cu;
        const uint32_t o = host.MemoryRead32(w468);
        if (o == 0x1AFFFFFBu) {
            host.MemoryWrite32(w468, 0xE1A00000u);  // BNE -> NOP
            host.InvalidateGuestCode(w468, 4);
            DiagTrace::NotePersist("W468 dispatch-wait BNE NOPped");
        } else {
            char eb[96];
            snprintf(eb, sizeof(eb), "[W468] unexpected word at 0x4058DF5C: %08X", o);
            DiagTrace::NotePersist(std::string(eb));
        }
    }

    // W470 (run618): DISABLE the armcc dispatch machinery entirely.
    // The dispatch iframe (0x4058DF18) processes pending inits in an
    // infinite loop and the EOR-lock waiter (0x4058DF38) spins forever
    // under the bridge. Patch both to BX LR so they return immediately.
    host.MemoryWrite32(0x4058DF18u, 0xE12FFF1Eu);  // BX LR (dispatch iframe)
    host.InvalidateGuestCode(0x4058DF18u, 4);
    host.MemoryWrite32(0x4058DF38u, 0xE12FFF1Eu);  // BX LR (waiter)
    host.InvalidateGuestCode(0x4058DF38u, 4);
    host.MemoryWrite32(0x4058DE7Cu, 0xE12FFF1Eu);  // BX LR (register helper)
    host.InvalidateGuestCode(0x4058DE7Cu, 4);
    DiagTrace::NotePersist("W470 dispatch disabled");
    // W432-PLT: hardening moved to the lazy per-tick pass (W432b).
}
std::mutex g_w40_mutex;
std::map<uint32_t, std::vector<W40Dispatch>> g_w40_active;
std::once_flag g_w40_watchdog_once;
DynarmicHost* g_w40_host = nullptr;  // set on first dispatch; outlives shutdown races here

// W418 (run556): callable early GOT heal. The 5 s tick missed the poison
// window entirely -- W264's handle_cmd(cmd=6) wild-jumped through a
// poisoned PLT GOT slot at ~1.3 s, before the first watchdog tick. The
// lifecycle replay now heals immediately before every guest dispatch.
static int g_w418_fixes = 0;
// W426 (run566): the every-5s heal raced guest TRANSLATION -- restoring a
// slot invalidates a block mid-build on another thread and Dynarmic's
// IR::Block::SetTerminal assert aborted the process (SIGABRT 'terminating',
// Thread-11, t=11.5s). The W385 lesson repeats: the game re-points import
// slots legitimately at runtime. Heal only in the boot window (a budget of
// 6 calls covers the W264 pre-dispatch heals); afterwards this is a no-op.
// W432b (run582): lazy PLT hardener. The PLT slots are unresolved (zero)
// at snapshot time -- resolution happens on first call -- so hardening runs
// per tick: once a slot carries a resolved target, its PLT entry is
// rewritten into a direct literal jump (GOT never consulted again).
static std::vector<uint8_t> g_plt_hardened;
static uint32_t g_plt_hardened_count = 0;
static bool g_plt_hardened_logged = false;
void W432PltHardenTick() {
    if (!g_w40_host || g_got_shadow.empty()) return;
    if (g_plt_hardened.size() != g_got_shadow.size())
        g_plt_hardened.assign(g_got_shadow.size(), 0);
    for (size_t gi = 0; gi < g_got_shadow.size(); ++gi) {
        if (g_plt_hardened[gi]) continue;
        const uint32_t slot = g_got_base + static_cast<uint32_t>(gi) * 4u;
        const uint32_t v = g_w40_host->MemoryRead32(slot);
        if (v == 0) continue;
        const uint32_t entry = 0x40166384u + static_cast<uint32_t>(gi) * 12u;
        g_w40_host->MemoryWrite32(entry, 0xE51FF004u);      // ldr pc,[pc,#-4]
        g_w40_host->MemoryWrite32(entry + 4u, v);           // resolved target
        g_w40_host->MemoryWrite32(entry + 8u, 0xE1A00000u); // nop pad
        g_w40_host->InvalidateGuestCode(entry, 12);
        g_plt_hardened[gi] = 1;
        ++g_plt_hardened_count;
        if (!g_plt_hardened_logged) {
            DiagTrace::NotePersist("W432PLT first entry hardened");
            g_plt_hardened_logged = true;
        }
    }
}
static int g_w418_budget = 6;
void W418GotHealNow() {
    // GOT contents are mutable guest state. Restoring a boot snapshot from a
    // host watchdog races guest relocation and legitimate runtime rebinding.
    // Leave observation to the diagnostics; never rewrite the guest here.
    return;
    if (g_w418_budget <= 0) return;
    --g_w418_budget;
    if (!g_w40_host || g_got_shadow.empty()) return;
    for (size_t gi = 0; gi < g_got_shadow.size(); ++gi) {
        const uint32_t slot = g_got_base + (uint32_t)(gi * 4u);
        const uint32_t cur = g_w40_host->MemoryRead32(slot);
        if (cur != g_got_shadow[gi]) {
            g_w40_host->MemoryWrite32(slot, g_got_shadow[gi]);
            if (g_w418_fixes < 8) {
                char gb[128];
                snprintf(gb, sizeof(gb), "W418GOTFIX slot=%08X poisoned=%08X restored=%08X",
                         slot, cur, g_got_shadow[gi]);
                DiagTrace::NotePersist(std::string(gb));
                LOGE("%s", gb);
            }
            ++g_w418_fixes;
        }
    }
}

void W40WatchdogLoop() {
    for (;;) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        // W40PCS: freeze-frame of every guest thread's JIT PC. A thread
        // parked inside a thunk (or any host-side wait) shows a frozen PC;
        // comparing consecutive samples separates parked from looping.
        if (g_w40_host) {
            auto tpcs = g_w40_host->SampleGuestThreadPcs();
            std::string line = "W40PCS n=" + std::to_string(tpcs.size());
            for (size_t i = 0; i < tpcs.size() && i < 40; ++i) {
                char pb[112];
                // W94: SP in the sample. The glue thread's SP was seen
                // switching from the 0x7E4xxxxx worker stack to garbage
                // (0xC77D169E) mid-run; the 10 s samples bracket the flip.
                // W310 (run414): a parked thread's PC sits at
                // trampoline+4 inside its blocking thunk -- resolve the
                // name so the freeze-frame says WHICH wait each thread
                // is in (decoded the 0x10C74 ambiguity of run413).
                const char* tn = nullptr;
                static std::unordered_map<uint32_t, std::string> rev;
                static std::once_flag rev_once;
                std::call_once(rev_once, [] {
                    if (g_w40_host)
                        for (auto& kv : g_w40_host->GetThunkManager().GetThunkSymbolTable())
                            rev[kv.second] = kv.first;
                });
                auto rit = rev.find(tpcs[i].pc);
                if (rit == rev.end()) rit = rev.find(tpcs[i].pc - 4);
                if (rit != rev.end()) tn = rit->second.c_str();
                // W445: r0-r3 in the sample -- the armcc EOR-lock waiter's
                // wait arguments live there (r0=loaded value, r2=flag, r3=ptr).
                if (tn)
                    snprintf(pb, sizeof(pb), " t%u=0x%08X[%s] lr=%08X sp=%08X r4=0x%08X r0=%08X r1=%08X r2=%08X r3=%08X",
                             tpcs[i].tid, tpcs[i].pc, tn, tpcs[i].lr, tpcs[i].sp, tpcs[i].r4,
                             tpcs[i].r0, tpcs[i].r1, tpcs[i].r2, tpcs[i].r3);
                else
                    snprintf(pb, sizeof(pb), " t%u=0x%08X lr=%08X sp=%08X r4=0x%08X r0=%08X r1=%08X r2=%08X r3=%08X",
                             tpcs[i].tid, tpcs[i].pc, tpcs[i].lr, tpcs[i].sp, tpcs[i].r4,
                             tpcs[i].r0, tpcs[i].r1, tpcs[i].r2, tpcs[i].r3);
                line += pb;
            }
            // W352 (run464): did the machine run? W48 counts
            // StateMachine_Enter entries (0x4065CD5C), the destroy flag is
            // bzgAndroidDestroyApp (0x406D9159) -- if Enter>0 and destroy=1
            // the boot COMPLETED and the game exited itself (the W84APP
            // mystery of run462: the RET log cap 4096, exhausted by the
            // FMOD pulse, hid the legal android_app_entry return).
            {
                char eb[160];
                snprintf(eb, sizeof(eb),
                         " W352 enter=%u destroy=%u proc=%u fc0=%08X"
                         " W374 err=%u code=%08X sys=%u errind=%u w377c=%u w377v=%08X",
                         g_w40_host->MemoryRead32(0x4065CD5Cu),
                         g_w40_host->MemoryRead32(0x406D9159u),
                         g_w40_host->MemoryRead32(0x4065CD58u),
                         g_w40_host->MemoryRead32(0x403F2428u),
                         g_w40_host->MemoryRead32(0x93001564u),
                         g_w40_host->MemoryRead32(0x93001568u),
                         g_w40_host->MemoryRead32(0x406E3DC4u),
                         g_w40_host->MemoryRead32(0x406925FCu),
                         g_w40_host->MemoryRead32(0x93001728u),
                         g_w40_host->MemoryRead32(0x9300172Cu));  // W428: started cell
            // W379 (run508): dump the W100 stub #15 bytes at tick time --
            // the game thread reproducibly freezes at pc=lr=0x0001179C
            // (stub+0x1C, the displaced MOV R0,#0) with sp inside the stub
            // window. Verifies the installed words survive (W131 zeroing
            // order, JIT scribbles) and shows the live registers context.
            {
                char sb[560];
                int sn = snprintf(sb, sizeof(sb), "W379STUB:");
                for (int w = 0; w < 12 && sn > 0; ++w)
                    sn += snprintf(sb + sn, sizeof(sb) - static_cast<size_t>(sn),
                                   " %08X",
                                   g_w40_host->MemoryRead32(0x8F111780u +
                                   static_cast<uint32_t>(w) * 4u));
                // W380b: stubs 13 (0x00011700) and 14 (0x00011740) too.
                sn += snprintf(sb + sn, sizeof(sb) - static_cast<size_t>(sn),
                               " S13:");
                for (int w = 0; w < 8 && sn > 0; ++w)
                    sn += snprintf(sb + sn, sizeof(sb) - static_cast<size_t>(sn),
                                   " %08X",
                                   g_w40_host->MemoryRead32(0x8F111700u +
                                   static_cast<uint32_t>(w) * 4u));
                sn += snprintf(sb + sn, sizeof(sb) - static_cast<size_t>(sn),
                               " S14:");
                for (int w = 0; w < 8 && sn > 0; ++w)
                    sn += snprintf(sb + sn, sizeof(sb) - static_cast<size_t>(sn),
                                   " %08X",
                                   g_w40_host->MemoryRead32(0x8F111740u +
                                   static_cast<uint32_t>(w) * 4u));
                line += sb;
            // W401b (run541): per-stub word summary (word0/1/5 of stubs
            // 13/14/15) so the born-vs-current A/B survives ring rotation.
            {
                char z[260];
                int zn = snprintf(z, sizeof(z), " W401B st13=%08X/%08X/%08X st14=%08X/%08X/%08X st15=%08X/%08X/%08X",
                                  g_w40_host->MemoryRead32(0x8F111700u),
                                  g_w40_host->MemoryRead32(0x8F111704u),
                                  g_w40_host->MemoryRead32(0x8F111714u),
                                  g_w40_host->MemoryRead32(0x8F111740u),
                                  g_w40_host->MemoryRead32(0x8F111744u),
                                  g_w40_host->MemoryRead32(0x8F111754u),
                                  g_w40_host->MemoryRead32(0x8F111780u),
                                  g_w40_host->MemoryRead32(0x8F111784u),
                                  g_w40_host->MemoryRead32(0x8F111794u));
                line += z;
            // W410 counters: entry probes for Init_PostBZ and StateMachine_DoInit.
            {
                char w410c[100];
                snprintf(w410c, sizeof(w410c), " W410C ipbz=%u smdi=%u",
                         g_w40_host->MemoryRead32(0x93001590u),
                         g_w40_host->MemoryRead32(0x93001734u));
                line += w410c;
            }
            // W406 (run539): verify the W394b NOP window (0x4040D9F8..0x4040DA0C)
            // W412 (run553): was 0x40D9F8 -- IDB paste missed the +0x40000000 base; the
            // dump has been reading a dead 4MB region (always zeros) since run539.
            // stays NOPped through the boot -- 5 words of the auto-init.
            {
                char vb[180];
                int vn = snprintf(vb, sizeof(vb), " W406AUTO:");
                for (int w = 0; w < 5 && vn > 0; ++w)
                    vn += snprintf(vb + vn, sizeof(vb) - (size_t)vn, " %08X",
                                   g_w40_host->MemoryRead32(0x4040D9F8u +
                                   static_cast<uint32_t>(w) * 4u));
                line += vb;
            }
            // W402b (run542): gfx-family state (mutex word, recursion count,
            // thread handle) + the log-string pointer that was aliased.
            {
                char gb[220];
                snprintf(gb, sizeof(gb), " W402B gfxmtx=%08X gfxrec=%d gfxtid=%08X logstr=%08X",
                         g_w40_host->MemoryRead32(0x406D95A4u),
                         static_cast<int32_t>(g_w40_host->MemoryRead32(0x406D95A8u)),
                         g_w40_host->MemoryRead32(0x406D95B0u),
                         g_w40_host->MemoryRead32(0x405F7168u));
                line += gb;
            // W403c (run543): LogManager object dump (bzgLogManager
            // points at 0x50843C40-family heap object) -- first 12 words
            // to locate the entry-ring base/head fields.
            {
                const uint32_t lm = g_w40_host->MemoryRead32(0x406D9538u);
                char lb[340];
                int ln2 = snprintf(lb, sizeof(lb), " W403C LM@%08X:", lm);
                if (lm >= 0x50800000u && lm < 0x90000000u) {
                    for (int w = 0; w < 12 && ln2 > 0; ++w)
                        ln2 += snprintf(lb + ln2, sizeof(lb) - (size_t)ln2, " %08X",
                                        g_w40_host->MemoryRead32(lm + (uint32_t)w * 4u));
                }
                line += lb;
            // W410 (run547): ActualMain call-site integrity check.
            // Dump 4 words at each call site: Init_PostBZ (0x4054E0A0),
            // StateMachine_DoInit (0x4054E0A4), StateMachine_Enter
            // (0x4054E0AC) -- verifies the call instructions are intact.
            {
                char cb[340];
                int cn = snprintf(cb, sizeof(cb), " W410 IPBZ:");
                for (int w = 0; w < 4 && cn > 0; ++w)
                    cn += snprintf(cb + cn, sizeof(cb) - (size_t)cn, " %08X",
                                   g_w40_host->MemoryRead32(0x4054E0A0u +
                                   static_cast<uint32_t>(w) * 4u));
                cn += snprintf(cb + cn, sizeof(cb) - (size_t)cn, " SMI:");
                for (int w = 0; w < 4 && cn > 0; ++w)
                    cn += snprintf(cb + cn, sizeof(cb) - (size_t)cn, " %08X",
                                   g_w40_host->MemoryRead32(0x405694ACu +
                                   static_cast<uint32_t>(w) * 4u));
                cn += snprintf(cb + cn, sizeof(cb) - (size_t)cn, " SME:");
                for (int w = 0; w < 4 && cn > 0; ++w)
                    cn += snprintf(cb + cn, sizeof(cb) - (size_t)cn, " %08X",
                                   g_w40_host->MemoryRead32(0x40569B8Cu +
                                   static_cast<uint32_t>(w) * 4u));
                line += cb;
            // W411 (run548): Init_PostBZ veneer stub bytes + entry bytes of
            // Init_PostBZ and StateMachine_DoInit to verify patch integrity.
            {
                char vb[340];
                int vn = snprintf(vb, sizeof(vb), " W411 veneer:");
                for (int w = 0; w < 6 && vn > 0; ++w)
                    vn += snprintf(vb + vn, sizeof(vb) - (size_t)vn, " %08X",
                                   g_w40_host->MemoryRead32(0x8F113040u +
                                   static_cast<uint32_t>(w) * 4u));
                vn += snprintf(vb + vn, sizeof(vb) - (size_t)vn, " IPBZ:");
                for (int w = 0; w < 3 && vn > 0; ++w)
                    vn += snprintf(vb + vn, sizeof(vb) - (size_t)vn, " %08X",
                                   g_w40_host->MemoryRead32(0x40543B88u +
                                   static_cast<uint32_t>(w) * 4u));
                vn += snprintf(vb + vn, sizeof(vb) - (size_t)vn, " SMDI:");
                for (int w = 0; w < 3 && vn > 0; ++w)
                    vn += snprintf(vb + vn, sizeof(vb) - (size_t)vn, " %08X",
                                   g_w40_host->MemoryRead32(0x405694ACu +
                                   static_cast<uint32_t>(w) * 4u));
                line += vb;
            }
            }
                // W404b (run544): survive rotation -- persist the LM dump
                // only when the pointer is live (first non-zero catch).
                if (lm != 0) DiagTrace::NotePersist(std::string(lb, (size_t)ln2));
            }
            }
            }
            // W381 (run512): site/callee/mutex/counter state for the
            // marker-15 freeze: site patch words, callee entry, gfx mutex
            // recursion + lock word, marker-15 counter cell.
            {
                char fb[240];
                snprintf(fb, sizeof(fb),
                         " W381 site=%08X/%08X callee=%08X mtx_cnt=%d mtx=%08X m15cnt=%u",
                         g_w40_host->MemoryRead32(0x403DC070u),
                         g_w40_host->MemoryRead32(0x403DC074u),
                         g_w40_host->MemoryRead32(0x403F3CE8u),
                         static_cast<int32_t>(g_w40_host->MemoryRead32(0x406D95A8u)),
                         g_w40_host->MemoryRead32(0x406D95A4u),
                         g_w40_host->MemoryRead32(0x93001538u));
                line += fb;
            // W181 (run526): pool-table base comparison. W180 found the
            // LIVE table at 0x406C8490 while the file symbol is
            // dword_6DAE5C (0x406DAE5C). Dump the first words of both to
            // see which one InitMemorySystem actually populated.
            {
                char pb2[240];
                int pn = snprintf(pb2, sizeof(pb2), "W181TBL sym:");
                for (int w = 0; w < 4 && pn > 0; ++w)
                    pn += snprintf(pb2 + pn, sizeof(pb2) - (size_t)pn, " %08X",
                                   g_w40_host->MemoryRead32(0x406DAE5Cu +
                                   static_cast<uint32_t>(w) * 4u));
                pn += snprintf(pb2 + pn, sizeof(pb2) - (size_t)pn, " | rt:");
                for (int w = 0; w < 4 && pn > 0; ++w)
                    pn += snprintf(pb2 + pn, sizeof(pb2) - (size_t)pn, " %08X",
                                   g_w40_host->MemoryRead32(0x406C8490u +
                                   static_cast<uint32_t>(w) * 4u));
                line += pb2;
            }
            }
            }
                line += eb;
            }
            // W96 (run154): pauseGameThread(false) returned 0 yet the
            // PDStartup_0 pause loop kept spinning. Sample the guest flag
            // verbatim every tick so we can see whether the write lands.
            {
                const uint32_t flag = g_w40_host->MemoryRead32(0x40673288u) & 0xFFu;
                line += " paused_flag=" + std::to_string(flag);
            }
            // W141c (run189b): sample the LLMem alignment global
            // dword_67332C -- if zero/garbage under the bridge, the pool
            // bunch geometry breaks and the fill loops run away.
            {
                const uint32_t align = g_w40_host->MemoryRead32(0x4067332Cu);
                line += " llmem_align=" + std::to_string(align);
            }
            // W100: bz_StartInternal progress probe counters (bridge-allocated).
            {
                char wb[320];
                wb[0] = '\0';
                if (g_w100_counter_addr) {
                    snprintf(wb, sizeof(wb), " boot=[%u %u %u %u %u %u %u %u %u %u %u %u %u %u %u]",
                             g_w40_host->MemoryRead32(g_w100_counter_addr),
                             g_w40_host->MemoryRead32(g_w100_counter_addr + 4),
                             g_w40_host->MemoryRead32(g_w100_counter_addr + 8),
                             g_w40_host->MemoryRead32(g_w100_counter_addr + 12),
                             g_w40_host->MemoryRead32(g_w100_counter_addr + 16),
                             g_w40_host->MemoryRead32(g_w100_counter_addr + 20),
                             g_w40_host->MemoryRead32(g_w100_counter_addr + 24),
                             g_w40_host->MemoryRead32(g_w100_counter_addr + 28),
                             g_w40_host->MemoryRead32(g_w100_counter_addr + 32),
                             g_w40_host->MemoryRead32(g_w100_counter_addr + 36),
                             g_w40_host->MemoryRead32(g_w100_counter_addr + 40),
                             g_w40_host->MemoryRead32(g_w100_counter_addr + 44),
                             g_w40_host->MemoryRead32(g_w100_counter_addr + 48),
                             g_w40_host->MemoryRead32(g_w100_counter_addr + 52),
                             g_w40_host->MemoryRead32(g_w100_counter_addr + 56));
                }
                line += wb;
            }
            // W421 (run561): init-stage counters (W420 veneers) + smear-bank
            // watch. The stage cells name the deepest init stage entered;
            // the bank slice shows the 12-byte node-chain writer at work.
            {
                char s421[720];
                uint32_t veneer_bits = 0;
                {   // W430: live-veneer presence at tick time -- bit set =
                    // site still holds the E51FF004 veneer word.
                    const uint32_t sites[10] = {
                        0x403DAB14u, 0x403DB0FCu, 0x403DB118u, 0x403DBCB0u,
                        0x4054E0B8u, 0x4054E078u, 0x40543B88u, 0x40543B04u,
                        0x40543B38u, 0x4054E090u };
                    for (int sb = 0; sb < 10; ++sb)
                        if (g_w40_host->MemoryRead32(sites[sb]) == 0xE51FF004u)
                            veneer_bits |= (1u << sb);
                }
                int n421 = snprintf(s421, sizeof(s421),
                        "W421STAGE v=%03X am=%08X am2=%08X ipbz=%08X w258=%08X spin=%08X"
                        " msg=%08X epi=%08X lm=%08X lm0=%08X lm10=%08X"
                        " gae=%08X piped=%08X reach=%03X pass=%u boot#=%u iv=%08X p1a=%08X p1b=%08X p1c=%08X ps1=%08X ps2=%08X ps3=%08X smdi=%08X w377st=%08X bank:",

                        veneer_bits,
                        g_w40_host->MemoryRead32(0x93001710u),
                        g_w40_host->MemoryRead32(0x93001714u),
                        g_w40_host->MemoryRead32(0x93001718u),
                        g_w40_host->MemoryRead32(0x93001724u),
                        g_w40_host->MemoryRead32(0x40670900u),
                        g_w40_host->MemoryRead32(0x9300171Cu),
                        g_w40_host->MemoryRead32(0x93001720u),
                        g_w40_host->MemoryRead32(0x406D9538u),
                        g_w40_host->MemoryRead32(0x406D9544u),
                        g_w40_host->MemoryRead32(0x406D9548u),
                        g_w40_host->MemoryRead32(0x93001738u),
                        g_w40_host->MemoryRead32(0x9300173Cu),
                        g_w40_host->MemoryRead32(0x93001790u),
                        g_w40_host->MemoryRead32(0x930017A4u),
                        g_w40_host->MemoryRead32(0x930017A8u),
                        g_w40_host->MemoryRead32(0x930017ACu),
                        g_w40_host->MemoryRead32(0x40670900u) != 0 ?
                            g_w40_host->MemoryRead32(g_w40_host->MemoryRead32(0x40670900u)) : 0xDEAD0000u,
                        g_w40_host->MemoryRead32(0x93001748u),
                        g_w40_host->MemoryRead32(0x93001560u),
                        g_w40_host->MemoryRead32(0x93001570u),
                        g_w40_host->MemoryRead32(0x93001574u),
                        g_w40_host->MemoryRead32(0x93001564u),
                        g_w40_host->MemoryRead32(0x93001568u),
                        g_w40_host->MemoryRead32(0x9300156Cu));
                for (uint32_t a421 = 0x93001700u;
                     a421 <= 0x93001740u && n421 > 0 &&
                     static_cast<size_t>(n421) < sizeof(s421) - 16; a421 += 16)
                    n421 += snprintf(s421 + n421, sizeof(s421) - static_cast<size_t>(n421),
                                     " %08X", g_w40_host->MemoryRead32(a421));
                if (n421 < 0) n421 = 0;
                if (static_cast<size_t>(n421) >= sizeof(s421) - 16)
                    n421 = static_cast<int>(sizeof(s421)) - 17;
                n421 += snprintf(s421 + n421, sizeof(s421) - static_cast<size_t>(n421),
                                 " ps1site=%08X ps2site=%08X ps3site=%08X ps1stub=%08X %08X %08X %08X",
                                 g_w40_host->MemoryRead32(0x403DAB14u),
                                 g_w40_host->MemoryRead32(0x403DB0FCu),
                                 g_w40_host->MemoryRead32(0x403DB118u),
                                 g_w40_host->MemoryRead32(0x8F117200u),
                                 g_w40_host->MemoryRead32(0x8F117204u),
                                 g_w40_host->MemoryRead32(0x8F117208u),
                                 g_w40_host->MemoryRead32(0x8F11720Cu));
                for (int k421 = 0; k421 < 8 && n421 > 0 &&
                     static_cast<size_t>(n421) < sizeof(s421) - 16; ++k421)
                    n421 += snprintf(s421 + n421, sizeof(s421) - static_cast<size_t>(n421),
                                     " %08X",
                                     g_w40_host->MemoryRead32(0x93000150u +
                                     static_cast<uint32_t>(k421) * 12u));
                if (n421 < 0) n421 = 0;
                if (static_cast<size_t>(n421) >= sizeof(s421))
                    n421 = static_cast<int>(sizeof(s421)) - 1;
                DiagTrace::NotePersist(std::string(s421, (size_t)n421));
                // W464: Init_BZ check pointer dump
                {
                    char ib[128];
                    uint32_t p1 = g_w40_host->MemoryRead32(0x4066E388u);
                    uint32_t v1 = p1 ? g_w40_host->MemoryRead32(p1) : 0xDEAD0001u;
                    snprintf(ib, sizeof(ib), "W464 initbz_ptr=%08X initbz_val=%08X",
                             p1, v1);
                    DiagTrace::NotePersist(std::string(ib));
                }
            }
            // W122/W51b: bzd call/return + last LLMemCreateNewPool args.
            {
                char wb2[160];
                wb2[0] = '\0';
                snprintf(wb2, sizeof(wb2), " bzd=[%u ret=%08X] pool=[%u args %08X %08X %08X]",
                         g_w122_counter_addr ? g_w40_host->MemoryRead32(g_w122_counter_addr) : 0,
                         g_w122_counter_addr ? g_w40_host->MemoryRead32(g_w122_counter_addr + 4) : 0,
                         g_w40_host->MemoryRead32(0x0065CD60u),
                         g_w40_host->MemoryRead32(0x0065CD70u),
                         g_w40_host->MemoryRead32(0x0065CD74u),
                         g_w40_host->MemoryRead32(0x0065CD78u));
                line += wb2;
            }
            // W124: per-D_* step counters (the one that lags names the fail).
            {
                char wb3[256];
                wb3[0] = '\0';
                if (g_w124_counter_addr) {
                    snprintf(wb3, sizeof(wb3), " dyn=[%u %u %u %u %u %u %u %u %u %u]",
                             g_w40_host->MemoryRead32(g_w124_counter_addr),
                             g_w40_host->MemoryRead32(g_w124_counter_addr + 4),
                             g_w40_host->MemoryRead32(g_w124_counter_addr + 8),
                             g_w40_host->MemoryRead32(g_w124_counter_addr + 12),
                             g_w40_host->MemoryRead32(g_w124_counter_addr + 16),
                             g_w40_host->MemoryRead32(g_w124_counter_addr + 20),
                             g_w40_host->MemoryRead32(g_w124_counter_addr + 24),
                             g_w40_host->MemoryRead32(g_w124_counter_addr + 28),
                             g_w40_host->MemoryRead32(g_w124_counter_addr + 32),
                             g_w40_host->MemoryRead32(g_w124_counter_addr + 36));
                }
                line += wb3;
            }
            // W130: bridge heap state.
            line += g_w40_host->DiagHeapState();
            // W125: bzd entry count.
            {
                char wb4[64];
                wb4[0] = '\0';
                if (g_w125_counter_addr) {
                    snprintf(wb4, sizeof(wb4), " ent=%u",
                             g_w40_host->MemoryRead32(g_w125_counter_addr));
                }
                line += wb4;
            }
            // W128: last LLMemCreateNewPool alloc result (0 = alloc failed).
            {
                char wb5[64];
                wb5[0] = '\0';
                if (g_w128_counter_addr) {
                    snprintf(wb5, sizeof(wb5), " alloc=%08X",
                             g_w40_host->MemoryRead32(g_w128_counter_addr + 20));
                }
                line += wb5;
            }
            // W76: host-side window-ready flag write. PDStartup_0's spin
            // waits for [bzAndroidInfo+0x350] != 0. For any thread inside
            // PDStartup_0 (pc in range), write the live bridge window handle
            // into its r5-targeted flag — bypasses the message pipe entirely.
            // W76d: extensive diagnostics.
            {
                static std::atomic<uint32_t> w76d{0};
                bool w76_diag = (w76d.fetch_add(1) < 8);
                ANativeWindow* win = BridgeCurrentSurfaceWindow();
                if (w76_diag) {
                    char db[128];
                    snprintf(db, sizeof(db), "W76D win=%p handle=%u nthreads=%zu",
                             (void*)win, win ? GuestHandleFor(win) : 0, tpcs.size());
                    DiagTrace::NotePersist(db);
                }
                // W136 (run182): the r5-targeted write REMOVED -- a sampled
                // garbage r5 inside [0x40000000,0x80000000) turned this into
                // an arbitrary guest-memory writer (the pause flag at
                // 0x40673288 was among the victims). Diagnostics only now.
            }
            // W43: the WAD-mode globals that steer bz_StartScanningForFiles.
            // nsflags = [0x7AC0B0] = [WAD-singleton+0xCC]: bit1=!WADsFirst,
            // bit2=WADsOnly. wcount = [0x40700AF0].
            char wb[320];
            snprintf(wb, sizeof(wb), " paused=%u destroy=%u exc=%u proc=%u enter=%u "
                     "st1=%u st5=%u nf=%u si=%u aps=%u pa=%u pb=%u pc2=%u siarg=0x%08X pd0=%u pdarg=0x%08X aps70=%u r5x=0x%08X w71=%u w71lo=%u apslo=%u w72=0x%08X w77=0x%08X",
                     g_w40_host->MemoryRead32(0x40673288),
                     g_w40_host->MemoryRead32(0x50843C34),
                     g_w40_host->MemoryRead32(0x65CD50),
                     g_w40_host->MemoryRead32(0x65CD58),
                     g_w40_host->MemoryRead32(0x65CD5C),
                     g_w40_host->MemoryRead32(0x65CD80),
                     g_w40_host->MemoryRead32(0x65CD84),
                     g_w40_host->MemoryRead32(0x65CD88),
                     g_w40_host->MemoryRead32(0x65CD8C),
                     g_w40_host->MemoryRead32(0x65CD90),
                     g_w40_host->MemoryRead32(0x65CDA0),
                     g_w40_host->MemoryRead32(0x65CDA4),
                     g_w40_host->MemoryRead32(0x65CDA8),
                     g_w40_host->MemoryRead32(0x4065CD70),
                     g_w40_host->MemoryRead32(0x4065CD74),
                     g_w40_host->MemoryRead32(0x4065CD78),
                     g_w40_host->MemoryRead32(0x4065CDA4 + 12),
                     g_w40_host->MemoryRead32(0x65CDB4),
                     g_w40_host->MemoryRead32(0x65CDB4 + 12),
                     g_w40_host->MemoryRead32(0x65CDD0),
                     g_w40_host->MemoryRead32(0x65CDD4),
                     g_w40_host->MemoryRead32(0x65CDD8),
                     g_w40_host->MemoryRead32(0x65CDD8),
                     g_w40_host->MemoryRead32(0x65CDD0),
                     g_w40_host->MemoryRead32(0x4040D64C),
                     g_w40_host->MemoryRead32(0x4040DA8F8));
            // W136 (run182): W70's write REMOVED -- it wrote through
            // MemoryRead32(0x65CDD4)+0x350, a cell in the guest-corrupted
            // 0x65CDxx window, with NO range check: an arbitrary wild write
            // every 5 seconds (the pause flag at 0x40673288 was among the
            // victims). The window-ready flag is set by the guest's own
            // INIT_WINDOW handler.
            // W64 diag: the guest window-ready flag live
            {
                const uint32_t inst = g_w40_host->MemoryRead32(0x40672A68);
                const uint32_t info = inst ? g_w40_host->MemoryRead32(inst + 0xC) : 0;
                const uint32_t wf = info ? g_w40_host->MemoryRead32(info + 0x350) : 0xDEAD;
                char vb[64];
                snprintf(vb, sizeof(vb), " info=0x%08X winflag=%u", info, wf);
                line += vb;
            }
            line += wb;
            // W43b: runtime state of the encrypted asset-dir-name blob at
            // 0x40616B04 (PDStartScanningForFiles' openDir argument).
            static std::atomic<uint32_t> w43b{0};
            if (w43b.fetch_add(1) < 2) {
                line += " blob:";
                for (int w = 0; w < 8; ++w) {
                    snprintf(wb, sizeof(wb), " %08X",
                             g_w40_host->MemoryRead32(0x40616B04 + static_cast<uint32_t>(w) * 4));
                    line += wb;
                }
            }
            DiagTrace::NotePersist(line);
        }
        // W330 (run444): wild-writer watchpoint. The failing WAD-member
        // descriptor's address is published by W318 (0x000106D4). Each
        // tick dump its first 8 fields so the moment trap-page words
        // (0xEF000000/0xDF00DF00) appear can be correlated with boot time.
        if (g_w40_host) {
            const uint32_t fp = g_w40_host->MemoryRead32(0x000106D4u);
            if (fp >= 0x50000000u && fp < 0x7E000000u) {
                char wb6[240];
                int n6 = snprintf(wb6, sizeof(wb6), "W330 desc=%08X:", fp);
                for (int w = 0; w < 8 && n6 > 0 && (size_t)n6 < sizeof(wb6); ++w) {
                    n6 += snprintf(wb6 + n6, sizeof(wb6) - (size_t)n6, " %08X",
                                   g_w40_host->MemoryRead32(fp + (uint32_t)w * 4u));
                }
                DiagTrace::NotePersist(std::string(wb6, (size_t)n6));
            }
        }
        // W432PltHardenTick retired: rewriting PLT text from a watchdog races
        // Dynarmic translation and guest-side lazy binding.
        // W442/W445 RETIRED: force-clearing the EOR-lock word corrupts the
        // armcc lock protocol and SIGABRTs the boot (~30 s). The word at
        // 0x40670900 -> 0x4067CBF8 = the armcc dispatch iframe's own
        // "pending init" indicator; the iframe (0x4058DF18) loops processing
        // pending inits and clears the flag itself when the queue drains.
        // W335 (run448): GOT shadow + heal. The wild-writer poisons GOT
        // import slots (fseek slot = 0x4066E98C observed) causing jumps
        // into .data. Snapshot the plt GOT on the first tick; each tick,
        // restore any slot that drifted and name it.
        // W418GotHealNow retired; see the function comment above.

        // W347b (run460): stack snapshot of every "interesting" live guest
        // thread (PC not at the exit traps / thunk trampolines), fired from
        // the watchdog tick. run456: the boot's stall point vanished from
        // the W40PCS 12-thread cap; this dump names every remaining live
        // PC + LR + stack tail so the stall site is never invisible.
        if (g_w40_host && w347b_dump_count < 6) {
            auto tpcs2 = g_w40_host->SampleGuestThreadPcs();
            for (size_t i2 = 0; i2 < tpcs2.size(); ++i2) {
                const uint32_t pc2 = tpcs2[i2].pc;
                if (pc2 == 0x4u || pc2 == 0x8u || pc2 == 0x00010C78u || pc2 == 0x000108B8u)
                    continue;
                ++w347b_dump_count;
                char sb[260];
                int sn = snprintf(sb, sizeof(sb),
                                  "W347b tid=%u pc=%08X lr=%08X sp=%08X stk:",
                                  tpcs2[i2].tid, pc2, tpcs2[i2].lr, tpcs2[i2].sp);
                for (int w = 0; w < 10 && sn > 0 && (size_t)sn < sizeof(sb); ++w)
                    sn += snprintf(sb + sn, sizeof(sb) - (size_t)sn, " %08X",
                                   g_w40_host->MemoryRead32(tpcs2[i2].sp + (uint32_t)w * 4u));
                DiagTrace::NotePersist(std::string(sb, (size_t)sn));
                break;
            }
        }

        // W336 (run449): shadow+heal for .data.rel.ro function pointers.
        // W385 (run516): DISABLED. The snapshot-heal fights the game's
        // RUNTIME re-pointing of import/JUMP slots (NovaFile hooks,
        // bz_InstallFileIOHooks): every 5 s it restores stale boot-time
        // words (incl. neighbour pointers and instruction values) over
        // live slots -- run514/515 post-release exceptions at 0x40667260
        // / 0x4055FB34 fire exactly at heal boundaries. Runtime values
        // now stand; the drift log remains available via W336 history.
        if (false && g_w40_host && !g_dro_shadow.empty()) {
            for (size_t gi = 0; gi < g_dro_shadow.size(); ++gi) {
                const uint32_t slot = 0x4066A000u + (uint32_t)(gi * 4u);
                const uint32_t cur = g_w40_host->MemoryRead32(slot);
                if (cur != g_dro_shadow[gi]) {
                    g_w40_host->MemoryWrite32(slot, g_dro_shadow[gi]);
                    char gb2[128];
                    snprintf(gb2, sizeof(gb2), "W336DROFIX addr=%08X poisoned=%08X restored=%08X",
                             slot, cur, g_dro_shadow[gi]);
                    DiagTrace::NotePersist(std::string(gb2));
                    LOGE("%s", gb2);
                }
            }
        }
        std::lock_guard<std::mutex> lk(g_w40_mutex);
        const auto now = std::chrono::steady_clock::now();
        for (auto& kv : g_w40_active) {
            for (auto& d : kv.second) {
                const long long age_ms =
                    std::chrono::duration_cast<std::chrono::milliseconds>(now - d.t0).count();
                if (age_ms < 3000) continue;
                char b[160];
                snprintf(b, sizeof(b), "W40STUCK tid=%u thunk=%s pc=0x%08X lr=0x%08X age_ms=%lld",
                         kv.first, d.name.c_str(), d.pc, d.lr, age_ms);
                DiagTrace::NotePersist(b);
                d.t0 = now;  // re-report every 5 s while still parked
            }
        }
    }
}

// W335: boot-time GOT snapshot entry point (wrapper; the statics live in
// the anonymous namespace above).
}  // namespace
void SnapshotGotShadow(DynarmicHost& host) { SnapshotGotShadowImpl(host); }
void W418GotHealNow_public();
void W418GotHealNow_public() { W418GotHealNow(); }

void ThunkManager::DispatchThunk(uint32_t thunk_id, Dynarmic::A32::Jit& jit) {
    const auto* entry = thunk_id && thunk_id <= kMaxThunks
        ? m_dispatch[thunk_id - 1].load(std::memory_order_acquire) : nullptr;
    static const std::string kUnknownName = "unknown";
    const std::string& name = entry ? entry->name : kUnknownName;
    if (entry) {
        if (thunk_id == 160) {
            LOGE("[W524] id160 dispatched name=%s lr=%08X r0=%08X", name.c_str(), jit.Regs()[14], jit.Regs()[0]);
        }
        std::call_once(g_w40_watchdog_once, [this] {
            g_w40_host = &m_host;
            std::thread(W40WatchdogLoop).detach();
        });
#if BRIDGE_ENABLE_PER_CALL_TRACE
        // Only diagnostic builds record every call and track nested thunks.
        DiagTrace::Thunk(name.c_str(), jit.Regs()[14]);
        const uint32_t w40tid = static_cast<uint32_t>(gettid());
        // W105 (run159): a guest thread was seen dying on a foreign stack
        // (sp=0xC77D169E) without any pollAll in between. Name the FIRST
        // thunk executed outside the worker-stack window.
        {
            const uint32_t sp_chk = jit.Regs()[13];
            static std::atomic<uint32_t> w105_flips{0};
            if ((sp_chk < 0x7E000000u || sp_chk >= 0x93000000u) &&
                w105_flips.fetch_add(1) < 32) {
                char b[160];
                snprintf(b, sizeof(b),
                         "W105STACK thunk=%s tid=%u n=%u sp=%08X lr=%08X pc=%08X r4=%08X",
                         name.c_str(), w40tid, w105_flips.load(), sp_chk,
                         jit.Regs()[14], jit.Regs()[15], jit.Regs()[4]);
                DiagTrace::NotePersist(b);
            }
        }
        g_w40_mutex.lock();
        g_w40_active[w40tid].push_back(
            {name, jit.Regs()[15], jit.Regs()[14], std::chrono::steady_clock::now()});
        g_w40_mutex.unlock();
#endif
        try { entry->handler(jit, m_host); }
        catch (const std::exception& error) {
            LOGE("[THUNK] %s: %s", name.c_str(), error.what());
            char b[224];
            snprintf(b, sizeof(b), "THUNK-FAULT kind=std name=%s id=%u tid=%u pc=%08X lr=%08X sp=%08X",
                     name.c_str(), thunk_id, static_cast<uint32_t>(gettid()), jit.Regs()[15],
                     jit.Regs()[14], jit.Regs()[13]);
            DiagTrace::NotePersist(b);
            jit.Regs()[0] = 0xFFFFFFFFu;
            jit.HaltExecution(Dynarmic::HaltReason::UserDefined1);
        } catch (...) {
            LOGE("[THUNK] exception in %s", name.c_str());
            char b[224];
            snprintf(b, sizeof(b), "THUNK-FAULT kind=unknown name=%s id=%u tid=%u pc=%08X lr=%08X sp=%08X",
                     name.c_str(), thunk_id, static_cast<uint32_t>(gettid()), jit.Regs()[15],
                     jit.Regs()[14], jit.Regs()[13]);
            DiagTrace::NotePersist(b);
            jit.Regs()[0] = 0xFFFFFFFFu;
            jit.HaltExecution(Dynarmic::HaltReason::UserDefined1);
        }
#if BRIDGE_ENABLE_PER_CALL_TRACE
        g_w40_mutex.lock();
        auto w40it = g_w40_active.find(w40tid);
        if (w40it != g_w40_active.end() && !w40it->second.empty())
            w40it->second.pop_back();
        if (w40it != g_w40_active.end() && w40it->second.empty())
            g_w40_active.erase(w40it);
        g_w40_mutex.unlock();
#endif
    } else {
        LOGE("[THUNK] Unknown thunk ID: %u (%s) at PC: 0x%08X", thunk_id, name.c_str(), jit.Regs()[15]);
        char b[224];
        snprintf(b, sizeof(b), "THUNK-FAULT kind=unmapped name=%s id=%u tid=%u pc=%08X lr=%08X sp=%08X",
                 name.c_str(), thunk_id, static_cast<uint32_t>(gettid()), jit.Regs()[15],
                 jit.Regs()[14], jit.Regs()[13]);
        DiagTrace::NotePersist(b);
        if (thunk_id == 0x00113200u || jit.Regs()[15] == 0x403F705Cu) {
            snprintf(b, sizeof(b), "THUNK-FAULT W199 code=%08X/%08X/%08X/%08X/%08X/%08X site=%08X/%08X",
                     m_host.MemoryRead32(0x8F113200u), m_host.MemoryRead32(0x8F113204u),
                     m_host.MemoryRead32(0x8F113208u), m_host.MemoryRead32(0x8F11320Cu),
                     m_host.MemoryRead32(0x8F113210u), m_host.MemoryRead32(0x8F113214u),
                     m_host.MemoryRead32(0x403F7054u), m_host.MemoryRead32(0x403F7058u));
            DiagTrace::NotePersist(b);
            snprintf(b, sizeof(b), "THUNK-FAULT W199+18=%08X/%08X/%08X/%08X/%08X/%08X/%08X/%08X",
                     m_host.MemoryRead32(0x8F113218u), m_host.MemoryRead32(0x8F11321Cu),
                     m_host.MemoryRead32(0x8F113220u), m_host.MemoryRead32(0x8F113224u),
                     m_host.MemoryRead32(0x8F113228u), m_host.MemoryRead32(0x8F11322Cu),
                     m_host.MemoryRead32(0x8F113230u), m_host.MemoryRead32(0x8F113234u));
            DiagTrace::NotePersist(b);
        }
        jit.Regs()[0] = 0xFFFFFFFFu;
        jit.HaltExecution(Dynarmic::HaltReason::UserDefined1);
    }
}
