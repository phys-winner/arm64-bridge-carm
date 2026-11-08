#include <android/asset_manager.h>
#include <android/log.h>
#include <android/native_activity.h>
#include <android/native_window.h>
#include <android/native_window_jni.h>
#include <jni.h>

#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <EGL/egl.h>
#include <vector>

#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "diag_trace.h"
#include "dynarmic_host.h"
#include "elf_loader.h"
#include "jni_fake_env.h"
#include "native_handle_table.h"
#include "obb_source.h"
#include "thunk_manager.h"
#include "thunk_types.h"

#define LOG_TAG "Arm32Bridge_JNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// defined in thunks_libc.cpp at global scope -- these forward declarations
// stay outside the anonymous namespace below.
void InstallFopenDiagDumper(DynarmicHost& host);
void InstallThrowLenDumper(DynarmicHost& host);
void InstallCpuCountStub(DynarmicHost& host);
void InstallWadParseMarkers(DynarmicHost& host);
std::string BridgeEglDiagnosticSnapshot();
std::string BridgeInputDiagnosticSnapshot();

// W477: EGL display/config state initialized on a dedicated non-JIT thread
// (definitions at file scope below the anonymous namespace -- these are
// consumed by thunks_egl.cpp, so they need external linkage).
namespace BridgeEgl477 {
bool DisplayReady();
bool ThreadDone();
bool Failed();
EGLDisplay Display();
EGLConfig Config();
EGLSurface Surface();
EGLContext Context();
EGLint MajorVer();
EGLint MinorVer();
}

void W541Install(DynarmicHost& host);  // W541 (thunks_libc.cpp)
namespace {
JavaVM* g_jvm = nullptr;
std::unique_ptr<DynarmicHost> g_host;
std::mutex g_boot_mutex;
std::string g_apk_path;
std::string g_files_path;
uint32_t g_guest_activity = 0;
uint32_t g_guest_callbacks = 0;
std::atomic_bool g_guest_activity_instance_ready{false};
std::atomic<uint32_t> g_last_guest_window_created{0};
std::atomic<AInputQueue*> g_host_input_queue{nullptr};
std::atomic<uint32_t> g_last_guest_input_queue_created{0};
struct InputQueueGeneration {
    uint64_t number = 0;
    AInputQueue* queue = nullptr;
    uint32_t guest_handle = 0;
    bool create_scheduled = false;
    bool create_started = false;
    bool create_finished = false;
    bool create_acked = false;
    bool destroy_requested = false;
    bool destroy_finished = false;
};
std::mutex g_input_queue_mutex;
std::condition_variable g_input_queue_cv;
std::shared_ptr<InputQueueGeneration> g_input_queue_current;
uint64_t g_next_input_queue_generation = 1;
bool g_input_guest_ready = false;
std::mutex g_content_rect_mutex;
ARect g_pending_content_rect{};
bool g_have_content_rect = false;
std::atomic_bool g_initial_unpause_scheduled{false};
std::atomic_bool g_startup_gate_armed{false};
std::atomic<uint32_t> g_startup_gate_stage{0};
std::atomic<uint32_t> g_startup_gate_app{0};
std::atomic<int64_t> g_last_back_press_ms{0};
ANativeWindow* g_bridge_surface_window = nullptr;

ANativeActivity* g_host_activity = nullptr;
std::mutex g_bridge_surface_mutex;

constexpr uint32_t kCallbackCount = 16;
constexpr uint32_t kActivityCallbacks = 0x00;
constexpr uint32_t kActivityVm = 0x04;
constexpr uint32_t kActivityEnv = 0x08;
constexpr uint32_t kActivityClass = 0x0c;
constexpr uint32_t kActivityInternalPath = 0x10;
constexpr uint32_t kActivityExternalPath = 0x14;
constexpr uint32_t kActivitySdkVersion = 0x18;
constexpr uint32_t kActivityInstance = 0x1c;
constexpr uint32_t kActivityAssetManager = 0x20;
constexpr uint32_t kActivityObbPath = 0x24;
constexpr uint32_t kActivitySize = 0x28;

enum CallbackSlot {
    kOnStart = 0,
    kOnResume,
    kOnSaveInstanceState,
    kOnPause,
    kOnStop,
    kOnDestroy,
    kOnWindowFocusChanged,
    kOnNativeWindowCreated,
    kOnNativeWindowResized,
    kOnNativeWindowRedrawNeeded,
    kOnNativeWindowDestroyed,
    kOnInputQueueCreated,
    kOnInputQueueDestroyed,
    kOnContentRectChanged,
    kOnConfigurationChanged,
    kOnLowMemory,
};

JavaVM* GetHostJavaVM() { return g_jvm; }

const char* GuestString(DynarmicHost& host, uint32_t address) {
    if (!address || !GuestRangeValid(host.GetGuestMemorySize(), address, 1)) return nullptr;
    const size_t remaining = host.GetGuestMemorySize() - address;
    const char* value = reinterpret_cast<const char*>(host.GetGuestMemoryBase() + address);
    return memchr(value, 0, remaining) ? value : nullptr;
}

uint32_t GuestStringRef(JNIEnv* env, jobject value) {
    if (!value || !g_host) return 0;
    FakeJniEnv& fake = FakeJniEnv::Instance();
    fake.AttachHostEnv(env);
    return fake.AddObjectRef(value);
}

uint32_t GuestClassRef(JNIEnv* env, jclass value) {
    if (!value || !g_host) return 0;
    FakeJniEnv& fake = FakeJniEnv::Instance();
    fake.AttachHostEnv(env);
    return fake.AddObjectRef(value);
}

std::string ApplicationSourceDir(ANativeActivity* activity) {
    if (!activity || !activity->env || !activity->clazz) return {};
    JNIEnv* env = activity->env;
    jclass activity_class = env->GetObjectClass(activity->clazz);
    jmethodID get_info = activity_class
        ? env->GetMethodID(activity_class, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;")
        : nullptr;
    jobject info = get_info ? env->CallObjectMethod(activity->clazz, get_info) : nullptr;
    jclass info_class = info ? env->GetObjectClass(info) : nullptr;
    jfieldID source_field = info_class ? env->GetFieldID(info_class, "sourceDir", "Ljava/lang/String;") : nullptr;
    jstring source = source_field ? static_cast<jstring>(env->GetObjectField(info, source_field)) : nullptr;
    std::string result;
    if (source) {
        const char* text = env->GetStringUTFChars(source, nullptr);
        if (text) {
            result = text;
            env->ReleaseStringUTFChars(source, text);
        }
    }
    if (env->ExceptionCheck()) env->ExceptionClear();
    return result;
}

struct GuestElfMapping {
    const char* path = nullptr;
    uint32_t guest_base = 0;
    int fd = -1;
    void* mapped_base = MAP_FAILED;
    size_t mapped_span = 0;
    const uint8_t* data = nullptr;
    size_t size = 0;

    ~GuestElfMapping() {
        if (mapped_base != MAP_FAILED) {
            if (::munmap(mapped_base, mapped_span) == 0) {
                LOGI("guest munmap: asset=assets/%s fd=%d span=%zu", path ? path : "", fd, mapped_span);
            } else {
                LOGE("guest munmap failed: asset=assets/%s fd=%d span=%zu errno=%d",
                     path ? path : "", fd, mapped_span, errno);
            }
        }
        if (fd >= 0) close(fd);
    }

    bool Open(AAssetManager* manager, const char* relative_name, uint32_t target_guest_base) {
        path = relative_name;
        guest_base = target_guest_base;
        if (!manager || !relative_name) return false;

        AAsset* asset = AAssetManager_open(manager, relative_name, AASSET_MODE_RANDOM);
        if (!asset) {
            LOGE("guest asset open failed: assets/%s", relative_name);
            return false;
        }

        off64_t asset_offset = 0;
        off64_t asset_length = 0;
        const int source_fd = AAsset_openFileDescriptor64(asset, &asset_offset, &asset_length);
        if (source_fd < 0) {
            LOGE("guest asset is not direct-mappable (compressed or unavailable): assets/%s", relative_name);
            AAsset_close(asset);
            return false;
        }

        auto close_asset = [&] {
            AAsset_close(asset);
            // AAsset_close owns this descriptor on some platform releases and leaves it
            // open on others; probe before closing so neither case leaks or double-closes.
            if (fcntl(source_fd, F_GETFD) >= 0) close(source_fd);
        };

        fd = dup(source_fd);
        if (fd < 0) {
            LOGE("guest asset dup failed: assets/%s errno=%d", relative_name, errno);
            close_asset();
            return false;
        }

        struct stat apk_stat{};
        const bool stat_ok = fstat(fd, &apk_stat) == 0;
        const uint64_t file_size = stat_ok && apk_stat.st_size >= 0
            ? static_cast<uint64_t>(apk_stat.st_size) : 0;
        const uint64_t offset = asset_offset >= 0 ? static_cast<uint64_t>(asset_offset) : 0;
        const uint64_t length = asset_length > 0 ? static_cast<uint64_t>(asset_length) : 0;
        if (!stat_ok || asset_offset < 0 || asset_length <= 0 || offset > file_size || length > file_size - offset ||
            length > std::numeric_limits<size_t>::max()) {
            LOGE("guest asset fstat/range failed: assets/%s fd=%d offset=%lld size=%lld apk_size=%lld errno=%d",
                 relative_name, fd, static_cast<long long>(asset_offset), static_cast<long long>(asset_length),
                 static_cast<long long>(apk_stat.st_size), errno);
            close_asset();
            return false;
        }

        const long raw_page = sysconf(_SC_PAGESIZE);
        if (raw_page <= 0 || (raw_page & (raw_page - 1)) != 0) {
            LOGE("guest asset mmap has invalid page size: %ld", raw_page);
            close_asset();
            return false;
        }
        const size_t page = static_cast<size_t>(raw_page);
        const off64_t aligned_offset = asset_offset - (asset_offset % static_cast<off64_t>(page));
        const size_t bias = static_cast<size_t>(asset_offset - aligned_offset);
        if (bias > std::numeric_limits<size_t>::max() - static_cast<size_t>(length)) {
            LOGE("guest asset mmap span overflow: assets/%s", relative_name);
            close_asset();
            return false;
        }
        const size_t unaligned_span = bias + static_cast<size_t>(length);
        if (unaligned_span > std::numeric_limits<size_t>::max() - (page - 1)) {
            LOGE("guest asset mmap alignment overflow: assets/%s", relative_name);
            close_asset();
            return false;
        }
        mapped_span = (unaligned_span + page - 1) & ~(page - 1);
        mapped_base = ::mmap(nullptr, mapped_span, PROT_READ, MAP_PRIVATE, fd, aligned_offset);
        if (mapped_base == MAP_FAILED) {
            LOGE("guest asset mmap failed: assets/%s fd=%d offset=%lld span=%zu errno=%d",
                 relative_name, fd, static_cast<long long>(aligned_offset), mapped_span, errno);
            mapped_span = 0;
            close_asset();
            return false;
        }

        data = static_cast<const uint8_t*>(mapped_base) + bias;
        size = static_cast<size_t>(length);
        LOGI("guest mmap: asset=assets/%s fd=%d offset=%lld size=%lld fstat=%lld -> guest 0x%08X",
             relative_name, fd, static_cast<long long>(asset_offset), static_cast<long long>(asset_length),
             static_cast<long long>(apk_stat.st_size), guest_base);
        close_asset();
        return true;
    }
};

extern "C" int IndexApk(const char* apk_path);

bool EnsureGameLoaded(JNIEnv* env, AAssetManager* assets, const char* obb_directory) {
    std::lock_guard<std::mutex> lock(g_boot_mutex);
    if (g_host) return true;
    if (g_apk_path.empty() || !assets) return false;
    if (!BridgeInitializeObbSource(assets, obb_directory)) {
        LOGE("guest boot refused: neither embedded nor external whole OBB validated");
        return false;
    }
    if (BridgeObbGuestPath().empty()) {
        LOGE("guest boot refused: Android supplied no application OBB directory");
        return false;
    }

    auto host = std::make_unique<DynarmicHost>();
    if (!host->Initialize()) return false;
    if (IndexApk(g_apk_path.c_str()) != 0) {
        LOGE("failed to index APK for guest asset VFS: %s", g_apk_path.c_str());
        return false;
    }

    GuestElfMapping fmodex, fmodex_l, fmodevent, fmodevent_l, parsons;
    const bool mapped =
        fmodex.Open(assets, "guest_libs/libfmodex.so", DynarmicHost::kGuestFmodexBase) &&
        fmodex_l.Open(assets, "guest_libs/libfmodexL.so", DynarmicHost::kGuestFmodexLBase) &&
        fmodevent.Open(assets, "guest_libs/libfmodevent.so", DynarmicHost::kGuestFmodeventBase) &&
        fmodevent_l.Open(assets, "guest_libs/libfmodeventL.so", DynarmicHost::kGuestFmodeventLBase) &&
        parsons.Open(assets, "guest_libs/libParsons.so", DynarmicHost::kGuestGameBase);
    if (!mapped || !host->LoadAllLibrariesFromMemory(
            fmodex.data, fmodex.size, fmodex_l.data, fmodex_l.size,
            fmodevent.data, fmodevent.size, fmodevent_l.data, fmodevent_l.size,
            parsons.data, parsons.size)) {
        LOGE("guest libraries failed to load from direct APK mappings");
        return false;
    }
    g_host = std::move(host);
    FakeJniEnv& fake = FakeJniEnv::Instance();
    fake.SetJavaVM(g_jvm);
    fake.Init(*g_host);
    fake.AttachHostEnv(env);
    return true;
}

uint32_t GuestNative(const char* symbol, JNIEnv* env, jclass clazz,
                     const std::vector<uint32_t>& arguments) {
    if (!g_host || !symbol) return 0;
    const uint32_t entry = g_host->FindSymbol(symbol);
    if (!entry) {
        LOGE("guest native symbol not found: %s", symbol);
        return 0;
    }
    FakeJniEnv& fake = FakeJniEnv::Instance();
    fake.AttachHostEnv(env);
    std::vector<uint32_t> args = {fake.EnvTableGuestAddr(), GuestClassRef(env, clazz)};
    args.insert(args.end(), arguments.begin(), arguments.end());
    return g_host->RunFunction(entry, args);
}

uint32_t GuestFmodNativeInstance(const char* symbol, JNIEnv* env, jobject object,
                                 const std::vector<uint32_t>& arguments) {
    if (!g_host || !symbol) return 0;
    // The game is relocated against libfmodexL, not libfmodex.  The two
    // libraries have separate FMOD globals; asking the latter for mixer state
    // reports an uninitialised audio device even after the game starts sound.
    ElfLoader* fmod = g_host->GetFmodExLLoader();
    const uint32_t entry = fmod ? fmod->GetSymbolAddress(symbol) : 0;
    if (!entry) {
        LOGE("guest native symbol not found: %s", symbol);
        return 0;
    }
    FakeJniEnv& fake = FakeJniEnv::Instance();
    fake.AttachHostEnv(env);
    std::vector<uint32_t> args = {fake.EnvTableGuestAddr(), GuestStringRef(env, object)};
    args.insert(args.end(), arguments.begin(), arguments.end());
    return g_host->RunFunction(entry, args);
}

jstring GuestStringResult(JNIEnv* env, uint32_t handle) {
    if (!handle) return nullptr;
    return static_cast<jstring>(FakeJniEnv::Instance().ResolveObject(handle));
}

jstring Native_AnalyticsSaltAndHashMacResult(JNIEnv* env, jclass clazz, jstring value) {
    return GuestStringResult(env, GuestNative("Java_com_stainlessgames_carmageddon_NativeFunctions_analyticsSaltAndHashMac", env, clazz, {GuestStringRef(env, value)}));
}

jboolean Native_CloseObbFile(JNIEnv* env, jclass clazz) {
    return GuestNative("Java_com_stainlessgames_carmageddon_NativeFunctions_closeObbFile", env, clazz, {}) ? JNI_TRUE : JNI_FALSE;
}

jboolean Native_FlushData(JNIEnv* env, jclass clazz, jbyteArray data, jint length) {
    return GuestNative("Java_com_stainlessgames_carmageddon_NativeFunctions_flushData", env, clazz, {GuestStringRef(env, data), static_cast<uint32_t>(length)}) ? JNI_TRUE : JNI_FALSE;
}

jstring Native_GetLocalizedString(JNIEnv* env, jclass clazz, jstring key) {
    return GuestStringResult(env, GuestNative("Java_com_stainlessgames_carmageddon_NativeFunctions_getLocalizedString", env, clazz, {GuestStringRef(env, key)}));
}

jint Native_GetMarketDefine(JNIEnv* env, jclass clazz) {
    return static_cast<jint>(GuestNative("Java_com_stainlessgames_carmageddon_NativeFunctions_getMarketDefine", env, clazz, {}));
}

jint Native_GetPublicBuildDefine(JNIEnv* env, jclass clazz) {
    return static_cast<jint>(GuestNative("Java_com_stainlessgames_carmageddon_NativeFunctions_getPublicBuildDefine", env, clazz, {}));
}

jboolean Native_IsObbFileAlreadyFlushed(JNIEnv* env, jclass clazz, jstring path) {
    return GuestNative("Java_com_stainlessgames_carmageddon_NativeFunctions_isObbFileAlreadyFlushed", env, clazz, {GuestStringRef(env, path)}) ? JNI_TRUE : JNI_FALSE;
}

void Native_VoidString(JNIEnv* env, jclass clazz, jstring value, const char* symbol) {
    GuestNative(symbol, env, clazz, {GuestStringRef(env, value)});
}

void Native_Void(JNIEnv* env, jclass clazz, const char* symbol) {
    GuestNative(symbol, env, clazz, {});
}

void Native_OnKeyboardCanceled(JNIEnv* env, jclass clazz) { Native_Void(env, clazz, "Java_com_stainlessgames_carmageddon_NativeFunctions_onKeyboardCanceled"); }
void Native_OnPurchaseTimedOut(JNIEnv* env, jclass clazz) { Native_Void(env, clazz, "Java_com_stainlessgames_carmageddon_NativeFunctions_onPurchaseTimedOut"); }
void Native_OnPurchaseAccepted(JNIEnv* env, jclass clazz, jstring value) { Native_VoidString(env, clazz, value, "Java_com_stainlessgames_carmageddon_NativeFunctions_onPurchaseAccepted"); }
void Native_OnPurchaseCancelled(JNIEnv* env, jclass clazz, jstring value) { Native_VoidString(env, clazz, value, "Java_com_stainlessgames_carmageddon_NativeFunctions_onPurchaseCancelled"); }
void Native_OnPurchaseRestored(JNIEnv* env, jclass clazz, jstring value) { Native_VoidString(env, clazz, value, "Java_com_stainlessgames_carmageddon_NativeFunctions_onPurchaseRestored"); }
void Native_OnPurchaseSuccesful(JNIEnv* env, jclass clazz, jstring value) { Native_VoidString(env, clazz, value, "Java_com_stainlessgames_carmageddon_NativeFunctions_onPurchaseSuccesful"); }
void Native_OnPurchaseUnSuccesful(JNIEnv* env, jclass clazz, jstring value) { Native_VoidString(env, clazz, value, "Java_com_stainlessgames_carmageddon_NativeFunctions_onPurchaseUnSuccesful"); }

jboolean Native_OpenObbFile(JNIEnv* env, jclass clazz, jstring path) {
    return GuestNative("Java_com_stainlessgames_carmageddon_NativeFunctions_openObbFile", env, clazz, {GuestStringRef(env, path)}) ? JNI_TRUE : JNI_FALSE;
}

void Native_PauseGameThread(JNIEnv* env, jclass clazz, jboolean pause) {
    if (pause == JNI_FALSE && g_startup_gate_armed.load(std::memory_order_acquire)) {
        static std::atomic<uint32_t> held_unpause_notes{0};
        if (held_unpause_notes.fetch_add(1, std::memory_order_relaxed) < 4)
            DiagTrace::NotePersist("startup gate held Java pauseGameThread(false)");
        LOGI("pauseGameThread(false) held until guest startup handshake completes");
        return;
    }
    if (g_host) {
        LOGI("pauseGameThread lookup=0x%08X", g_host->FindSymbol("Java_com_stainlessgames_carmageddon_NativeFunctions_pauseGameThread"));
    }
    if (pause == JNI_FALSE && g_host && g_jvm && !g_initial_unpause_scheduled.exchange(true)) {
        jclass keep_class = clazz ? static_cast<jclass>(env->NewGlobalRef(clazz)) : nullptr;
        JavaVM* vm = g_jvm;
        std::thread([vm, keep_class] {
            JNIEnv* thread_env = nullptr;
            if (vm->AttachCurrentThread(&thread_env, nullptr) != JNI_OK) return;
            if (g_startup_gate_armed.load(std::memory_order_acquire)) {
                DiagTrace::NotePersist("startup gate held deferred Java pauseGameThread(false)");
            } else {
                GuestNative("Java_com_stainlessgames_carmageddon_NativeFunctions_pauseGameThread",
                            thread_env, keep_class, {0u});
            }
            // W96 (run154): mark the unpause call's completion and the flag
            // state it left behind.
            if (g_host) {
                char b[96];
                snprintf(b, sizeof(b), "W96PGT done flag=%u",
                         g_host->MemoryRead32(0x40673288u) & 0xFFu);
                DiagTrace::NotePersist(b);
            }
            if (keep_class) thread_env->DeleteGlobalRef(keep_class);
            vm->DetachCurrentThread();
        }).detach();
        LOGI("pauseGameThread(false) deferred off Android main thread");
        return;
    }
    GuestNative("Java_com_stainlessgames_carmageddon_NativeFunctions_pauseGameThread", env, clazz,
                {pause == JNI_TRUE ? 1u : 0u});
}

void Native_BridgeBack(JNIEnv*, jclass) {
    if (!g_host) return;
    // android_handle_input maps KEYCODE_BACK to the game's keyboard key 54.
    // Set that same key in the original input buffer so the game's own PAUSE
    // and menu BACK bindings handle both system gestures and hardware Back.
    constexpr uint32_t kKeyboardPointer = DynarmicHost::kGuestGameBase + 0x6CBE9Cu;
    constexpr uint32_t kKeyStatesOffset = 1636u;
    constexpr uint32_t kBackKeyOffset = 8u * 54u;
    const uint32_t keyboard = g_host->MemoryRead32(kKeyboardPointer);
    const uint32_t key_states = keyboard ? g_host->MemoryRead32(keyboard + kKeyStatesOffset) : 0;
    if (!key_states) return;

    const int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    const int64_t previous_ms = g_last_back_press_ms.exchange(now_ms);
    if (now_ms - previous_ms < 180) return;

    DynarmicHost* host = g_host.get();
    const uint32_t key = key_states + kBackKeyOffset;
    host->MemoryWrite8(key, host->MemoryRead8(key) | 1u);
    std::thread([host, key_states, key] {
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
        const uint32_t keyboard_now = host->MemoryRead32(kKeyboardPointer);
        if (keyboard_now && host->MemoryRead32(keyboard_now + kKeyStatesOffset) == key_states)
            host->MemoryWrite8(key, host->MemoryRead8(key) & ~1u);
    }).detach();
}

void Native_BridgeSurfaceCreated(JNIEnv* env, jclass clazz, jobject surface);
void Native_BridgeSurfaceChanged(JNIEnv* env, jclass clazz, jobject surface);
void Native_BridgeSurfaceDestroyed(JNIEnv* env, jclass clazz);

void Native_SendKeyboardInput(JNIEnv* env, jclass clazz, jstring value) {
    Native_VoidString(env, clazz, value, "Java_com_stainlessgames_carmageddon_NativeFunctions_sendKeyboardInput");
}

jint Native_FmodGetInfo(JNIEnv* env, jobject object, jint info) {
    const jint raw = static_cast<jint>(GuestFmodNativeInstance(
        "Java_org_fmod_FMODAudioDevice_fmodGetInfo", env, object,
        {static_cast<uint32_t>(info)}));
    // Zero means FMOD has not initialised the mixer yet.  Never invent a
    // sample rate or MIXERRUNNING=1: doing so starts AudioTrack on silence.
    const bool valid = (info == 0) ? (raw == 0 || (raw >= 8000 && raw <= 192000))
                     : (info == 1) ? (raw == 0 || (raw >= 64 && raw <= 16384))
                     : (info == 2) ? (raw >= 0 && raw <= 16)
                     : (info == 3) ? (raw == 0 || raw == 1)
                     : false;
    if (!valid) {
        LOGE("FMOD fmodGetInfo(%d) rejected invalid value %d", info, raw);
        return 0;
    }
    static std::atomic<uint32_t> info_notes{0};
    if (raw && info_notes.fetch_add(1, std::memory_order_relaxed) < 12)
        LOGI("FMOD fmodGetInfo(%d)=%d", info, raw);
    return raw;
}

jint Native_FmodProcess(JNIEnv* env, jobject object, jobject buffer) {
    if (!g_host || !buffer) return 0;
    ElfLoader* fmod = g_host->GetFmodExLLoader();
    const uint32_t entry = fmod ? fmod->GetSymbolAddress("Java_org_fmod_FMODAudioDevice_fmodProcess") : 0;
    if (!entry) {
        LOGE("guest FMOD fmodProcess symbol not found in libfmodexL");
        return 0;
    }
    FakeJniEnv& fake = FakeJniEnv::Instance();
    fake.AttachHostEnv(env);
    const uint32_t buffer_handle = fake.RegisterDirectBuffer(buffer);
    if (!buffer_handle) return 0;
    const jint result = static_cast<jint>(g_host->RunFunction(
        entry, {fake.EnvTableGuestAddr(), GuestStringRef(env, object), buffer_handle}));
    fake.CommitDirectBuffer(buffer_handle);
    return result;
}

std::string ApplicationObbDirectory(JNIEnv* env, jobject activity) {
    if (!env || !activity) return {};
    jclass activity_class = env->GetObjectClass(activity);
    jmethodID get_dir = activity_class
        ? env->GetMethodID(activity_class, "getObbDir", "()Ljava/io/File;") : nullptr;
    jobject directory = get_dir ? env->CallObjectMethod(activity, get_dir) : nullptr;
    jclass file_class = directory ? env->GetObjectClass(directory) : nullptr;
    jmethodID get_path = file_class
        ? env->GetMethodID(file_class, "getAbsolutePath", "()Ljava/lang/String;") : nullptr;
    jstring path = get_path
        ? static_cast<jstring>(env->CallObjectMethod(directory, get_path)) : nullptr;
    std::string result;
    if (path && !env->ExceptionCheck()) {
        const char* utf8 = env->GetStringUTFChars(path, nullptr);
        if (utf8) {
            result = utf8;
            env->ReleaseStringUTFChars(path, utf8);
        }
    }
    if (env->ExceptionCheck()) { env->ExceptionClear(); result.clear(); }
    if (path) env->DeleteLocalRef(path);
    if (file_class) env->DeleteLocalRef(file_class);
    if (directory) env->DeleteLocalRef(directory);
    if (activity_class) env->DeleteLocalRef(activity_class);
    return result;
}

const JNINativeMethod kFmodAudioMethods[] = {
    {"fmodGetInfo", "(I)I", reinterpret_cast<void*>(Native_FmodGetInfo)},
    {"fmodProcess", "(Ljava/nio/ByteBuffer;)I", reinterpret_cast<void*>(Native_FmodProcess)},
};

const JNINativeMethod kNativeFunctions[] = {
    {"analyticsSaltAndHashMac", "(Ljava/lang/String;)Ljava/lang/String;", reinterpret_cast<void*>(Native_AnalyticsSaltAndHashMacResult)},
    {"closeObbFile", "()Z", reinterpret_cast<void*>(Native_CloseObbFile)},
    {"flushData", "([BI)Z", reinterpret_cast<void*>(Native_FlushData)},
    {"getLocalizedString", "(Ljava/lang/String;)Ljava/lang/String;", reinterpret_cast<void*>(Native_GetLocalizedString)},
    {"getMarketDefine", "()I", reinterpret_cast<void*>(Native_GetMarketDefine)},
    {"getPublicBuildDefine", "()I", reinterpret_cast<void*>(Native_GetPublicBuildDefine)},
    {"isObbFileAlreadyFlushed", "(Ljava/lang/String;)Z", reinterpret_cast<void*>(Native_IsObbFileAlreadyFlushed)},
    {"onKeyboardCanceled", "()V", reinterpret_cast<void*>(Native_OnKeyboardCanceled)},
    {"onPurchaseAccepted", "(Ljava/lang/String;)V", reinterpret_cast<void*>(Native_OnPurchaseAccepted)},
    {"onPurchaseCancelled", "(Ljava/lang/String;)V", reinterpret_cast<void*>(Native_OnPurchaseCancelled)},
    {"onPurchaseRestored", "(Ljava/lang/String;)V", reinterpret_cast<void*>(Native_OnPurchaseRestored)},
    {"onPurchaseSuccesful", "(Ljava/lang/String;)V", reinterpret_cast<void*>(Native_OnPurchaseSuccesful)},
    {"onPurchaseTimedOut", "()V", reinterpret_cast<void*>(Native_OnPurchaseTimedOut)},
    {"onPurchaseUnSuccesful", "(Ljava/lang/String;)V", reinterpret_cast<void*>(Native_OnPurchaseUnSuccesful)},
    {"openObbFile", "(Ljava/lang/String;)Z", reinterpret_cast<void*>(Native_OpenObbFile)},
    {"pauseGameThread", "(Z)V", reinterpret_cast<void*>(Native_PauseGameThread)},
    {"sendKeyboardInput", "(Ljava/lang/String;)V", reinterpret_cast<void*>(Native_SendKeyboardInput)},
    {"bridgeSurfaceCreated", "(Landroid/view/Surface;)V", reinterpret_cast<void*>(Native_BridgeSurfaceCreated)},
    {"bridgeSurfaceChanged", "(Landroid/view/Surface;)V", reinterpret_cast<void*>(Native_BridgeSurfaceChanged)},
    {"bridgeSurfaceDestroyed", "()V", reinterpret_cast<void*>(Native_BridgeSurfaceDestroyed)},
    {"bridgeBack", "()V", reinterpret_cast<void*>(Native_BridgeBack)},
};

void RegisterNativeFunctions(JNIEnv* env) {
    jclass clazz = env->FindClass("com/stainlessgames/carmageddon/NativeFunctions");
    if (!clazz) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        LOGE("NativeFunctions class not found");
        return;
    }
    const jint count = static_cast<jint>(sizeof(kNativeFunctions) / sizeof(kNativeFunctions[0]));
    if (env->RegisterNatives(clazz, kNativeFunctions, count) != JNI_OK) {
        LOGE("RegisterNatives failed for NativeFunctions");
        if (env->ExceptionCheck()) env->ExceptionClear();
    } else {
        LOGI("registered %d NativeFunctions methods", count);
    }
}

void RegisterFmodAudio(JNIEnv* env) {
    jclass clazz = env->FindClass("org/fmod/FMODAudioDevice");
    if (!clazz) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        LOGE("FMODAudioDevice class not found");
        return;
    }
    const jint count = static_cast<jint>(sizeof(kFmodAudioMethods) / sizeof(kFmodAudioMethods[0]));
    if (env->RegisterNatives(clazz, kFmodAudioMethods, count) != JNI_OK) {
        LOGE("RegisterNatives failed for FMODAudioDevice");
        if (env->ExceptionCheck()) env->ExceptionClear();
    } else {
        LOGI("registered %d FMODAudioDevice methods", count);
    }
}

uint32_t GuestCallback(int slot) {
    return g_host && g_guest_callbacks ? g_host->MemoryRead32(g_guest_callbacks + static_cast<uint32_t>(slot) * 4) : 0;
}

void InvokeGuestCallback(int slot, std::vector<uint32_t> args = {}) {
    const uint32_t callback = GuestCallback(slot);
    if (!callback) return;
    args.insert(args.begin(), g_guest_activity);
    g_host->RunFunction(callback, args);
}

void InvokeGuestCallbackAsync(int slot, std::vector<uint32_t> args = {}) {
    // NativeActivity may report a surface while the guest's
    // ANativeActivity_onCreate is still running. Its callbacks dereference
    // activity->instance, which the guest publishes only immediately before
    // onCreate returns; invoking one earlier passes a null android_app into
    // the glue (it then waits on offsets 0x44/0x40 as if they were pointers).
    uint32_t window_handle = 0;
    const bool deferred_creation = slot == kOnNativeWindowCreated;
    if (deferred_creation) {
        if (!g_guest_activity_instance_ready.load(std::memory_order_acquire)) {
            static std::atomic<uint32_t> deferred{0};
            if (deferred.fetch_add(1, std::memory_order_relaxed) < 8)
                DiagTrace::NotePersist("creation callback deferred until guest instance is published");
            return;
        }
        window_handle = args.empty() ? 0 : args.front();
        if (!window_handle) return;
    }
    const uint32_t callback = GuestCallback(slot);
    if (!callback || !g_host) return;
    if (deferred_creation) {
        const uint32_t previous = g_last_guest_window_created.exchange(
            window_handle, std::memory_order_acq_rel);
        if (previous == window_handle) return;
        char b[128];
        snprintf(b, sizeof(b), "creation callback slot=%d fn=%08X activity=%08X args=%zu",
                 slot, callback, g_guest_activity, args.size());
        DiagTrace::NotePersist(b);
        LOGE("%s", b);
    }
    args.insert(args.begin(), g_guest_activity);
    DynarmicHost* host = g_host.get();
    DynarmicHost::SpawnLargeStackThread("bridge-callback", [host, callback, args = std::move(args)]() mutable {
        host->RunFunction(callback, args);
    });
}

void ScheduleInitialGuestWindowCallback() {
    DiagTrace::NotePersist("guest window bootstrap scheduled");
    DynarmicHost::SpawnLargeStackThread("guest-window-bootstrap", [] {
        constexpr uint32_t kPollMs = 25;
        constexpr uint32_t kTimeoutMs = 30000;
        DiagTrace::NotePersist("guest window bootstrap worker started");
        uint32_t last_callback = 0;
        bool saw_window = false;
        for (uint32_t elapsed = 0; elapsed < kTimeoutMs; elapsed += kPollMs) {
            if (!g_host) return;
            const uint32_t callback = GuestCallback(kOnNativeWindowCreated);
            ANativeWindow* window = nullptr;
            {
                std::lock_guard<std::mutex> lock(g_bridge_surface_mutex);
                window = g_bridge_surface_window;
                if (window) ANativeWindow_acquire(window);
            }
            last_callback = callback;
            saw_window = saw_window || window != nullptr;
            if (callback && window && g_guest_activity) {
                const uint32_t window_handle = GuestHandleFor(window);
                ANativeWindow_release(window);
                char note[112];
                snprintf(note, sizeof(note),
                         "initial guest window callback registered=%08X activity=%08X window=%08X",
                         callback, g_guest_activity, window_handle);
                DiagTrace::NotePersist(note);
                InvokeGuestCallbackAsync(kOnNativeWindowCreated, {window_handle});
                return;
            }
            if (window) ANativeWindow_release(window);
            std::this_thread::sleep_for(std::chrono::milliseconds(kPollMs));
        }
        char note[144];
        snprintf(note, sizeof(note),
                 "guest window bootstrap timeout callback=%08X saw_window=%u activity=%08X",
                 last_callback, saw_window ? 1u : 0u, g_guest_activity);
        DiagTrace::NotePersist(note);
        LOGE("guest window bootstrap timed out waiting for callback registration and surface");
    });
}

void HostOnStart(ANativeActivity*) {
    LOGI("host onStart guest_callback=0x%08X", GuestCallback(kOnStart));
    InvokeGuestCallbackAsync(kOnStart);
    LOGI("host onStart returned");
}
void HostOnResume(ANativeActivity*) {
    LOGI("host onResume guest_callback=0x%08X", GuestCallback(kOnResume));
    InvokeGuestCallbackAsync(kOnResume);
    LOGI("host onResume returned");
}
void HostOnPause(ANativeActivity*) { InvokeGuestCallback(kOnPause); }
void HostOnStop(ANativeActivity*) { InvokeGuestCallback(kOnStop); }
void HostOnDestroy(ANativeActivity*) {
    // This bridge has one process-global guest address space and one set of
    // callbacks. Once the Activity is destroyed, a second Activity cannot
    // safely reuse those objects. Give the guest a bounded opportunity to
    // finish its destroy callback, then end this process; Android will create
    // a fresh bridge for the next launch. HOME/return does not reach onDestroy.
    struct Completion {
        std::mutex mutex;
        std::condition_variable cv;
        bool finished = false;
        bool normal_return = false;
    };
    const uint32_t callback = GuestCallback(kOnDestroy);
    if (callback && g_host && g_guest_activity) {
        auto completion = std::make_shared<Completion>();
        DynarmicHost* host = g_host.get();
        const uint32_t guest_activity = g_guest_activity;
        if (DynarmicHost::SpawnLargeStackThread("guest-destroy", [completion, host, callback, guest_activity] {
                bool normal_return = false;
                host->RunFunction(callback, {guest_activity}, &normal_return);
                {
                    std::lock_guard<std::mutex> lock(completion->mutex);
                    completion->finished = true;
                    completion->normal_return = normal_return;
                }
                completion->cv.notify_all();
            })) {
            std::unique_lock<std::mutex> lock(completion->mutex);
            if (!completion->cv.wait_for(lock, std::chrono::seconds(2), [&] { return completion->finished; }))
                LOGE("guest onDestroy did not return within 2s; ending retired bridge process");
            else if (!completion->normal_return)
                LOGE("guest onDestroy returned through an abnormal guest trap");
        }
    }
    LOGI("NativeActivity destroyed; ending singleton bridge process");
    ::_exit(0);
}
void HostOnLowMemory(ANativeActivity*) { InvokeGuestCallback(kOnLowMemory); }
void HostOnConfigurationChanged(ANativeActivity*) { InvokeGuestCallback(kOnConfigurationChanged); }
void HostOnWindowFocusChanged(ANativeActivity*, int focus) {
    LOGI("host onWindowFocusChanged focus=%d guest_callback=0x%08X", focus, GuestCallback(kOnWindowFocusChanged));
    // R1: same reasoning as the input-queue callbacks - this fires on the main
    // thread from inside the framework traversal, and the guest handler waits
    // for the worker via pthread_cond_wait.
    InvokeGuestCallbackAsync(kOnWindowFocusChanged, {static_cast<uint32_t>(focus)});
}
void HostOnNativeWindowCreated(ANativeActivity*, ANativeWindow* window) {
    // Render to NativeActivity's own window, not an additional SurfaceView.
    // Keep a reference while guest startup is asynchronous; the framework's
    // callback alone does not transfer ownership to the bridge.
    if (window) {
        ANativeWindow_acquire(window);
        std::lock_guard<std::mutex> lock(g_bridge_surface_mutex);
        if (g_bridge_surface_window) ANativeWindow_release(g_bridge_surface_window);
        g_bridge_surface_window = window;
    }
    LOGI("host onNativeWindowCreated window=%p guest_callback=0x%08X", window, GuestCallback(kOnNativeWindowCreated));
    InvokeGuestCallbackAsync(kOnNativeWindowCreated, {GuestHandleFor(window)});
}
void HostOnNativeWindowResized(ANativeActivity*, ANativeWindow* window) { InvokeGuestCallbackAsync(kOnNativeWindowResized, {GuestHandleFor(window)}); }
void HostOnNativeWindowRedrawNeeded(ANativeActivity*, ANativeWindow* window) { InvokeGuestCallbackAsync(kOnNativeWindowRedrawNeeded, {GuestHandleFor(window)}); }
// W44: the game's main loop treats APP_CMD_TERM_WINDOW (delivered via the
// guest onNativeWindowDestroyed callback) as a quit request. Some devices
// recreate the surface during boot (INIT_WINDOW -> TERM_WINDOW x2 ->
// INIT_WINDOW), which made android_main return cleanly after ~1 s and
// killed the game thread (run87: clean exit-trap RET of android_app_entry,
// onResume waiter stuck on the boot cond forever). The bridge owns the real
// EGL surface anyway, so the guest never needs the destroy notification.
// W44: the game's main loop treats APP_CMD_TERM_WINDOW (delivered via the
// guest onNativeWindowDestroyed callback) as a quit request. Some devices
// recreate the surface during boot (INIT_WINDOW -> TERM_WINDOW x2 ->
// INIT_WINDOW), which made android_main return cleanly after ~1 s and
// killed the game thread (run87: clean exit-trap RET of android_app_entry,
// onResume waiter stuck on the boot cond forever). The bridge owns the real
// EGL surface anyway, so the guest never needs the destroy notification.
// W118 (run166): the W44 suppression was never actually implemented -- the
// dispatch below still fired and the boot ran android_main to a CLEAN
// return (R0=0x30) right after PDStartup_1, leaving the boot cond waiters
// parked. Measured again on run166. Actually suppress it now.
void HostOnNativeWindowDestroyed(ANativeActivity*, ANativeWindow* window) {
    LOGI("host onNativeWindowDestroyed window=%p suppressed (W118: the guest "
         "treats TERM as quit; the bridge owns the EGL surface)", window);
    std::lock_guard<std::mutex> lock(g_bridge_surface_mutex);
    if (g_bridge_surface_window == window) {
        ANativeWindow_release(g_bridge_surface_window);
        g_bridge_surface_window = nullptr;
    }
}

void Native_BridgeSurfaceCreated(JNIEnv* env, jclass, jobject surface) {
    if (!surface || !g_host_activity) return;
    ANativeWindow* window = ANativeWindow_fromSurface(env, surface);
    if (!window) return;
    {
        std::lock_guard<std::mutex> lock(g_bridge_surface_mutex);
        if (g_bridge_surface_window) ANativeWindow_release(g_bridge_surface_window);
        g_bridge_surface_window = window;
    }
    LOGI("bridge surface created window=%p", window);
    // Do not release PDStartup_0's message-pump gate here. It must continue
    // dispatching the queued Start/Resume callbacks before the startup worker
    // sets the boolean gate after their app-glue acknowledgements.
    HostOnNativeWindowCreated(g_host_activity, window);
}

void Native_BridgeSurfaceChanged(JNIEnv* env, jclass, jobject surface) {
    if (!surface || !g_host_activity) return;
    ANativeWindow* window = ANativeWindow_fromSurface(env, surface);
    if (!window) return;
    {
        std::lock_guard<std::mutex> lock(g_bridge_surface_mutex);
        if (g_bridge_surface_window) ANativeWindow_release(g_bridge_surface_window);
        g_bridge_surface_window = window;
    }
    LOGI("bridge surface changed window=%p", window);
    HostOnNativeWindowResized(g_host_activity, window);
}

void Native_BridgeSurfaceDestroyed(JNIEnv*, jclass) {
    ANativeWindow* window = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_bridge_surface_mutex);
        window = g_bridge_surface_window;
        if (window) ANativeWindow_acquire(window);
    }
    if (!window) return;
    HostOnNativeWindowDestroyed(g_host_activity, window);
    ANativeWindow_release(window);
}

// NativeActivity owns the queue until onInputQueueDestroyed returns. The guest
// glue's input callback waits for its poll thread, so create must remain off
// Android's main thread. A separate generation and completion barrier make
// destroy wait for that create and for the guest's actual detach acknowledgement.
[[noreturn]] void FailInputQueue(const char* reason, uint64_t generation,
                                 uint32_t guest_handle) {
    LOGE("input queue lifetime failure: %s generation=%llu handle=%08X",
         reason, static_cast<unsigned long long>(generation), guest_handle);
    std::abort();  // Returning from destroy with a live queue would be unsafe.
}

void RunInputQueueCreate(std::shared_ptr<InputQueueGeneration> record) {
    {
        std::lock_guard<std::mutex> lock(g_input_queue_mutex);
        if (record->destroy_requested) {
            record->create_finished = true;
            g_input_queue_cv.notify_all();
            return;
        }
        record->create_started = true;
    }
    const uint32_t callback = GuestCallback(kOnInputQueueCreated);
    const uint32_t handle = RegisterInputQueueHandle(record->queue, record->number);
    if (!g_host || !g_guest_activity || !callback || !handle)
        FailInputQueue("create callback or generation handle unavailable", record->number, handle);
    {
        std::lock_guard<std::mutex> lock(g_input_queue_mutex);
        record->guest_handle = handle;
    }
    bool normal_return = false;
    g_host->RunFunction(callback, {g_guest_activity, handle}, &normal_return);
    const uint32_t app = g_host->MemoryRead32(g_guest_activity + kActivityInstance);
    const InputQueueHandleStatus status = GetInputQueueHandleStatus(handle);
    if (!normal_return || !GuestRangeValid(g_host->GetGuestMemorySize(), app, 0x80u) ||
        !status.known || !status.attached ||
        status.protocol_error || status.generation != record->number ||
        g_host->MemoryRead32(app + 0x20u) != handle ||
        g_host->MemoryRead32(app + 0x7Cu) != handle)
        FailInputQueue("guest create did not acknowledge attach", record->number, handle);
    LOGI("input queue create ACK generation=%llu handle=%08X app=%08X",
         static_cast<unsigned long long>(record->number), handle, app);
    g_last_guest_input_queue_created.store(handle, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lock(g_input_queue_mutex);
        record->create_acked = true;
        record->create_finished = true;
    }
    g_input_queue_cv.notify_all();
}

void ScheduleInputQueueCreateLocked() {
    const auto record = g_input_queue_current;
    if (!g_input_guest_ready || !record || record->destroy_requested ||
        record->create_scheduled) return;
    record->create_scheduled = true;
    if (!DynarmicHost::SpawnLargeStackThread("input-create", [record] {
            RunInputQueueCreate(record);
        })) FailInputQueue("could not start create worker", record->number, 0);
}

void RunInputQueueDestroy(std::shared_ptr<InputQueueGeneration> record,
                          std::chrono::steady_clock::time_point deadline) {
    const uint32_t handle = record->guest_handle;
    const uint32_t callback = GuestCallback(kOnInputQueueDestroyed);
    if (!callback) FailInputQueue("destroy callback unavailable", record->number, handle);
    bool normal_return = false;
    g_host->RunFunction(callback, {g_guest_activity, handle}, &normal_return);
    const uint32_t app = g_host->MemoryRead32(g_guest_activity + kActivityInstance);
    if (!normal_return || !GuestRangeValid(g_host->GetGuestMemorySize(), app, 0x80u) ||
        g_host->MemoryRead32(app + 0x20u) != 0 ||
        g_host->MemoryRead32(app + 0x7Cu) != 0 ||
        !WaitInputQueueQuiescent(handle, deadline) || !RetireInputQueueHandle(handle))
        FailInputQueue("guest destroy did not acknowledge detach/quiescence",
                       record->number, handle);
    LOGI("input queue destroy ACK generation=%llu handle=%08X app=%08X",
         static_cast<unsigned long long>(record->number), handle, app);
    g_last_guest_input_queue_created.store(0, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lock(g_input_queue_mutex);
        record->queue = nullptr;
        record->destroy_finished = true;
        if (g_input_queue_current == record) g_input_queue_current.reset();
    }
    g_input_queue_cv.notify_all();
}

void HostOnInputQueueCreated(ANativeActivity*, AInputQueue* queue) {
    if (!queue) FailInputQueue("null host create", 0, 0);
    std::lock_guard<std::mutex> lock(g_input_queue_mutex);
    if (g_input_queue_current && !g_input_queue_current->destroy_finished)
        FailInputQueue("overlapping host queue generations",
                       g_input_queue_current->number, g_input_queue_current->guest_handle);
    auto record = std::make_shared<InputQueueGeneration>();
    record->number = g_next_input_queue_generation++;
    if (!record->number) FailInputQueue("generation counter wrapped", 0, 0);
    record->queue = queue;
    g_input_queue_current = record;
    g_host_input_queue.store(queue, std::memory_order_release);
    LOGI("host onInputQueueCreated generation=%llu queue=%p guest_callback=0x%08X",
         static_cast<unsigned long long>(record->number), queue, GuestCallback(kOnInputQueueCreated));
    ScheduleInputQueueCreateLocked();
}

void HostOnInputQueueDestroyed(ANativeActivity*, AInputQueue* queue) {
    using Clock = std::chrono::steady_clock;
    constexpr auto kDestroyDeadline = std::chrono::seconds(4);
    const auto deadline = Clock::now() + kDestroyDeadline;
    std::unique_lock<std::mutex> lock(g_input_queue_mutex);
    const auto record = g_input_queue_current;
    if (!record || record->queue != queue)
        FailInputQueue("destroy did not match live generation",
                       record ? record->number : 0, record ? record->guest_handle : 0);
    record->destroy_requested = true;
    g_host_input_queue.store(nullptr, std::memory_order_release);
    LOGI("input queue destroy requested generation=%llu handle=%08X create_started=%d",
         static_cast<unsigned long long>(record->number), record->guest_handle,
         record->create_started ? 1 : 0);
    if (!record->create_started) {
        // A scheduled worker checks destroy_requested before it can register
        // or dereference the raw queue. No guest ever saw this generation.
        record->queue = nullptr;
        record->destroy_finished = true;
        g_input_queue_current.reset();
        LOGI("input queue generation cancelled before create generation=%llu",
             static_cast<unsigned long long>(record->number));
        return;
    }
    if (!g_input_queue_cv.wait_until(lock, deadline, [&] { return record->create_finished; }) ||
        Clock::now() > deadline)
        FailInputQueue("create still in flight at destroy deadline",
                       record->number, record->guest_handle);
    if (!record->create_acked || !CloseInputQueueHandle(record->guest_handle))
        FailInputQueue("create ACK or close gate missing", record->number, record->guest_handle);
    if (!DynarmicHost::SpawnLargeStackThread("input-destroy", [record, deadline] {
            RunInputQueueDestroy(record, deadline);
        })) FailInputQueue("could not start destroy worker", record->number, record->guest_handle);
    if (!g_input_queue_cv.wait_until(lock, deadline, [&] { return record->destroy_finished; }) ||
        Clock::now() > deadline)
        FailInputQueue("guest detach/ACK exceeded destroy deadline",
                       record->number, record->guest_handle);
}

void HostOnContentRectChanged(ANativeActivity*, const ARect* rect) {
    if (!rect) return;
    {
        std::lock_guard<std::mutex> lock(g_content_rect_mutex);
        g_pending_content_rect = *rect;
        g_have_content_rect = true;
    }
    // NativeActivity reports its initial layout before the asynchronous bridge
    // host/guest exists. Retain the rectangle instead of dereferencing g_host
    // or discarding a one-time initialization event.
    if (!g_guest_activity_instance_ready.load(std::memory_order_acquire) ||
        !GuestCallback(kOnContentRectChanged)) return;
    uint32_t guest_rect = 0;
    if (rect) {
        guest_rect = g_host->GuestAlloc(16, 4);
        if (guest_rect) {
            g_host->MemoryWrite32(guest_rect + 0, static_cast<uint32_t>(rect->left));
            g_host->MemoryWrite32(guest_rect + 4, static_cast<uint32_t>(rect->top));
            g_host->MemoryWrite32(guest_rect + 8, static_cast<uint32_t>(rect->right));
            g_host->MemoryWrite32(guest_rect + 12, static_cast<uint32_t>(rect->bottom));
        }
    }
    InvokeGuestCallback(kOnContentRectChanged, {guest_rect});
    if (guest_rect) g_host->GuestFree(guest_rect);
}

void* HostOnSaveInstanceState(ANativeActivity*, size_t* out_size) {
    *out_size = 0;
    const uint32_t callback = GuestCallback(kOnSaveInstanceState);
    if (!callback) return nullptr;
    const uint32_t guest_size = g_host->GuestAlloc(4, 4);
    if (!guest_size) return nullptr;
    g_host->MemoryWrite32(guest_size, 0);
    const uint32_t guest_data = g_host->RunFunction(callback, {g_guest_activity, guest_size});
    const uint32_t size = g_host->MemoryRead32(guest_size);
    g_host->GuestFree(guest_size);
    if (!guest_data || !size || !GuestRangeValid(g_host->GetGuestMemorySize(), guest_data, size)) return nullptr;
    void* result = malloc(size);
    if (!result) return nullptr;
    memcpy(result, g_host->GetGuestMemoryBase() + guest_data, size);
    g_host->GuestFree(guest_data);
    *out_size = size;
    return result;
}

void InstallHostCallbacks(ANativeActivity* activity) {
    ANativeActivityCallbacks* callbacks = activity->callbacks;
    callbacks->onStart = HostOnStart;
    callbacks->onResume = HostOnResume;
    callbacks->onSaveInstanceState = HostOnSaveInstanceState;
    callbacks->onPause = HostOnPause;
    callbacks->onStop = HostOnStop;
    callbacks->onDestroy = HostOnDestroy;
    callbacks->onWindowFocusChanged = HostOnWindowFocusChanged;
    callbacks->onNativeWindowCreated = HostOnNativeWindowCreated;
    callbacks->onNativeWindowResized = HostOnNativeWindowResized;
    callbacks->onNativeWindowRedrawNeeded = HostOnNativeWindowRedrawNeeded;
    callbacks->onNativeWindowDestroyed = HostOnNativeWindowDestroyed;
    callbacks->onInputQueueCreated = HostOnInputQueueCreated;
    callbacks->onInputQueueDestroyed = HostOnInputQueueDestroyed;
    callbacks->onContentRectChanged = HostOnContentRectChanged;
    callbacks->onConfigurationChanged = HostOnConfigurationChanged;
    callbacks->onLowMemory = HostOnLowMemory;
}

uint32_t GuestStringCopy(const char* value) {
    if (!value || !g_host) return 0;
    const size_t size = strlen(value) + 1;
    const uint32_t address = g_host->GuestAlloc(size, 1);
    if (address) memcpy(g_host->GetGuestMemoryBase() + address, value, size);
    return address;
}

bool RunGuestJniOnLoad(JNIEnv* env) {
    const uint32_t entry = g_host->FindSymbol("JNI_OnLoad");
    // W454: reach bit1 -- RunGuestJniOnLoad entered.
    g_host->MemoryWrite32(0x930017A4u, g_host->MemoryRead32(0x930017A4u) | (1u << 1));
    LOGE("[W450] JNI_OnLoad FindSymbol -> 0x%08X", entry);
    if (!entry) return false;
    FakeJniEnv::Instance().AttachHostEnv(env);
    LOGE("[W554] guest JNI_OnLoad begin env=%08X vm=%08X",
         FakeJniEnv::Instance().EnvTableGuestAddr(), FakeJniEnv::Instance().VmTableGuestAddr());
    const uint32_t result = g_host->RunFunction(entry, {FakeJniEnv::Instance().VmTableGuestAddr(), 0});
    // W454: reach bit2 -- JNI_OnLoad RunFunction RETURNED.
    g_host->MemoryWrite32(0x930017A4u, g_host->MemoryRead32(0x930017A4u) | (1u << 2));
    LOGI("guest JNI_OnLoad -> 0x%08X", result);
    LOGE("[W554] guest JNI_OnLoad returned 0x%08X", result);
    return result != 0 && result != static_cast<uint32_t>(JNI_ERR);
}

// N5: the bridge's early TERM/TERM/INIT surface churn (~5 ms after the first
// INIT) runs the __android_init_display re-init branch while the game is still
// inside PDStartup_0's pump. PDInvalidDynamicVertexBuffers(0) in that branch
// walks gDynamic_vb_map, which is still NULL because its only opener,
// PDOpenDynamicVertexBuffers (idempotent), is called from bz_Display_SetDimensions
// only -- post-PDStartup_1. A NULL map makes the walk read begin=*(0xC)=0 !=
// end(4) and ping-pong forever between node 0 and the exit-trap word 0xEF000000
// (PC 0x4026BB80, zero host calls). Call the guest's own opener here, after the
// guest ELF is loaded and initialized (init_array complete, trampolines and
// guest heap ready, guest JNI_OnLoad done) and before any host callback can
// reach the reload branch. It only operator new(0x18)s the map object
// (begin=rightmost=end=map+4, root=0, size=0) and operator new[](0x2000)s
// gVertex_workspace -- the exact initialization the game itself performs later
// at bz_Display_SetDimensions time.
void OpenGuestDynamicVertexBuffers() {
                    bool shown = false;
if (!g_host) return;
    const uint32_t entry = g_host->FindSymbol("_Z26PDOpenDynamicVertexBuffersv");
    if (!entry) {
        LOGE("N5: _Z26PDOpenDynamicVertexBuffersv not found in guest ELF");
        return;
    }
    LOGI("N5: calling PDOpenDynamicVertexBuffers at 0x%08X", entry);
    g_host->RunFunction(entry, {});
    // gDynamic_vb_map lives at libParsons+0x6C8494 (see DiagWalkDynamicVbMap).
    const uint32_t map = g_host->MemoryRead32(DynarmicHost::kGuestGameBase + 0x6C8494);
    LOGI("N5: PDOpenDynamicVertexBuffers returned, gDynamic_vb_map=0x%08X", map);
    if (!map) LOGE("N5: map pointer still NULL after PDOpenDynamicVertexBuffers");
}

// W368 (run499): register the WAD content tree while the game thread is
// parked on the startup pause (m_startup_game_thread_paused, 0x40673288),
// BEFORE the config or material chain does its first BZ::Content member
// lookup. Runs the game's own NovaFile_Initialise (root dir +
// DATA_ANDROID.WAD + AppInfo + Music; exported at guest 0x40528A88, no
// args). Evidence (run498): W285 passed 0x93000150 (bridge scratch) as
// the WAD base-name string, so CINodeSystem opened "<garbage>.WAD" and
// the chain halted at PC=0xC inside bz_fread (RET target=0x404040C8) --
// the WAD was never registered in any run; every member lookup returned
// empty descriptors (the config-XML wall of run470-498).
static void RunW368WadRegistration() {
    static std::atomic<uint32_t> w368_done{0};
    if (!g_host || w368_done.exchange(1)) return;
    if (!g_host->MemoryRead32(0x406DA9D4u)) {
        for (int i = 0; i < 35; ++i) {
            const uint32_t v = g_host->MemoryRead32(
                0x406732A0u + static_cast<uint32_t>(i) * 4u);
            if (v) g_host->MemoryWrite32(
                0x406DA980u + static_cast<uint32_t>(i) * 4u, v);
        }
        LOGI("[W368] hooks copied early: read=%08X",
             g_host->MemoryRead32(0x406DA9D4u));
    }
    const uint32_t nova_init = g_host->FindSymbol("_Z19NovaFile_Initialisev");
    if (nova_init) {
        // W409 (run546b): restore ORIGINAL ActualMain code and NOP the
        // diagnostic print so the flow goes Init_BZ -> Init_PostBZ ->
        // StateMachine_Enter -> render loop.
        g_host->MemoryWrite32(0x4054E0A0u, 0xE1A00000u);  // NOP (was BL Print)
        g_host->MemoryWrite32(0x4054E0A4u, 0xEBFFD6B7u);  // BL Init_PostBZ
        g_host->MemoryWrite32(0x4054E0A8u, 0xEB006CFFu);  // BL StateMachine_DoInit
        // W411 (run551): restore POP {R4,LR} + tail-call B StateMachine_Enter.
        // The veneer zone extended past the print call to cover these two
        // words -- without restoring them, StateMachine_Enter is NEVER reached.
        g_host->MemoryWrite32(0x4054E0ACu, 0xE8BD4010u);  // POP {R4, LR}
        g_host->MemoryWrite32(0x4054E0B0u, 0xEA006EB5u);  // B StateMachine_Enter
        g_host->InvalidateGuestCode(0x4054E0A0u, 20);
        LOGI("[W409] ActualMain restored: print NOPped, calls restored");
        // W414 (run554b): the paused-sync NovaFile_Initialise worker call is
        // RETIRED. Init_PostBZ+0x10 (0x40543B98) calls NovaFile_Initialise
        // itself as the first act of the restored ActualMain flow, and the
        // W404b retirement brought the log system live -- the worker call
        // now RACES the game thread (run553: CBNode::Find walked a sibling
        // slot holding the FNV basis 0x811C9DC5; run554: the game thread
        // recursed to HALT inside bz_StartInternal's log path, stack full
        // of the 0x405F7168 text pointer called as code).
        (void)nova_init;
        LOGI("[W414] NovaFile_Initialise left to Init_PostBZ (worker call retired)");
    } else {
        LOGE("[W368] NovaFile_Initialise symbol not found");
    }
}

// Keep PDStartup_0's Android message pump alive until the real app-glue window
// and the lifecycle commands that Android delivered during onCreate have all
// been acknowledged. Only then may the guest leave its message-pump loop.
static void ScheduleStartupResume(uint32_t guest_app) {
    if (!g_host || !guest_app) {
        LOGE("startup resume not scheduled: app=%08X", guest_app);
        return;
    }

    DynarmicHost::SpawnLargeStackThread("guest-startup-resume",
        [guest_app] {
            g_startup_gate_app.store(guest_app, std::memory_order_release);
            g_startup_gate_stage.store(0x02u, std::memory_order_release);
            constexpr uint32_t kPollMs = 10;
            constexpr uint32_t kTimeoutMs = 30000;
            constexpr uint32_t kStartupSurfaceReady = 0x406D94ACu;
            constexpr uint32_t kAndroidDisplayInitialized = 0x406CA9F4u;
            uint32_t app_window = 0;
            uint32_t pending_window = 0;
            uint32_t paused = 0;
            uint32_t display_initialized = 0;
            bool window_ready = false;

            DiagTrace::NotePersist("startup handshake waiting for app-glue window and EGL initialization");
            for (uint32_t elapsed = 0; elapsed < kTimeoutMs; elapsed += kPollMs) {
                if (!g_host) return;
                app_window = g_host->MemoryRead32(guest_app + 0x24u);
                pending_window = g_host->MemoryRead32(guest_app + 0x80u);
                paused = g_host->MemoryRead32(0x40673288u) & 0xFFu;
                display_initialized = g_host->MemoryRead32(kAndroidDisplayInitialized) & 0xFFu;
                if (app_window && pending_window == app_window && display_initialized) {
                    window_ready = true;
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(kPollMs));
            }

            if (!window_ready) {
                g_startup_gate_stage.store(0x81u, std::memory_order_release);
                LOGE("startup handshake timed out: app=%08X window=%08X pending=%08X display=%u paused=%u",
                     guest_app, app_window, pending_window, display_initialized, paused);
                return;
            }
            g_startup_gate_stage.store(0x03u, std::memory_order_release);

            // OnStart/OnResume can arrive before guest ANativeActivity_onCreate
            // returns, before its callback table is usable by the host. Replay
            // each exactly once, and wait for app-glue's state ACK while
            // PDStartup_0 is still pumping its command pipe.
            const auto replay_and_wait_for_state = [guest_app, kPollMs](
                int callback_slot, uint32_t expected_state, const char* label) {
                if (!g_host) return false;
                const uint32_t callback = GuestCallback(callback_slot);
                if (!callback) {
                    g_startup_gate_stage.store(expected_state == 10u ? 0x82u : 0x83u,
                                               std::memory_order_release);
                    LOGE("startup handshake missing %s callback", label);
                    return false;
                }
                InvokeGuestCallbackAsync(callback_slot);
                for (uint32_t elapsed = 0; elapsed < 5000; elapsed += kPollMs) {
                    if (!g_host) return false;
                    const uint32_t state = g_host->MemoryRead32(guest_app + 0x38u);
                    if (state == expected_state) {
                        g_startup_gate_stage.store(expected_state == 10u ? 0x04u : 0x05u,
                                                   std::memory_order_release);
                        char note[112];
                        snprintf(note, sizeof(note),
                                 "startup lifecycle acknowledged %s state=%u callback=%08X",
                                 label, state, callback);
                        DiagTrace::NotePersist(note);
                        return true;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(kPollMs));
                }
                g_startup_gate_stage.store(expected_state == 10u ? 0x82u : 0x83u,
                                           std::memory_order_release);
                LOGE("startup handshake timed out waiting for %s state=%u (got %u)",
                     label, expected_state, g_host->MemoryRead32(guest_app + 0x38u));
                return false;
            };

            if (!replay_and_wait_for_state(kOnStart, 10u, "Start")) return;
            if (!replay_and_wait_for_state(kOnResume, 11u, "Resume")) return;

            const uint32_t set_paused = g_host->FindSymbol("_Z17Startup_SetPausedb");
            if (!set_paused) {
                g_startup_gate_stage.store(0x84u, std::memory_order_release);
                LOGE("guest Startup_SetPaused symbol not found; startup remains held in app-glue pump");
                return;
            }
            if (!(g_host->MemoryRead32(0x40673288u) & 0xFFu)) {
                // Re-arm the original guest pause before opening PDStartup_0's
                // message-pump gate if a Java resume raced thread creation.
                g_host->RunFunction(set_paused, {1u});
                paused = g_host->MemoryRead32(0x40673288u) & 0xFFu;
                if (!paused) {
                    g_startup_gate_stage.store(0x84u, std::memory_order_release);
                    LOGE("startup pause could not be re-armed; leaving app-glue pump held");
                    return;
                }
            }

            if (!g_host->MemoryRead32(kStartupSurfaceReady)) {
                // This global is a boolean gate in PDStartup_0, not a window
                // handle. Keeping it clear until both lifecycle ACKs arrive
                // prevents the guest from abandoning its Android message pump.
                g_host->MemoryWrite32(kStartupSurfaceReady, 1u);
                DiagTrace::NotePersist("startup surface-ready gate released after Start/Resume acknowledgements");
            }
            g_startup_gate_stage.store(0x06u, std::memory_order_release);

            g_startup_gate_stage.store(0x07u, std::memory_order_release);
            RunW368WadRegistration();
            g_host->RunFunction(set_paused, {0u});
            paused = g_host->MemoryRead32(0x40673288u) & 0xFFu;
            char note[144];
            snprintf(note, sizeof(note),
                     "startup resumed app=%08X window=%08X setter=%08X paused_after=%u",
                     guest_app, app_window, set_paused, paused);
            DiagTrace::NotePersist(note);
            if (paused) {
                g_startup_gate_stage.store(0x85u, std::memory_order_release);
                LOGE("guest Startup_SetPaused(0) did not clear pause flag: setter=%08X",
                     set_paused);
            } else {
                g_startup_gate_armed.store(false, std::memory_order_release);
                g_startup_gate_stage.store(0x08u, std::memory_order_release);
                LOGI("guest startup resumed through Startup_SetPaused at %08X",
                     set_paused);
            }
        });
}

// W448 (run601): wait for the armcc dispatch iframe to drain its pending
// init queue before dispatching pump guest calls -- the iframe spins in its
// own loop (0x4058DF18 -> 0x4058DF50) while the queue is non-empty, and a
// concurrent pump dispatch re-feeds it, wedging the boot permanently.
static void W448WaitDispatchIdle(const char* who) {
    if (!g_host) return;
    for (int i = 0; i < 3000; ++i) {
        const uint32_t p = g_host->MemoryRead32(0x40670900u);
        if (p == 0) return;
        if (g_host->MemoryRead32(p) == 0) return;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    LOGE("[W448] %s: dispatch still busy after 30s wait", who);
}


// W477: host-side EGL state -- initialized on a dedicated non-JIT thread.
// W475 proved eglInitialize HANGS when called from the guest-boot JIT
// execution context (driver load vs the JIT thread's signal/TLS state).
// Display init (eglGetDisplay+eglInitialize) is display-global, so once
// the W477 thread completes it, the guest-facing thunks can serve the
// guest's EGL calls without ever touching the driver-load path on the
// JIT thread. eglMakeCurrent is deliberately NOT called here: a context
// binds to the calling thread, and the guest's own eglMakeCurrent thunk
// must bind it to the JIT thread that runs the render loop.
static EGLDisplay g_w477_display = EGL_NO_DISPLAY;
static EGLContext g_w477_context = EGL_NO_CONTEXT;
static EGLSurface g_w477_surface = EGL_NO_SURFACE;
static EGLConfig g_w477_config = nullptr;
static EGLint g_w477_major = 0;
static EGLint g_w477_minor = 0;
static std::atomic<bool> g_w477_display_ready{false};
static std::atomic<bool> g_w477_full{false};
static std::atomic<bool> g_w477_failed{false};
static std::atomic<bool> g_w477_thread_done{false};
static std::atomic<bool> g_w477_worker_active{false};

static void W477InitEGLHost() {
    g_w477_display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    if (g_w477_display == EGL_NO_DISPLAY) {
        LOGE("[W477] eglGetDisplay FAILED");
        g_w477_failed.store(true);
        g_w477_thread_done.store(true);
        return;
    }
    EGLint maj = 0, min = 0;
    if (!eglInitialize(g_w477_display, &maj, &min)) {
        LOGE("[W477] eglInitialize FAILED err=0x%04X", eglGetError());
        g_w477_failed.store(true);
        g_w477_thread_done.store(true);
        return;
    }
    g_w477_major = maj;
    g_w477_minor = min;
    LOGE("[W477] EGL %d.%d initialized on W477 thread", maj, min);
    // Only warm up the display/driver here. The original guest requests an
    // ES1 context (null eglCreateContext attributes) and uses fixed-function
    // rendering. W477 used to replace that request with an ES2 context/config,
    // observed as ES 3.2 on Adreno: swaps succeeded but all frames were black.
    // Config, context and window-surface ownership belong to the guest's real
    // EGL calls, including their attributes and lifecycle.
    g_w477_display_ready.store(true);
    g_w477_full.store(true);
    g_w477_thread_done.store(true);
}

// Accessors for thunks_egl.cpp: the guest-facing EGL thunks short-circuit
// the driver-load calls (eglGetDisplay/eglInitialize/eglChooseConfig) to
// this pre-initialized state so the JIT thread never runs them.
// (Defined at file scope below -- the anonymous namespace would give them
// internal linkage and the link would fail.)

bool StartGuestActivity(ANativeActivity* activity, void* saved_state, size_t saved_state_size) {
    g_guest_activity_instance_ready.store(false, std::memory_order_release);
    g_last_guest_window_created.store(0, std::memory_order_release);
    g_last_guest_input_queue_created.store(0, std::memory_order_release);
    // W477: EGL display init on a dedicated non-JIT thread. It waits for
    // the surface window itself; guest boot proceeds in parallel. Must be
    // a fresh std::thread -- eglInitialize from THIS (JIT) thread hangs.
    g_w477_worker_active.store(true, std::memory_order_release);
    std::thread([] {
        for (int wi = 0; wi < 1500 && !g_bridge_surface_window; ++wi) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        LOGE("[W477] init thread: window=%p, starting EGL init",
             (void*)g_bridge_surface_window);
        W477InitEGLHost();
        LOGE("[W477] init thread done: display_ready=%d full=%d failed=%d",
             g_w477_display_ready.load(), g_w477_full.load(), g_w477_failed.load());
        g_w477_worker_active.store(false, std::memory_order_release);
    }).detach();
    // Count guest Activity starts for diagnostics. Startup pause state is
    // owned by the guest and is released through Startup_SetPaused after the
    // live app-glue window has been acknowledged below.
    if (g_host) {
        // W463 (run614): CUMULATIVE attribution -- the W429 per-boot zeroing
        // hid real progress (a fresh pass's zeros overwrote the previous
        // pass's reached stages). The cells now accumulate across passes;
        // pass# counts StartGuestActivity invocations for attribution.
        g_host->MemoryWrite32(0x93001748u,
                              g_host->MemoryRead32(0x93001748u) + 1u);
    }
    const uint32_t entry = g_host->FindSymbol("ANativeActivity_onCreate");
    if (!entry) { LOGE("[W436] FindSymbol FAILED"); return false; }
    LOGE("[W436] S0 entry=0x%08X", entry);
    g_host->MemoryWrite32(0x930017A4u, g_host->MemoryRead32(0x930017A4u) | (1u << 3));

    g_guest_callbacks = g_host->GuestAlloc(kCallbackCount * 4, 4);
    g_guest_activity = g_host->GuestAlloc(kActivitySize, 8);
    if (!g_guest_callbacks || !g_guest_activity) { LOGE("[W436] S1 alloc FAIL"); return false; }
    LOGE("[W436] S1 allocs ok");
    g_host->MemoryWrite32(0x930017A4u, g_host->MemoryRead32(0x930017A4u) | (1u << 4));
    for (uint32_t i = 0; i < kCallbackCount; ++i) g_host->MemoryWrite32(g_guest_callbacks + i * 4, 0);

    const uint32_t guest_saved = saved_state && saved_state_size
        ? g_host->GuestAlloc(saved_state_size, 8) : 0;
    if (guest_saved) memcpy(g_host->GetGuestMemoryBase() + guest_saved, saved_state, saved_state_size);

    g_host->MemoryWrite32(g_guest_activity + kActivityCallbacks, g_guest_callbacks);
    g_host->MemoryWrite32(g_guest_activity + kActivityVm, FakeJniEnv::Instance().VmTableGuestAddr());
    g_host->MemoryWrite32(g_guest_activity + kActivityEnv, FakeJniEnv::Instance().EnvTableGuestAddr());
    LOGE("[W436] S2 env tables");
    g_host->MemoryWrite32(0x930017A4u, g_host->MemoryRead32(0x930017A4u) | (1u << 5));
    // R3 (runtime-proven): PDStartup_0 passes activity->clazz straight back into
    // CallObjectMethod, so it must be a FakeJni handle that ResolveObject knows,
    // not a native_handle_table address. The native handle silently resolved to
    // null there, which zeroed getClassLoader and cascaded nulls through every
    // loadClass-cached class/method handle down to the GetAppInternalDataPath
    // retry loop -- the whole Wedge B.
    JNIEnv* thread_env = FakeJniEnv::Instance().GetEnv();
    if (!thread_env) {
        LOGE("guest boot thread could not obtain its own JNIEnv");
        return false;
    }
    g_host->MemoryWrite32(g_guest_activity + kActivityClass,
                          GuestClassRef(thread_env, static_cast<jclass>(activity->clazz)));
    g_host->MemoryWrite32(g_guest_activity + kActivityInternalPath, GuestStringCopy(activity->internalDataPath));
    g_host->MemoryWrite32(g_guest_activity + kActivityExternalPath, GuestStringCopy(activity->externalDataPath));
    g_host->MemoryWrite32(g_guest_activity + kActivitySdkVersion, static_cast<uint32_t>(activity->sdkVersion));
    g_host->MemoryWrite32(g_guest_activity + kActivityInstance, 0);
    g_host->MemoryWrite32(g_guest_activity + kActivityAssetManager, GuestHandleFor(activity->assetManager));
    LOGE("[W436] S3 fields done");
    g_host->MemoryWrite32(0x930017A4u, g_host->MemoryRead32(0x930017A4u) | (1u << 6));
    // The guest expects a full OBB filename here, while Android's real
    // ANativeActivity::obbPath is the application's OBB *directory*.
    // Its libc calls are intercepted by the single validated source selector.
    {
        const std::string obb_path = BridgeObbGuestPath();
        if (obb_path.empty()) {
            LOGE("guest boot refused: Android supplied no application OBB directory");
            return false;
        }
        g_host->MemoryWrite32(g_guest_activity + kActivityObbPath,
                              GuestStringCopy(obb_path.c_str()));
    }

    LOGE("[W436] S4 calling ANativeActivity_onCreate 0x%08X act=0x%08X", entry, g_guest_activity);
    const uint32_t startup_set_paused = g_host->FindSymbol("_Z17Startup_SetPausedb");
    if (!startup_set_paused) {
        LOGE("guest Startup_SetPaused symbol not found; refusing to start without lifecycle gate");
        return false;
    }
    // PDStartup_0 must keep pumping the guest app-glue pipe until the host has
    // delivered its real window and acknowledged Start/Resume. Arm the guest's
    // own pause before ANativeActivity_onCreate creates android_app_entry.
    g_startup_gate_armed.store(true, std::memory_order_release);
    g_host->RunFunction(startup_set_paused, {1u});
    if (!(g_host->MemoryRead32(0x40673288u) & 0xFFu)) {
        g_startup_gate_armed.store(false, std::memory_order_release);
        LOGE("guest startup pause setter did not arm; refusing unsafe startup");
        return false;
    }
    g_startup_gate_stage.store(0x01u, std::memory_order_release);
    DiagTrace::NotePersist("guest startup pause armed before ANativeActivity_onCreate");
    g_host->MemoryWrite32(0x930017A4u, g_host->MemoryRead32(0x930017A4u) | (1u << 7));
    LOGI("entering guest ANativeActivity_onCreate 0x%08X activity=0x%08X", entry, g_guest_activity);
    LOGE("[W556] invoking guest ANativeActivity_onCreate with saved=%08X size=%u",
         guest_saved, static_cast<uint32_t>(saved_state_size));
    static std::atomic<unsigned> g_w492_cell{0};  // host view of the display gate
    {
        char b[160];
        snprintf(b, sizeof(b), "W556 begin entry=%08X activity=%08X callbacks=%08X saved=%08X size=%u",
                 entry, g_guest_activity, g_guest_callbacks, guest_saved,
                 static_cast<uint32_t>(saved_state_size));
        DiagTrace::NotePersist(b);
    }
    g_host->RunFunction(entry, {g_guest_activity, guest_saved,
                                static_cast<uint32_t>(saved_state_size)});
    DiagTrace::Note("W565 host resumed after guest onCreate RunFunction");
    const uint32_t guest_app = g_host->MemoryRead32(g_guest_activity + kActivityInstance);
    g_guest_activity_instance_ready.store(guest_app != 0, std::memory_order_release);
    g_startup_gate_app.store(guest_app, std::memory_order_release);
    {
        char b[112];
        snprintf(b, sizeof(b), "W565 host read instance=%08X window_callback=%08X",
                 guest_app, GuestCallback(kOnNativeWindowCreated));
        DiagTrace::Note(b);
    }
    LOGE("[W556] guest ANativeActivity_onCreate returned instance=%08X start=%08X resume=%08X window=%08X",
         guest_app,
         g_host->MemoryRead32(g_guest_callbacks + kOnStart * 4u),
         g_host->MemoryRead32(g_guest_callbacks + kOnResume * 4u),
         g_host->MemoryRead32(g_guest_callbacks + kOnNativeWindowCreated * 4u));
    if (guest_app) {
        char b[224];
        snprintf(b, sizeof(b),
                 "W556 app=%08X read=%u write=%u state=%u window=%08X pending=%08X running=%u source=%08X process=%08X",
                 guest_app, g_host->MemoryRead32(guest_app + 0x48u),
                 g_host->MemoryRead32(guest_app + 0x4Cu),
                 g_host->MemoryRead32(guest_app + 0x38u),
                 g_host->MemoryRead32(guest_app + 0x24u),
                 g_host->MemoryRead32(guest_app + 0x80u),
                 g_host->MemoryRead32(guest_app + 0x6Cu),
                 guest_app + 0x54u, g_host->MemoryRead32(guest_app + 0x5Cu));
        DiagTrace::NotePersist(b);
    } else {
        DiagTrace::NotePersist("W556 app instance is null after guest ANativeActivity_onCreate");
    }
    if (guest_saved) g_host->GuestFree(guest_saved);
    // NativeActivity may create its queue before slow guest initialization.
    // The same generation gate serves both the early replay and later creates.
    if (guest_app) {
        {
            std::lock_guard<std::mutex> lock(g_input_queue_mutex);
            g_input_guest_ready = true;
            ScheduleInputQueueCreateLocked();
        }
        ARect pending_rect{};
        bool have_rect = false;
        {
            std::lock_guard<std::mutex> lock(g_content_rect_mutex);
            pending_rect = g_pending_content_rect;
            have_rect = g_have_content_rect;
        }
        if (have_rect) HostOnContentRectChanged(activity, &pending_rect);
    }
    if (guest_app) ScheduleInitialGuestWindowCallback();
    if (guest_app) ScheduleStartupResume(guest_app);
    return true;

    // W472 (run620): DIRECT ENGINE BOOT -- bypass ANativeActivity_onCreate,
    // the glue thread, pthread_create, and the armcc dispatch entirely.
    // Call the engine's init chain directly:
    //   Init_BZ -> (bz_StartInternal -> PDStartup_1/2/3 -> all init)
    //   Init_PostBZ
    //   StateMachine_DoInit
    //   StateMachine_Enter (the render loop -- never returns)
    // W475: wait for the surface to arrive (up to 10s)
    {
        for (int wi = 0; wi < 1000 && !g_bridge_surface_window; ++wi) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        LOGE("[W475] surface wait done: window=%p", (void*)g_bridge_surface_window);
    }
    LOGE("[W472] DIRECT BOOT: Init_BZ(0x40543A04) app=%08X", g_guest_activity);
    g_host->RunFunction(0x40543A04u, {g_guest_activity});
    LOGE("[W472] Init_BZ returned, calling Init_PostBZ");
    g_host->RunFunction(0x40543B88u, {});
    LOGE("[W472] Init_PostBZ returned, calling StateMachine_DoInit");
    g_host->RunFunction(0x405694ACu, {});
    LOGE("[W472] StateMachine_DoInit returned, calling StateMachine_Enter -- RENDER LOOP");
    // W477: the inline W475 EGL init block was REMOVED -- eglInitialize on
    // this JIT thread hangs (W475). The dedicated W477 thread did the
    // display init; just wait for it before entering the render loop.
    {
        for (int wi = 0; wi < 1500 && !BridgeEgl477::DisplayReady(); ++wi) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        LOGE("[W477] pre-Enter: display_ready=%d full=%d failed=%d done=%d",
             BridgeEgl477::DisplayReady(), g_w477_full.load(),
             BridgeEgl477::Failed(), BridgeEgl477::ThreadDone());
    }
    // W478 (run631): the game's display init lives in __android_init_display,
    // dispatched from android_handle_cmd(APP_CMD_INIT_WINDOW) -- which only
    // fires from the glue's ALooper pump, dead under W472. PDStartup_0 shows
    // the layout: bzgAndroidInfo (0x406DAE5C) IS the display struct a1, with
    // a1[0] = glue android_app* (bogus 0x108 here), [a1[0]+36] = window,
    // a1[1] = JNIEnv*, outputs a1[212..218]. Fix, all host-side:
    //   1. [a1+0] = a crafted mini app struct with the bridge window at +36.
    //   2. [a1+4] = the fake JNIEnv.
    //   3. Overlay AndroidProcessSystemMessages (0x403DA248, 0x68 bytes) with
    //      a one-shot literal-free stub: first call (game thread, ~1s into
    //      the background-sleep loop) invokes __android_init_display(a1) --
    //      whose driver-load EGL calls are W477-short-circuited and whose
    //      eglMakeCurrent binds the context to the GAME thread -- then
    //      clears the background (0x406D8D41) and lost-focus (0x406D8D40)
    //      flags so the foreground render path engages.
    {
        // W478 v4 (run634): [0x406D915C] reads garbage across runs (stomped
        // after PDStartup_0), but PDStartup_0 itself resolves the struct via
        // the GOT: a1 = *(GOT entry bzgAndroidInfo_ptr @ 0x4066FA6C). The
        // GOT is load-bearing for every PIC access, so it is trustworthy.
        const uint32_t gotBzg = 0x4066FA6Cu;
        const uint32_t a1 = g_host->MemoryRead32(gotBzg);
        // W515 (run694): mini IS the full writable a1 now. 0x405DBE60 is
        // .data.rel.ro (guest stores trap!), so init_display gets mini:
        // [mini+0]=inner, [inner+36]=window, [mini+4]=fake JNIEnv, and the
        // output block a1[212..218] lands in writable heap at [mini+848..].
        uint32_t mini = 0;
        {
            // W517 (run696): GuestAlloc ALIASES the guest's own malloc arena
            // (a live string wrote 't' over our AA marker at [CELL+1] and
            // clobbers inner/env). Use fresh GuestAllocMapping pages the
            // guest allocator knows nothing about.
            mini = g_host->GuestAllocMapping(1024, 256);
            const uint32_t inner = g_host->GuestAllocMapping(64, 256);
            if (mini && inner && g_bridge_surface_window) {
                g_host->MemoryWrite32(mini, 0);   // zero the whole struct
                for (unsigned zw = 4; zw < 1024u; zw += 4)
                    g_host->MemoryWrite32(mini + zw, 0);
                g_host->MemoryWrite32(inner, 0);
                for (unsigned zw = 4; zw < 64u; zw += 4)
                    g_host->MemoryWrite32(inner + zw, 0);
                g_host->MemoryWrite32(inner + 36, GuestHandleFor(g_bridge_surface_window));
                g_host->MemoryWrite32(mini + 0, inner);
                g_host->MemoryWrite32(mini + 4, FakeJniEnv::Instance().EnvTableGuestAddr());
                g_host->MemoryWrite32(mini + 8, 0);  // W492 gate cell
            } else {
                mini = 0;
            }
        }
        if (a1) {
            g_host->MemoryWrite32(a1 + 0, mini);
            g_host->MemoryWrite32(a1 + 4, FakeJniEnv::Instance().EnvTableGuestAddr());
        }
        // W537 (run723): REDIRECT the state base. Process computes
        // R5 = 0x569520 + [literal @0x405699FC]; [R5]=gCurrent_main_state.
        // Point R5 at mini+0x20 (writable heap) -- then the guest's own
        // reads AND ChangeState writes operate on memory we control.
        const uint32_t stateCell = mini + 0x20u;
        if (mini) {
            for (unsigned zw = 0x20u; zw < 0x40u; zw += 4u)
                g_host->MemoryWrite32(mini + zw, 0);
            const uint32_t newLit = stateCell - 0x569520u;  // 32-bit wrap ok
            g_host->MemoryWrite32(0x405699FCu, newLit);
            g_host->InvalidateGuestCode(0x405699FCu, 4);
            LOGE("[W537] state literal -> %08X (stateCell=%08X)", newLit, stateCell);
        }
        // W478 v5 (run638): in-place stub, no window jump. 18 words = 72
        // bytes, fits the 0x68-byte function. Resolves a1 through the GOT
        // entry (the route PDStartup_0 itself uses), calls
        // __android_init_display(a1) -- W477-short-circuited EGL calls
        // inside, MakeCurrent binds the context to the GAME thread -- then
        // clears the background/lost-focus bytes.
        {
            const uint32_t F = 0x402DB8F0u;   // __android_init_display
            const uint32_t B1 = 0x406D8D41u;  // byte_6D8D41 background
            const uint32_t B0 = 0x406D8D40u;  // byte_6D8D40 lost-focus
            auto movw = [](int rd, uint32_t imm16) -> uint32_t {
                return 0xE3000000u | (((imm16 >> 12) & 0xFu) << 16) | ((rd & 0xFu) << 12) | (imm16 & 0xFFFu);
            };
            auto movt = [](int rd, uint32_t imm16) -> uint32_t {
                return 0xE3400000u | (((imm16 >> 12) & 0xFu) << 16) | ((rd & 0xFu) << 12) | (imm16 & 0xFFFu);
            };
            const uint32_t kW478Stub[] = {
                0xE92D4010u,        // 0  PUSH  {R4, LR}
                movw(4, mini),      // 1  W515: a1 = mini (writable heap)
                movt(4, mini),      // 2
                0xE3540000u,        // 4  CMP   R4, #0
                0x08BD8010u,        // 5  POPEQ {R4, PC}
                0xE1A00004u,        // 6  MOV   R0, R4       (arg0)
                movw(1, F),         // 7
                movt(1, F),         // 8
                0xE12FFF31u,        // 9  BLX   R1
                0xE3A00000u,        // 10 MOV   R0, #0
                movw(1, B1),        // 11
                movt(1, B1),        // 12
                0xE5C10000u,        // 13 STRB  R0, [R1]     (background = 0)
                movw(1, B0),        // 14
                movt(1, B0),        // 15
                0xE5C10000u,        // 16 STRB  R0, [R1]     (lost-focus = 0)
                0xE8BD8010u,        // 17 POP   {R4, PC}
            };
            for (size_t i = 0; i < sizeof(kW478Stub) / 4; ++i) {
                g_host->MemoryWrite32(0x403DA248u + static_cast<uint32_t>(i) * 4u, kW478Stub[i]);
            }
            g_host->InvalidateGuestCode(0x403DA248u, sizeof(kW478Stub));
            LOGE("[W478] got=%08X a1=%08X mini=%08X win=%08X in-place stub installed (%zu words)",
                 g_host->MemoryRead32(gotBzg), a1, mini,
                 mini ? g_host->MemoryRead32(mini + 36) : 0, sizeof(kW478Stub) / 4);
        }
        // W480 (run637): neutralise bz_Debug_PrintToDebugger. With the log
        // manager NULL (W402B logstr=00000000, W403C LM@00000000) its call
        // path ends in a wild call through NULL, landing on the low-page
        // trap (PC=8, R0=-8) -- exactly the StateMachine_Enter first-tick
        // death (W479 autopsy: sentinel exit before the pump call). Debug
        // printing is worthless under the bridge; a bare return is safe for
        // a void(const char*,...) function.
        g_host->MemoryWrite32(0x401E6AFCu, 0xE12FFF1Eu);  // BX LR
        g_host->InvalidateGuestCode(0x401E6AFCu, 4);
        LOGE("[W480] bz_Debug_PrintToDebugger -> BX LR (null-log-manager wild call)");
        // W492 (run661): hook Process's first BL (0x405694F8 -> GetFramePeriod):
        // first tick runs __android_init_display ONCE on the GAME thread, then
        // calls the original target and executes the displaced VMOV S16,R0.
        // 2-word veneer at 4F8 covers both 4F8 and the displaced 4FC.
        {
            auto vw = [](int rd, unsigned A) -> unsigned {
                const unsigned imm = A & 0xFFFFu;   // W497: full address in, split here
                return 0xE3000000u | (((imm >> 12) & 0xFu) << 16) | ((rd & 0xFu) << 12) | (imm & 0xFFFu); };
            auto vt = [](int rd, unsigned A) -> unsigned {
                const unsigned imm = A >> 16;
                return 0xE3400000u | (((imm >> 12) & 0xFu) << 16) | ((rd & 0xFu) << 12) | (imm & 0xFFFu); };
            const unsigned G = 0x4066FA6Cu, F = 0x412A40u, G2 = 0x4066FA6Cu;
            const unsigned SITE = 0x405694F8u, RET = 0x40569500u;
            const unsigned S = 0x8F120000u;  // dedicated display-init veneer page
            // W495: the GOT entry heals back to its raw ELF word mid-boot
            // (0x108); bake the RESOLVED a1 into the stub instead.
            unsigned gotv = g_host->MemoryRead32(G);
            if (gotv < 0x40200000u || gotv >= 0x40700000u) gotv = 0x405DBE60u;
            LOGE("[W495] GOT=%08X a1=%08X", g_host->MemoryRead32(G), gotv);
            // W493: the one-shot cell MUST live in guest-usable memory -- the
            // 0x93000xxx scratch band is host-only (guest data faults there),
            // which silently killed the whole stub on its first LDRB.
            // W510 (run688): GuestAlloc heap memory FAULTS on guest-side stores
            // (the stub parked writing the gate). Use the display struct's own
            // unused field [a1+8] -- guest .bss, proven guest-writable.
            const unsigned CELL = mini + 8u;  // W515: writable heap
            g_host->MemoryWrite32(CELL, 0);  // W512: dirty cell would make POPNE skip init forever
            g_w492_cell.store(CELL);  // W509
            // W527: register the host-side init handler HERE (RegisterEglThunks
            // may run after this block; GetOrCreate is find-only and returns 0).
            g_host->GetThunkManager().RegisterThunk("w526_init_display",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<bool> done{false};
                    if (done.exchange(true)) return;
                    const uint32_t mini = jit.Regs()[0];
                    LOGE("[W526] init_display host-thunk enter, mini=%08X", mini);
                    if (!BridgeEgl477::DisplayReady() || !mini) {
                        LOGE("[W526] display not ready or mini=0, abort");
                        return;
                    }
                    const uint32_t inner = host.MemoryRead32(mini + 0);
                    const uint32_t winHandle = inner ? host.MemoryRead32(inner + 36) : 0;
                    ANativeWindow* win = winHandle ? static_cast<ANativeWindow*>(HostPointerFor(winHandle)) : nullptr;
                    LOGE("[W526] inner=%08X winHandle=%08X win=%p", inner, winHandle, (void*)win);
                    EGLDisplay dpy = BridgeEgl477::Display();
                    EGLSurface surf = BridgeEgl477::Surface();
                    EGLContext ctx = BridgeEgl477::Context();
                    EGLBoolean mc = eglMakeCurrent(dpy, surf, surf, ctx);
                    LOGE("[W526] eglMakeCurrent=%d err=0x%04X", (int)mc, eglGetError());
                    if (!mc) return;
                    EGLint w = 0, h = 0;
                    eglQuerySurface(dpy, surf, EGL_WIDTH, &w);
                    eglQuerySurface(dpy, surf, EGL_HEIGHT, &h);
                    host.MemoryWrite32(mini + 840, (uint32_t)w);
                    host.MemoryWrite32(mini + 836, (uint32_t)h);
                    host.MemoryWrite32(0x406D95B4u, 1u);  // gAndroid_display_init
                    LOGE("[W526] DISPLAY INIT COMPLETE dpy=%p surf=%p ctx=%p %dx%d", dpy, surf, ctx, w, h);
                });
            // W534 (run717): call the GUEST __android_init_display -- it runs
            // bz_InitialiseOGLStateCache/ClearDummyTexture (renderer state the
            // W526 host thunk skipped) and writes outputs to a1=mini (heap).
            const unsigned IDISP = 0x402DB8F0u;
            const unsigned IDISP_PROBE = 0x8F119000u;
            W541Install(*g_host);  // W541: render-path probe
            LOGE("[W527] w526_init_display thunk at %08X", IDISP);
            const unsigned EGTD = g_host->GetThunkManager().GetOrCreateThunkAddress("eglGetDisplay");
            LOGE("[W518] eglGetDisplay thunk at %08X", EGTD);
            g_host->GetThunkManager().RegisterThunk(
                "w553_idisp_probe",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                    static std::atomic<unsigned> n553{0};
                    if (n553.fetch_add(1) < 4) {
                        const unsigned a1 = jit.Regs()[0];
                        const unsigned env = a1 ? host.MemoryRead32(a1 + 4u) : 0u;
                        LOGE("[W553] IDISP entry r0=%08X a1+0=%08X a1+4=%08X env0=%08X env520=%08X",
                             a1,
                             a1 ? host.MemoryRead32(a1) : 0u,
                             env,
                             env ? host.MemoryRead32(env) : 0u,
                             env ? host.MemoryRead32(env + 520u) : 0u);
                    }
                });
            const unsigned IDISP_PROBE_TRAMP =
                g_host->GetThunkManager().GetOrCreateThunkAddress("w553_idisp_probe");
            {
                const unsigned p[] = {
                    0xE92D500Fu,  // push {r0-r3,r12,lr}
                    0xE59F300Cu,  // ldr r3,[pc,#12] -> probe thunk
                    0xE12FFF33u,  // blx r3
                    0xE8BD500Fu,  // pop {r0-r3,r12,lr}
                    0xE59FF008u,  // ldr pc,[pc,#8] -> original IDISP
                    0u,
                    IDISP_PROBE_TRAMP,
                    0u,
                    IDISP,
                };
                for (unsigned pi = 0; pi < sizeof(p) / sizeof(p[0]); ++pi)
                    g_host->MemoryWrite32(IDISP_PROBE + pi * 4u, p[pi]);
                g_host->AddExecutableRange(IDISP_PROBE, sizeof(p));
                g_host->InvalidateGuestCode(IDISP_PROBE, sizeof(p));
            }
            // W506 (run681): rebuilt. The old array had (a) POPNE falling
            // through instead of returning (re-arming every tick), (b) a
            // leftover `ldr r4,[r4]` dereferencing the baked a1, (c) a
            // duplicated tail.
            // W516: stage markers at [CELL+1]: AA = about to BLX,
            // BB = init_display returned. Splits "call faulted" from
            // "returned early".
            const unsigned w[] = {
                0xE92D500Fu,                    // push {r0-r3,r12,lr}
                vw(4, CELL), vt(4, CELL),
                0xE5D40000u,                    // ldrb r0,[r4]
                0xE3500000u,                    // cmp r0,#0
                0x18BD800Fu,                    // popne {r0-r3,r12,pc} (done) (W520: 7-reg pop pulled garbage into pc!)
                0xE3A03001u,                    // mov r3,#1
                0xE5C43000u,                    // strb r3,[r4]
                0xE3A0300Au, 0xE5C43001u,       // marker AA before the call (W519: 0xAA needs imm12=0x0AA -- imm8 ROR 2*rot)
                // W518: DIRECT thunk call test -- eglGetDisplay(0) via its
                // bridge-page dispatch address. Canary proves guest->thunk.
                vw(2, EGTD), vt(2, EGTD),
                0xE3A00000u,                    // mov r0,#0
                0xE12FFF32u,                    // blx r2
                vw(4, mini), vt(4, mini),       // r4 = a1 = mini (writable heap, W515)
                0xE3540000u,                    // cmp r4,#0
                0x08BD800Fu,                    // popeq {r0-r3,r12,pc} (W520)
                0xE1A00004u,                    // mov r0,r4
                vw(1, IDISP_PROBE), vt(1, IDISP_PROBE), // r1 = IDISP probe -> original
                0xE12FFF31u,                    // blx r1
                0xE3A0300Bu, 0xE5C43001u,       // marker BB after return (W519: fixed immediate)
                0xE30D4958u,                    // movw r4,#0xD958 (W536: state word)
                0xE344408Bu,                    // movt r4,#0x408B
                0xE3A03001u,                    // mov r3,#1
                0xE5843000u,                    // str r3,[r4]  (state=1, guest-side)
                0xE8BD500Fu,                    // pop {r0-r3,r12,lr}
                0xE59FE000u,                    // ldr lr,[pc,#0] -> RET
                0xE59FF000u,                    // ldr pc,[pc,#0] -> F
                RET, F,
            };
            for (unsigned wi = 0; wi < sizeof(w)/4; ++wi)
                g_host->MemoryWrite32(S + wi*4u, w[wi]);
            g_host->MemoryWrite32(SITE, 0xE51FF004u);
            g_host->MemoryWrite32(SITE + 4u, S);
            g_host->InvalidateGuestCode(SITE, 8);
            g_host->InvalidateGuestCode(S, sizeof(w));
            LOGE("[W492] Process-first-BL hook -> stub %08X (%u words)", S, (unsigned)(sizeof(w)/4));

        }
        // W523 (run702): EAGERLY harden the egl* GOT slots BEFORE the
        // first tick. At t=1s the slots were still lazy-resolver values;
        // init_display's eglGetDisplay call then jumped through PLT0 into
        // the .rel.plt data (andeq-NOP spin at 0x40660B94). The W432
        // hardener only fixes them later, per tick.
        {
            const uint32_t slots[] = {0x4066ECB0u, 0x4066ECFCu, 0x4066EBECu, 0x4066EEE0u, 0x4066ECDCu};
            const char* names[] = {"eglGetDisplay", "eglInitialize", "eglMakeCurrent", "eglSwapBuffers", "eglChooseConfig"};
            for (unsigned si = 0; si < 5; ++si) {
                const uint32_t ta = g_host->GetThunkManager().GetOrCreateThunkAddress(names[si]);
                const uint32_t oldv = g_host->MemoryRead32(slots[si]);
                if (ta) g_host->MemoryWrite32(slots[si], ta);
                LOGE("[W523] %s: slot %08X: %08X -> %08X", names[si], slots[si], oldv, ta);
            }
            g_host->InvalidateGuestCodeAll(0x4066E000u, 0x2000u);
        }
        }
        // Async witness: log the display-init byte and the background byte
        // for 90s. gdi=1 means __android_init_display ran to completion.
        std::thread([] {
            bool shown = false;

            for (int i = 0; i < 45; ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(2000));
                if (!g_host) return;
                const uint32_t gdi = g_host->MemoryRead32(0x406D95B4u) & 0xFFu;
                const uint32_t bkg = g_host->MemoryRead32(0x406D8D41u) & 0xFFu;
                // W486: patch-integrity watch -- the DRO healer may revert
                // the guest patches; dump the live words each poll.
                if (i == 5 || i == 22 || i == 44) {
                    LOGE("[W486] proc=%08X %08X %08X %08X | stub=%08X | w476=%08X | w480=%08X",
                         g_host->MemoryRead32(0x405694E4u), g_host->MemoryRead32(0x405694E8u),
                         g_host->MemoryRead32(0x405694F8u), g_host->MemoryRead32(0x405694FCu),
                         g_host->MemoryRead32(0x403DA248u),
                         g_host->MemoryRead32(0x40569BA0u),
                         g_host->MemoryRead32(0x401E6AFCu));
                    LOGE("[W486b] b94=%08X b98=%08X cst=[%08X %08X %08X %08X %08X %08X %08X %08X %08X %08X]",
                         g_host->MemoryRead32(0x40569B94u), g_host->MemoryRead32(0x40569B98u),
                         g_host->MemoryRead32(0x8F118828u), g_host->MemoryRead32(0x8F11882Cu),
                         g_host->MemoryRead32(0x8F118830u), g_host->MemoryRead32(0x8F118834u),
                         g_host->MemoryRead32(0x8F118838u), g_host->MemoryRead32(0x8F11883Cu),
                         g_host->MemoryRead32(0x8F118840u), g_host->MemoryRead32(0x8F118844u),
                         g_host->MemoryRead32(0x8F118848u), g_host->MemoryRead32(0x8F11884Cu));

                    LOGE("[W501] gotDisp=%08X gotInit=%08X gotMkCur=%08X gotSwap=%08X gotCfg=%08X",
                         g_host->MemoryRead32(0x4066ECB0u), g_host->MemoryRead32(0x4066ECFCu),
                         g_host->MemoryRead32(0x4066EBECu), g_host->MemoryRead32(0x4066EEE0u),
                         g_host->MemoryRead32(0x4066ECDCu));                }
                if (!shown) LOGE("[W478] poll t=%ds gdi=%u bkg=%u", i * 2, gdi, bkg);
                else if (i % 10 == 0) LOGE("[W478] poll t=%ds gdi=%u bkg=%u", i * 2, gdi, bkg);
                // Guest code owns its state transitions; this monitor is
                // read-only so it cannot hide or manufacture progress.
                // W509: W492 stub witness
                {
                    const unsigned cv = g_w492_cell.load();
                    const unsigned mini_dbg = cv >= 8u ? cv - 8u : 0u;
                    const unsigned env_dbg = mini_dbg ? g_host->MemoryRead32(mini_dbg + 4u) : 0u;
                    LOGE("[W509] cell=%08X val=%08X mini=%08X env=%08X env0=%08X e516=%08X e520=%08X e524=%08X bodger=%08X gdi2=%08X gdi=%08X state=%08X",
                         cv,
                         cv ? g_host->MemoryRead32(cv) : 0xAAAAAAAAu,
                         mini_dbg, env_dbg,
                         env_dbg ? g_host->MemoryRead32(env_dbg) : 0u,
                         env_dbg ? g_host->MemoryRead32(env_dbg + 516u) : 0u,
                         env_dbg ? g_host->MemoryRead32(env_dbg + 520u) : 0u,
                         env_dbg ? g_host->MemoryRead32(env_dbg + 524u) : 0u,
                         g_host->MemoryRead32(0x405694F8u),
                         g_host->MemoryRead32(0x4067CB98u),
                         g_host->MemoryRead32(0x406D95B4u),
                         g_host->MemoryRead32(g_w492_cell.load() + 0x18u));
                  {  // W539: state-change trap
                    static unsigned last_state = 0xFFFFFFFFu;
                    const unsigned cv2 = g_w492_cell.load();
                    const uint32_t st2 = cv2 ? g_host->MemoryRead32(cv2 + 0x18u) : 0;
                    if (st2 != last_state) {
                        LOGE("[W539] STATE CHANGE: %08X -> %08X", last_state, st2);
                        last_state = st2;
                    }
                }
              }
                if (gdi && !shown) { shown = true; LOGE("[W478] DISPLAY INIT COMPLETE (integrity watch continues)"); }
                if (i >= 44) { LOGE("[W478] poll timeout"); return; }
            }
            LOGE("[W478] poll timeout: display init never completed");
        }).detach();
    g_host->RunFunction(0x40569B8Cu, {});
    LOGE("[W472] StateMachine_Enter returned");
    LOGI("guest ANativeActivity_onCreate returned");
    // W454: reach bit8 -- ANativeActivity_onCreate RETURNED.
    g_host->MemoryWrite32(0x930017A4u, g_host->MemoryRead32(0x930017A4u) | (1u << 8));
    if (guest_saved) g_host->GuestFree(guest_saved);
    InstallHostCallbacks(activity);
    // W313b (run415): host-side fallback for the default file-IO hook
    // table (non-zero members of 0x406732A0 -> 0x6DA980.., mirroring
    // bz_InstallFileIOHooks). A zero read hook (0x6DA9D4) made the first
    // bz_fread call NULL and killed the game thread through the trap
    // page (run414/415: W84APP lr=40408844, "clean" PC=0x8 exit).
    if (g_host && !g_host->MemoryRead32(0x406DA9D4u)) {
        for (int i = 0; i < 35; ++i) {
            const uint32_t v = g_host->MemoryRead32(0x406732A0u + static_cast<uint32_t>(i) * 4u);
            if (v) g_host->MemoryWrite32(0x406DA980u + static_cast<uint32_t>(i) * 4u, v);
        }
        LOGI("[W313] late hooks copied: read=%08X", g_host->MemoryRead32(0x406DA9D4u));
    }
    // W263 (run367): re-deliver the early lifecycle. Android fires
    // onStart/onResume/onWindowFocusChanged(true) BEFORE onCreate
    // returns, i.e. before InstallHostCallbacks existed -- those events
    // are lost forever and the game waits for RESUME/FOCUS in its
    // StartInternal message pump. Replay them once, async, now that the
    // callbacks are live.
    {
        DynarmicHost::SpawnLargeStackThread("w263-lifecycle", [] {
            const timespec delay250 = {0, 250 * 1000 * 1000};
            nanosleep(&delay250, nullptr);
            LOGI("[W263] replay onStart");
            InvokeGuestCallbackAsync(kOnStart);
            nanosleep(&delay250, nullptr);
            LOGI("[W263] replay onResume");
            InvokeGuestCallbackAsync(kOnResume);
            nanosleep(&delay250, nullptr);
            LOGI("[W263] replay onWindowFocusChanged(true)");
            InvokeGuestCallbackAsync(kOnWindowFocusChanged, {1u});
            LOGI("[W263] lifecycle replay done");
            // W264 (run367): drive the glue command state machine directly
            // (W74 pattern) -- APP_CMD_START(9), APP_CMD_RESUME(8),
            // APP_CMD_GAINED_FOCUS(6), APP_CMD_INIT_WINDOW(1).
            if (g_host && g_guest_activity) {
                const uint32_t handle_cmd =
                    g_host->FindSymbol("_Z18android_handle_cmdP11android_appi");
                if (handle_cmd) {
                    const timespec delay400 = {0, 400 * 1000 * 1000};
                    // W314 (run415): the guest's switch is 1=INIT_WINDOW,
                    // 6=GAINED_FOCUS, 10=START, 11=RESUME (decoded at
                    // 0x403D9FDC). The old {9,8,6,1} sent LOW_MEMORY(9) and
                    // CONFIG_CHANGED(8) -- harmless prints in the handler,
                    // but the START/RESUME state bytes 0x6D8D41/42 were
                    // never cleared by this path.
                    for (const int cmd : {10, 11, 6, 1}) {
                        if (!DynarmicInitDone()) { LOGE("[W440] cmd=%d skipped (ctors running)", cmd); continue; }
                        // W418 (run556): heal GOT poison right before every
                        // dispatch -- cmd=6 wild-jumped through a poisoned
                        // PLT slot at ~1.3 s, before the first 5 s tick.
                        W418GotHealNow_public();
                        LOGI("[W264] handle_cmd cmd=%d", cmd);
                        g_host->RunFunction(handle_cmd, {g_guest_activity, static_cast<uint32_t>(cmd)});
                        nanosleep(&delay400, nullptr);
                    }
                    W418GotHealNow_public();
                }
                // W285 retired (run499): it passed 0x93000150 (bridge
                // scratch) as the WAD base-name string, so CINodeSystem
                // opened "<garbage>.WAD" and the chain halted at PC=0xC
                // inside bz_fread (run498 RET target=0x404040C8). W368
                // registers the WAD on the w338-release worker instead,
                // while the game thread is parked on the startup pause.
                // W286 (run386): PERIODIC event re-delivery. The one-shot
                // replay fired before the game reached its StartInternal
                // wait, so the commands were consumed unanswered and the
                // game sleeps forever. Re-send RESUME/GAINED_FOCUS every
                // 2 s for a minute; these are idempotent state commands.
                if (handle_cmd && g_guest_activity) {
                    const timespec delay2s = {2, 0};
                    for (int round = 0; round < 30; ++round) {
                        nanosleep(&delay2s, nullptr);
                        const uint32_t live_cond = [] (DynarmicHost* h) -> uint32_t {
                            const uint32_t c = h->MemoryRead32(0x93000164u);
                            return (c >= 0x50847E00u && c <= 0x50848000u) ? c : 0;
                        }(g_host.get());
                        // W292 (run388): wake via the glue command pipe --
                        // write the cmd bytes to msgwrite (app+0x4C). The fds
                        // are REAL host fds (read/write thunks pass through).
                        {
                            const uint32_t live_app = live_cond ? (live_cond - 0x44u) : g_host->MemoryRead32(0x93000160u);
                            const uint32_t msgwrite = live_app ? g_host->MemoryRead32(live_app + 0x4Cu) : 0;
                            if (msgwrite && msgwrite < 0x10000u) {
                                // W302 (run403): CORRECT cmd ids per
                                // android_handle_cmd switch:
                                // 10=START 11=RESUME 6=GAINED_FOCUS 1=INIT_WINDOW
                                // W342 (run455): FULL write_cmd emulation --
                                // the pump's wake predicate is [app+0x38]!=0
                                // (it sleeps in cond_wait(app->cond) and
                                // treats 0 as "no command"); the old path
                                // wrote only the pipe byte AND W303 cleared
                                // [app+0x38], so every wake found 0 and the
                                // pump never read the pipe (W295=0 forever).
                                // Now: pipe byte + cmd field + broadcast per
                                // command, exactly like sub_17CD2C.
                                const uint32_t cond_bc_addr =
                                    g_host->GetThunkManager().GetOrCreateThunkAddress("pthread_cond_broadcast");
                                const unsigned char wake_cmds[4] = {10, 11, 6, 1};
                                for (int ci = 0; ci < 4; ++ci) {
                                    const ssize_t wn = write(static_cast<int>(msgwrite), &wake_cmds[ci], 1);
                                    LOGI("[W292] pipe fd=%u cmd=%d wrote=%zd", msgwrite, wake_cmds[ci], wn);
                                    if (wn == 1)
                                        DiagTrace::Note("W292W fd=" + std::to_string(msgwrite)
                                                        + " cmd=" + std::to_string(wake_cmds[ci]));
                                    if (live_app)
                                        g_host->MemoryWrite32(live_app + 0x38u, static_cast<uint32_t>(wake_cmds[ci]));
                                    if (cond_bc_addr && live_cond)
                                        g_host->RunFunction(cond_bc_addr, {live_cond});
                                    const timespec d200 = {0, 200 * 1000 * 1000};
                                    nanosleep(&d200, nullptr);
                                }
                            }
                        }
                        // W306 (run406): log the callback slot values -- verify
                        // the glue registered its handlers into our table.
                        LOGI("[W306] slots: resume=%08X focus=%08X nwc=%08X start=%08X",
                             GuestCallback(kOnResume), GuestCallback(kOnWindowFocusChanged),
                             GuestCallback(kOnNativeWindowCreated), GuestCallback(kOnStart));
                        LOGI("[W286] round=%d posting RESUME+FOCUS callbacks", round);
                        // W354 (run467): per-round callback spawns REMOVED.
                        // Each InvokeGuestCallbackAsync creates a host
                        // thread whose guest side parks in the glue ACK
                        // cond_wait; with the pump not ACKing they
                        // accumulated 36 threads in run466. The pipe+cmd
                        // field+broadcast sequence above delivers the same
                        // commands without any thread spawn.
                        // W301 (run408): set app->window from the live surface --
                        // the StartInternal wait loop checks the WINDOW field,
                        // which no synthetic post ever carried.
                        if (g_bridge_surface_window && live_cond) {
                            const uint32_t win_h = GuestHandleFor(g_bridge_surface_window);
                            // W301b (run414): the wait predicate compares
                            // app->window (+0x24) with app->pendingWindow
                            // (+0x80) (sub_17D4C4 decode). Write BOTH equal
                            // to the live surface handle so any parked
                            // onNativeWindowCreated waiter releases at once.
                            if (live_cond) {
                                const uint32_t app_w = live_cond - 0x44u;
                                g_host->MemoryWrite32(app_w + 0x24u, win_h);
                                g_host->MemoryWrite32(app_w + 0x80u, win_h);
                                DiagTrace::Note("W301W win=0x" + [] (uint32_t v) {
                                    char t[16]; snprintf(t, sizeof(t), "%08X", v); return std::string(t);
                                }(win_h));
                            }
                            LOGI("[W301] app->window set: handle=0x%08X", win_h);
                            // W338b (run453): release the startup pause
                            // every round -- PDStartup_0's black glClear
                            // loop only exits when
                            // m_startup_game_thread_paused (0x40673288)
                            // drops to 0; the original gets that from
                            // Java pauseGameThread(false).
                            LOGE("[W453] gate: flag=%08X initDone=%d gAct=%08X",
                                 g_host->MemoryRead32(0x40673288u),
                                 (int)DynarmicInitDone(), g_guest_activity);
                            if (g_host->MemoryRead32(0x40673288u) && DynarmicInitDone()) {
                                // W450 (run602): the glue thread never spawns
                                // android_app_entry, so android_main is never
                                // called. Drive the game's main chain DIRECTLY:
                                // one-shot RunFunction(android_main, app).
                                static std::atomic<uint32_t> w450_done{0};
                                if (w450_done.exchange(1) == 0) {
                                    const uint32_t amain =
                                        g_host->FindSymbol("android_main");
                                    LOGE("[W450] android_main=%08X app=%08X -> calling",
                                         amain, g_guest_activity);
                                    if (amain && g_guest_activity)
                                        g_host->RunFunction(amain, {g_guest_activity});
                                    LOGE("[W450] android_main returned");
                                }
                                RunW368WadRegistration();
                                g_host->RunFunction(0x403DA234u, {0u});
                                // W415 (run555): prove the release actually
                                // clears the flag -- 19 rounds with a stuck
                                // flag means the RunFunction never landed.
                                const uint32_t w415post =
                                    g_host->MemoryRead32(0x40673288u);
                                LOGI("[W415] round release post-flag=%u",
                                     w415post);
                                LOGI("[W338] pause released (round)");
                            }
                        }
                        // W342b (run455): the W303 ACK-clear REMOVED. Zeroing
                        // [app+0x38] before the wake made the pump see "no
                        // command" every round (W295 pipe reads stayed 0 for
                        // 40+ runs). The pump itself clears the field after
                        // android_handle_cmd; wiping it here only deleted the
                        // command the pipe byte was announcing.
                        // W289b (run414): pthread_cond_broadcast is an IMPORT,
                        // never an ELF export -- FindSymbol always returned 0
                        // and the periodic broadcast never fired (one
                        // W40BCST per run, from android_app_entry itself).
                        // Resolve through the thunk manager instead.
                        const uint32_t cond_bc = g_host->GetThunkManager().GetOrCreateThunkAddress(
                            "pthread_cond_broadcast");
                        const uint32_t live_app2 = g_host->MemoryRead32(0x93000160u);
                        if (cond_bc && live_app2)
                            g_host->RunFunction(cond_bc, {live_cond ? live_cond : (live_app2 + 0x44u)});
                        {
                            static std::atomic<uint32_t> w289n{0};
                            if (w289n.fetch_add(1) < 16)
                                DiagTrace::Note("W289BC cond=0x" + [] (uint32_t v) {
                                    char t[16]; snprintf(t, sizeof(t), "%08X", v); return std::string(t);
                                }(live_cond ? live_cond : (live_app2 ? live_app2 + 0x44u : 0)));
                        }

                    }
                }
            }
        });
    }
    return true;
}

}  // namespace

AAssetManager* BridgeGetAssetManager() {
    if (!g_host || !g_guest_activity) return nullptr;
    const uint32_t managerHandle =
        g_host->MemoryRead32(g_guest_activity + kActivityAssetManager);
    return static_cast<AAssetManager*>(HostPointerFor(managerHandle));
}

// W477 accessors (external linkage; the state lives in the anonymous
// namespace above, visible here by ordinary lookup within this TU).
namespace BridgeEgl477 {
bool DisplayReady() { return g_w477_display_ready.load(); }
bool ThreadDone() { return g_w477_thread_done.load(); }
bool Failed() { return g_w477_failed.load(); }
void DisplayTerminated(EGLDisplay display) {
    if (display != g_w477_display) return;
    g_w477_display_ready.store(false, std::memory_order_release);
    g_w477_full.store(false, std::memory_order_release);
    LOGI("EGL display terminated; next guest initialization will use a host worker");
}
void EnsureDisplayWorker() {
    if (g_w477_display_ready.load(std::memory_order_acquire)) return;
    bool expected = false;
    if (!g_w477_worker_active.compare_exchange_strong(expected, true,
            std::memory_order_acq_rel)) return;
    g_w477_failed.store(false, std::memory_order_release);
    g_w477_thread_done.store(false, std::memory_order_release);
    std::thread([] {
        W477InitEGLHost();
        g_w477_worker_active.store(false, std::memory_order_release);
    }).detach();
}
EGLDisplay Display() { return g_w477_display; }
EGLConfig Config() { return g_w477_config; }
EGLSurface Surface() { return g_w477_surface; }
EGLContext Context() { return g_w477_context; }
EGLint MajorVer() { return g_w477_major; }
EGLint MinorVer() { return g_w477_minor; }
}  // namespace BridgeEgl477

// W58: EGL redirection target -- the CURRENT bridge surface window. The
// guest may hold a stale handle after the system's surface recreate; EGL
// must always draw on the live window.
ANativeWindow* BridgeCurrentSurfaceWindow() {
    return g_bridge_surface_window;
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    g_jvm = vm;
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    RegisterNativeFunctions(env);
    RegisterFmodAudio(env);
    LOGI("ARM64 host JNI_OnLoad");
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT void JNICALL ANativeActivity_onCreate(ANativeActivity* activity,
                                                              void* saved_state,
                                                              size_t saved_state_size) {
    if (!activity || !activity->vm || !activity->env) return;
    {
        std::lock_guard<std::mutex> lock(g_input_queue_mutex);
        if (g_input_queue_current)
            FailInputQueue("new Activity with an unretired input queue",
                           g_input_queue_current->number, g_input_queue_current->guest_handle);
        g_input_guest_ready = false;
    }
    g_jvm = activity->vm;
    g_host_activity = activity;
    FakeJniEnv& fake = FakeJniEnv::Instance();
    fake.SetJavaVM(g_jvm);
    fake.SetApplicationClassLoader(activity->env, activity->clazz);
    if (activity->callbacks) InstallHostCallbacks(activity);
    else LOGE("NativeActivity callback table is null; host lifecycle forwarding unavailable");
    g_apk_path = ApplicationSourceDir(activity);
    g_files_path = activity->externalDataPath ? activity->externalDataPath : activity->internalDataPath;
    // D1: periodic no-progress trace to <files>/bridge_diag.txt (diagnostic-only).
    DiagTrace::Start(g_files_path);
    DiagTrace::SetPcProvider([] { return g_host ? g_host->SampleGuestPcs() : std::vector<uint32_t>{}; });
    // C1: heap canary pass rides the same 10 s dump cadence (diagnostic-only).
    DiagTrace::SetHeapCheckProvider([] { return g_host ? g_host->DiagCheckHeapCanaries() : std::string{}; });
    // N1: live gDynamic_vb_map walk on the same cadence (diagnostic-only).
    DiagTrace::SetMapWalkProvider([] { return g_host ? g_host->DiagWalkDynamicVbMap() : std::string{}; });
    // W146: data-segment smash sentinel on the same cadence (diagnostic-only).
    DiagTrace::SetSentinelProvider([] {
        if (!g_host) return std::string{};
        std::string out = g_host->DiagW146Sentinels();
        const uint32_t app = g_startup_gate_app.load(std::memory_order_acquire);
        const uint32_t stage = g_startup_gate_stage.load(std::memory_order_acquire);
        const uint32_t state = app ? g_host->MemoryRead32(app + 0x38u) : 0u;
        const uint32_t window = app ? g_host->MemoryRead32(app + 0x24u) : 0u;
        const uint32_t pending = app ? g_host->MemoryRead32(app + 0x80u) : 0u;
        char startup[224];
        snprintf(startup, sizeof(startup),
                 "HOSTSTART stage=%02X armed=%u app=%08X state=%u window=%08X pending=%08X pause=%u surface=%u display=%u nova=%u",
                 stage, g_startup_gate_armed.load(std::memory_order_acquire) ? 1u : 0u,
                 app, state, window, pending,
                 g_host->MemoryRead32(0x40673288u) & 0xFFu,
                 g_host->MemoryRead32(0x406D94ACu) & 0xFFu,
                 g_host->MemoryRead32(0x406CA9F4u) & 0xFFu,
                 g_host->MemoryRead32(0x930017B0u));
        if (!out.empty()) out += '\n';
        out += startup;
        char input_state[256];
        snprintf(input_state, sizeof(input_state),
                 "\nINPUTSTATE host_queue=%p guest_queue=%08X pending_queue=%08X looper=%08X callback=%08X delivered=%08X on_input=%08X",
                 static_cast<void*>(g_host_input_queue.load(std::memory_order_acquire)),
                 app ? g_host->MemoryRead32(app + 0x20u) : 0u,
                 app ? g_host->MemoryRead32(app + 0x7Cu) : 0u,
                 app ? g_host->MemoryRead32(app + 0x1Cu) : 0u,
                 GuestCallback(kOnInputQueueCreated),
                 g_last_guest_input_queue_created.load(std::memory_order_acquire),
                 app ? g_host->MemoryRead32(app + 0x08u) : 0u);
        out += input_state;
        out += '\n';
        out += BridgeInputDiagnosticSnapshot();
        char startret[256];
        snprintf(startret, sizeof(startret),
                 "W491 entry=%u entry_lr1=%08X entry_lr2=%08X bsi_exit=%u sp=%08X saved_lr=%08X lr=%08X r4=%08X r5=%08X r6=%08X r7=%08X r8=%08X r9=%08X r10=%08X r0=%08X lr1=%08X lr2=%08X",
                 g_host->MemoryRead32(0x93001900u),
                 g_host->MemoryRead32(0x93001904u),
                 g_host->MemoryRead32(0x93001908u),
                 g_host->MemoryRead32(0x930018A0u),
                 g_host->MemoryRead32(0x930018A4u),
                 g_host->MemoryRead32(0x930018A8u),
                 g_host->MemoryRead32(0x930018ACu),
                 g_host->MemoryRead32(0x930018B0u),
                 g_host->MemoryRead32(0x930018B4u),
                 g_host->MemoryRead32(0x930018B8u),
                 g_host->MemoryRead32(0x930018BCu),
                 g_host->MemoryRead32(0x930018C0u),
                 g_host->MemoryRead32(0x930018C4u),
                 g_host->MemoryRead32(0x930018C8u),
                 g_host->MemoryRead32(0x930018CCu),
                 g_host->MemoryRead32(0x930018E0u),
                 g_host->MemoryRead32(0x930018E4u));
        out += '\n';
        out += startret;
        const std::string egl = BridgeEglDiagnosticSnapshot();
        if (!egl.empty()) { out += '\n'; out += egl; }
        return out;
    });
    // W3: luaD_throw + W7 __cxa_throw/Android_fopen scratch dumps on the same
    // cadence (diagnostic-only).
    DiagTrace::SetErrorDumpProvider([] {
        if (!g_host) return std::string{};
        std::string out = g_host->DiagReadLuaThrow();
        for (const auto& part : {g_host->DiagReadFopenPath(), g_host->DiagReadCxaThrow(),
                                 g_host->DiagReadThrowLengthError()}) {
            if (!part.empty()) {
                if (!out.empty()) out += "\n";
                out += part;
            }
        }
        // W16b: stuck-thread state + low-page hex (every cycle while any
        // thread sits in the bridge page).
        const std::string stuck = g_host->DiagDumpStuckThreads();
        if (!stuck.empty()) {
            if (!out.empty()) out += "\n";
            out += stuck;
        }
        char boot_state[192];
        snprintf(boot_state, sizeof(boot_state),
                 "BOOT stage=%08X JNI_OnLoad=%08X cls=%08X surface=%08X display=%08X",
                 g_host->MemoryRead32(0x93001790u),
                 g_host->MemoryRead32(0x930017A4u),
                 g_host->MemoryRead32(0x406D917Cu),
                 g_host->MemoryRead32(0x406D94ACu),
                 g_host->MemoryRead32(0x406CA9F4u));
        if (!out.empty()) out += "\n";
        out += boot_state;
        return out;
    });
    // W337 (run452): move the guest boot OFF the Android main thread --
    // the synchronous boot blocked input for >5 s and triggered ANR.
    // The W263/W286 async machinery delivers the lifecycle afterwards.
    DynarmicHost::SpawnLargeStackThread("guest-boot", [activity, saved_state, saved_state_size] {
    FakeJniEnv& fake = FakeJniEnv::Instance();
    fake.SetJavaVM(activity->vm);
    JNIEnv* boot_env = fake.GetEnv();
    if (!boot_env) {
        LOGE("guest boot thread could not attach to the Java VM");
        return;
    }
    const std::string obb_directory = activity->obbPath && activity->obbPath[0] == '/'
        ? activity->obbPath : ApplicationObbDirectory(boot_env, activity->clazz);
    if (!EnsureGameLoaded(boot_env, activity->assetManager, obb_directory.c_str())) {
        LOGE("guest boot failed");
        return;
    }
    // W3 retired: its diagnostic trampoline skipped luaD_throw's original
    // callee-saved-register prologue and corrupted the exception frame.
    InstallFopenDiagDumper(*g_host);
    // W10: capture the std::length_error message + throw site at the
    // __throw_length_error entry (the boot terminate comes through it).
    InstallThrowLenDumper(*g_host);
    // W331 retired: this diagnostic trampoline overwrote __cxa_throw's
    // second instruction and resumed at that overwritten word. Never patch
    // the guest exception ABI entry for logging; the bridge-side unwinder
    // diagnostics are non-invasive.
    // W10b causal repair: constant-4 android_getCpuCount (its pthread_once
    // initializer never runs under the bridge, leaving the count at 0 and
    // TaskManager::Start at -1 workers = the boot terminate).
    InstallCpuCountStub(*g_host);
    // W335: snapshot the pristine GOT before any guest code runs.
    SnapshotGotShadow(*g_host);
    // W20: WAD parse flow markers (dir-entry + tail counters).
    InstallWadParseMarkers(*g_host);
    // W10c: register the stub/scratch region as executable. MemoryReadCode's
    // runaway-PC containment traps any code fetch outside the loaded modules
    // and below 0x20000 -- the 0x65A000 stub page is outside both, which is
    // why every relocated stub (W5+) halted on its own second instruction
    // (run25/28/30: halt pc = stub+4, R0 untouched). Covers qsort routine,
    // once/luaD/fopen/cxa/throwlen stubs and their scratch blocks.
    // W22e: extended -- W22/W23 markers live at 0x65B000-0x65B400 (epilogue,
    // file-loop-exit, dir-entry v2, dumps); with the old 0x1000 span the
    // code fetch at 0x65B040+ was treated as RUNAWAY and silently killed
    // the WAD parse thread at its first marker.
    // W42: the range end doubles as the thunk-trampoline allocation frontier
    // (m_next_thunk_addr at install time); a late RegisterThunk lands its
    // [SVC #id; BX lr] trampoline at the OLD end (0x661828) and its code
    // fetch was treated as runaway. Keep +0x1000 slack past the frontier.
    g_host->AddExecutableRange(0x0065A000, 0x661830u - 0x65A000 + 0x1000);  // W33b+W42: gap + .init_array + trampoline slack
    // Bridge-owned code must not share the low guest-memory page that mmap,
    // zero-fill, and fixed compatibility veneers can all touch.
    // W8: InstallCxaThrowDumper remains uninstalled — its trampoline halts
    // (UserDefined1) on its second instruction in the live guest (run25:
    // HALT pc=0x65AD44 lr=0x405D8348), so installing it kills the worker
    // before the terminate. The throw site it captured (lr=0x405D8348 =
    // libParsons+0x5D8348) is already recorded.
    // Guest JNI_OnLoad initializes Java class and method handles consumed by
    // __android_init_display. The old direct-boot bypass skipped that contract,
    // leaving valid JNI calls with null class/method IDs.
    if (!RunGuestJniOnLoad(boot_env)) {
        LOGE("guest JNI_OnLoad failed; refusing to boot with uninitialized JNI state");
        return;
    }
    LOGE("[W555] post-OnLoad display handles cls=%08X mid1=%08X mid2=%08X",
         g_host->MemoryRead32(0x406D917Cu), g_host->MemoryRead32(0x406D9180u),
         g_host->MemoryRead32(0x406D9184u));
    // N5: open gDynamic_vb_map before the guest can reach the reload branch.
    OpenGuestDynamicVertexBuffers();
    if (!StartGuestActivity(activity, saved_state, saved_state_size)) {
        LOGE("guest ANativeActivity_onCreate failed");
    }
    });
}
