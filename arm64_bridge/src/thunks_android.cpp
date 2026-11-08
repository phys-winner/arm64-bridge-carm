#include "thunks_android.h"

#include "diag_trace.h"
#include "dynarmic_host.h"
#include "jni_fake_env.h"
#include "native_handle_table.h"
#include "obb_source.h"
#include "thunk_manager.h"
#include "thunk_types.h"

#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <android/configuration.h>
#include <android/input.h>
#include <android/log.h>
#include <android/looper.h>
#include <android/native_window.h>
#include <android/sensor.h>
#include <jni.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <fcntl.h>
#include <limits>
#include <memory>
#include <sched.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include <zlib.h>

#define LOG_TAG "Arm32Bridge_Android"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {
using Jit = Dynarmic::A32::Jit;
std::mutex g_input_diag_mutex;
std::string g_input_attach_diag;

// The original OBB has one 40-byte directory entry wrapping DATA_ANDROID.WAD.
// Keep the container intact in the APK; only this guest-visible asset name gets
// a bounded view into its payload. Ordinary AAssets still use Android directly.
constexpr char kWadName[] = "DATA_ANDROID.WAD";
constexpr uint32_t kWadSize = 78691960u;
constexpr uint32_t kObbHeaderSize = 40u;
constexpr uint32_t kObbCrc32 = 0xdc78f4d0u;

enum class ObbKind { None, Embedded, External };
struct SelectedObb {
    int fd = -1;
    off64_t base = 0;
    AAsset* embedded_asset = nullptr;  // Keeps the AssetManager FD alive.
    ObbKind kind = ObbKind::None;
    std::string guest_path;
};
std::mutex g_obb_source_mutex;
SelectedObb g_selected_obb;

struct AssetView {
    AssetView(int source_fd, off64_t base, uint32_t size)
        : fd(source_fd), physical_base(base), length(size) {}
    ~AssetView() { close(fd); }

    int fd;
    off64_t physical_base;
    uint32_t length;
    uint32_t cursor = 0;
    std::mutex cursor_mutex;
};

std::mutex g_asset_view_mutex;
std::unordered_map<AAsset*, std::shared_ptr<AssetView>> g_asset_views;
std::atomic<uint64_t> g_asset_view_token{1};

bool IsViewToken(AAsset* asset) {
    return (reinterpret_cast<uintptr_t>(asset) & 1u) != 0;
}

std::shared_ptr<AssetView> FindAssetView(AAsset* asset) {
    std::lock_guard<std::mutex> lock(g_asset_view_mutex);
    auto it = g_asset_views.find(asset);
    return it == g_asset_views.end() ? nullptr : it->second;
}

uint32_t ReadLe32(const uint8_t* bytes) {
    return static_cast<uint32_t>(bytes[0]) |
           (static_cast<uint32_t>(bytes[1]) << 8) |
           (static_cast<uint32_t>(bytes[2]) << 16) |
           (static_cast<uint32_t>(bytes[3]) << 24);
}

bool ReadExactlyAt(int fd, void* buffer, size_t length, off64_t offset) {
    auto* out = static_cast<uint8_t*>(buffer);
    while (length != 0) {
        ssize_t count = pread(fd, out, length, offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        out += count;
        length -= static_cast<size_t>(count);
        offset += count;
    }
    return true;
}

bool ValidateWholeObb(int fd, off64_t base, off64_t length) {
    struct stat source_stat{};
    if (fd < 0 || base < 0 || length != kBridgeObbSize ||
        fstat(fd, &source_stat) != 0 || !S_ISREG(source_stat.st_mode) ||
        source_stat.st_size < 0 ||
        static_cast<uint64_t>(base) > static_cast<uint64_t>(source_stat.st_size) ||
        static_cast<uint64_t>(length) >
            static_cast<uint64_t>(source_stat.st_size) - static_cast<uint64_t>(base)) {
        return false;
    }
    uint8_t directory[kObbHeaderSize]{};
    uint8_t wad_header[4]{};
    const bool header_read = ReadExactlyAt(fd, directory, sizeof(directory), base);
    const uint32_t payload_offset = header_read ? ReadLe32(directory + 28) : 0;
    const uint32_t payload_size = header_read ? ReadLe32(directory + 32) : 0;
    const bool structure_valid = header_read &&
        ReadLe32(directory) == 1u && ReadLe32(directory + 4) == 1u &&
        ReadLe32(directory + 8) == sizeof(kWadName) - 1u &&
        memcmp(directory + 12, kWadName, sizeof(kWadName) - 1u) == 0 &&
        payload_offset == kObbHeaderSize && payload_size == kWadSize &&
        static_cast<uint64_t>(payload_offset) + payload_size == kBridgeObbSize &&
        ReadLe32(directory + 36) == UINT32_MAX &&
        ReadExactlyAt(fd, wad_header, sizeof(wad_header), base + payload_offset) &&
        wad_header[0] == 0x34 && wad_header[1] == 0x12 &&
        wad_header[2] == 0x02 && wad_header[3] == 0x02;
    if (!structure_valid) return false;

    // Check the *entire* original container before choosing a source. A good
    // 40-byte wrapper alone cannot distinguish a damaged external WAD.
    std::array<uint8_t, 64 * 1024> block{};
    uLong crc = crc32(0L, Z_NULL, 0);
    for (off64_t cursor = 0; cursor < length;) {
        const size_t count = std::min<size_t>(block.size(), length - cursor);
        if (!ReadExactlyAt(fd, block.data(), count, base + cursor)) return false;
        crc = crc32(crc, block.data(), static_cast<uInt>(count));
        cursor += count;
    }
    if (static_cast<uint32_t>(crc) != kObbCrc32) {
        LOGE("whole OBB CRC32 mismatch: got=%08x expected=%08x",
             static_cast<uint32_t>(crc), kObbCrc32);
        return false;
    }
    return true;
}

std::string ObbPathFromDirectory(const char* directory) {
    if (!directory || directory[0] != '/') return {};
    std::string path(directory);
    while (path.size() > 1 && path.back() == '/') path.pop_back();
    if (path == "/") return {};
    return path + "/" + kBridgeObbName;
}

AAsset* OpenWholeObbWad() {
    BridgeObbHandle source;
    if (!BridgeOpenSelectedObb(&source)) {
        LOGE("WAD view unavailable: no validated whole OBB source");
        return nullptr;
    }
    auto view = std::make_shared<AssetView>(source.fd, source.offset + kObbHeaderSize, kWadSize);
    // Odd, monotonically increasing opaque tokens cannot alias Android's
    // aligned AAsset pointers. A concurrent read after close fails closed,
    // rather than passing a freed synthetic pointer to Android's AAsset API.
    const uintptr_t token_bits = (g_asset_view_token.fetch_add(1) << 1) | 1u;
    AAsset* token = reinterpret_cast<AAsset*>(token_bits);

    {
        std::lock_guard<std::mutex> lock(g_asset_view_mutex);
        g_asset_views.emplace(token, std::move(view));
    }
    LOGI("WAD view: source=%s payload offset=%u length=%u",
         BridgeSelectedObbSourceName(), kObbHeaderSize, kWadSize);
    return token;
}

int ReadAsset(AAsset* asset, void* buffer, uint32_t length) {
    if (!asset || (!buffer && length != 0)) return -1;
    auto view = FindAssetView(asset);
    if (!view) return IsViewToken(asset) ? -1 : AAsset_read(asset, buffer, length);
    std::lock_guard<std::mutex> lock(view->cursor_mutex);
    if (length == 0 || view->cursor == view->length) return 0;
    const size_t count = std::min<size_t>(
        {length, view->length - view->cursor, static_cast<size_t>(std::numeric_limits<int>::max())});
    ssize_t result;
    do {
        result = pread(view->fd, buffer, count, view->physical_base + view->cursor);
    } while (result < 0 && errno == EINTR);
    if (result == 0) {
        errno = EIO;  // EOF before the validated logical end is a corrupt source.
        return -1;
    }
    if (result > 0) view->cursor += static_cast<uint32_t>(result);
    return static_cast<int>(result);
}

off_t SeekAsset(AAsset* asset, int32_t offset, int whence) {
    if (!asset) return -1;
    auto view = FindAssetView(asset);
    if (!view) return IsViewToken(asset) ? -1 : AAsset_seek(asset, static_cast<off_t>(offset), whence);
    std::lock_guard<std::mutex> lock(view->cursor_mutex);
    int64_t origin;
    switch (whence) {
        case SEEK_SET: origin = 0; break;
        case SEEK_CUR: origin = view->cursor; break;
        case SEEK_END: origin = view->length; break;
        default: return -1;
    }
    const int64_t target = origin + offset;
    if (target < 0 || target > view->length) return -1;
    view->cursor = static_cast<uint32_t>(target);
    return static_cast<off_t>(target);
}

uint32_t AssetLength(AAsset* asset) {
    if (!asset) return 0;
    auto view = FindAssetView(asset);
    return view ? view->length : IsViewToken(asset) ? 0u
                : static_cast<uint32_t>(AAsset_getLength(asset));
}

void CloseAsset(AAsset* asset) {
    if (!asset) return;
    const bool synthetic = IsViewToken(asset);
    {
        std::lock_guard<std::mutex> lock(g_asset_view_mutex);
        if (synthetic) g_asset_views.erase(asset);
    }
    if (!synthetic) AAsset_close(asset);
    ReleaseGuestHandle(asset);
}

const char* GuestString(DynarmicHost& host, uint32_t addr) {
    if (!addr || !GuestRangeValid(host.GetGuestMemorySize(), addr, 1)) return nullptr;
    const size_t remaining = host.GetGuestMemorySize() - addr;
    const char* text = reinterpret_cast<const char*>(host.GetGuestMemoryBase() + addr);
    return static_cast<const char*>(memchr(text, 0, remaining)) ? text : nullptr;
}

uint32_t FloatBits(float value) {
    uint32_t bits;
    memcpy(&bits, &value, sizeof(bits));
    return bits;
}

void SetInt64(Jit& jit, int64_t value) {
    const uint64_t bits = static_cast<uint64_t>(value);
    jit.Regs()[0] = static_cast<uint32_t>(bits);
    jit.Regs()[1] = static_cast<uint32_t>(bits >> 32);
}

template <typename T>
T* Host(uint32_t handle) {
    return static_cast<T*>(HostPointerFor(handle));
}

uint32_t CopyHostString(DynarmicHost& host, const char* value) {
    if (!value) return 0;
    const size_t size = strlen(value) + 1;
    const uint32_t guest = host.GuestAlloc(size, 4);
    if (guest) memcpy(host.GetGuestMemoryBase() + guest, value, size);
    return guest;
}

struct CallbackBinding {
    DynarmicHost* host;
    uint32_t guest_callback;
    uint32_t guest_data;
};

int ForwardLooperCallback(int fd, int events, void* data) {
    auto* binding = static_cast<CallbackBinding*>(data);
    if (!binding || !binding->host || !binding->guest_callback) return 0;
    const uint32_t result = binding->host->RunFunction(
        binding->guest_callback,
        {static_cast<uint32_t>(fd), static_cast<uint32_t>(events), binding->guest_data});
    if (!result) delete binding;
    return result ? 1 : 0;
}

int PollAll(int timeout, int* out_fd, int* out_events, void** out_data) {
    // W485 (run640): the game thread's display-wait loop polls with an
    // infinite timeout; with no looper fds ever registered (the glue never
    // ran under the W472 direct boot) that parks the thread in host epoll
    // forever -- even after the W478 stub completed display init. Cap
    // negative timeouts at 100 ms so every guest wait loop keeps cycling.
    if (timeout < 0) timeout = 100;
    for (;;) {
        const int result = ALooper_pollOnce(timeout, out_fd, out_events, out_data);
        if (result != ALOOPER_POLL_CALLBACK) return result;
    }
}

std::mutex g_asset_dir_mutex;
std::unordered_map<uint32_t, uint32_t> g_asset_dir_names;
std::mutex g_sensor_mutex;
std::unordered_map<uint32_t, uint32_t> g_sensor_lists;
std::unordered_map<const void*, uint32_t> g_sensor_strings;

uint32_t AssetDirName(DynarmicHost& host, uint32_t dir_handle, const char* name) {
    if (!name) return 0;
    std::lock_guard<std::mutex> lock(g_asset_dir_mutex);
    uint32_t& guest = g_asset_dir_names[dir_handle];
    if (!guest) guest = host.GuestAlloc(256, 1);
    if (!guest) return 0;
    char* out = reinterpret_cast<char*>(host.GetGuestMemoryBase() + guest);
    strncpy(out, name, 255);
    out[255] = 0;
    return guest;
}

uint32_t SensorString(DynarmicHost& host, const void* sensor, const char* value) {
    if (!value) return 0;
    std::lock_guard<std::mutex> lock(g_sensor_mutex);
    auto it = g_sensor_strings.find(sensor);
    if (it != g_sensor_strings.end()) return it->second;
    const uint32_t guest = CopyHostString(host, value);
    if (guest) g_sensor_strings.emplace(sensor, guest);
    return guest;
}

}  // namespace

bool BridgeInitializeObbSource(AAssetManager* manager, const char* obb_directory) {
    std::lock_guard<std::mutex> lock(g_obb_source_mutex);
    if (g_selected_obb.fd >= 0) {
        if (g_selected_obb.guest_path.empty())
            g_selected_obb.guest_path = ObbPathFromDirectory(obb_directory);
        return true;  // One source for this process.
    }
    g_selected_obb.guest_path = ObbPathFromDirectory(obb_directory);

    // Test-only source fault injection. A valid embedded asset normally wins;
    // bypassing it here lets an ABB diagnostic exercise the external fallback
    // without altering the signed game data. Production builds set this OFF.
#if BRIDGE_TEST_FORCE_EXTERNAL_OBB
    LOGI("diagnostic source selection: embedded OBB deliberately skipped");
#else
    if (manager) {
        AAsset* asset = AAssetManager_open(manager, kBridgeObbName, AASSET_MODE_RANDOM);
        if (asset) {
            off64_t start = 0;
            off64_t length = 0;
            const int fd = AAsset_openFileDescriptor64(asset, &start, &length);
            if (AAsset_getLength64(asset) == kBridgeObbSize &&
                ValidateWholeObb(fd, start, length)) {
                g_selected_obb.fd = fd;
                g_selected_obb.base = start;
                g_selected_obb.embedded_asset = asset;
                g_selected_obb.kind = ObbKind::Embedded;
                LOGI("OBB source=embedded base=%lld size=%u crc32=%08x",
                     static_cast<long long>(start), kBridgeObbSize, kObbCrc32);
                return true;
            }
            LOGE("embedded OBB rejected: missing direct FD, bad length, header or CRC32");
            if (fd >= 0) close(fd);
            AAsset_close(asset);
        } else {
            LOGE("embedded OBB asset missing: %s", kBridgeObbName);
        }
    }
#endif

    if (!g_selected_obb.guest_path.empty()) {
        const int fd = open(g_selected_obb.guest_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        struct stat file_stat{};
        if (fd >= 0 && fstat(fd, &file_stat) == 0 &&
            file_stat.st_size == kBridgeObbSize &&
            ValidateWholeObb(fd, 0, kBridgeObbSize)) {
            g_selected_obb.fd = fd;
            g_selected_obb.base = 0;
            g_selected_obb.kind = ObbKind::External;
            LOGI("OBB source=external path=%s size=%u crc32=%08x",
                 g_selected_obb.guest_path.c_str(), kBridgeObbSize, kObbCrc32);
            return true;
        }
        LOGE("external OBB missing or rejected: %s", g_selected_obb.guest_path.c_str());
        if (fd >= 0) close(fd);
    } else {
        LOGE("external OBB unavailable: Android supplied no application OBB directory");
    }
    return false;
}

bool BridgeOpenSelectedObb(BridgeObbHandle* out) {
    if (!out) return false;
    std::lock_guard<std::mutex> lock(g_obb_source_mutex);
    if (g_selected_obb.fd < 0) return false;
    const int fd = dup(g_selected_obb.fd);
    if (fd < 0) return false;
    *out = {fd, g_selected_obb.base, kBridgeObbSize};
    return true;
}

bool BridgeIsObbPath(const char* path) {
    if (!path) return false;
    const char* slash = strrchr(path, '/');
    return strcmp(slash ? slash + 1 : path, kBridgeObbName) == 0;
}

std::string BridgeObbGuestPath() {
    std::lock_guard<std::mutex> lock(g_obb_source_mutex);
    return g_selected_obb.guest_path;
}

const char* BridgeSelectedObbSourceName() {
    std::lock_guard<std::mutex> lock(g_obb_source_mutex);
    switch (g_selected_obb.kind) {
        case ObbKind::Embedded: return "embedded";
        case ObbKind::External: return "external";
        default: return "none";
    }
}

std::string BridgeInputDiagnosticSnapshot() {
    std::lock_guard<std::mutex> lock(g_input_diag_mutex);
    return g_input_attach_diag;
}

void RegisterAndroidThunks(ThunkManager& manager) {
    manager.RegisterThunk("ALooper_prepare", [](Jit& jit, DynarmicHost&) {
        void* lp = ALooper_prepare(static_cast<int>(jit.Regs()[0]));
        // W341 (run454): the glue's looper creation -- the pump wakes only
        // through this looper; log via diag ring (logcat drops it).
        {
            static std::atomic<uint32_t> w341{0};
            if (w341.fetch_add(1) < 8) {
                char b[160];
                snprintf(b, sizeof(b), "W341 prepare opt=%d -> looper=%p tid=%u",
                         static_cast<int>(jit.Regs()[0]), lp,
                         static_cast<uint32_t>(gettid()));
                DiagTrace::NotePersist(b);
            }
        }
        jit.Regs()[0] = GuestHandleFor(lp);
    });
    manager.RegisterThunk("ALooper_addFd", [](Jit& jit, DynarmicHost& host) {
        ALooper* looper = Host<ALooper>(jit.Regs()[0]);
        const int fd = static_cast<int>(jit.Regs()[1]);
        const int ident = static_cast<int>(jit.Regs()[2]);
        const int events = static_cast<int>(jit.Regs()[3]);
        const uint32_t callback = host.MemoryRead32(jit.Regs()[13]);
        const uint32_t guest_data = host.MemoryRead32(jit.Regs()[13] + 4);
        CallbackBinding* binding = nullptr;
        ALooper_callbackFunc callback_fn = nullptr;
        if (callback) {
            binding = new CallbackBinding{&host, callback, guest_data};
            callback_fn = ForwardLooperCallback;
        }
        const int result = looper ? ALooper_addFd(
            looper, fd, ident, events, callback_fn,
            binding ? static_cast<void*>(binding) : reinterpret_cast<void*>(static_cast<uintptr_t>(guest_data))) : -1;
        if (result < 0 && binding) delete binding;
        // W309 (run404c): trace every looper fd registration -- the msgread
        // fd must land in the real poll set, or pollAll never wakes.
        {
            static std::atomic<uint32_t> w309{0};
            if (w309.fetch_add(1) < 16) {
                char b[160];
                snprintf(b, sizeof(b),
                         "W309 addFd looper=%p fd=%d ident=%d events=%d callback=%08X data=%08X -> %d",
                         (const void*)looper, fd, ident, events, callback, guest_data, result);
                LOGI("%s", b);
                // W339 (run454): persist through the diag ring -- logcat
                // throttling dropped this line in run453.
                DiagTrace::NotePersist(std::string(b));
            }
        }
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });
    manager.RegisterThunk("ALooper_pollAll", [](Jit& jit, DynarmicHost& host) {
        int fd = 0;
        int events = 0;
        void* data = nullptr;
        const int timeout = static_cast<int>(jit.Regs()[0]);
        // C3 companion fix: the guest's startup pump polls with timeout=0 and
        // burned a JIT core at ~130 kHz of empty polls (324,648 calls in ~2.5 s
        // in the D1 route). Yield on every empty poll and back off to a 1 ms
        // sleep after a long run of empties; any real event resets the counter,
        // so event latency is unchanged.
        static thread_local uint32_t t_empty_polls = 0;
        const int result = PollAll(timeout, &fd, &events, &data);
        const uintptr_t raw_data = reinterpret_cast<uintptr_t>(data);
        const uint32_t guest_data = raw_data <= UINT32_MAX ? static_cast<uint32_t>(raw_data) : 0;
        // Persist non-timeout returns with the guest source pointer and caller
        // so a ready fd can be distinguished from a dispatched app command.
        {
            static std::atomic<uint32_t> w340_events{0};
            if (result != ALOOPER_POLL_TIMEOUT) {
                const uint32_t n = w340_events.fetch_add(1);
                if (n < 32) {
                    char b[320];
                    const uint32_t source_process = guest_data
                        ? host.MemoryRead32(guest_data + 8u) : 0u;
                    const uint32_t cmdproc_hits = host.MemoryRead32(0x93001744u);
                    const uint32_t dispatch_hits = host.MemoryRead32(0x9300174Cu);
                    const uint32_t dispatch_target = host.MemoryRead32(0x93001750u);
                    const uint32_t cmdproc_entry = host.MemoryRead32(0x4017D9ACu);
                    const uint32_t cmdproc_stub = host.MemoryRead32(0x8F117940u);
                    const uint32_t dispatch_call = host.MemoryRead32(0x403DA2A8u);
                    snprintf(b, sizeof(b),
                             "W340 event n=%u res=%d fd=%d ev=%d data=%08X proc=%08X hits=%u dispatch=%u target=%08X entry=%08X stub=%08X call=%08X raw=%p lr=%08X tid=%u",
                             n, result, fd, events, guest_data, source_process,
                             cmdproc_hits, dispatch_hits, dispatch_target,
                             cmdproc_entry, cmdproc_stub, dispatch_call, data, jit.Regs()[14],
                             static_cast<uint32_t>(gettid()));
                    DiagTrace::NotePersist(b);
                }
            }
        }
        {
            static std::atomic<uint32_t> w301b{0};
            if (result != 0 /*ALOOPER_POLL_TIMEOUT*/ && w301b.fetch_add(1) < 40) {
                char b[128];
                snprintf(b, sizeof(b), "W301b poll fd=%d events=%d res=%d to=%d", fd, events, result, timeout);
                DiagTrace::NotePersist(b);
            }
        }
        // W85: -3 is ALOOPER_POLL_TIMEOUT, not an error. Record only the
        // documented -4 ALOOPER_POLL_ERROR result; normal empty polls must
        // not flood the persistent diagnostic ring and evict causal events.
        if (result == ALOOPER_POLL_ERROR) {
            static std::atomic<uint32_t> w85_errors{0};
            const uint32_t n = w85_errors.fetch_add(1);
            if (n < 512) {
                char b[128];
                snprintf(b, sizeof(b), "W85POLLERR res=%d errno=%d n=%u lr=%08X tid=%u",
                         result, errno, n, jit.Regs()[14], static_cast<uint32_t>(gettid()));
                DiagTrace::NotePersist(b);
            }
        }
        if (result == ALOOPER_POLL_TIMEOUT) {
            if (++t_empty_polls >= 2048) {
                t_empty_polls = 0;
                usleep(1000);
            } else {
                sched_yield();
            }
        } else {
            t_empty_polls = 0;
        }
        if (raw_data > UINT32_MAX) LOGE("ALooper_pollAll returned non-guest data %p", data);
        if (jit.Regs()[1]) host.MemoryWrite32(jit.Regs()[1], static_cast<uint32_t>(fd));
        if (jit.Regs()[2]) host.MemoryWrite32(jit.Regs()[2], static_cast<uint32_t>(events));
        if (jit.Regs()[3]) host.MemoryWrite32(jit.Regs()[3], guest_data);
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });

    manager.RegisterThunk("AInputQueue_attachLooper", [](Jit& jit, DynarmicHost& host) {
        AInputQueue* queue = Host<AInputQueue>(jit.Regs()[0]);
        ALooper* looper = Host<ALooper>(jit.Regs()[1]);
        const uint32_t callback = jit.Regs()[3];
        const uint32_t guest_data = host.MemoryRead32(jit.Regs()[13]);
        CallbackBinding* binding = nullptr;
        ALooper_callbackFunc callback_fn = nullptr;
        if (callback) {
            binding = new CallbackBinding{&host, callback, guest_data};
            callback_fn = ForwardLooperCallback;
        }
        if (queue && looper) {
            AInputQueue_attachLooper(queue, looper, static_cast<int>(jit.Regs()[2]), callback_fn,
                                     binding ? static_cast<void*>(binding) : reinterpret_cast<void*>(static_cast<uintptr_t>(guest_data)));
        } else if (binding) {
            delete binding;
        }
        char note[256];
        snprintf(note, sizeof(note),
                 "INPUTATTACH tid=%u queue=%p looper=%p thread_looper=%p ident=%d callback=%08X source=%08X",
                 static_cast<uint32_t>(gettid()), static_cast<void*>(queue), static_cast<void*>(looper),
                 static_cast<void*>(ALooper_forThread()), static_cast<int>(jit.Regs()[2]), callback, guest_data);
        { std::lock_guard<std::mutex> lock(g_input_diag_mutex); g_input_attach_diag = note; }
        jit.Regs()[0] = 0;
    });
    manager.RegisterThunk("AInputQueue_detachLooper", [](Jit& jit, DynarmicHost&) {
        if (AInputQueue* queue = Host<AInputQueue>(jit.Regs()[0])) AInputQueue_detachLooper(queue);
        jit.Regs()[0] = 0;
    });
    manager.RegisterThunk("AInputQueue_finishEvent", [](Jit& jit, DynarmicHost&) {
        AInputQueue* queue = Host<AInputQueue>(jit.Regs()[0]);
        AInputEvent* event = Host<AInputEvent>(jit.Regs()[1]);
        if (queue && event) AInputQueue_finishEvent(queue, event, static_cast<int>(jit.Regs()[2]));
        if (event) ReleaseGuestHandle(event);
        jit.Regs()[0] = 0;
    });
    manager.RegisterThunk("AInputQueue_getEvent", [](Jit& jit, DynarmicHost& host) {
        AInputQueue* queue = Host<AInputQueue>(jit.Regs()[0]);
        AInputEvent* event = nullptr;
        const int32_t result = queue ? AInputQueue_getEvent(queue, &event) : -1;
        if (jit.Regs()[1]) host.MemoryWrite32(jit.Regs()[1], GuestHandleFor(event));
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });
    manager.RegisterThunk("AInputQueue_preDispatchEvent", [](Jit& jit, DynarmicHost&) {
        AInputQueue* queue = Host<AInputQueue>(jit.Regs()[0]);
        AInputEvent* event = Host<AInputEvent>(jit.Regs()[1]);
        const int32_t result = queue && event ? AInputQueue_preDispatchEvent(queue, event) : 0;
        if (result && event) ReleaseGuestHandle(event);
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });

    auto event_int = [](int32_t (*fn)(const AInputEvent*)) {
        return [fn](Jit& jit, DynarmicHost&) {
            const AInputEvent* event = Host<AInputEvent>(jit.Regs()[0]);
            jit.Regs()[0] = event ? static_cast<uint32_t>(fn(event)) : 0;
        };
    };
    manager.RegisterThunk("AInputEvent_getType", event_int(&AInputEvent_getType));
    manager.RegisterThunk("AInputEvent_getSource", event_int(&AInputEvent_getSource));
    manager.RegisterThunk("AKeyEvent_getKeyCode", event_int(&AKeyEvent_getKeyCode));
    manager.RegisterThunk("AKeyEvent_getMetaState", event_int(&AKeyEvent_getMetaState));
    // The original game imports the motion accessor for both event kinds.
    // Android only defines it for motion events; key actions have their own accessor.
    manager.RegisterThunk("AMotionEvent_getAction", [](Jit& jit, DynarmicHost&) {
        const AInputEvent* event = Host<AInputEvent>(jit.Regs()[0]);
        if (!event) {
            jit.Regs()[0] = 0;
        } else if (AInputEvent_getType(event) == AINPUT_EVENT_TYPE_KEY) {
            jit.Regs()[0] = static_cast<uint32_t>(AKeyEvent_getAction(event));
        } else {
            jit.Regs()[0] = static_cast<uint32_t>(AMotionEvent_getAction(event));
        }
    });

    manager.RegisterThunk("AMotionEvent_getPointerCount", [](Jit& jit, DynarmicHost&) {
        const AInputEvent* event = Host<AInputEvent>(jit.Regs()[0]);
        jit.Regs()[0] = event ? static_cast<uint32_t>(AMotionEvent_getPointerCount(event)) : 0;
    });
    manager.RegisterThunk("AMotionEvent_getPointerId", [](Jit& jit, DynarmicHost&) {
        const AInputEvent* event = Host<AInputEvent>(jit.Regs()[0]);
        jit.Regs()[0] = event ? static_cast<uint32_t>(AMotionEvent_getPointerId(event, jit.Regs()[1])) : 0;
    });
    auto motion_float = [](float (*fn)(const AInputEvent*, size_t)) {
        return [fn](Jit& jit, DynarmicHost&) {
            const AInputEvent* event = Host<AInputEvent>(jit.Regs()[0]);
            jit.Regs()[0] = FloatBits(event ? fn(event, jit.Regs()[1]) : 0.0f);
        };
    };
    manager.RegisterThunk("AMotionEvent_getX", motion_float(&AMotionEvent_getX));
    manager.RegisterThunk("AMotionEvent_getY", motion_float(&AMotionEvent_getY));

    manager.RegisterThunk("AAssetManager_open", [](Jit& jit, DynarmicHost& host) {
        AAssetManager* assets = Host<AAssetManager>(jit.Regs()[0]);
        const char* name = GuestString(host, jit.Regs()[1]);
        AAsset* asset = nullptr;
        if (assets && name) {
            asset = strcmp(name, kWadName) == 0
                ? OpenWholeObbWad()
                : AAssetManager_open(assets, name, static_cast<int>(jit.Regs()[2]));
        }
        const uint32_t handle = GuestHandleFor(asset);
        if (asset && !handle) {
            CloseAsset(asset);
            asset = nullptr;
        }
        // W1 diagnostic: the WAD zero-read trace. The game upper-cases asset
        // names before opening; log every open with the resolved length.
        {
            char b[160];
            snprintf(b, sizeof(b), "AOPEN mgr=%p name=%s -> asset=%p len=%u",
                     static_cast<void*>(assets), name ? name : "(null)",
                     static_cast<void*>(asset), AssetLength(asset));
            DiagTrace::Note(b);
            // W17: persist failed opens (and the first successes) -- the
            // post-freeze ring flush erases Note() entries within ~0.2 s.
            static std::atomic<uint32_t> aopen_ok{0}, aopen_fail{0};
            if (asset ? aopen_ok.fetch_add(1) < 8 : aopen_fail.fetch_add(1) < 64) {
                DiagTrace::NotePersist(b);
            }
        }
        jit.Regs()[0] = handle;
    });
    manager.RegisterThunk("AAssetManager_openDir", [](Jit& jit, DynarmicHost& host) {
        AAssetManager* assets = Host<AAssetManager>(jit.Regs()[0]);
        const char* name = GuestString(host, jit.Regs()[1]);
        // W41: dir-open trail -- which directories the scanner walks, in order.
        {
            static std::atomic<uint32_t> w41od{0};
            if (w41od.fetch_add(1) < 96) {
                char b[192];
                snprintf(b, sizeof(b), "W41OPENDIR lr=0x%08X r1=0x%08X name=%s",
                         jit.Regs()[14], jit.Regs()[1], name ? name : "(null)");
                DiagTrace::NotePersist(b);
            }
        }
        AAssetDir* dir = assets && name ? AAssetManager_openDir(assets, name) : nullptr;
        jit.Regs()[0] = GuestHandleFor(dir);
    });
    manager.RegisterThunk("AAsset_read", [](Jit& jit, DynarmicHost& host) {
        AAsset* asset = Host<AAsset>(jit.Regs()[0]);
        void* buffer = GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[1], jit.Regs()[2]);
        const uint32_t wad_saved_lr_slot = host.MemoryRead32(0x93001A08u);
        const bool wad_read_trace = host.MemoryRead32(0x93001A0Cu) == 1u &&
                                    wad_saved_lr_slot != 0u &&
                                    static_cast<uint64_t>(wad_saved_lr_slot) + 4u <=
                                        host.GetGuestMemorySize();
        const uint32_t wad_saved_lr_before = wad_read_trace
            ? host.MemoryRead32(wad_saved_lr_slot) : 0u;
        const int result = buffer ? ReadAsset(asset, buffer, jit.Regs()[2]) : -1;
        if (wad_read_trace) {
            static std::atomic<uint32_t> wad_read_trace_count{0};
            if (wad_read_trace_count.fetch_add(1, std::memory_order_relaxed) < 32) {
                char line[144];
                snprintf(line, sizeof(line),
                         "WAD-AREAD n=%u buf=%08X lr=%08X->%08X result=%d",
                         jit.Regs()[2], jit.Regs()[1], wad_saved_lr_before,
                         host.MemoryRead32(wad_saved_lr_slot), result);
                DiagTrace::NotePersist(line);
            }
        }
        // W328 (run439): persist the first asset reads with their sizes.
        {
            static std::atomic<uint32_t> w328r{0};
            if (w328r.fetch_add(1) < 64) {
                char b[128];
                snprintf(b, sizeof(b), "W328READ asset=%p size=%u -> %d",
                         static_cast<void*>(asset), jit.Regs()[2], result);
                DiagTrace::NotePersist(b);
            }
        }
        // W1 diagnostic: log the first reads and every short/failed read.
        {
            static std::atomic<uint32_t> diag_ok{0}, diag_bad{0};
            char b[128];
            if (result > 0 && diag_ok.fetch_add(1) < 48) {
                snprintf(b, sizeof(b), "AREAD asset=%p size=%u -> %d", static_cast<void*>(asset),
                         jit.Regs()[2], result);
                DiagTrace::Note(b);
            } else if (result <= 0 && diag_bad.fetch_add(1) < 512) {
                snprintf(b, sizeof(b), "AREAD-SHORT asset=%p size=%u -> %d", static_cast<void*>(asset),
                         jit.Regs()[2], result);
                DiagTrace::Note(b);
            }
            // W19: persist every large read with its result (the WAD parse's
            // string-table/tree/directory reads) and every short read -- the
            // parse story must survive the post-freeze ring flush.
            if (jit.Regs()[2] >= 0x2000 && diag_ok.load() <= 96) {
                snprintf(b, sizeof(b), "AREAD-BIG asset=%p size=%u -> %d", static_cast<void*>(asset),
                         jit.Regs()[2], result);
                DiagTrace::NotePersist(b);
            }
            if (result <= 0 && diag_bad.load() <= 96) {
                snprintf(b, sizeof(b), "AREAD-SHORT asset=%p size=%u -> %d", static_cast<void*>(asset),
                         jit.Regs()[2], result);
                DiagTrace::NotePersist(b);
            }
        }
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });
    manager.RegisterThunk("AAsset_seek", [](Jit& jit, DynarmicHost& host) {
        AAsset* asset = Host<AAsset>(jit.Regs()[0]);
        const off_t result = SeekAsset(asset, static_cast<int32_t>(jit.Regs()[1]), static_cast<int>(jit.Regs()[2]));
        // W328 (run439): persist the first asset seeks -- the WAD parse's
        // position bookkeeping must match the real asset position exactly,
        // or every later field reads shifted bytes (garbage member offsets
        // -> File Read Error -> lethal unwind).
        {
            static std::atomic<uint32_t> w328s{0};
            if (w328s.fetch_add(1) < 64) {
                char b[128];
                snprintf(b, sizeof(b), "W328SEEK asset=%p off=%d whence=%d -> %d",
                         static_cast<void*>(asset), static_cast<int>(jit.Regs()[1]),
                         static_cast<int>(jit.Regs()[2]), static_cast<int>(result));
                DiagTrace::NotePersist(b);
            }
        }
        // W1 diagnostic: deep seeks land in the WAD offset-table region.
        {
            static std::atomic<uint32_t> diag_deep{0};
            if (result >= 0x4000000 && diag_deep.fetch_add(1) < 256) {
                char b[128];
                snprintf(b, sizeof(b), "ASEEK asset=%p off=%d whence=%d -> %d", static_cast<void*>(asset),
                         static_cast<int>(jit.Regs()[1]), static_cast<int>(jit.Regs()[2]),
                         static_cast<int>(result));
                DiagTrace::Note(b);
            }
        }
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });
    manager.RegisterThunk("AAsset_getLength", [](Jit& jit, DynarmicHost&) {
        AAsset* asset = Host<AAsset>(jit.Regs()[0]);
        jit.Regs()[0] = AssetLength(asset);
    });
    manager.RegisterThunk("AAsset_close", [](Jit& jit, DynarmicHost& host) {
        AAsset* asset = Host<AAsset>(jit.Regs()[0]);
        // Capture the guest-side close frame before entering Android. The
        // current startup failure is an invalid return to 0x44 after this
        // call; these words distinguish a bad saved LR from corruption in
        // the asset implementation itself.
        static std::atomic<uint32_t> close_trace_count{0};
        if (close_trace_count.fetch_add(1, std::memory_order_relaxed) < 16) {
            const uint32_t sp = jit.Regs()[13];
            char line[320];
            snprintf(line, sizeof(line),
                     "ASSET-CLOSE asset=%08X lr=%08X sp=%08X stack=%08X/%08X/%08X/%08X/%08X/%08X/%08X/%08X/%08X/%08X/%08X/%08X/%08X/%08X/%08X",
                     jit.Regs()[0], jit.Regs()[14], sp,
                     host.MemoryRead32(sp), host.MemoryRead32(sp + 4),
                     host.MemoryRead32(sp + 8), host.MemoryRead32(sp + 12),
                     host.MemoryRead32(sp + 16), host.MemoryRead32(sp + 20),
                     host.MemoryRead32(sp + 24), host.MemoryRead32(sp + 28),
                     host.MemoryRead32(sp + 32), host.MemoryRead32(sp + 36),
                     host.MemoryRead32(sp + 40), host.MemoryRead32(sp + 44),
                     host.MemoryRead32(sp + 48), host.MemoryRead32(sp + 52),
                     host.MemoryRead32(sp + 56));
            DiagTrace::NotePersist(line);
        }
        if (asset) {
            CloseAsset(asset);
        }
        jit.Regs()[0] = 0;
    });
    manager.RegisterThunk("AAssetDir_getNextFileName", [](Jit& jit, DynarmicHost& host) {
        const uint32_t handle = jit.Regs()[0];
        AAssetDir* dir = Host<AAssetDir>(handle);
        const char* w41name = dir ? AAssetDir_getNextFileName(dir) : nullptr;
        // W41: entry trail -- the names the scanner iterates (LR = caller).
        {
            static std::atomic<uint32_t> w41nx{0};
            if (w41name && w41nx.fetch_add(1) < 400) {
                char b[192];
                snprintf(b, sizeof(b), "W41NEXT lr=0x%08X h=%u name=%s",
                         jit.Regs()[14], handle, w41name);
                DiagTrace::NotePersist(b);
            }
        }
        jit.Regs()[0] = dir ? AssetDirName(host, handle, w41name) : 0;
    });
    manager.RegisterThunk("AAssetDir_close", [](Jit& jit, DynarmicHost& host) {
        const uint32_t handle = jit.Regs()[0];
        AAssetDir* dir = Host<AAssetDir>(handle);
        if (dir) {
            AAssetDir_close(dir);
            ReleaseGuestHandle(dir);
        }
        std::lock_guard<std::mutex> lock(g_asset_dir_mutex);
        auto it = g_asset_dir_names.find(handle);
        if (it != g_asset_dir_names.end()) {
            host.GuestFree(it->second);
            g_asset_dir_names.erase(it);
        }
        jit.Regs()[0] = 0;
    });

    manager.RegisterThunk("AConfiguration_new", [](Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = GuestHandleFor(AConfiguration_new());
    });
    manager.RegisterThunk("AConfiguration_delete", [](Jit& jit, DynarmicHost&) {
        AConfiguration* config = Host<AConfiguration>(jit.Regs()[0]);
        if (config) {
            AConfiguration_delete(config);
            ReleaseGuestHandle(config);
        }
        jit.Regs()[0] = 0;
    });
    manager.RegisterThunk("AConfiguration_fromAssetManager", [](Jit& jit, DynarmicHost&) {
        AConfiguration* config = Host<AConfiguration>(jit.Regs()[0]);
        AAssetManager* assets = Host<AAssetManager>(jit.Regs()[1]);
        if (config && assets) AConfiguration_fromAssetManager(config, assets);
        jit.Regs()[0] = 0;
    });
    manager.RegisterThunk("AConfiguration_getMcc", [](Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = static_cast<uint32_t>(AConfiguration_getMcc(Host<AConfiguration>(jit.Regs()[0])));
    });
    manager.RegisterThunk("AConfiguration_getMnc", [](Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = static_cast<uint32_t>(AConfiguration_getMnc(Host<AConfiguration>(jit.Regs()[0])));
    });
    manager.RegisterThunk("AConfiguration_getOrientation", [](Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = static_cast<uint32_t>(AConfiguration_getOrientation(Host<AConfiguration>(jit.Regs()[0])));
    });
    manager.RegisterThunk("AConfiguration_getTouchscreen", [](Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = static_cast<uint32_t>(AConfiguration_getTouchscreen(Host<AConfiguration>(jit.Regs()[0])));
    });
    manager.RegisterThunk("AConfiguration_getDensity", [](Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = static_cast<uint32_t>(AConfiguration_getDensity(Host<AConfiguration>(jit.Regs()[0])));
    });
    manager.RegisterThunk("AConfiguration_getKeyboard", [](Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = static_cast<uint32_t>(AConfiguration_getKeyboard(Host<AConfiguration>(jit.Regs()[0])));
    });
    manager.RegisterThunk("AConfiguration_getKeysHidden", [](Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = static_cast<uint32_t>(AConfiguration_getKeysHidden(Host<AConfiguration>(jit.Regs()[0])));
    });
    manager.RegisterThunk("AConfiguration_getNavHidden", [](Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = static_cast<uint32_t>(AConfiguration_getNavHidden(Host<AConfiguration>(jit.Regs()[0])));
    });
    manager.RegisterThunk("AConfiguration_getNavigation", [](Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = static_cast<uint32_t>(AConfiguration_getNavigation(Host<AConfiguration>(jit.Regs()[0])));
    });
    manager.RegisterThunk("AConfiguration_getScreenSize", [](Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = static_cast<uint32_t>(AConfiguration_getScreenSize(Host<AConfiguration>(jit.Regs()[0])));
    });
    manager.RegisterThunk("AConfiguration_getScreenLong", [](Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = static_cast<uint32_t>(AConfiguration_getScreenLong(Host<AConfiguration>(jit.Regs()[0])));
    });
    manager.RegisterThunk("AConfiguration_getSdkVersion", [](Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = static_cast<uint32_t>(AConfiguration_getSdkVersion(Host<AConfiguration>(jit.Regs()[0])));
    });
    manager.RegisterThunk("AConfiguration_getUiModeNight", [](Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = static_cast<uint32_t>(AConfiguration_getUiModeNight(Host<AConfiguration>(jit.Regs()[0])));
    });
    manager.RegisterThunk("AConfiguration_getUiModeType", [](Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = static_cast<uint32_t>(AConfiguration_getUiModeType(Host<AConfiguration>(jit.Regs()[0])));
    });
    manager.RegisterThunk("AConfiguration_getLanguage", [](Jit& jit, DynarmicHost& host) {
        AConfiguration* config = Host<AConfiguration>(jit.Regs()[0]);
        const uint32_t out = jit.Regs()[1];
        if (config && GuestRangeValid(host.GetGuestMemorySize(), out, 2)) {
            char language[2] = {};
            AConfiguration_getLanguage(config, language);
            memcpy(host.GetGuestMemoryBase() + out, language, sizeof(language));
        }
        jit.Regs()[0] = 0;
    });
    manager.RegisterThunk("AConfiguration_getCountry", [](Jit& jit, DynarmicHost& host) {
        AConfiguration* config = Host<AConfiguration>(jit.Regs()[0]);
        const uint32_t out = jit.Regs()[1];
        if (config && GuestRangeValid(host.GetGuestMemorySize(), out, 2)) {
            char country[2] = {};
            AConfiguration_getCountry(config, country);
            memcpy(host.GetGuestMemoryBase() + out, country, sizeof(country));
        }
        jit.Regs()[0] = 0;
    });

    manager.RegisterThunk("ANativeWindow_setBuffersGeometry", [](Jit& jit, DynarmicHost&) {
        ANativeWindow* window = Host<ANativeWindow>(jit.Regs()[0]);
        const int32_t result = window ? ANativeWindow_setBuffersGeometry(
            window, static_cast<int32_t>(jit.Regs()[1]), static_cast<int32_t>(jit.Regs()[2]), static_cast<int32_t>(jit.Regs()[3])) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });

    manager.RegisterThunk("ASensorManager_getInstance", [](Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = GuestHandleFor(ASensorManager_getInstance());
    });
    manager.RegisterThunk("ASensorManager_getDefaultSensor", [](Jit& jit, DynarmicHost&) {
        ASensorManager* manager_ptr = Host<ASensorManager>(jit.Regs()[0]);
        jit.Regs()[0] = GuestHandleFor(manager_ptr ? ASensorManager_getDefaultSensor(manager_ptr, static_cast<int>(jit.Regs()[1])) : nullptr);
    });
    manager.RegisterThunk("ASensorManager_getSensorList", [](Jit& jit, DynarmicHost& host) {
        const uint32_t manager_handle = jit.Regs()[0];
        ASensorManager* manager_ptr = Host<ASensorManager>(manager_handle);
        ASensorList list = nullptr;
        const int count = manager_ptr ? ASensorManager_getSensorList(manager_ptr, &list) : -1;
        if (count > 0 && jit.Regs()[1]) {
            std::lock_guard<std::mutex> lock(g_sensor_mutex);
            uint32_t& guest_list = g_sensor_lists[manager_handle];
            if (!guest_list) guest_list = host.GuestAlloc(static_cast<size_t>(count) * 4, 4);
            if (guest_list) {
                for (int i = 0; i < count; ++i) {
                    host.MemoryWrite32(guest_list + static_cast<uint32_t>(i) * 4, GuestHandleFor(list[i]));
                }
                host.MemoryWrite32(jit.Regs()[1], guest_list);
            }
        } else if (jit.Regs()[1]) {
            host.MemoryWrite32(jit.Regs()[1], 0);
        }
        jit.Regs()[0] = static_cast<uint32_t>(count);
    });
    manager.RegisterThunk("ASensorManager_createEventQueue", [](Jit& jit, DynarmicHost& host) {
        ASensorManager* manager_ptr = Host<ASensorManager>(jit.Regs()[0]);
        ALooper* looper = Host<ALooper>(jit.Regs()[1]);
        const uint32_t callback = jit.Regs()[3];
        const uint32_t guest_data = host.MemoryRead32(jit.Regs()[13]);
        CallbackBinding* binding = callback ? new CallbackBinding{&host, callback, guest_data} : nullptr;
        ASensorEventQueue* queue = manager_ptr ? ASensorManager_createEventQueue(
            manager_ptr, looper, static_cast<int>(jit.Regs()[2]), callback ? ForwardLooperCallback : nullptr,
            binding ? static_cast<void*>(binding) : reinterpret_cast<void*>(static_cast<uintptr_t>(guest_data))) : nullptr;
        if (!queue && binding) delete binding;
        jit.Regs()[0] = GuestHandleFor(queue);
    });
    manager.RegisterThunk("ASensorEventQueue_enableSensor", [](Jit& jit, DynarmicHost&) {
        ASensorEventQueue* queue = Host<ASensorEventQueue>(jit.Regs()[0]);
        ASensor const* sensor = Host<ASensor>(jit.Regs()[1]);
        jit.Regs()[0] = static_cast<uint32_t>(queue && sensor ? ASensorEventQueue_enableSensor(queue, sensor) : -1);
    });
    manager.RegisterThunk("ASensorEventQueue_setEventRate", [](Jit& jit, DynarmicHost&) {
        ASensorEventQueue* queue = Host<ASensorEventQueue>(jit.Regs()[0]);
        ASensor const* sensor = Host<ASensor>(jit.Regs()[1]);
        jit.Regs()[0] = static_cast<uint32_t>(queue && sensor ? ASensorEventQueue_setEventRate(queue, sensor, static_cast<int32_t>(jit.Regs()[2])) : -1);
    });
    manager.RegisterThunk("ASensorEventQueue_getEvents", [](Jit& jit, DynarmicHost& host) {
        ASensorEventQueue* queue = Host<ASensorEventQueue>(jit.Regs()[0]);
        const uint32_t out = jit.Regs()[1];
        const size_t count = std::min<size_t>(jit.Regs()[2], 64);
        if (!queue || !out || !GuestRangeValid(host.GetGuestMemorySize(), out, count * sizeof(ASensorEvent))) {
            jit.Regs()[0] = static_cast<uint32_t>(-1);
            return;
        }
        std::vector<ASensorEvent> events(count);
        const ssize_t result = ASensorEventQueue_getEvents(queue, events.data(), count);
        if (result > 0) memcpy(host.GetGuestMemoryBase() + out, events.data(), static_cast<size_t>(result) * sizeof(ASensorEvent));
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });
    manager.RegisterThunk("ASensor_getName", [](Jit& jit, DynarmicHost& host) {
        ASensor const* sensor = Host<ASensor>(jit.Regs()[0]);
        jit.Regs()[0] = SensorString(host, sensor, sensor ? ASensor_getName(sensor) : nullptr);
    });
    manager.RegisterThunk("ASensor_getVendor", [](Jit& jit, DynarmicHost& host) {
        ASensor const* sensor = Host<ASensor>(jit.Regs()[0]);
        jit.Regs()[0] = SensorString(host, sensor, sensor ? ASensor_getVendor(sensor) : nullptr);
    });
    manager.RegisterThunk("ASensor_getType", [](Jit& jit, DynarmicHost&) {
        ASensor const* sensor = Host<ASensor>(jit.Regs()[0]);
        jit.Regs()[0] = static_cast<uint32_t>(sensor ? ASensor_getType(sensor) : -1);
    });
    manager.RegisterThunk("ASensor_getResolution", [](Jit& jit, DynarmicHost&) {
        ASensor const* sensor = Host<ASensor>(jit.Regs()[0]);
        jit.Regs()[0] = FloatBits(sensor ? ASensor_getResolution(sensor) : 0.0f);
    });
    manager.RegisterThunk("ASensor_getMinDelay", [](Jit& jit, DynarmicHost&) {
        ASensor const* sensor = Host<ASensor>(jit.Regs()[0]);
        jit.Regs()[0] = static_cast<uint32_t>(sensor ? ASensor_getMinDelay(sensor) : -1);
    });

    manager.RegisterThunk("__android_log_vprint", [](Jit& jit, DynarmicHost& host) {
        const int priority = static_cast<int>(jit.Regs()[0]);
        const char* tag = GuestString(host, jit.Regs()[1]);
        const char* format = GuestString(host, jit.Regs()[2]);
        if (format) __android_log_print(priority, tag ? tag : "Arm32Bridge_Guest", "%s", format);
        jit.Regs()[0] = 1;
    });
}
