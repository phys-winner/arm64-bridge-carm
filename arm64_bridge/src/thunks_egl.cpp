#include "thunk_manager.h"
#include "dynarmic_host.h"
#include "native_handle_table.h"
#include "thunk_types.h"
#include "diag_trace.h"

#include <EGL/egl.h>
#include <GLES/gl.h>
#include <android/log.h>
#include <android/native_window.h>

ANativeWindow* BridgeCurrentSurfaceWindow();  // W58: jni_bridge

// W477 (jni_bridge.cpp): display/config state initialized on a dedicated
// non-JIT thread. eglInitialize HANGS on the guest-boot JIT thread (W475),
// so the driver-load thunks below serve this pre-initialized state instead
// of touching the driver from the JIT thread.
namespace BridgeEgl477 {
bool DisplayReady();
bool ThreadDone();
bool Failed();
void DisplayTerminated(EGLDisplay display);
void EnsureDisplayWorker();
EGLDisplay Display();
EGLConfig Config();
EGLSurface Surface();
EGLContext Context();
EGLint MajorVer();
EGLint MinorVer();
}  // namespace BridgeEgl477

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#define LOG_TAG "Arm32Bridge_EGL"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {
using Jit = Dynarmic::A32::Jit;
thread_local EGLint diagnosticEglError = EGL_SUCCESS;
std::mutex diagnosticEglMutex;
std::string diagnosticEglState[4];
void SaveEglDiagnostic(size_t slot, const char* note) {
    std::lock_guard<std::mutex> lock(diagnosticEglMutex);
    diagnosticEglState[slot] = note;
}

template <typename T>
T Host(uint32_t handle) {
    return static_cast<T>(HostPointerFor(handle));
}

std::vector<EGLint> Attributes(DynarmicHost& host, uint32_t addr) {
    if (!addr) return {};
    std::vector<EGLint> result;
    for (size_t i = 0; i < 128; ++i) {
        if (!GuestRangeValid(host.GetGuestMemorySize(), addr + static_cast<uint32_t>(i * 4), 4)) {
            LOGE("EGL attribute list escaped guest memory at 0x%08X", addr);
            return {};
        }
        const EGLint value = static_cast<EGLint>(host.MemoryRead32(addr + static_cast<uint32_t>(i * 4)));
        result.push_back(value);
        if (value == EGL_NONE) return result;
    }
    LOGE("EGL attribute list at 0x%08X is not EGL_NONE terminated", addr);
    return {};
}

uint32_t GuestString(DynarmicHost& host, const char* text) {
    if (!text) return 0;
    static std::mutex mutex;
    static std::unordered_map<std::string, uint32_t> cache;
    std::lock_guard<std::mutex> lock(mutex);
    auto it = cache.find(text);
    if (it != cache.end()) return it->second;
    const uint32_t guest = host.GuestAlloc(strlen(text) + 1, 4);
    if (!guest) return 0;
    memcpy(host.GetGuestMemoryBase() + guest, text, strlen(text) + 1);
    cache.emplace(text, guest);
    return guest;
}

}  // namespace

// The shared persist ring is flooded by legacy W255 allocation notes. Keep
// low-frequency EGL observations independently so every periodic dump has them.
// GL/EGL queries remain on the owning render thread; this accessor only copies.
std::string BridgeEglDiagnosticSnapshot() {
    std::lock_guard<std::mutex> lock(diagnosticEglMutex);
    std::string result;
    for (const auto& line : diagnosticEglState) {
        if (line.empty()) continue;
        if (!result.empty()) result += '\n';
        result += line;
    }
    return result;
}

// W477: give the init thread a bounded chance to finish before any
// driver-load call falls through to the (hang-prone) JIT-thread path.
static void W477WaitReady() {
    for (int i = 0; i < 800; ++i) {
        if (BridgeEgl477::DisplayReady() || BridgeEgl477::ThreadDone()) return;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

static bool W477EnsureReady() {
    if (BridgeEgl477::DisplayReady()) return true;
    BridgeEgl477::EnsureDisplayWorker();
    W477WaitReady();
    return BridgeEgl477::DisplayReady();
}

// W526 (run706): the ENTIRE display init as ONE host-side thunk. The guest
// stub (W492) calls it with r0 = mini (the writable a1: [mini+0]=inner,
// [inner+36]=window handle, [mini+4]=fake JNIEnv). Runs on the CALLING
// (game) thread, so eglMakeCurrent binds the W477 context there -- exactly
// where Render_RenderScene issues GL. Skips the guest PLT/GOT entirely.
static void W526InitDisplay(Dynarmic::A32::Jit& jit, DynarmicHost& host) {
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
    if (win) {
        ANativeWindow_setBuffersGeometry(win, 0, 0, 1 /*RGBX8888 fallback*/);
    }
    EGLBoolean mc = eglMakeCurrent(dpy, surf, surf, ctx);
    LOGE("[W526] eglMakeCurrent=%d err=0x%04X", (int)mc, eglGetError());
    if (!mc) return;
    EGLint w = 0, h = 0;
    eglQuerySurface(dpy, surf, EGL_WIDTH, &w);
    eglQuerySurface(dpy, surf, EGL_HEIGHT, &h);
    // a1[212..218] outputs (words at mini+848..): Display, Surface, Context,
    // h, w, dpi, rotation -- layout per __android_init_display.
    host.MemoryWrite32(mini + 848, 0);  // dpi placeholder (JNI call skipped)
    host.MemoryWrite32(mini + 852, 0);  // rotation
    host.MemoryWrite32(mini + 840, w);
    host.MemoryWrite32(mini + 836, h);
    // The REAL guest flag the renderer checks (host write: rel.ro is only
    // guest-RO).
    host.MemoryWrite32(0x406D95B4u, 1u);
    LOGE("[W526] DISPLAY INIT COMPLETE: dpy=%p surf=%p ctx=%p %dx%d",
         dpy, surf, ctx, w, h);
}

void RegisterEglThunks(ThunkManager& manager) {
    manager.RegisterThunk("w526_init_display", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        W526InitDisplay(jit, host);
    });
    manager.RegisterThunk("eglGetDisplay", [](Jit& jit, DynarmicHost&) {
        if (!W477EnsureReady()) {
            LOGE("guest eglGetDisplay failed: host initialization worker did not finish");
            jit.Regs()[0] = 0;
            return;
        }
        jit.Regs()[0] = GuestHandleFor(BridgeEgl477::Display());
    });
    manager.RegisterThunk("eglInitialize", [](Jit& jit, DynarmicHost& host) {
        if (!W477EnsureReady()) {
            LOGE("guest eglInitialize failed: host initialization worker did not finish");
            diagnosticEglError = EGL_NOT_INITIALIZED;
            jit.Regs()[0] = EGL_FALSE;
            return;
        }
        if (jit.Regs()[1] && GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[1], 4))
            host.MemoryWrite32(jit.Regs()[1], static_cast<uint32_t>(BridgeEgl477::MajorVer()));
        if (jit.Regs()[2] && GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[2], 4))
            host.MemoryWrite32(jit.Regs()[2], static_cast<uint32_t>(BridgeEgl477::MinorVer()));
        jit.Regs()[0] = EGL_TRUE;
    });
    manager.RegisterThunk("eglTerminate", [](Jit& jit, DynarmicHost&) {
        const EGLDisplay display = Host<EGLDisplay>(jit.Regs()[0]);
        const EGLBoolean ok = eglTerminate(display);
        LOGI("guest eglTerminate ok=%d display=%p", ok, display);
        if (ok) BridgeEgl477::DisplayTerminated(display);
        jit.Regs()[0] = ok;
    });
    manager.RegisterThunk("eglChooseConfig", [](Jit& jit, DynarmicHost& host) {
        const std::vector<EGLint> attrs = Attributes(host, jit.Regs()[1]);
        if (jit.Regs()[1] && attrs.empty()) { jit.Regs()[0] = EGL_FALSE; return; }
        const EGLint capacity = static_cast<EGLint>(jit.Regs()[3]);
        const uint32_t configs_addr = jit.Regs()[2];
        const uint32_t count_addr = host.MemoryRead32(jit.Regs()[13]);
        if (capacity < 0 || (configs_addr && !GuestRangeValid(host.GetGuestMemorySize(), configs_addr, static_cast<size_t>(capacity) * 4)) ||
            (count_addr && !GuestRangeValid(host.GetGuestMemorySize(), count_addr, 4))) {
            jit.Regs()[0] = EGL_FALSE;
            return;
        }
        EGLint count = 0;
        const EGLint* attr_ptr = attrs.empty() ? nullptr : attrs.data();
        EGLBoolean ok = eglChooseConfig(Host<EGLDisplay>(jit.Regs()[0]), attr_ptr, nullptr, 0, &count);
        if (ok && configs_addr && capacity > 0 && count > 0) {
            const EGLint take = count < capacity ? count : capacity;
            std::vector<EGLConfig> configs(static_cast<size_t>(take));
            ok = eglChooseConfig(Host<EGLDisplay>(jit.Regs()[0]), attr_ptr, configs.data(), take, &count);
            if (ok) {
                for (EGLint i = 0; i < take && i < count; ++i) {
                    host.MemoryWrite32(configs_addr + static_cast<uint32_t>(i * 4), GuestHandleFor(configs[static_cast<size_t>(i)]));
                }
            }
        }
        if (count_addr) host.MemoryWrite32(count_addr, static_cast<uint32_t>(count));
        jit.Regs()[0] = ok;
    });
    manager.RegisterThunk("eglGetConfigAttrib", [](Jit& jit, DynarmicHost& host) {
        EGLint value = 0;
        const EGLBoolean ok = eglGetConfigAttrib(Host<EGLDisplay>(jit.Regs()[0]), Host<EGLConfig>(jit.Regs()[1]),
                                                 static_cast<EGLint>(jit.Regs()[2]), &value);
        if (jit.Regs()[3] && GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[3], 4)) host.MemoryWrite32(jit.Regs()[3], static_cast<uint32_t>(value));
        jit.Regs()[0] = ok;
    });
    manager.RegisterThunk("eglQuerySurface", [](Jit& jit, DynarmicHost& host) {
        EGLint value = 0;
        const EGLBoolean ok = eglQuerySurface(Host<EGLDisplay>(jit.Regs()[0]), Host<EGLSurface>(jit.Regs()[1]),
                                              static_cast<EGLint>(jit.Regs()[2]), &value);
        if (jit.Regs()[3] && GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[3], 4)) host.MemoryWrite32(jit.Regs()[3], static_cast<uint32_t>(value));
        jit.Regs()[0] = ok;
    });
    manager.RegisterThunk("eglCreateWindowSurface", [](Jit& jit, DynarmicHost& host) {
        const std::vector<EGLint> attrs = Attributes(host, jit.Regs()[3]);
        if (jit.Regs()[3] && attrs.empty()) { jit.Regs()[0] = 0; return; }
        const EGLint* attr_ptr = attrs.empty() ? nullptr : attrs.data();
        // W58: always create the EGL surface on the CURRENT bridge surface
        // window. The guest may hold a stale handle after the system's
        // surface recreate (W44b suppresses the repeat callback), and EGL
        // on a destroyed window stalls/fails -- the black screen at boot.
        ANativeWindow* win = BridgeCurrentSurfaceWindow();
        if (!win) win = Host<ANativeWindow*>(jit.Regs()[2]);
        EGLSurface surface = eglCreateWindowSurface(Host<EGLDisplay>(jit.Regs()[0]), Host<EGLConfig>(jit.Regs()[1]),
                                                    win, attr_ptr);
        char note[192];
        snprintf(note, sizeof(note), "EGLTRACE create_surface window=%p surface=%p guest_window=%08X current_window=%p",
                 static_cast<void*>(win), surface, jit.Regs()[2], static_cast<void*>(BridgeCurrentSurfaceWindow()));
        SaveEglDiagnostic(0, note);
        if (surface == EGL_NO_SURFACE) LOGE("eglCreateWindowSurface failed: 0x%04X", eglGetError());
        jit.Regs()[0] = GuestHandleFor(surface);
    });
    manager.RegisterThunk("eglDestroySurface", [](Jit& jit, DynarmicHost&) {
        const uint32_t handle = jit.Regs()[1];
        EGLSurface surface = Host<EGLSurface>(handle);
        const EGLBoolean ok = eglDestroySurface(Host<EGLDisplay>(jit.Regs()[0]), surface);
        if (surface) ReleaseGuestHandle(surface);
        jit.Regs()[0] = ok;
    });
    manager.RegisterThunk("eglCreateContext", [](Jit& jit, DynarmicHost& host) {
        const std::vector<EGLint> attrs = Attributes(host, jit.Regs()[3]);
        if (jit.Regs()[3] && attrs.empty()) { jit.Regs()[0] = 0; return; }
        const EGLint* attr_ptr = attrs.empty() ? nullptr : attrs.data();
        EGLContext context = eglCreateContext(Host<EGLDisplay>(jit.Regs()[0]), Host<EGLConfig>(jit.Regs()[1]),
                                               Host<EGLContext>(jit.Regs()[2]), attr_ptr);
        char note[128];
        snprintf(note, sizeof(note), "EGLTRACE create_context ctx=%p attr0=%04X attr1=%d",
                 context, attrs.empty() ? EGL_NONE : attrs[0], attrs.size() > 1u ? attrs[1] : 0);
        SaveEglDiagnostic(1, note);
        if (context == EGL_NO_CONTEXT) LOGE("eglCreateContext failed: 0x%04X", eglGetError());
        jit.Regs()[0] = GuestHandleFor(context);
    });
    manager.RegisterThunk("eglDestroyContext", [](Jit& jit, DynarmicHost&) {
        const uint32_t handle = jit.Regs()[1];
        EGLContext context = Host<EGLContext>(handle);
        const EGLBoolean ok = eglDestroyContext(Host<EGLDisplay>(jit.Regs()[0]), context);
        if (context) ReleaseGuestHandle(context);
        jit.Regs()[0] = ok;
    });
    manager.RegisterThunk("eglMakeCurrent", [](Jit& jit, DynarmicHost&) {
        LOGE("[W477] guest eglMakeCurrent entered (JIT thread)");
        const EGLBoolean ok = eglMakeCurrent(Host<EGLDisplay>(jit.Regs()[0]), Host<EGLSurface>(jit.Regs()[1]),
                                              Host<EGLSurface>(jit.Regs()[2]), Host<EGLContext>(jit.Regs()[3]));
        LOGE("[W477] guest eglMakeCurrent returned ok=%d", (int)ok);
        char note[160];
        snprintf(note, sizeof(note), "EGLTRACE make_current ok=%u dpy=%p draw=%p read=%p ctx=%p",
                 ok, Host<EGLDisplay>(jit.Regs()[0]), Host<EGLSurface>(jit.Regs()[1]),
                 Host<EGLSurface>(jit.Regs()[2]), Host<EGLContext>(jit.Regs()[3]));
        SaveEglDiagnostic(2, note);
        if (!ok) LOGE("eglMakeCurrent failed: 0x%04X", eglGetError());
        jit.Regs()[0] = ok;
    });
    manager.RegisterThunk("eglSwapBuffers", [](Jit& jit, DynarmicHost&) {
        static std::atomic<uint32_t> swaps{0};
        const uint32_t n = swaps.fetch_add(1) + 1;
        if (n == 1 || n % 60 == 0) LOGE("[W477] eglSwapBuffers #%u", n);
        const EGLDisplay display = Host<EGLDisplay>(jit.Regs()[0]);
        const EGLSurface surface = Host<EGLSurface>(jit.Regs()[1]);
        const EGLBoolean ok = eglSwapBuffers(display, surface);
        EGLint error = EGL_SUCCESS;
        if (!ok) {
            error = eglGetError();
            diagnosticEglError = error; // Preserve the guest's next error query.
        }
        if (n <= 3u || n % 600u == 0u) {
            EGLint width = 0, height = 0;
            eglQuerySurface(display, surface, EGL_WIDTH, &width);
            eglQuerySurface(display, surface, EGL_HEIGHT, &height);
            GLint viewport[4]{};
            const EGLContext current = eglGetCurrentContext();
            const char* version = "no-current-context";
            if (current != EGL_NO_CONTEXT) {
                glGetIntegerv(GL_VIEWPORT, viewport);
                version = reinterpret_cast<const char*>(glGetString(GL_VERSION));
            }
            char note[400];
            snprintf(note, sizeof(note),
                     "EGLTRACE swap=%u ok=%u err=%04X dpy=%p surface=%p current_dpy=%p current_draw=%p ctx=%p size=%dx%d vp=%d,%d,%d,%d gl=%s window=%p",
                     n, ok, error, display, surface, eglGetCurrentDisplay(), eglGetCurrentSurface(EGL_DRAW),
                     current, width, height, viewport[0], viewport[1], viewport[2], viewport[3],
                     version ? version : "null", static_cast<void*>(BridgeCurrentSurfaceWindow()));
            SaveEglDiagnostic(3, note);
        }
        jit.Regs()[0] = ok;
    });
    manager.RegisterThunk("eglGetError", [](Jit& jit, DynarmicHost&) {
        if (diagnosticEglError != EGL_SUCCESS) {
            jit.Regs()[0] = static_cast<uint32_t>(diagnosticEglError);
            diagnosticEglError = EGL_SUCCESS;
        } else {
            jit.Regs()[0] = static_cast<uint32_t>(eglGetError());
        }
    });
    manager.RegisterThunk("eglQueryString", [](Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = GuestString(host, eglQueryString(Host<EGLDisplay>(jit.Regs()[0]), static_cast<EGLint>(jit.Regs()[1])));
    });
    manager.RegisterThunk("eglGetProcAddress", [&manager](Jit& jit, DynarmicHost& host) {
        const char* name = nullptr;
        if (jit.Regs()[0] && GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[0], 1)) {
            const char* candidate = reinterpret_cast<const char*>(host.GetGuestMemoryBase() + jit.Regs()[0]);
            if (memchr(candidate, 0, host.GetGuestMemorySize() - jit.Regs()[0])) name = candidate;
        }
        if (!name) { jit.Regs()[0] = 0; return; }
        jit.Regs()[0] = manager.FindRegisteredSymbol(name);
    });
}
