#include <EGL/egl.h>

#include <cstdio>
#include <cstdlib>

int main() {
    const EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    if (display == EGL_NO_DISPLAY || !eglInitialize(display, nullptr, nullptr)) {
        std::fprintf(stderr, "eglInitialize failed: 0x%04x\n", eglGetError());
        return 1;
    }

    EGLint count = 0;
    if (!eglGetConfigs(display, nullptr, 0, &count) || count <= 0) {
        std::fprintf(stderr, "eglGetConfigs count failed: 0x%04x\n", eglGetError());
        return 2;
    }
    auto* configs = static_cast<EGLConfig*>(std::calloc(static_cast<size_t>(count), sizeof(EGLConfig)));
    if (!configs || !eglGetConfigs(display, configs, count, &count)) {
        std::fprintf(stderr, "eglGetConfigs list failed: 0x%04x\n", eglGetError());
        std::free(configs);
        return 3;
    }

    int es1_window_configs = 0;
    int max_below_two = 0;
    int max_at_least_two = 0;
    for (EGLint i = 0; i < count; ++i) {
        EGLint surface = 0, renderable = 0, min_interval = 0, max_interval = 0, id = 0;
        if (!eglGetConfigAttrib(display, configs[i], EGL_SURFACE_TYPE, &surface) ||
            !eglGetConfigAttrib(display, configs[i], EGL_RENDERABLE_TYPE, &renderable) ||
            !eglGetConfigAttrib(display, configs[i], EGL_MIN_SWAP_INTERVAL, &min_interval) ||
            !eglGetConfigAttrib(display, configs[i], EGL_MAX_SWAP_INTERVAL, &max_interval) ||
            !eglGetConfigAttrib(display, configs[i], EGL_CONFIG_ID, &id)) {
            std::fprintf(stderr, "eglGetConfigAttrib failed for config %d: 0x%04x\n", i, eglGetError());
            std::free(configs);
            return 4;
        }
        if ((surface & EGL_WINDOW_BIT) && (renderable & EGL_OPENGL_ES_BIT)) {
            ++es1_window_configs;
            if (max_interval >= 2) ++max_at_least_two;
            else ++max_below_two;
            std::printf("ES1 window config id=%d swap_interval=[%d,%d]\n", id, min_interval, max_interval);
        }
    }
    std::printf("summary total=%d ES1_window=%d max_lt_2=%d max_ge_2=%d\n",
                count, es1_window_configs, max_below_two, max_at_least_two);
    std::free(configs);
    eglTerminate(display);
    return 0;
}
