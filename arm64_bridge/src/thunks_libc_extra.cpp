#include "thunk_manager.h"
#include "diag_trace.h"
#include "dynarmic_host.h"
#include "thunk_types.h"
#include "guest_varargs32.h"
#include "guest_printf32.h"
#include "guest_scan32.h"

#include <android/log.h>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <ctime>
#include <locale.h>
#include <poll.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#include <array>
#include <algorithm>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#define LOG_TAG "Arm32Bridge_LibcExtra"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

extern FILE* GuestFileFor(uint32_t handle);

namespace {
using Jit = Dynarmic::A32::Jit;

char* GuestChars(DynarmicHost& host, uint32_t addr) {
    if (!addr || !GuestRangeValid(host.GetGuestMemorySize(), addr, 1)) return nullptr;
    char* result = reinterpret_cast<char*>(host.GetGuestMemoryBase() + addr);
    return memchr(result, 0, host.GetGuestMemorySize() - addr) ? result : nullptr;
}

wchar_t* GuestWide(DynarmicHost& host, uint32_t addr) {
    if (!addr || !GuestRangeValid(host.GetGuestMemorySize(), addr, sizeof(wchar_t))) return nullptr;
    wchar_t* result = reinterpret_cast<wchar_t*>(host.GetGuestMemoryBase() + addr);
    const size_t count = (host.GetGuestMemorySize() - addr) / sizeof(wchar_t);
    for (size_t i = 0; i < count; ++i) if (result[i] == L'\0') return result;
    return nullptr;
}

uint32_t GuestPointer(DynarmicHost& host, const void* value) {
    if (!value) return 0;
    const uintptr_t base = reinterpret_cast<uintptr_t>(host.GetGuestMemoryBase());
    const uintptr_t pointer = reinterpret_cast<uintptr_t>(value);
    if (pointer < base || pointer - base > UINT32_MAX) return 0;
    return static_cast<uint32_t>(pointer - base);
}

uint32_t CopyStable(DynarmicHost& host, const char* text) {
    if (!text) return 0;
    const size_t size = strlen(text) + 1;
    const uint32_t guest = host.GuestAlloc(size, 4);
    if (guest) memcpy(host.GetGuestMemoryBase() + guest, text, size);
    return guest;
}

float ReadFloat(Jit& jit, unsigned index) {
    float value;
    const uint32_t bits = jit.Regs()[index];
    memcpy(&value, &bits, sizeof(value));
    return value;
}

void WriteFloat(Jit& jit, unsigned index, float value) {
    uint32_t bits;
    memcpy(&bits, &value, sizeof(bits));
    jit.Regs()[index] = bits;
}

double ReadDouble(Jit& jit, unsigned index) {
    index = (index + 1u) & ~1u;
    const uint64_t bits = static_cast<uint64_t>(jit.Regs()[index]) |
                          (static_cast<uint64_t>(jit.Regs()[index + 1]) << 32);
    double value;
    memcpy(&value, &bits, sizeof(value));
    return value;
}

void WriteDouble(Jit& jit, double value) {
    uint64_t bits;
    memcpy(&bits, &value, sizeof(bits));
    jit.Regs()[0] = static_cast<uint32_t>(bits);
    jit.Regs()[1] = static_cast<uint32_t>(bits >> 32);
}

using GuestWords = GuestWords32<Jit, DynarmicHost>;

std::string FormatGuestWords(DynarmicHost& host, const char* format, GuestWords& words) {
    return GuestPrintf32::Format(host, format, words);
}

struct GuestTmFields {
    int32_t sec, min, hour, mday, mon, year, wday, yday, isdst, gmtoff, zone;
};

bool ReadGuestTm(DynarmicHost& host, uint32_t addr, struct tm& out) {
    if (!GuestRangeValid(host.GetGuestMemorySize(), addr, sizeof(GuestTmFields))) return false;
    memset(&out, 0, sizeof(out));
    out.tm_sec = static_cast<int32_t>(host.MemoryRead32(addr + 0));
    out.tm_min = static_cast<int32_t>(host.MemoryRead32(addr + 4));
    out.tm_hour = static_cast<int32_t>(host.MemoryRead32(addr + 8));
    out.tm_mday = static_cast<int32_t>(host.MemoryRead32(addr + 12));
    out.tm_mon = static_cast<int32_t>(host.MemoryRead32(addr + 16));
    out.tm_year = static_cast<int32_t>(host.MemoryRead32(addr + 20));
    out.tm_wday = static_cast<int32_t>(host.MemoryRead32(addr + 24));
    out.tm_yday = static_cast<int32_t>(host.MemoryRead32(addr + 28));
    out.tm_isdst = static_cast<int32_t>(host.MemoryRead32(addr + 32));
#if defined(__ANDROID__)
    out.tm_gmtoff = static_cast<long>(static_cast<int32_t>(host.MemoryRead32(addr + 36)));
#endif
    return true;
}

bool WriteGuestTm(DynarmicHost& host, uint32_t addr, const struct tm& value) {
    if (!GuestRangeValid(host.GetGuestMemorySize(), addr, sizeof(GuestTmFields))) return false;
    const int32_t fields[] = {value.tm_sec, value.tm_min, value.tm_hour, value.tm_mday,
                              value.tm_mon, value.tm_year, value.tm_wday, value.tm_yday,
                              value.tm_isdst};
    for (unsigned i = 0; i < 9; ++i) host.MemoryWrite32(addr + i * 4, static_cast<uint32_t>(fields[i]));
#if defined(__ANDROID__)
    host.MemoryWrite32(addr + 36, static_cast<uint32_t>(value.tm_gmtoff));
#else
    host.MemoryWrite32(addr + 36, 0);
#endif
    host.MemoryWrite32(addr + 40, 0);
    return true;
}

struct JumpState {
    std::array<uint32_t, 8> r4_r11{};
    uint32_t sp = 0;
    uint32_t lr = 0;
    uint32_t cpsr = 0;
};
thread_local std::unordered_map<uint32_t, JumpState> g_jump_states;
thread_local uint32_t g_strtok_cursor = 0;
thread_local uint32_t g_tm_buffer = 0;
thread_local uint32_t g_ctime_buffer = 0;

uint32_t GuestStrtok(DynarmicHost& host, uint32_t input, uint32_t delimiters) {
    char* cursor = input ? GuestChars(host, input) : GuestChars(host, g_strtok_cursor);
    const char* delim = GuestChars(host, delimiters);
    if (!cursor || !delim) return 0;
    while (*cursor && strchr(delim, static_cast<unsigned char>(*cursor))) ++cursor;
    if (!*cursor) { g_strtok_cursor = 0; return 0; }
    char* token = cursor;
    while (*cursor && !strchr(delim, static_cast<unsigned char>(*cursor))) ++cursor;
    if (*cursor) {
        *cursor++ = 0;
        g_strtok_cursor = GuestPointer(host, cursor);
    } else {
        g_strtok_cursor = 0;
    }
    return GuestPointer(host, token);
}

uint32_t ScanWide(DynarmicHost& host, const wchar_t* input, const wchar_t* format, GuestWords& words) {
    if (!input || !format) return 0;
    const wchar_t* in = input;
    uint32_t assigned = 0;
    for (const wchar_t* f = format; *f; ++f) {
        if (*f != L'%') {
            if (iswspace(*f)) while (iswspace(*in)) ++in;
            else if (*in++ != *f) break;
            continue;
        }
        ++f;
        bool long_value = false;
        while (*f >= L'0' && *f <= L'9') ++f;
        if (*f == L'l') { long_value = true; ++f; }
        if (*f == L's') {
            wchar_t* out = reinterpret_cast<wchar_t*>(GuestChars(host, words.Next()));
            if (!out) break;
            while (iswspace(*in)) ++in;
            while (*in && !iswspace(*in)) *out++ = *in++;
            *out = 0;
            ++assigned;
        } else if (*f == L'd' || *f == L'i' || *f == L'u' || *f == L'x') {
            wchar_t* end = nullptr;
            const long value = wcstol(in, &end, *f == L'x' ? 16 : 10);
            if (end == in) break;
            const uint32_t out = words.Next();
            if (out) host.MemoryWrite32(out, static_cast<uint32_t>(value));
            in = end;
            ++assigned;
        } else if (*f == L'f' || *f == L'e' || *f == L'g') {
            wchar_t* end = nullptr;
            const double value = wcstod(in, &end);
            if (end == in) break;
            const uint32_t out = words.Next();
            if (out) {
                if (long_value) { uint64_t bits; memcpy(&bits, &value, 8); host.MemoryWrite64(out, bits); }
                else { float v = static_cast<float>(value); uint32_t bits; memcpy(&bits, &v, 4); host.MemoryWrite32(out, bits); }
            }
            in = end;
            ++assigned;
        } else {
            break;
        }
    }
    return assigned;
}

}  // namespace

void RegisterLibcExtraThunks(ThunkManager& manager, DynarmicHost& host) {
    const uint32_t ctype_table = host.GuestAlloc(384, 16);
    const uint32_t ctype_object = host.GuestAlloc(4, 4);
    if (!ctype_table || !ctype_object) {
        LOGE("failed to allocate guest _ctype_ data");
    } else {
        memset(host.GetGuestMemoryBase() + ctype_table, 0, 384);
        for (uint32_t c = 0; c < 256; ++c) {
            const bool space = c == ' ' || (c >= 9 && c <= 13);
            const bool upper = c >= 'A' && c <= 'Z';
            const bool lower = c >= 'a' && c <= 'z';
            const bool digit = c >= '0' && c <= '9';
            const bool hex = digit || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
            const bool control = c < 32 || c == 127;
            const bool punct = c >= 33 && c <= 126 && !upper && !lower && !digit;
            const uint8_t flags = (upper ? 0x01 : 0) | (lower ? 0x02 : 0) |
                                  (digit ? 0x04 : 0) | (space ? 0x08 : 0) |
                                  (punct ? 0x10 : 0) | (control ? 0x20 : 0) |
                                  (hex ? 0x40 : 0) | (c == ' ' ? 0x80 : 0);
            host.MemoryWrite8(ctype_table + 127 + c, flags);
        }
        host.MemoryWrite32(ctype_object, ctype_table + 127);
        manager.RegisterSymbol("_ctype_", ctype_object);
    }

    manager.RegisterThunk("dlerror", [](Jit& jit, DynarmicHost& host) {
        static thread_local uint32_t message = 0;
        if (!message) message = host.GuestAlloc(1, 1);
        if (message) host.MemoryWrite8(message, 0);
        jit.Regs()[0] = message;
    });
    manager.RegisterThunk("ungetwc", [](Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = static_cast<uint32_t>(WEOF);
    });
    manager.RegisterThunk("rand", [](Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = static_cast<uint32_t>(rand());
    });
    manager.RegisterThunk("srand", [](Jit& jit, DynarmicHost&) {
        srand(jit.Regs()[0]);
        jit.Regs()[0] = 0;
    });
    manager.RegisterThunk("asin", [](Jit& jit, DynarmicHost&) { WriteDouble(jit, asin(ReadDouble(jit, 0))); });
    manager.RegisterThunk("atan", [](Jit& jit, DynarmicHost&) { WriteDouble(jit, atan(ReadDouble(jit, 0))); });
    manager.RegisterThunk("cosh", [](Jit& jit, DynarmicHost&) { WriteDouble(jit, cosh(ReadDouble(jit, 0))); });
    manager.RegisterThunk("sinh", [](Jit& jit, DynarmicHost&) { WriteDouble(jit, sinh(ReadDouble(jit, 0))); });
    manager.RegisterThunk("tanh", [](Jit& jit, DynarmicHost&) { WriteDouble(jit, tanh(ReadDouble(jit, 0))); });
    manager.RegisterThunk("fmod", [](Jit& jit, DynarmicHost&) { WriteDouble(jit, fmod(ReadDouble(jit, 0), ReadDouble(jit, 2))); });
    manager.RegisterThunk("ceil", [](Jit& jit, DynarmicHost&) { WriteDouble(jit, ceil(ReadDouble(jit, 0))); });
    manager.RegisterThunk("atof", [](Jit& jit, DynarmicHost& host) { const char* s = GuestChars(host, jit.Regs()[0]); WriteDouble(jit, s ? atof(s) : 0.0); });
    manager.RegisterThunk("ceilf", [](Jit& jit, DynarmicHost&) { WriteFloat(jit, 0, ceilf(ReadFloat(jit, 0))); });
    manager.RegisterThunk("floorf", [](Jit& jit, DynarmicHost&) { WriteFloat(jit, 0, floorf(ReadFloat(jit, 0))); });
    manager.RegisterThunk("modf", [](Jit& jit, DynarmicHost& host) {
        double integer = 0.0;
        const double fraction = modf(ReadDouble(jit, 0), &integer);
        if (jit.Regs()[2]) { uint64_t bits; memcpy(&bits, &integer, 8); host.MemoryWrite64(jit.Regs()[2], bits); }
        WriteDouble(jit, fraction);
    });

    manager.RegisterThunk("clock_gettime", [](Jit& jit, DynarmicHost& host) {
        struct timespec value{};
        const int result = clock_gettime(static_cast<clockid_t>(jit.Regs()[0]), &value);
        if (result == 0 && GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[1], 8)) {
            host.MemoryWrite32(jit.Regs()[1], static_cast<uint32_t>(value.tv_sec));
            host.MemoryWrite32(jit.Regs()[1] + 4, static_cast<uint32_t>(value.tv_nsec));
        }
        jit.Regs()[0] = static_cast<uint32_t>(result);
    });
    manager.RegisterThunk("ctime", [](Jit& jit, DynarmicHost& host) {
        const time_t value = static_cast<time_t>(static_cast<int32_t>(host.MemoryRead32(jit.Regs()[0])));
        const char* text = ctime(&value);
        if (!g_ctime_buffer) g_ctime_buffer = host.GuestAlloc(26, 1);
        if (g_ctime_buffer && text) memcpy(host.GetGuestMemoryBase() + g_ctime_buffer, text, 26);
        jit.Regs()[0] = g_ctime_buffer;
    });
    manager.RegisterThunk("gmtime", [](Jit& jit, DynarmicHost& host) {
        const time_t value = static_cast<time_t>(static_cast<int32_t>(host.MemoryRead32(jit.Regs()[0])));
        const struct tm* result = gmtime(&value);
        if (!g_tm_buffer) g_tm_buffer = host.GuestAlloc(sizeof(GuestTmFields), 4);
        jit.Regs()[0] = result && WriteGuestTm(host, g_tm_buffer, *result) ? g_tm_buffer : 0;
    });
    manager.RegisterThunk("strftime", [](Jit& jit, DynarmicHost& host) {
        char* out = jit.Regs()[1] ? static_cast<char*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[0], jit.Regs()[1])) : nullptr;
        const char* format = GuestChars(host, jit.Regs()[2]);
        struct tm value{};
        jit.Regs()[0] = out && format && ReadGuestTm(host, jit.Regs()[3], value)
            ? static_cast<uint32_t>(strftime(out, jit.Regs()[1], format, &value)) : 0;
    });
    manager.RegisterThunk("wcsftime", [](Jit& jit, DynarmicHost& host) {
        auto* out = jit.Regs()[1] ? reinterpret_cast<wchar_t*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[0], static_cast<size_t>(jit.Regs()[1]) * sizeof(wchar_t))) : nullptr;
        auto* format = GuestWide(host, jit.Regs()[2]);
        struct tm value{};
        jit.Regs()[0] = out && format && ReadGuestTm(host, jit.Regs()[3], value)
            ? static_cast<uint32_t>(wcsftime(out, jit.Regs()[1], format, &value)) : 0;
    });

    manager.RegisterThunk("getenv", [](Jit& jit, DynarmicHost& host) {
        const char* name = GuestChars(host, jit.Regs()[0]);
        static std::mutex mutex;
        static std::unordered_map<std::string, uint32_t> cache;
        const char* value = name ? getenv(name) : nullptr;
        if (!value) { jit.Regs()[0] = 0; return; }
        std::lock_guard<std::mutex> lock(mutex);
        auto it = cache.find(name);
        if (it == cache.end()) it = cache.emplace(name, CopyStable(host, value)).first;
        jit.Regs()[0] = it->second;
    });
    manager.RegisterThunk("setlocale", [](Jit& jit, DynarmicHost& host) {
        const char* requested = jit.Regs()[1] ? GuestChars(host, jit.Regs()[1]) : nullptr;
        const char* value = setlocale(static_cast<int>(jit.Regs()[0]), requested);
        static std::mutex mutex;
        static std::unordered_map<std::string, uint32_t> cache;
        if (!value) { jit.Regs()[0] = 0; return; }
        std::lock_guard<std::mutex> lock(mutex);
        auto it = cache.find(value);
        if (it == cache.end()) it = cache.emplace(value, CopyStable(host, value)).first;
        jit.Regs()[0] = it->second;
    });
    manager.RegisterThunk("localeconv", [](Jit& jit, DynarmicHost& host) {
        static uint32_t result = 0;
        static std::array<uint32_t, 10> strings{};
        if (!result) {
            const struct lconv* source = localeconv();
            result = host.GuestAlloc(56, 4);
            if (result && source) {
                const char* values[] = {source->decimal_point, source->thousands_sep, source->grouping,
                    source->int_curr_symbol, source->currency_symbol, source->mon_decimal_point,
                    source->mon_thousands_sep, source->mon_grouping, source->positive_sign, source->negative_sign};
                for (unsigned i = 0; i < 10; ++i) {
                    strings[i] = CopyStable(host, values[i] ? values[i] : "");
                    host.MemoryWrite32(result + i * 4, strings[i]);
                }
                const char chars[] = {source->int_frac_digits, source->frac_digits, source->p_cs_precedes,
                    source->p_sep_by_space, source->n_cs_precedes, source->n_sep_by_space, source->p_sign_posn,
                    source->n_sign_posn, source->int_p_cs_precedes, source->int_p_sep_by_space,
                    source->int_n_cs_precedes, source->int_n_sep_by_space, source->int_p_sign_posn,
                    source->int_n_sign_posn};
                for (unsigned i = 0; i < sizeof(chars); ++i) host.MemoryWrite8(result + 40 + i, static_cast<uint8_t>(chars[i]));
            }
        }
        jit.Regs()[0] = result;
    });

    auto ctype_handler = [](int (*fn)(int)) {
        return [fn](Jit& jit, DynarmicHost&) {
            const int value = static_cast<int>(jit.Regs()[0]);
            jit.Regs()[0] = static_cast<uint32_t>(fn(value == -1 ? EOF : static_cast<unsigned char>(value)));
        };
    };
    manager.RegisterThunk("isalnum", ctype_handler(&isalnum));
    manager.RegisterThunk("isalpha", ctype_handler(&isalpha));
    manager.RegisterThunk("iscntrl", ctype_handler(&iscntrl));
    manager.RegisterThunk("isprint", ctype_handler(&isprint));
    manager.RegisterThunk("ispunct", ctype_handler(&ispunct));
    manager.RegisterThunk("isspace", ctype_handler(&isspace));
    manager.RegisterThunk("isupper", ctype_handler(&isupper));
    manager.RegisterThunk("tolower", ctype_handler(&tolower));
    manager.RegisterThunk("toupper", ctype_handler(&toupper));
    manager.RegisterThunk("iswdigit", [](Jit& jit, DynarmicHost&) { jit.Regs()[0] = iswdigit(static_cast<wint_t>(jit.Regs()[0])); });
    manager.RegisterThunk("iswspace", [](Jit& jit, DynarmicHost&) { jit.Regs()[0] = iswspace(static_cast<wint_t>(jit.Regs()[0])); });
    manager.RegisterThunk("towlower", [](Jit& jit, DynarmicHost&) { jit.Regs()[0] = static_cast<uint32_t>(towlower(static_cast<wint_t>(jit.Regs()[0]))); });
    manager.RegisterThunk("towupper", [](Jit& jit, DynarmicHost&) { jit.Regs()[0] = static_cast<uint32_t>(towupper(static_cast<wint_t>(jit.Regs()[0]))); });
    manager.RegisterThunk("wctype", [](Jit& jit, DynarmicHost& host) {
        const char* name = GuestChars(host, jit.Regs()[0]);
        uint32_t value = 0;
        if (name) {
            if (strcmp(name, "alpha") == 0) value = 1;
            else if (strcmp(name, "digit") == 0) value = 2;
            else if (strcmp(name, "space") == 0) value = 3;
            else if (strcmp(name, "alnum") == 0) value = 4;
            else if (strcmp(name, "upper") == 0) value = 5;
            else if (strcmp(name, "lower") == 0) value = 6;
        }
        jit.Regs()[0] = value;
    });
    manager.RegisterThunk("iswctype", [](Jit& jit, DynarmicHost&) {
        const wint_t value = static_cast<wint_t>(jit.Regs()[0]);
        switch (jit.Regs()[1]) {
            case 1: jit.Regs()[0] = iswalpha(value); break;
            case 2: jit.Regs()[0] = iswdigit(value); break;
            case 3: jit.Regs()[0] = iswspace(value); break;
            case 4: jit.Regs()[0] = iswalnum(value); break;
            case 5: jit.Regs()[0] = iswupper(value); break;
            case 6: jit.Regs()[0] = iswlower(value); break;
            default: jit.Regs()[0] = 0; break;
        }
    });
    manager.RegisterThunk("btowc", [](Jit& jit, DynarmicHost&) { const int value = static_cast<int>(jit.Regs()[0]); jit.Regs()[0] = value == EOF ? WEOF : static_cast<unsigned char>(value); });
    manager.RegisterThunk("wctob", [](Jit& jit, DynarmicHost&) { const wint_t value = static_cast<wint_t>(jit.Regs()[0]); jit.Regs()[0] = value <= 0xFF ? static_cast<unsigned char>(value) : EOF; });

    manager.RegisterThunk("strchr", [](Jit& jit, DynarmicHost& host) { const uint32_t base = jit.Regs()[0]; const char* text = GuestChars(host, base); const char* found = text ? strchr(text, static_cast<int>(jit.Regs()[1])) : nullptr; jit.Regs()[0] = found ? base + static_cast<uint32_t>(found - text) : 0; });
    manager.RegisterThunk("strstr", [](Jit& jit, DynarmicHost& host) { const uint32_t base = jit.Regs()[0]; const char* text = GuestChars(host, base); const char* needle = GuestChars(host, jit.Regs()[1]); const char* found = text && needle ? strstr(text, needle) : nullptr; jit.Regs()[0] = found ? base + static_cast<uint32_t>(found - text) : 0; });
    manager.RegisterThunk("strpbrk", [](Jit& jit, DynarmicHost& host) { const uint32_t base = jit.Regs()[0]; const char* text = GuestChars(host, base); const char* accept = GuestChars(host, jit.Regs()[1]); const char* found = text && accept ? strpbrk(text, accept) : nullptr; jit.Regs()[0] = found ? base + static_cast<uint32_t>(found - text) : 0; });
    manager.RegisterThunk("strcspn", [](Jit& jit, DynarmicHost& host) { const char* a = GuestChars(host, jit.Regs()[0]); const char* b = GuestChars(host, jit.Regs()[1]); jit.Regs()[0] = a && b ? static_cast<uint32_t>(strcspn(a, b)) : 0; });
    manager.RegisterThunk("strncat", [](Jit& jit, DynarmicHost& host) { char* a = GuestChars(host, jit.Regs()[0]); const char* b = GuestChars(host, jit.Regs()[1]); if (a && b) strncat(a, b, jit.Regs()[2]); });
    manager.RegisterThunk("stpcpy", [](Jit& jit, DynarmicHost& host) { char* a = GuestChars(host, jit.Regs()[0]); const char* b = GuestChars(host, jit.Regs()[1]); jit.Regs()[0] = a && b ? GuestPointer(host, stpcpy(a, b)) : 0; });
    manager.RegisterThunk("strcoll", [](Jit& jit, DynarmicHost& host) { const char* a = GuestChars(host, jit.Regs()[0]); const char* b = GuestChars(host, jit.Regs()[1]); jit.Regs()[0] = a && b ? static_cast<uint32_t>(strcoll(a, b)) : 0; });
    manager.RegisterThunk("strxfrm", [](Jit& jit, DynarmicHost& host) { char* a = GuestChars(host, jit.Regs()[0]); const char* b = GuestChars(host, jit.Regs()[1]); jit.Regs()[0] = a && b ? static_cast<uint32_t>(strxfrm(a, b, jit.Regs()[2])) : 0; });
    manager.RegisterThunk("strtod", [](Jit& jit, DynarmicHost& host) { const uint32_t base = jit.Regs()[0]; const char* text = GuestChars(host, base); char* end = nullptr; const double value = text ? strtod(text, &end) : 0.0; if (jit.Regs()[1]) host.MemoryWrite32(jit.Regs()[1], end ? base + static_cast<uint32_t>(end - text) : base); WriteDouble(jit, value); });
    manager.RegisterThunk("strtof", [](Jit& jit, DynarmicHost& host) { const uint32_t base = jit.Regs()[0]; const char* text = GuestChars(host, base); char* end = nullptr; const float value = text ? strtof(text, &end) : 0.0f; if (jit.Regs()[1]) host.MemoryWrite32(jit.Regs()[1], end ? base + static_cast<uint32_t>(end - text) : base); WriteFloat(jit, 0, value); });
    manager.RegisterThunk("strtok", [](Jit& jit, DynarmicHost& host) { jit.Regs()[0] = GuestStrtok(host, jit.Regs()[0], jit.Regs()[1]); });

    manager.RegisterThunk("wcscat", [](Jit& jit, DynarmicHost& host) { auto* a = GuestWide(host, jit.Regs()[0]); auto* b = GuestWide(host, jit.Regs()[1]); if (a && b) wcscat(a, b); });
    manager.RegisterThunk("wcscmp", [](Jit& jit, DynarmicHost& host) { auto* a = GuestWide(host, jit.Regs()[0]); auto* b = GuestWide(host, jit.Regs()[1]); jit.Regs()[0] = a && b ? static_cast<uint32_t>(wcscmp(a, b)) : 0; });
    manager.RegisterThunk("wcscoll", [](Jit& jit, DynarmicHost& host) { auto* a = GuestWide(host, jit.Regs()[0]); auto* b = GuestWide(host, jit.Regs()[1]); jit.Regs()[0] = a && b ? static_cast<uint32_t>(wcscoll(a, b)) : 0; });
    manager.RegisterThunk("wcscpy", [](Jit& jit, DynarmicHost& host) { auto* a = GuestWide(host, jit.Regs()[0]); auto* b = GuestWide(host, jit.Regs()[1]); if (a && b) wcscpy(a, b); });
    manager.RegisterThunk("wcslen", [](Jit& jit, DynarmicHost& host) { auto* a = GuestWide(host, jit.Regs()[0]); jit.Regs()[0] = a ? static_cast<uint32_t>(wcslen(a)) : 0; });
    manager.RegisterThunk("wcsncpy", [](Jit& jit, DynarmicHost& host) { auto* a = GuestWide(host, jit.Regs()[0]); auto* b = GuestWide(host, jit.Regs()[1]); if (a && b) wcsncpy(a, b, jit.Regs()[2]); });
    manager.RegisterThunk("wcsstr", [](Jit& jit, DynarmicHost& host) { const uint32_t base = jit.Regs()[0]; auto* a = GuestWide(host, base); auto* b = GuestWide(host, jit.Regs()[1]); auto* found = a && b ? wcsstr(a, b) : nullptr; jit.Regs()[0] = found ? base + static_cast<uint32_t>(found - a) * sizeof(wchar_t) : 0; });
    manager.RegisterThunk("wcsxfrm", [](Jit& jit, DynarmicHost& host) { auto* a = GuestWide(host, jit.Regs()[0]); auto* b = GuestWide(host, jit.Regs()[1]); jit.Regs()[0] = a && b ? static_cast<uint32_t>(wcsxfrm(a, b, jit.Regs()[2])) : 0; });
    manager.RegisterThunk("wmemcpy", [](Jit& jit, DynarmicHost& host) { const size_t n = jit.Regs()[2]; auto* a = reinterpret_cast<wchar_t*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[0], n * sizeof(wchar_t))); auto* b = reinterpret_cast<const wchar_t*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[1], n * sizeof(wchar_t))); jit.Regs()[0] = a && b ? GuestPointer(host, wmemcpy(a, b, n)) : 0; });
    manager.RegisterThunk("wmemmove", [](Jit& jit, DynarmicHost& host) { const size_t n = jit.Regs()[2]; auto* a = reinterpret_cast<wchar_t*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[0], n * sizeof(wchar_t))); auto* b = reinterpret_cast<const wchar_t*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[1], n * sizeof(wchar_t))); jit.Regs()[0] = a && b ? GuestPointer(host, wmemmove(a, b, n)) : 0; });
    manager.RegisterThunk("wmemset", [](Jit& jit, DynarmicHost& host) { const size_t n = jit.Regs()[2]; auto* a = reinterpret_cast<wchar_t*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[0], n * sizeof(wchar_t))); jit.Regs()[0] = a ? GuestPointer(host, wmemset(a, static_cast<wchar_t>(jit.Regs()[1]), n)) : 0; });
    manager.RegisterThunk("wmemchr", [](Jit& jit, DynarmicHost& host) { const uint32_t base = jit.Regs()[0]; auto* a = reinterpret_cast<const wchar_t*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), base, static_cast<size_t>(jit.Regs()[2]) * sizeof(wchar_t))); const wchar_t* found = a ? wmemchr(a, static_cast<wchar_t>(jit.Regs()[1]), jit.Regs()[2]) : nullptr; jit.Regs()[0] = found ? base + static_cast<uint32_t>(found - a) * sizeof(wchar_t) : 0; });
    manager.RegisterThunk("wmemcmp", [](Jit& jit, DynarmicHost& host) {
        const uint32_t guest_s1 = jit.Regs()[0];
        const uint32_t guest_s2 = jit.Regs()[1];
        const size_t n = jit.Regs()[2];
        const auto* a = reinterpret_cast<const wchar_t*>(GuestSpan(
            host.GetGuestMemoryBase(), host.GetGuestMemorySize(), guest_s1, n * sizeof(wchar_t)));
        const auto* b = reinterpret_cast<const wchar_t*>(GuestSpan(
            host.GetGuestMemoryBase(), host.GetGuestMemorySize(), guest_s2, n * sizeof(wchar_t)));
        static std::atomic<uint32_t> initial_calls{0};
        const uint32_t initial_sample = initial_calls.fetch_add(1);
        if (initial_sample < 4u) {
            LOGE("W578 entry #%u lr=%08X r0=%08X r1=%08X r2=%u",
                 initial_sample, jit.Regs()[14], guest_s1, guest_s2,
                 static_cast<uint32_t>(n));
        }

        // W578: non-invasive snapshot of Arabica::NamespaceSupport::processName
        // tree comparisons observed as the live hot loop on ABB. The four
        // call sites distinguish namespace-tree traversal from name lookup.
        const uint32_t lr = jit.Regs()[14];
        if (lr == 0x401AC4C4u || lr == 0x401AC50Cu ||
            lr == 0x401AC75Cu || lr == 0x401AC7A4u) {
            static std::atomic<uint32_t> samples{0};
            const uint32_t sample = samples.fetch_add(1);
            if (sample < 64 || (sample % 2048u) == 0) {
                const size_t guest_size = host.GetGuestMemorySize();
                auto read_link = [&host, guest_size](uint32_t node, uint32_t offset) {
                    return static_cast<size_t>(node) <= guest_size &&
                           16u <= guest_size - static_cast<size_t>(node)
                        ? host.MemoryRead32(node + offset) : 0u;
                };
                auto preview = [&host, guest_size](uint32_t address) {
                    char out[20] = {};
                    if (static_cast<size_t>(address) <= guest_size &&
                        8u <= guest_size - static_cast<size_t>(address)) {
                        snprintf(out, sizeof(out), "%04X,%04X,%04X,%04X",
                                 host.MemoryRead16(address),
                                 host.MemoryRead16(address + 2u),
                                 host.MemoryRead16(address + 4u),
                                 host.MemoryRead16(address + 6u));
                    }
                    return std::string(out);
                };
                const uint32_t r4 = jit.Regs()[4];
                const uint32_t r7 = jit.Regs()[7];
                char line[256];
                snprintf(line, sizeof(line),
                         "W578 #%u lr=%08X r4=%08X[%08X,%08X] r7=%08X[%08X,%08X] r8=%08X r9=%08X n=%u s1=%08X:%s s2=%08X:%s",
                         sample, lr, r4, read_link(r4, 8u), read_link(r4, 12u),
                         r7, read_link(r7, 8u), read_link(r7, 12u),
                         jit.Regs()[8], jit.Regs()[9], static_cast<uint32_t>(n),
                         guest_s1, preview(guest_s1).c_str(),
                         guest_s2, preview(guest_s2).c_str());
                DiagTrace::NotePersist(line);
                if (sample < 8u) LOGE("%s", line);
            }
        }
        jit.Regs()[0] = a && b ? static_cast<uint32_t>(wmemcmp(a, b, n)) : 0;
    });
    manager.RegisterThunk("wcrtomb", [](Jit& jit, DynarmicHost& host) { char buffer[MB_LEN_MAX] = {}; const size_t result = wcrtomb(buffer, static_cast<wchar_t>(jit.Regs()[1]), nullptr); if (jit.Regs()[0] && result != static_cast<size_t>(-1)) memcpy(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]), buffer, result); jit.Regs()[0] = static_cast<uint32_t>(result); });
    manager.RegisterThunk("mbrtowc", [](Jit& jit, DynarmicHost& host) { auto* out = reinterpret_cast<wchar_t*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0])); const char* input = GuestChars(host, jit.Regs()[1]); const size_t result = mbrtowc(out, input, jit.Regs()[2], nullptr); jit.Regs()[0] = static_cast<uint32_t>(result); });

    manager.RegisterThunk("fgets", [](Jit& jit, DynarmicHost& host) { char* buffer = GuestChars(host, jit.Regs()[0]); FILE* file = GuestFileFor(jit.Regs()[2]); jit.Regs()[0] = buffer && file && fgets(buffer, static_cast<int>(jit.Regs()[1]), file) ? jit.Regs()[0] : 0; });
    manager.RegisterThunk("getc", [](Jit& jit, DynarmicHost&) { FILE* file = GuestFileFor(jit.Regs()[0]); jit.Regs()[0] = file ? static_cast<uint32_t>(getc(file)) : static_cast<uint32_t>(EOF); });
    manager.RegisterThunk("getwc", [](Jit& jit, DynarmicHost&) { FILE* file = GuestFileFor(jit.Regs()[0]); jit.Regs()[0] = file ? static_cast<uint32_t>(getwc(file)) : static_cast<uint32_t>(WEOF); });
    manager.RegisterThunk("ungetc", [](Jit& jit, DynarmicHost&) { FILE* file = GuestFileFor(jit.Regs()[1]); jit.Regs()[0] = file ? static_cast<uint32_t>(ungetc(static_cast<int>(jit.Regs()[0]), file)) : static_cast<uint32_t>(EOF); });
    manager.RegisterThunk("putchar", [](Jit& jit, DynarmicHost&) { const int value = static_cast<int>(jit.Regs()[0]); LOGI("[guest putchar] %c", value); jit.Regs()[0] = static_cast<uint32_t>(value); });
    manager.RegisterThunk("putwc", [](Jit& jit, DynarmicHost&) { jit.Regs()[0] = jit.Regs()[0]; });

    manager.RegisterThunk("vsprintf", [](Jit& jit, DynarmicHost& host) { const char* format = GuestChars(host, jit.Regs()[1]); GuestWords words{jit, host, jit.Regs()[2], true}; const std::string text = FormatGuestWords(host, format, words); if (jit.Regs()[0] && GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[0], text.size() + 1)) memcpy(host.GetGuestMemoryBase() + jit.Regs()[0], text.c_str(), text.size() + 1); jit.Regs()[0] = static_cast<uint32_t>(text.size()); });
    manager.RegisterThunk("__android_log_vprint", [](Jit& jit, DynarmicHost& host) {
        const int priority = static_cast<int>(jit.Regs()[0]);
        const char* tag = GuestChars(host, jit.Regs()[1]);
        const char* format = GuestChars(host, jit.Regs()[2]);
        GuestWords words{jit, host, jit.Regs()[3], true};
        const std::string text = FormatGuestWords(host, format, words);
        jit.Regs()[0] = static_cast<uint32_t>(__android_log_print(
            priority, tag ? tag : "Arm32Bridge_Guest", "%s", text.c_str()));
    });
    manager.RegisterThunk("vsscanf", [](Jit& jit, DynarmicHost& host) { const char* input = GuestChars(host, jit.Regs()[0]); const char* format = GuestChars(host, jit.Regs()[1]); GuestWords words{jit, host, jit.Regs()[2], true}; jit.Regs()[0] = GuestScan32::Scan(host, input, format, words); });
    manager.RegisterThunk("swscanf", [](Jit& jit, DynarmicHost& host) { auto* input = GuestWide(host, jit.Regs()[0]); auto* format = GuestWide(host, jit.Regs()[1]); GuestWords words{jit, host, 2, false}; jit.Regs()[0] = ScanWide(host, input, format, words); });

    manager.RegisterThunk("pipe", [](Jit& jit, DynarmicHost& host) { int fds[2] = {-1, -1}; const int result = pipe(fds); if (result == 0 && GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[0], 8)) { host.MemoryWrite32(jit.Regs()[0], fds[0]); host.MemoryWrite32(jit.Regs()[0] + 4, fds[1]);
        // W86 (run149): record every guest-visible pipe fd. The glue's cmd
        // pipe feeds the looper the game thread polls; if one of these
        // numbers is later closed, W85POLLERR explains itself.
        { static std::atomic<uint32_t> w86{0}; if (w86.fetch_add(1) < 64) { char b[96]; snprintf(b, sizeof(b), "W86PIPE r=%d w=%d lr=%08X", fds[0], fds[1], jit.Regs()[14]); DiagTrace::NotePersist(b); } }
    } jit.Regs()[0] = static_cast<uint32_t>(result); });
    manager.RegisterThunk("poll", [](Jit& jit, DynarmicHost& host) { const size_t count = jit.Regs()[1]; const uint32_t addr = jit.Regs()[0]; if (count > 256 || (count && !GuestRangeValid(host.GetGuestMemorySize(), addr, count * 8))) { jit.Regs()[0] = static_cast<uint32_t>(-1); return; } std::vector<pollfd> fds(count); for (size_t i = 0; i < count; ++i) { fds[i].fd = static_cast<int>(host.MemoryRead32(addr + static_cast<uint32_t>(i * 8))); fds[i].events = static_cast<short>(host.MemoryRead16(addr + static_cast<uint32_t>(i * 8 + 4))); } const int result = poll(fds.data(), count, static_cast<int>(jit.Regs()[2])); for (size_t i = 0; i < count; ++i) host.MemoryWrite16(addr + static_cast<uint32_t>(i * 8 + 6), static_cast<uint16_t>(fds[i].revents)); jit.Regs()[0] = static_cast<uint32_t>(result); });
    manager.RegisterThunk("ioctl", [](Jit& jit, DynarmicHost& host) { const int fd = static_cast<int>(jit.Regs()[0]); const unsigned long request = jit.Regs()[1]; const uint32_t arg = jit.Regs()[2]; const int result = arg ? ioctl(fd, request, GuestToHost(host.GetGuestMemoryBase(), arg)) : ioctl(fd, request); jit.Regs()[0] = static_cast<uint32_t>(result); });
    manager.RegisterThunk("writev", [](Jit& jit, DynarmicHost& host) { const int fd = static_cast<int>(jit.Regs()[0]); const uint32_t addr = jit.Regs()[1]; const int count = static_cast<int>(jit.Regs()[2]); if (count < 0 || count > 64 || (count && !GuestRangeValid(host.GetGuestMemorySize(), addr, static_cast<size_t>(count) * 8))) { jit.Regs()[0] = static_cast<uint32_t>(-1); return; } std::vector<iovec> vectors(static_cast<size_t>(count)); for (int i = 0; i < count; ++i) { const uint32_t data = host.MemoryRead32(addr + static_cast<uint32_t>(i * 8)); vectors[static_cast<size_t>(i)].iov_base = GuestToHost(host.GetGuestMemoryBase(), data); vectors[static_cast<size_t>(i)].iov_len = host.MemoryRead32(addr + static_cast<uint32_t>(i * 8 + 4)); } jit.Regs()[0] = static_cast<uint32_t>(writev(fd, vectors.data(), count)); });
    manager.RegisterThunk("syscall", [](Jit& jit, DynarmicHost&) { errno = ENOSYS; LOGE("guest syscall %u is unsupported", jit.Regs()[0]); jit.Regs()[0] = static_cast<uint32_t>(-1); });
    manager.RegisterThunk("sigaction", [](Jit& jit, DynarmicHost&) { jit.Regs()[0] = 0; });

    manager.RegisterThunk("pthread_attr_getschedparam", [](Jit& jit, DynarmicHost& host) { if (jit.Regs()[1] && GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[1], 4)) host.MemoryWrite32(jit.Regs()[1], 0); jit.Regs()[0] = 0; });
    manager.RegisterThunk("pthread_attr_setschedparam", [](Jit& jit, DynarmicHost&) { jit.Regs()[0] = 0; });
    manager.RegisterThunk("pthread_cond_init", [](Jit& jit, DynarmicHost&) { jit.Regs()[0] = 0; });
    manager.RegisterThunk("pthread_cond_destroy", [](Jit& jit, DynarmicHost&) { jit.Regs()[0] = 0; });
    manager.RegisterThunk("pthread_mutexattr_destroy", [](Jit& jit, DynarmicHost&) { jit.Regs()[0] = 0; });
    manager.RegisterThunk("pthread_key_delete", [](Jit& jit, DynarmicHost&) { jit.Regs()[0] = 0; });
    manager.RegisterThunk("pthread_join", [](Jit& jit, DynarmicHost&) { jit.Regs()[0] = 0; });
    manager.RegisterThunk("pthread_exit", [](Jit& jit, DynarmicHost& host) {
        LOGE("GUEST_PTHREAD_EXIT tid=%d value=%08X lr=%08X sp=%08X stack=%08X/%08X/%08X/%08X",
             gettid(), jit.Regs()[0], jit.Regs()[14], jit.Regs()[13],
             host.MemoryRead32(jit.Regs()[13]), host.MemoryRead32(jit.Regs()[13] + 4),
             host.MemoryRead32(jit.Regs()[13] + 8), host.MemoryRead32(jit.Regs()[13] + 12));
        { static std::atomic<uint32_t> w56{0}; if (w56.fetch_add(1) < 24) { char b[128]; snprintf(b, sizeof(b), "W56PEXIT code=0x%08X lr=0x%08X sp=0x%08X m0=0x%08X", jit.Regs()[0], jit.Regs()[14], jit.Regs()[13], host.MemoryRead32(jit.Regs()[13])); DiagTrace::NotePersist(b); } }
        jit.Regs()[15] = 0x4; jit.SetCpsr(jit.Cpsr() & ~0x20u); });
    manager.RegisterThunk("exit", [](Jit& jit, DynarmicHost&) { char eb[64]; snprintf(eb, sizeof(eb), "GUESTIT exit(%d)", static_cast<int32_t>(jit.Regs()[0])); DiagTrace::NotePersist(eb); LOGI("guest exit(%d)", static_cast<int32_t>(jit.Regs()[0])); jit.Regs()[15] = 0x4; jit.SetCpsr(jit.Cpsr() & ~0x20u); });

    manager.RegisterThunk("setjmp", [](Jit& jit, DynarmicHost&) { JumpState state; for (unsigned i = 0; i < state.r4_r11.size(); ++i) state.r4_r11[i] = jit.Regs()[4 + i]; state.sp = jit.Regs()[13]; state.lr = jit.Regs()[14]; state.cpsr = jit.Cpsr(); g_jump_states[jit.Regs()[0]] = state; jit.Regs()[0] = 0; });
    manager.RegisterThunk("longjmp", [](Jit& jit, DynarmicHost&) { const uint32_t env = jit.Regs()[0];
        { static std::atomic<uint32_t> w55{0}; if (w55.fetch_add(1) < 32) { char b[96]; snprintf(b, sizeof(b), "W55LJ env=0x%08X val=%u lr=0x%08X", env, jit.Regs()[1], jit.Regs()[14]); DiagTrace::NotePersist(b); } } const uint32_t value = jit.Regs()[1] ? jit.Regs()[1] : 1; auto it = g_jump_states.find(env); if (it == g_jump_states.end()) { LOGE("longjmp without matching setjmp env=0x%08X", env); jit.Regs()[0] = value; return; } const JumpState& state = it->second; for (unsigned i = 0; i < state.r4_r11.size(); ++i) jit.Regs()[4 + i] = state.r4_r11[i]; jit.Regs()[13] = state.sp; jit.Regs()[14] = state.lr; jit.SetCpsr((state.cpsr & ~0x20u) | ((state.lr & 1) ? 0x20u : 0)); jit.Regs()[0] = value; jit.Regs()[15] = state.lr & ~1u; });

    LOGI("libc/math/wchar/pthread import thunks registered");
}
