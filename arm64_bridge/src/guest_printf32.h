#pragma once

#include "guest_varargs32.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>

namespace GuestPrintf32 {

// Native libc formats a single, correctly typed value. Never pass an ARM32
// va_list to the host's variadic ABI, and never use host sizeof(long).
template <typename Value>
std::string Render(const std::string& spec, const int* stars, unsigned count, Value value) {
    auto print = [&](char* output, size_t capacity) {
        if (count == 2) return std::snprintf(output, capacity, spec.c_str(), stars[0], stars[1], value);
        if (count == 1) return std::snprintf(output, capacity, spec.c_str(), stars[0], value);
        return std::snprintf(output, capacity, spec.c_str(), value);
    };
    const int length = print(nullptr, 0);
    // Do not let a corrupt guest width allocate unbounded host memory.
    if (length < 0 || length > 1024 * 1024) return {};
    std::vector<char> output(static_cast<size_t>(length) + 1);
    print(output.data(), output.size());
    return std::string(output.data(), static_cast<size_t>(length));
}

template <typename Host, typename Words>
std::string Format(Host& host, const char* format, Words& words) {
    if (!format) return {};
    std::string result;
    for (const char* p = format; *p;) {
        if (*p != '%') { result += *p++; continue; }
        const char* begin = p++;
        if (*p == '%') { result += *p++; continue; }
        std::string spec = "%";
        while (*p && std::strchr("-+ #0'", *p)) spec += *p++;
        int stars[2]{};
        unsigned star_count = 0;
        if (*p == '*') { spec += *p++; stars[star_count++] = static_cast<int32_t>(words.Next()); }
        else while (*p >= '0' && *p <= '9') spec += *p++;
        if (*p == '.') {
            spec += *p++;
            if (*p == '*') { spec += *p++; stars[star_count++] = static_cast<int32_t>(words.Next()); }
            else while (*p >= '0' && *p <= '9') spec += *p++;
        }
        std::string length;
        if (*p && std::strchr("hljztL", *p)) {
            const char first = *p++;
            length += first;
            if ((first == 'h' || first == 'l') && *p == first) length += *p++;
        }
        const char conversion = *p;
        if (!conversion) { result.append(begin, p); break; }
        ++p;
        const bool wide_integer = length == "ll" || length == "j";
        if (conversion == 'd' || conversion == 'i') {
            int64_t value = wide_integer ? static_cast<int64_t>(words.Double())
                                        : static_cast<int32_t>(words.Next());
            if (length == "hh") value = static_cast<int8_t>(value);
            if (length == "h") value = static_cast<int16_t>(value);
            result += Render(spec + "ll" + conversion, stars, star_count, static_cast<long long>(value));
        } else if (std::strchr("uoxX", conversion)) {
            uint64_t value = wide_integer ? words.Double() : words.Next();
            if (length == "hh") value = static_cast<uint8_t>(value);
            if (length == "h") value = static_cast<uint16_t>(value);
            result += Render(spec + "ll" + conversion, stars, star_count, static_cast<unsigned long long>(value));
        } else if (std::strchr("fFeEgGaA", conversion)) {
            // Default argument promotion is double, including %f. AAPCS32
            // long double is also IEEE binary64, unlike some host ABIs.
            const uint64_t bits = words.Double();
            double value;
            std::memcpy(&value, &bits, sizeof(value));
            result += Render(spec + conversion, stars, star_count, value);
        } else if (conversion == 's') {
            const uint32_t address = words.Next();
            if (!address || address >= host.GetGuestMemorySize()) {
                result += Render(spec + 's', stars, star_count, "(null)");
            } else if (length == "l") {
                // Both Android ABIs use 32-bit wchar_t. Copy avoids host
                // alignment/aliasing assumptions and bounds the string.
                std::wstring value;
                const size_t count = std::min<size_t>((host.GetGuestMemorySize() - address) / 4, 1024 * 1024);
                for (size_t i = 0; i < count; ++i) {
                    const uint32_t ch = host.MemoryRead32(address + static_cast<uint32_t>(i * 4));
                    if (!ch) break;
                    value += static_cast<wchar_t>(ch);
                }
                result += Render(spec + "ls", stars, star_count, value.c_str());
            } else {
                const char* value = reinterpret_cast<const char*>(host.GetGuestMemoryBase() + address);
                const size_t available = std::min<size_t>(host.GetGuestMemorySize() - address, 1024 * 1024);
                const void* end = std::memchr(value, 0, available);
                const std::string bounded(value, end ? static_cast<const char*>(end) - value : available);
                result += Render(spec + 's', stars, star_count, bounded.c_str());
            }
        } else if (conversion == 'c') {
            const uint32_t value = words.Next();
            if (length == "l") result += Render(spec + "lc", stars, star_count, static_cast<wint_t>(value));
            else result += Render(spec + 'c', stars, star_count, static_cast<int>(value));
        } else if (conversion == 'p') {
            result += Render(spec + 'p', stars, star_count,
                             reinterpret_cast<void*>(static_cast<uintptr_t>(words.Next())));
        } else if (conversion == 'n') {
            const uint32_t address = words.Next();
            const size_t size = length == "hh" ? 1 : length == "h" ? 2 : wide_integer ? 8 : 4;
            if (address && address <= host.GetGuestMemorySize() && size <= host.GetGuestMemorySize() - address) {
                const uint64_t value = result.size();
                // Guest is little-endian, independent of the host layout.
                for (size_t i = 0; i < size; ++i)
                    host.GetGuestMemoryBase()[address + i] = static_cast<uint8_t>(value >> (i * 8));
            }
        } else {
            // Preserve unsupported syntax visibly, without guessing arguments.
            result.append(begin, p);
        }
    }
    return result;
}
} // namespace GuestPrintf32
