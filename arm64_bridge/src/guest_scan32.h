#pragma once

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace GuestScan32 {

template <typename Host>
bool Write(Host& host, uint32_t address, uint64_t value, size_t bytes) {
    const size_t size = host.GetGuestMemorySize();
    if (!address || address > size || bytes > size - address) return false;
    for (size_t i = 0; i < bytes; ++i)
        host.GetGuestMemoryBase()[address + i] = static_cast<uint8_t>(value >> (8 * i));
    return true;
}

template <typename Host, typename Words>
int Scan(Host& host, const char* input, const char* format, Words& words) {
    if (!input || !format) return 0;
    const char* in = input;
    int assigned = 0;
    auto failure = [&]() -> int { return assigned ? assigned : (*in ? 0 : EOF); };
    for (const char* f = format; *f;) {
        if (std::isspace(static_cast<unsigned char>(*f))) {
            while (std::isspace(static_cast<unsigned char>(*f))) ++f;
            while (std::isspace(static_cast<unsigned char>(*in))) ++in;
            continue;
        }
        if (*f != '%') {
            if (*in != *f) return failure();
            ++in;
            ++f;
            continue;
        }
        ++f;
        if (*f == '%') {
            if (*in != '%') return failure();
            ++in;
            ++f;
            continue;
        }
        const bool suppress = *f == '*';
        if (suppress) ++f;
        size_t width = 0;
        while (*f >= '0' && *f <= '9') {
            width = std::min<size_t>(width * 10 + static_cast<unsigned>(*f - '0'), 4096);
            ++f;
        }
        char length = 0;
        if (*f == 'h' || *f == 'l' || *f == 'L' || *f == 'j' || *f == 'z' || *f == 't') {
            length = *f++;
            if ((*f == 'h' && length == 'h') || (*f == 'l' && length == 'l')) {
                length = length == 'h' ? 'H' : 'q';
                ++f;
            }
        }
        const char conversion = *f;
        if (!conversion) return assigned;
        ++f;
        if (conversion == 'n') {
            if (!suppress) {
                const size_t bytes = length == 'H' ? 1 : length == 'h' ? 2 :
                                     (length == 'q' || length == 'j') ? 8 : 4;
                if (!Write(host, words.Next(), static_cast<uint64_t>(in - input), bytes)) return assigned;
            }
            continue;
        }
        if (conversion == '[') {
            // Unlike %s, a scanset does not skip leading whitespace. The
            // game's dynamics parser reads tags with "<%[^>]>", so leaving
            // this conversion unsupported silently drops mass and shape.
            const bool negate = *f == '^';
            if (negate) ++f;
            bool members[256] = {};
            bool have_previous = false;
            unsigned char previous = 0;
            if (*f == ']') {
                members[static_cast<unsigned char>(*f++)] = true;
                previous = ']';
                have_previous = true;
            }
            while (*f && *f != ']') {
                const auto current = static_cast<unsigned char>(*f);
                if (current == '-' && have_previous && f[1] && f[1] != ']' &&
                    static_cast<unsigned char>(f[1]) >= previous) {
                    const auto last = static_cast<unsigned char>(f[1]);
                    for (unsigned value = previous; value <= last; ++value) members[value] = true;
                    previous = last;
                    f += 2;
                } else {
                    members[current] = true;
                    previous = current;
                    have_previous = true;
                    ++f;
                }
            }
            if (*f != ']') return assigned;
            ++f;
            const size_t limit = width ? width : SIZE_MAX;
            size_t count = 0;
            while (count < limit && in[count] &&
                   (members[static_cast<unsigned char>(in[count])] != negate)) ++count;
            if (!count) return failure();
            if (!suppress) {
                const uint32_t address = words.Next();
                if (!address || address > host.GetGuestMemorySize() ||
                    count + 1 > host.GetGuestMemorySize() - address) return assigned;
                std::memcpy(host.GetGuestMemoryBase() + address, in, count);
                host.GetGuestMemoryBase()[address + count] = 0;
                ++assigned;
            }
            in += count;
            continue;
        }
        if (conversion == 'c' || conversion == 's') {
            if (conversion == 's') while (std::isspace(static_cast<unsigned char>(*in))) ++in;
            const size_t available = std::strlen(in);
            const size_t count = conversion == 'c' ? (width ? width : 1) :
                std::min(available, width ? width : available);
            if (!count || count > available) return failure();
            if (!suppress) {
                const uint32_t address = words.Next();
                const size_t bytes = count + (conversion == 's' ? 1 : 0);
                if (!address || address > host.GetGuestMemorySize() ||
                    bytes > host.GetGuestMemorySize() - address) return assigned;
                std::memcpy(host.GetGuestMemoryBase() + address, in, count);
                if (conversion == 's') host.GetGuestMemoryBase()[address + count] = 0;
                ++assigned;
            }
            in += count;
            continue;
        }
        const bool integer = std::strchr("diuoxXp", conversion) != nullptr;
        const bool floating = std::strchr("fFeEgGaA", conversion) != nullptr;
        if (!integer && !floating) return assigned;
        while (std::isspace(static_cast<unsigned char>(*in))) ++in;
        if (!*in) return failure();
        // strto* needs a NUL-terminated token to enforce a scanf field width.
        const std::string bounded = width ? std::string(in, std::min(width, std::strlen(in))) : std::string();
        const char* source = width ? bounded.c_str() : in;
        char* end = nullptr;
        uint64_t bits = 0;
        size_t bytes = 4;
        if (floating) {
            const double value = std::strtod(source, &end);
            if (end == source) return failure();
            if (length == 'l' || length == 'L') {
                bytes = 8;
                std::memcpy(&bits, &value, sizeof(value));
            } else {
                const float single = static_cast<float>(value);
                uint32_t single_bits;
                std::memcpy(&single_bits, &single, sizeof(single));
                bits = single_bits;
            }
        } else {
            const int base = conversion == 'i' ? 0 :
                             (conversion == 'x' || conversion == 'X' || conversion == 'p') ? 16 :
                             conversion == 'o' ? 8 : 10;
            bits = (conversion == 'd' || conversion == 'i')
                ? static_cast<uint64_t>(std::strtoll(source, &end, base))
                : std::strtoull(source, &end, base);
            if (end == source) return failure();
            bytes = length == 'H' ? 1 : length == 'h' ? 2 :
                    (length == 'q' || length == 'j') ? 8 : 4;
        }
        in += end - source;
        if (!suppress) {
            if (!Write(host, words.Next(), bits, bytes)) return assigned;
            ++assigned;
        }
    }
    return assigned;
}

} // namespace GuestScan32
