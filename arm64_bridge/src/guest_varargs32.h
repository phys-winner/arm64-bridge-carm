#pragma once

#include <cstdint>

// AAPCS32 base PCS: four argument registers followed by stack words. A
// va_list is instead a byte-addressed cursor; 64-bit values align to 8 bytes.
// Kept independent of Dynarmic so the ABI cursor can be tested on its own.
template <typename Jit, typename Host>
struct GuestWords32 {
    Jit& jit;
    Host& host;
    uint32_t word;
    bool memory_only;

    uint32_t Next() {
        if (!memory_only && word < 4) return jit.Regs()[word++];
        uint32_t address;
        if (memory_only) {
            address = word;
            word += 4;
        } else {
            address = jit.Regs()[13] + (word++ - 4u) * 4u;
        }
        return host.MemoryRead32(address);
    }

    uint64_t Double() {
        if (memory_only) word = (word + 7u) & ~7u;
        else word = (word + 1u) & ~1u;
        const uint32_t low = Next();
        const uint32_t high = Next();
        return static_cast<uint64_t>(low) | (static_cast<uint64_t>(high) << 32);
    }
};
