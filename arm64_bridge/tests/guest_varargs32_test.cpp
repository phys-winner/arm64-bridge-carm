#include "../src/guest_varargs32.h"
#include "../src/guest_printf32.h"
#include "../src/guest_scan32.h"
#include <array>
#include <cassert>
#include <cmath>
#include <cstdio>

struct TestJit {
    std::array<uint32_t, 16> regs{};
    auto& Regs() { return regs; }
};
struct TestHost {
    std::array<uint32_t, 64> words{};
    uint32_t MemoryRead32(uint32_t address) {
        assert((address & 3u) == 0 && address / 4 < words.size());
        return words[address / 4];
    }
    uint8_t* GetGuestMemoryBase() { return reinterpret_cast<uint8_t*>(words.data()); }
    size_t GetGuestMemorySize() const { return sizeof(words); }
};

int main() {
    TestJit jit;
    TestHost host;
    for (unsigned i = 0; i < host.words.size(); ++i) host.words[i] = 100 + i;
    jit.regs[2] = 22;
    jit.regs[3] = 33;
    jit.regs[13] = 64;

    GuestWords32<TestJit, TestHost> list{jit, host, 64, true};
    assert(list.Next() == 116);
    assert(list.Next() == 117);
    assert(list.Next() == 118);
    assert(list.word == 76);
    assert(list.Double() == (uint64_t(121) << 32 | 120));
    assert(list.Next() == 122);

    GuestWords32<TestJit, TestHost> regs{jit, host, 2, false};
    assert(regs.Next() == 22);
    assert(regs.Next() == 33);
    assert(regs.Next() == 116);
    assert(regs.Next() == 117);

    GuestWords32<TestJit, TestHost> aligned{jit, host, 3, false};
    assert(aligned.Double() == (uint64_t(117) << 32 | 116));
    assert(aligned.Next() == 118);
    GuestWords32<TestJit, TestHost> reg_pair{jit, host, 2, false};
    assert(reg_pair.Double() == (uint64_t(33) << 32 | 22));
    assert(reg_pair.Next() == 116);
    using Words = GuestWords32<TestJit, TestHost>;
    auto format_memory = [&](const char* format) {
        Words cursor{jit, host, 64, true};
        return GuestPrintf32::Format(host, format, cursor);
    };
    host.words[16] = 25;
    host.words[17] = 9;
    host.words[18] = 2026;
    assert(format_memory("%02ld-%02d-%d") == "25-09-2026");
    const double floating = 3.14159;
    std::memcpy(&host.words[16], &floating, sizeof(floating));
    host.words[18] = 7;
    assert(format_memory("%.3f:%d") == "3.142:7");
    assert(format_memory("%.4g") == "3.142");
    jit.regs[2] = host.words[16];
    jit.regs[3] = host.words[17];
    host.words[16] = 12;
    Words floating_regs{jit, host, 2, false};
    assert(GuestPrintf32::Format(host, "%.2f:%d", floating_regs) == "3.14:12");
    host.words[16] = 8;
    host.words[17] = 2;
    std::memcpy(&host.words[18], &floating, sizeof(floating));
    assert(format_memory("%*.*f") == "    3.14");
    host.words[16] = 192;
    std::memcpy(host.GetGuestMemoryBase() + 192, "abcdef", 7);
    host.words[17] = 0xab;
    assert(format_memory("%.3s %04X") == "abc 00AB");
    host.words[16] = 0xffffffffu;
    host.words[17] = 9;
    assert(format_memory("%ld %u") == "-1 9");
    host.words[16] = 0x89abcdef;
    host.words[17] = 0x12345678;
    host.words[18] = 7;
    assert(format_memory("%llx %d") == "1234567889abcdef 7");
    host.words[16] = 224;
    assert(format_memory("abc%n!") == "abc!");
    assert(host.words[56] == 3);
    TestJit scan_jit;
    TestHost scan_host;
    scan_jit.regs[2] = 128;
    scan_jit.regs[3] = 132;
    scan_jit.regs[13] = 64;
    GuestWords32<TestJit, TestHost> direct_scan{scan_jit, scan_host, 2, false};
    assert(GuestScan32::Scan(scan_host, "1 73.74", "%d %f", direct_scan) == 2);
    assert(scan_host.words[32] == 1);
    float scanned_float;
    std::memcpy(&scanned_float, &scan_host.words[33], sizeof(scanned_float));
    assert(std::fabs(scanned_float - 73.74f) < 0.0001f);
    scan_host.words[16] = 136;
    GuestWords32<TestJit, TestHost> memory_scan{scan_jit, scan_host, 64, true};
    assert(GuestScan32::Scan(scan_host, "0.35f", "%f", memory_scan) == 1);
    std::memcpy(&scanned_float, &scan_host.words[34], sizeof(scanned_float));
    assert(std::fabs(scanned_float - 0.35f) < 0.0001f);
    GuestWords32<TestJit, TestHost> suppressed_scan{scan_jit, scan_host, 2, false};
    assert(GuestScan32::Scan(scan_host, "12 25", "%*d %d", suppressed_scan) == 1);
    assert(scan_host.words[32] == 25);
    scan_jit.regs[2] = 140;
    GuestWords32<TestJit, TestHost> text_scan{scan_jit, scan_host, 2, false};
    assert(GuestScan32::Scan(scan_host, "hello", "%3s", text_scan) == 1);
    assert(std::strcmp(reinterpret_cast<char*>(scan_host.GetGuestMemoryBase() + 140), "hel") == 0);
    assert(GuestScan32::Scan(scan_host, "", "%d", text_scan) == EOF);
    scan_jit.regs[2] = 144;
    GuestWords32<TestJit, TestHost> tag_scan{scan_jit, scan_host, 2, false};
    assert(GuestScan32::Scan(scan_host, "<mass>", "<%[^>]>", tag_scan) == 1);
    assert(std::strcmp(reinterpret_cast<char*>(scan_host.GetGuestMemoryBase() + 144), "mass") == 0);
    GuestWords32<TestJit, TestHost> shape_scan{scan_jit, scan_host, 2, false};
    assert(GuestScan32::Scan(scan_host, "<shape>", "<%[^>]>", shape_scan) == 1);
    assert(std::strcmp(reinterpret_cast<char*>(scan_host.GetGuestMemoryBase() + 144), "shape") == 0);
    GuestWords32<TestJit, TestHost> width_scan{scan_jit, scan_host, 2, false};
    assert(GuestScan32::Scan(scan_host, "abcdef", "%3[a-z]", width_scan) == 1);
    assert(std::strcmp(reinterpret_cast<char*>(scan_host.GetGuestMemoryBase() + 144), "abc") == 0);
    GuestWords32<TestJit, TestHost> bracket_scan{scan_jit, scan_host, 2, false};
    assert(GuestScan32::Scan(scan_host, "]abcz", "%[]a-c]", bracket_scan) == 1);
    assert(std::strcmp(reinterpret_cast<char*>(scan_host.GetGuestMemoryBase() + 144), "]abc") == 0);
    GuestWords32<TestJit, TestHost> negated_scan{scan_jit, scan_host, 2, false};
    assert(GuestScan32::Scan(scan_host, "12 abc", "%[^a-z]", negated_scan) == 1);
    assert(std::strcmp(reinterpret_cast<char*>(scan_host.GetGuestMemoryBase() + 144), "12 ") == 0);
    GuestWords32<TestJit, TestHost> no_match_scan{scan_jit, scan_host, 2, false};
    assert(GuestScan32::Scan(scan_host, ">", "%[^>]", no_match_scan) == 0);
    GuestWords32<TestJit, TestHost> empty_scan{scan_jit, scan_host, 2, false};
    assert(GuestScan32::Scan(scan_host, "", "%[^>]", empty_scan) == EOF);
    scan_jit.regs[2] = 148;
    GuestWords32<TestJit, TestHost> suppressed_set_scan{scan_jit, scan_host, 2, false};
    assert(GuestScan32::Scan(scan_host, "<solid>17", "<%*[^>]>%d", suppressed_set_scan) == 1);
    assert(scan_host.words[37] == 17);
    puts("PASS: AAPCS32 sequential va_list, 64-bit alignment, register/stack transition");
    puts("PASS: shared printf formatter, double promotion, long32/longlong64, width/precision/stars, strings and %n");
    puts("PASS: shared scanf formatter, ARM32 output pointers, float/double, scansets, suppression, width and EOF");
}
