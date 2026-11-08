#include "../src/checkpoint_sort32.h"

#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <limits>

int main() {
    using namespace GuestCheckpointSort32;
    std::array<uint8_t, kRecordSize * 4> records{};
    const float distances[] = {90.0f, 10.0f, 40.0f, 10.0f};
    for (unsigned i = 0; i < 4; ++i) {
        auto* record = records.data() + i * kRecordSize;
        std::memset(record, int(0x30 + i), kRecordSize);
        std::memcpy(record + kDistanceOffset, &distances[i], sizeof(float));
    }
    assert(Sort(records.data(), 4));
    const unsigned expected[] = {1, 3, 2, 0};
    for (unsigned i = 0; i < 4; ++i) {
        const auto* record = records.data() + i * kRecordSize;
        assert(record[0] == 0x30 + expected[i]);
        assert(record[kRecordSize - 1] == 0x30 + expected[i]);
        float distance;
        std::memcpy(&distance, record + kDistanceOffset, sizeof(distance));
        assert(distance == distances[expected[i]]);
    }
    const auto sorted = records;
    assert(Sort(records.data(), 4) && records == sorted);
    const float invalid = std::numeric_limits<float>::quiet_NaN();
    std::memcpy(records.data() + kDistanceOffset, &invalid, sizeof(invalid));
    const auto before = records;
    assert(!Sort(records.data(), 4) && records == before);
    assert(!Sort(nullptr, 4));
    std::puts("PASS checkpoint qsort distance, stable ties, whole records, invalid input");
}
