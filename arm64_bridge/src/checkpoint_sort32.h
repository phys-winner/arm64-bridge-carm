#pragma once

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <vector>

namespace GuestCheckpointSort32 {

// libParsons Race_SortCheckpoints passes 0xA4-byte records to qsort. Its
// comparator (sub_55DDB0) reads the track-distance float at byte offset 52.
constexpr uint32_t kRecordSize = 0xA4;
constexpr uint32_t kDistanceOffset = 52;

inline bool Sort(uint8_t* records, uint32_t count) {
    if (!records || count > 4096) return false;
    struct Entry {
        std::array<uint8_t, kRecordSize> bytes;
        float distance;
    };
    std::vector<Entry> entries(count);
    for (uint32_t i = 0; i < count; ++i) {
        auto& entry = entries[i];
        std::memcpy(entry.bytes.data(), records + size_t(i) * kRecordSize,
                    kRecordSize);
        std::memcpy(&entry.distance, entry.bytes.data() + kDistanceOffset,
                    sizeof(entry.distance));
        // A NaN would make the guest comparator non-transitive.
        if (!std::isfinite(entry.distance)) return false;
    }
    std::stable_sort(entries.begin(), entries.end(),
                     [](const Entry& a, const Entry& b) {
                         return a.distance < b.distance;
                     });
    for (uint32_t i = 0; i < count; ++i)
        std::memcpy(records + size_t(i) * kRecordSize, entries[i].bytes.data(),
                    kRecordSize);
    return true;
}

} // namespace GuestCheckpointSort32
