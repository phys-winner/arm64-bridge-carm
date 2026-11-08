#include "diag_trace.h"

#include <android/log.h>
#include <unistd.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#define LOG_TAG "Arm32Bridge_Diag"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// ---------------------------------------------------------------------------
// D1 no-progress trace. All hot-path work is a couple of map/counter updates
// plus an RLE append into a small fixed ring; the writer thread formats and
// writes <files>/bridge_diag.txt every 10 s. Nothing here changes
// guest-visible behavior: no sleeps on the guest path, no locks the guest
// waits on, no return-value changes.
// ---------------------------------------------------------------------------

namespace DiagTrace {

namespace {

constexpr size_t kRingCapacity = 512;      // RLE entries
constexpr size_t kLogLines = 128;          // recent guest log lines
constexpr int kWriteIntervalSec = 10;

struct RingEntry {
    uint32_t seq;                          // seq of run end
    uint32_t count;                        // run length of consecutive repeats
    uint32_t lr;                           // guest call site (LR at thunk entry)
    uint32_t name_hash;                    // FNV-1a of the thunk name
    uint32_t tid;                          // C2: host thread id of the dispatch
};

uint32_t NameHash(const char* s) {
    uint32_t h = 2166136261u;
    while (*s) h = (h ^ static_cast<uint8_t>(*s++)) * 16777619u;
    return h ? h : 1;  // keep 0 as "no run"
}

std::mutex g_mutex;
RingEntry g_ring[kRingCapacity];
size_t g_ring_head = 0;                    // next slot to write
uint32_t g_seq = 0;                        // total thunk dispatches
uint32_t g_run_hash = 0;
uint32_t g_run_lr = 0;
uint32_t g_run_tid = 0;
uint32_t g_run_count = 0;

struct NamedCounter {
    uint32_t calls;
    uint32_t last_seq;
};
std::unordered_map<std::string, NamedCounter> g_by_name;  // guarded by g_mutex

std::string g_log_lines[kLogLines];
size_t g_log_head = 0;

std::mutex g_pc_mutex;
std::function<std::vector<uint32_t>()> g_pc_provider;      // guarded by g_pc_mutex
std::unordered_map<uint32_t, uint32_t> g_pc_histogram;     // pc -> samples, g_mutex

std::mutex g_heap_mutex;
std::function<std::string()> g_heap_provider;              // guarded by g_heap_mutex

std::mutex g_mapwalk_mutex;
std::function<std::string()> g_mapwalk_provider;           // guarded by g_mapwalk_mutex

// W146: data-segment smash sentinel provider (guarded by g_sentinel_mutex).
std::mutex g_sentinel_mutex;
std::function<std::string()> g_sentinel_provider;

// W3: luaD_throw dump provider (guarded by g_error_mutex, declared before
// WriteDump uses it).
std::mutex g_error_mutex;
std::function<std::string()> g_error_provider;

// N2: dedicated heap-event ring so heap traffic cannot flush guest markers.
constexpr size_t kHeapEventLines = 192;
std::string g_heap_event_lines[kHeapEventLines];
size_t g_heap_event_head = 0;

// Phase-7: dedicated notes ring for top-level returns and qsort context;
// logcat throttling cannot flush these.
constexpr size_t kNoteLines = 2048;
std::string g_note_lines[kNoteLines];
size_t g_note_head = 0;

// W15: persist ring for death-time events; only a new event moves it, the
// post-freeze usleep spam cannot.
constexpr size_t kPersistLines = 128;
std::string g_persist_lines[kPersistLines];
size_t g_persist_head = 0;

// W21: fast PC ring -- 500 ms snapshots of every thread's PC set.
constexpr size_t kPcFastRing = 64;
struct PcSnap {
    uint32_t tick = 0;
    std::vector<uint32_t> pcs;
};
PcSnap g_pc_fast_ring[kPcFastRing];
size_t g_pc_fast_head = 0;

std::string g_files_path;
std::atomic<bool> g_started{false};

std::string FindNameByHash(uint32_t hash) {
    // Small N; linear scan is fine for a 10 s periodic dump.
    for (const auto& kv : g_by_name) {
        if (NameHash(kv.first.c_str()) == hash) return kv.first;
    }
    char b[16];
    snprintf(b, sizeof(b), "?hash%08x", hash);
    return std::string(b);
}

void WriteDump() {
    std::string out;
    char buf[256];
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        using namespace std::chrono;
        const auto now = system_clock::now().time_since_epoch();
        snprintf(buf, sizeof(buf), "=== bridge_diag seq_total=%u time=%lld\n",
                 g_seq, static_cast<long long>(duration_cast<seconds>(now).count()));
        out += buf;

        // Per-name totals with last-seen seq: deltas between consecutive dumps
        // show which calls are still being made (hot loop vs frozen ring).
        out += "--- per-name totals: calls last_seq name\n";
        std::vector<const std::pair<const std::string, NamedCounter>*> sorted;
        sorted.reserve(g_by_name.size());
        for (const auto& kv : g_by_name) sorted.push_back(&kv);
        std::sort(sorted.begin(), sorted.end(), [](auto* a, auto* b) {
            return a->second.calls > b->second.calls;
        });
        size_t shown = 0;
        for (auto* p : sorted) {
            if (++shown > 40) break;
            snprintf(buf, sizeof(buf), "%12u %10u %s\n",
                     p->second.calls, p->second.last_seq, p->first.c_str());
            out += buf;
        }

        out += "--- input thunk counters\n";
        for (const auto& item : g_by_name) {
            if (item.first.rfind("AInput", 0) != 0 && item.first.rfind("AMotion", 0) != 0) continue;
            snprintf(buf, sizeof(buf), "%12u %10u %s\n", item.second.calls,
                     item.second.last_seq, item.first.c_str());
            out += buf;
        }
        out += "--- recent guest log lines\n";
        for (size_t i = 0; i < kLogLines; ++i) {
            const std::string& line = g_log_lines[(g_log_head + i) % kLogLines];
            if (line.empty()) continue;
            out += line;
            out += '\n';
        }

        out += "--- notes (RET/qsort)\n";
        for (size_t i = 0; i < kNoteLines; ++i) {
            const std::string& line = g_note_lines[(g_note_head + i) % kNoteLines];
            if (line.empty()) continue;
            out += line;
            out += '\n';
        }

        out += "--- persist (unwind/cxa events)\n";
        for (size_t i = 0; i < kPersistLines; ++i) {
            const std::string& line = g_persist_lines[(g_persist_head + i) % kPersistLines];
            if (line.empty()) continue;
            out += line;
            out += '\n';
        }

        // W21: fast PC snapshots (500 ms cadence, last ~32 s).
        out += "--- pc fast ring (tick pcs...)\n";
        {
            char pb[512];
            for (size_t i = 0; i < kPcFastRing; ++i) {
                const PcSnap& snap = g_pc_fast_ring[(g_pc_fast_head + i) % kPcFastRing];
                if (snap.pcs.empty()) continue;
                int n = snprintf(pb, sizeof(pb), "%u:", snap.tick);
                for (uint32_t pc : snap.pcs) {
                    if (n > 0 && static_cast<size_t>(n) < sizeof(pb)) {
                        n += snprintf(pb + n, sizeof(pb) - static_cast<size_t>(n), " %08X", pc);
                    }
                }
                out += pb;
                out += '\n';
            }
        }

        out += "--- thunk ring (seq count tid lr name)\n";
        for (size_t i = 0; i < kRingCapacity; ++i) {
            const RingEntry& e = g_ring[(g_ring_head + i) % kRingCapacity];
            if (!e.count) continue;
            snprintf(buf, sizeof(buf), "%10u %6u %5u 0x%08X %s\n",
                     e.seq, e.count, e.tid, e.lr, FindNameByHash(e.name_hash).c_str());
            out += buf;
        }

        if (!g_pc_histogram.empty()) {
            out += "--- guest PC histogram (samples pc)\n";
            std::vector<const std::pair<const uint32_t, uint32_t>*> pcs;
            pcs.reserve(g_pc_histogram.size());
            for (const auto& kv : g_pc_histogram) pcs.push_back(&kv);
            std::sort(pcs.begin(), pcs.end(), [](auto* a, auto* b) {
                return a->second > b->second;
            });
            for (auto* p : pcs) {
                snprintf(buf, sizeof(buf), "%8u 0x%08X\n", p->second, p->first);
                out += buf;
            }
        }
    }

    // The canary pass runs outside g_mutex on purpose: it walks live guest-heap
    // blocks under the host's heap mutex and can take a few milliseconds.
    {
        std::lock_guard<std::mutex> lock(g_heap_mutex);
        if (g_heap_provider) {
            out += "--- heap canary report (C1)\n";
            out += g_heap_provider();
        }
    }
    // N1: live gDynamic_vb_map walk. Also outside g_mutex: it only reads guest
    // memory, racing guest execution the same way the canary pass does.
    {
        std::lock_guard<std::mutex> lock(g_mapwalk_mutex);
        if (g_mapwalk_provider) {
            out += "--- gDynamic_vb_map walk (N1)\n";
            out += g_mapwalk_provider();
        }
    }
    // W146: boot-critical globals + LLMem pool-descriptor head, with per-field
    // change lines. Outside g_mutex: pure guest-memory reads that race the
    // guest like the C1 canary pass.
    {
        std::lock_guard<std::mutex> lock(g_sentinel_mutex);
        if (g_sentinel_provider) {
            out += "--- W146 sentinel poll\n";
            out += g_sentinel_provider();
        }
    }
    // W3: luaD_throw dump. Outside g_mutex: reads guest scratch memory only.
    {
        std::lock_guard<std::mutex> lock(g_error_mutex);
        if (g_error_provider) {
            out += "--- lua throw dump (W3)\n";
            out += g_error_provider();
        }
    }
    // N2: guest-heap event ring (large malloc/free, freed-block-write hits).
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        out += "--- guest heap events (N2)\n";
        for (size_t i = 0; i < kHeapEventLines; ++i) {
            const std::string& line = g_heap_event_lines[(g_heap_event_head + i) % kHeapEventLines];
            if (line.empty()) continue;
            out += line;
            out += '\n';
        }
    }
    const std::string path = g_files_path + "/bridge_diag.txt";
    FILE* f = fopen(path.c_str(), "w");
    if (!f) {
        LOGI("diag dump open failed: %s", path.c_str());
        return;
    }
    fwrite(out.data(), 1, out.size(), f);
    fclose(f);
}

}  // namespace

void Start(const std::string& files_path) {
    if (g_started.exchange(true)) return;
    g_files_path = files_path;
    std::thread([] {
        uint32_t tick = 0;
        for (;;) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            // PC sampling: read every registered JIT's PC. A JIT mid-Run on its
            // own thread may hand back a torn value; that just lands as noise
            // in the histogram, which is fine for localizing a hot loop.
            std::vector<uint32_t> pcs;
            {
                std::lock_guard<std::mutex> lock(g_pc_mutex);
                if (g_pc_provider) pcs = g_pc_provider();
            }
            if (!pcs.empty()) {
                std::lock_guard<std::mutex> lock(g_mutex);
                for (uint32_t pc : pcs) ++g_pc_histogram[pc & ~1u];
                // W21: fast PC ring -- 500 ms snapshots of every thread's PC,
                // 64 entries (~32 s of history). The WAD parse completes inside
                // one 10 s dump interval, so the diverting pc is only visible
                // here.
                PcSnap& snap = g_pc_fast_ring[g_pc_fast_head];
                snap.tick = tick;
                snap.pcs = pcs;
                g_pc_fast_head = (g_pc_fast_head + 1) % kPcFastRing;
            }
            ++tick;
            // W30: instant-first mode -- during the first 20 s dump every
            // 0.5 s tick (the WAD parse runaway completes inside that
            // window; a 10 s cadence never sees the live node state).
            if (tick < 40 || tick % (kWriteIntervalSec * 2) == 0) WriteDump();
        }
    }).detach();
}

void SetPcProvider(std::function<std::vector<uint32_t>()> provider) {
    std::lock_guard<std::mutex> lock(g_pc_mutex);
    g_pc_provider = std::move(provider);
}

void SetHeapCheckProvider(std::function<std::string()> provider) {
    std::lock_guard<std::mutex> lock(g_heap_mutex);
    g_heap_provider = std::move(provider);
}

void SetMapWalkProvider(std::function<std::string()> provider) {
    std::lock_guard<std::mutex> lock(g_mapwalk_mutex);
    g_mapwalk_provider = std::move(provider);
}

void SetSentinelProvider(std::function<std::string()> provider) {
    std::lock_guard<std::mutex> lock(g_sentinel_mutex);
    g_sentinel_provider = std::move(provider);
}

void SetErrorDumpProvider(std::function<std::string()> provider) {
    std::lock_guard<std::mutex> lock(g_error_mutex);
    g_error_provider = std::move(provider);
}

void HeapEvent(const std::string& line) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_heap_event_lines[g_heap_event_head] = line;
    g_heap_event_head = (g_heap_event_head + 1) % kHeapEventLines;
}

void Note(const std::string& line) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_note_lines[g_note_head] = line;
    g_note_head = (g_note_head + 1) % kNoteLines;
}

void NotePersist(const std::string& line) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_persist_lines[g_persist_head] = line;
    g_persist_head = (g_persist_head + 1) % kPersistLines;
}

void Thunk(const char* name, uint32_t guest_lr) {
    if (!name) return;
    const uint32_t hash = NameHash(name);
    const uint32_t tid = static_cast<uint32_t>(gettid());
    std::lock_guard<std::mutex> lock(g_mutex);
    ++g_seq;
    NamedCounter& c = g_by_name[name];
    ++c.calls;
    c.last_seq = g_seq;
    if (hash == g_run_hash && guest_lr == g_run_lr) {
        ++g_run_count;
        return;
    }
    // Close the previous run; cap pathological run counts so seq stays honest.
    if (g_run_count) {
        RingEntry& e = g_ring[g_ring_head];
        e.seq = g_seq;
        e.count = g_run_count;
        e.lr = g_run_lr;
        e.name_hash = g_run_hash;
        e.tid = g_run_tid;
        g_ring_head = (g_ring_head + 1) % kRingCapacity;
    }
    g_run_hash = hash;
    g_run_lr = guest_lr;
    g_run_tid = tid;
    g_run_count = 1;
}

void GuestLog(const std::string& line) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_log_lines[g_log_head] = line;
    g_log_head = (g_log_head + 1) % kLogLines;
    // W18: the WAD/content narration prints in the first seconds of boot; the
    // 128-line ring is flushed by the lube loader long before the freeze, so
    // persist every WAD/content-related line (formatted by the printf thunk).
    if (line.find("WAD") != std::string::npos ||
        line.find("directory") != std::string::npos ||
        line.find("String table") != std::string::npos ||
        line.find("Generic") != std::string::npos ||
        line.find("generic") != std::string::npos ||
        line.find("Content") != std::string::npos ||
        line.find("Couldn't") != std::string::npos ||
        line.find("COULD NOT") != std::string::npos ||
        line.find("Sound") != std::string::npos) {
        static uint32_t s_persist_count = 0;  // guarded by g_mutex
        if (s_persist_count < 96) {
            ++s_persist_count;
            g_persist_lines[g_persist_head] = "GUESTLOG " + line;
            g_persist_head = (g_persist_head + 1) % kPersistLines;
        }
    }
}

}  // namespace DiagTrace
