#include "thunk_manager.h"
#include "diag_trace.h"
#include "dynarmic_host.h"
#include "thunk_types.h"
#include "guest_printf32.h"
#include "guest_scan32.h"
#include "checkpoint_sort32.h"
#include "thunks_opensles.h"
#include "elf_loader.h"
#include "native_handle_table.h"
#include "obb_source.h"
#include <android/asset_manager.h>
#include <cmath>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <ctime>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <android/log.h>
#include <unordered_map>
#include <mutex>
#include <string>
#include <sstream>
#include <chrono>
#include <condition_variable>
#include <atomic>
#include <thread>
#include <chrono>
#include <memory>
#include <new>
#include <vector>
#include <algorithm>

#define LOG_TAG "Arm32Bridge_Libc"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

extern "C" FILE *funopen(const void *cookie,
                         int (*readfn)(void *, char *, int),
                         int (*writefn)(void *, const char *, int),
                         fpos_t (*seekfn)(void *, fpos_t, int),
                         int (*closefn)(void *));

AAssetManager* BridgeGetAssetManager();

struct ApkEntry {
    char name[128];
    off_t data_offset;
    off_t file_size;
};

static ApkEntry g_apk_entries[128];
static int g_num_apk_entries = 0;
static char g_apk_indexed_path[1024] = {0};
static int g_apk_indexed_fd = -1;

// W142: per-thread hold list of guest mutexes. A thread that halts inside a
// guest critical section used to leave the mutex locked forever (the boot
// froze on the LLMem allocator lock). GuestPthreadReleaseHeldMutexes()
// releases them all on top-level RunFunction exit.
struct HeldGuestMutexEntry {
    std::shared_ptr<std::recursive_mutex> m;
    uint32_t addr;
    uint32_t depth;
};
static thread_local std::vector<HeldGuestMutexEntry> t_held_guest_mutexes;

void GuestPthreadReleaseHeldMutexes();  // (definition below)



static std::vector<GuestThreadWorker> g_thread_workers;

// W100: guest address of the bz_StartInternal progress counter block, set at
// patch-install time and read by the W40PCS diag line in thunk_manager.cpp.
uint32_t g_w100_counter_addr = 0;
// W124: guest address of the bzd D_* step counters.
uint32_t g_w124_counter_addr = 0;
// W122: guest address of the bzd called/ret counter pair.
uint32_t g_w122_counter_addr = 0;
// W125: guest address of the bzd entry counter.
uint32_t g_w125_counter_addr = 0;
// W128: guest address of the pool-creator trace block.
uint32_t g_w128_counter_addr = 0;

const std::vector<GuestThreadWorker>& GetGuestThreadWorkers() {
    return g_thread_workers;
}

void AddGuestThreadWorker(uint32_t start_func, uint32_t arg) {
    g_thread_workers.push_back({start_func, arg});
}

struct FileCursor {
    std::mutex mutex;
    off_t pos = 0;
};

struct ApkCookie {
    int source_fd;
    off_t base_offset;
    off_t file_size;
    std::shared_ptr<FileCursor> cursor;
    bool clamp_seek;
};

static int ApkRead(void* cookie, char* buf, int size) {
    ApkCookie* c = static_cast<ApkCookie*>(cookie);
    if (size <= 0 || !c || c->source_fd < 0) return 0;
    std::lock_guard<std::mutex> lock(c->cursor->mutex);
    if (c->cursor->pos >= c->file_size) return 0;
    const size_t count = std::min<size_t>(size, c->file_size - c->cursor->pos);
    ssize_t n;
    do {
        n = pread(c->source_fd, buf, count, c->base_offset + c->cursor->pos);
    } while (n < 0 && errno == EINTR);
    if (n > 0) {
        c->cursor->pos += n;
        return static_cast<int>(n);
    }
    LOGE("file-backed read failed: size=%d offset=%lld result=%zd", size,
         static_cast<long long>(c->cursor->pos), n);
    if (n == 0) errno = EIO;  // The selected, validated file was truncated after selection.
    return -1;
}

static fpos_t ApkSeek(void* cookie, fpos_t offset, int whence) {
    ApkCookie* c = static_cast<ApkCookie*>(cookie);
    if (!c) return -1;
    std::lock_guard<std::mutex> lock(c->cursor->mutex);
    const off_t base = whence == SEEK_SET ? 0 :
                       whence == SEEK_CUR ? c->cursor->pos :
                       whence == SEEK_END ? c->file_size : -1;
    if (base < 0 || offset < -base) return -1;
    if (offset > c->file_size - base && !c->clamp_seek) return -1;
    const off_t target = offset > c->file_size - base ? c->file_size : base + offset;
    c->cursor->pos = target;
    return target;
}

static int ApkClose(void* cookie) {
    ApkCookie* c = static_cast<ApkCookie*>(cookie);
    if (c) {
        close(c->source_fd);
        delete c;
    }
    return 0;
}

// Takes ownership of source_fd even on failure. OBB streams are unbuffered so
// fileno()'s virtual FD and FILE callbacks observe one logical cursor.
static FILE* OpenFileBackedStream(int source_fd, off_t base, off_t size,
                                  const std::shared_ptr<FileCursor>& cursor,
                                  bool unbuffered) {
    if (source_fd < 0) return nullptr;
    auto* cookie = new (std::nothrow) ApkCookie{source_fd, base, size, cursor, !unbuffered};
    if (!cookie) { close(source_fd); return nullptr; }
    FILE* stream = funopen(cookie, ApkRead, nullptr, ApkSeek, ApkClose);
    if (!stream) { ApkClose(cookie); return nullptr; }
    if (unbuffered && setvbuf(stream, nullptr, _IONBF, 0) != 0) {
        fclose(stream);
        return nullptr;
    }
    return stream;
}

extern "C" int IndexApk(const char* apk_path) {
    if (!apk_path) return -1;
    strncpy(g_apk_indexed_path, apk_path, sizeof(g_apk_indexed_path) - 1);
    if (g_apk_indexed_fd >= 0) close(g_apk_indexed_fd);
    g_apk_indexed_fd = open(g_apk_indexed_path, O_RDONLY);
    if (g_apk_indexed_fd < 0) {
        LOGE("IndexApk: Failed to open APK: %s (errno %d)", g_apk_indexed_path, errno);
        return -1;
    }

    off_t file_len = lseek(g_apk_indexed_fd, 0, SEEK_END);
    if (file_len < 22) return -1;

    off_t search_len = file_len < 65536 + 22 ? file_len : 65536 + 22;
    off_t search_start = file_len - search_len;
    unsigned char* buf = static_cast<unsigned char*>(malloc(search_len));
    if (!buf) return -1;

    pread(g_apk_indexed_fd, buf, search_len, search_start);
    off_t eocd_offset = -1;
    for (ssize_t i = search_len - 22; i >= 0; --i) {
        if (buf[i] == 0x50 && buf[i+1] == 0x4b && buf[i+2] == 0x05 && buf[i+3] == 0x06) {
            eocd_offset = search_start + i;
            break;
        }
    }
    free(buf);

    if (eocd_offset < 0) {
        LOGE("IndexApk: EOCD not found in APK!");
        return -1;
    }

    unsigned char eocd[22];
    pread(g_apk_indexed_fd, eocd, 22, eocd_offset);
    uint16_t num_entries = *reinterpret_cast<uint16_t*>(eocd + 10);
    uint32_t cd_size = *reinterpret_cast<uint32_t*>(eocd + 12);
    uint32_t cd_offset = *reinterpret_cast<uint32_t*>(eocd + 16);

    unsigned char* cd = static_cast<unsigned char*>(malloc(cd_size));
    if (!cd) return -1;
    pread(g_apk_indexed_fd, cd, cd_size, cd_offset);

    g_num_apk_entries = 0;
    uint32_t pos = 0;
    for (int i = 0; i < num_entries && pos + 46 <= cd_size; ++i) {
        if (*reinterpret_cast<uint32_t*>(cd + pos) != 0x02014b50) break;
        uint16_t method = *reinterpret_cast<uint16_t*>(cd + pos + 10);
        uint32_t usize = *reinterpret_cast<uint32_t*>(cd + pos + 24);
        uint16_t fn_len = *reinterpret_cast<uint16_t*>(cd + pos + 28);
        uint16_t extra_len = *reinterpret_cast<uint16_t*>(cd + pos + 30);
        uint16_t comm_len = *reinterpret_cast<uint16_t*>(cd + pos + 32);
        uint32_t local_hdr_offset = *reinterpret_cast<uint32_t*>(cd + pos + 42);

        char fn[256] = {0};
        int cpy = fn_len < 255 ? fn_len : 255;
        memcpy(fn, cd + pos + 46, cpy);

        // Audio entries retain the existing APK VFS. The whole OBB is handled
        // exclusively by the validated source selector, never by this raw ZIP
        // index (which does not authenticate entries).
        //
        // Whatever you add MUST be stored uncompressed in the APK (apktool: doNotCompress,
        // aapt: -0): everything below reads raw bytes at the entry offset, so a deflated
        // entry hands the engine compressed garbage with no error anywhere.
        if (strstr(fn, "FMOD") != nullptr || strstr(fn, ".fsb") != nullptr || strstr(fn, ".fev") != nullptr
            || strstr(fn, "assets/data/audio") != nullptr) {
            unsigned char local_hdr[30];
            pread(g_apk_indexed_fd, local_hdr, 30, local_hdr_offset);
            uint16_t l_fn_len = *reinterpret_cast<uint16_t*>(local_hdr + 26);
            uint16_t l_extra_len = *reinterpret_cast<uint16_t*>(local_hdr + 28);
            off_t raw_data_offset = local_hdr_offset + 30 + l_fn_len + l_extra_len;

            if (g_num_apk_entries < 128) {
                strncpy(g_apk_entries[g_num_apk_entries].name, fn, 127);
                g_apk_entries[g_num_apk_entries].data_offset = raw_data_offset;
                g_apk_entries[g_num_apk_entries].file_size = usize;
                LOGI("IndexApk entry [%d]: %s (method=%d, size=%u, offset=%lld)",
                     g_num_apk_entries, fn, method, usize, static_cast<long long>(raw_data_offset));
                g_num_apk_entries++;
            }
        }
        pos += 46 + fn_len + extra_len + comm_len;
    }
    free(cd);
    LOGI("IndexApk: Indexed %d audio entries from APK: %s", g_num_apk_entries, apk_path);
    return 0;
}

static ApkEntry* FindApkEntry(const char* path) {
    if (!path || g_num_apk_entries == 0) return nullptr;
    const char* slash = strrchr(path, '/');
    const char* base = slash ? slash + 1 : path;

    char preferred[256];
    snprintf(preferred, sizeof(preferred), "assets/data/audio/%s", base);
    // Plain assets/<basename> is still used for legacy audio entries. OBB
    // requests are intercepted before reaching this unauthenticated index.
    char in_assets[256];
    snprintf(in_assets, sizeof(in_assets), "assets/%s", base);
    for (int i = 0; i < g_num_apk_entries; ++i) {
        if (strcmp(g_apk_entries[i].name, preferred) == 0 || strcmp(g_apk_entries[i].name, path) == 0
            || strcmp(g_apk_entries[i].name, in_assets) == 0) {
            return &g_apk_entries[i];
        }
    }

    // 3. Language suffix fallback (e.g. VOICE.fsb -> VOICE_eng.fsb)
    std::string base_str(base);
    if (base_str.size() > 4 && base_str.substr(base_str.size() - 4) == ".fsb") {
        std::string stem = base_str.substr(0, base_str.size() - 4);
        std::string eng_variant = "assets/data/audio/" + stem + "_eng.fsb";
        for (int i = 0; i < g_num_apk_entries; ++i) {
            if (g_apk_entries[i].name == eng_variant || strstr(g_apk_entries[i].name, (stem + "_eng").c_str()) != nullptr) {
                return &g_apk_entries[i];
            }
        }
        for (int i = 0; i < g_num_apk_entries; ++i) {
            if (strstr(g_apk_entries[i].name, stem.c_str()) != nullptr) {
                return &g_apk_entries[i];
            }
        }
    }
    return nullptr;
}

// A file region already laid into the guest arena. The mmap thunk consults this before
// making a new mapping: the arena is bump-allocated, so mapping the same 345 MB expansion
// file a second time is a second permanent hole. Engines do exactly that -- a "reinstall"
// or "reload paks" path closes every archive and reopens it.
struct GuestFileMapping {
    dev_t  dev;
    ino_t  ino;
    off_t  off;      // page-aligned file offset
    size_t span;     // page-aligned length
    uint32_t va;     // guest address
};
static std::vector<GuestFileMapping> g_guest_file_maps;
static std::mutex g_mapping_mutex;

struct VirtualFd {
    int source_fd;
    size_t file_size;
    off_t file_offset; // physical start of the logical file, in APK or external OBB
    std::shared_ptr<FileCursor> cursor;
};
static std::unordered_map<int, VirtualFd> g_vfd_map;
static int g_next_vfd = 1000;
static std::mutex g_vfd_mutex;

static int CreateVirtualFd(int fd, size_t size, off_t base,
                           const std::shared_ptr<FileCursor>& cursor) {
    if (fd < 0) return -1;
    std::lock_guard<std::mutex> lock(g_vfd_mutex);
    const int vfd = g_next_vfd++;
    g_vfd_map.emplace(vfd, VirtualFd{fd, size, base, cursor});
    return vfd;
}

static off_t SeekVirtualFd(VirtualFd& vfd, int64_t offset, int whence) {
    std::lock_guard<std::mutex> lock(vfd.cursor->mutex);
    const int64_t base = whence == SEEK_SET ? 0 :
                         whence == SEEK_CUR ? vfd.cursor->pos :
                         whence == SEEK_END ? static_cast<int64_t>(vfd.file_size) : -1;
    if (base < 0 || offset < -base || offset > static_cast<int64_t>(vfd.file_size) - base)
        return -1;
    vfd.cursor->pos = static_cast<off_t>(base + offset);
    return vfd.cursor->pos;
}

// Guest address of the real archive-open function, resolved by
// InstallAssetOverrideHook and tail-called from the veneer.
static uint32_t g_asset_override_real_fn = 0;

static std::unordered_map<uint32_t, FILE*> g_file_map;
static std::unordered_map<uint32_t, int> g_stream_vfd;  // FILE handle -> fileno() view
static uint32_t g_next_file_handle = 0x10001000;

FILE* GuestFileFor(uint32_t handle) {
    auto it = g_file_map.find(handle);
    return it == g_file_map.end() ? nullptr : it->second;
}

static std::unordered_map<uint32_t, void*> g_tls_map;
static uint32_t g_next_tls_key = 1;

#undef st_atime
#undef st_mtime
#undef st_ctime
#undef st_atime_nsec
#undef st_mtime_nsec
#undef st_ctime_nsec

// 32-bit ARM Linux/Android struct stat layout
struct Arm32Stat {
    uint32_t st_dev;
    uint32_t st_ino;
    uint16_t st_mode;
    uint16_t st_nlink;
    uint16_t st_uid;
    uint16_t st_gid;
    uint32_t st_rdev;
    uint32_t st_size;
    uint32_t st_blksize;
    uint32_t st_blocks;
    uint32_t st_atime;
    uint32_t st_atime_nsec;
    uint32_t st_mtime;
    uint32_t st_mtime_nsec;
    uint32_t st_ctime;
    uint32_t st_ctime_nsec;
};

static void WriteArm32Stat(uint8_t* guest_base, uint32_t gaddr, const struct stat& st) {
    if (!gaddr) return;
    Arm32Stat* arm_st = reinterpret_cast<Arm32Stat*>(GuestToHost(guest_base, gaddr));
    if (!arm_st) return;
    memset(arm_st, 0, sizeof(Arm32Stat));
    arm_st->st_dev = static_cast<uint32_t>(st.st_dev);
    arm_st->st_ino = static_cast<uint32_t>(st.st_ino);
    arm_st->st_mode = static_cast<uint16_t>(st.st_mode);
    arm_st->st_nlink = static_cast<uint16_t>(st.st_nlink);
    arm_st->st_uid = static_cast<uint16_t>(st.st_uid);
    arm_st->st_gid = static_cast<uint16_t>(st.st_gid);
    arm_st->st_rdev = static_cast<uint32_t>(st.st_rdev);
    arm_st->st_size = static_cast<uint32_t>(st.st_size);
    arm_st->st_blksize = static_cast<uint32_t>(st.st_blksize);
    arm_st->st_blocks = static_cast<uint32_t>(st.st_blocks);
    arm_st->st_atime = static_cast<uint32_t>(st.st_atim.tv_sec);
    arm_st->st_mtime = static_cast<uint32_t>(st.st_mtim.tv_sec);
    arm_st->st_ctime = static_cast<uint32_t>(st.st_ctim.tv_sec);
}

// ---------------------------------------------------------------------------
// The qsort thunk recognizes the game's pool and race-checkpoint comparators.
// The memory pool needs its descriptors in ascending size order; the race
// needs its checkpoint records in ascending track-distance order.
// ---------------------------------------------------------------------------

// W5: the original stub area 0x1E800/0x1E860/0x1E880/0x1F000 sat inside the
// .hash section of libParsons (0xf4..0x2396c) and corrupted runtime symbol
// lookup. Relocated into the free gap between .ARM.exidx end (0x65AA38) and
// .init_array (0x660828): 0x65AA40..0x660820 is genuinely unused.
// ARM MOVW/MOVT encoders (ARMv6T2+). Hand-encoded constants in this file
// historically swapped the imm4/Rd fields (one variant even wrote r15),
// halting the stub mid-run; generate them instead.
constexpr uint32_t EncodeMOVW(uint32_t rd, uint32_t imm16) {
    return 0xE3000000u | ((imm16 >> 12) << 16) | (rd << 12) | (imm16 & 0xFFFu);
}
constexpr uint32_t EncodeMOVT(uint32_t rd, uint32_t imm16) {
    return 0xE3400000u | ((imm16 >> 12) << 16) | (rd << 12) | (imm16 & 0xFFFu);
}

// W3: luaD_throw dump trampoline (guest ARM code on the executable scratch
// region below the SVC trampoline area).
//
// luaD_throw (sub_4DAB64) begins with:
//   0x4DAB64 PUSH {R4-R6,LR}
//   0x4DAB68 MOV  R4, R0            ; L
//   0x4DAB6C LDR  R3, [R0,#0x70]    ; errorJmp
//   0x4DAB70 MOV  R5, R1            ; errcode
// We replace the first word with BL 0x1E860 and re-emit the three following
// instructions after it, so every throw first runs the trampoline below: it
// snapshots {value, top-slot, tt} of the Lua stack's top-1 TValue plus L and
// the errcode into a scratch block at 0x1E880, stamps a magic word, restores
// the saved registers and returns into the patched site. The 10 s diag dump
// (DiagReadLuaThrow) prints the message and clears the magic.
constexpr uint32_t kLuaThrowStubAddr = 0x0065AB80;
constexpr uint32_t kLuaThrowScratchAddr = 0x0065AC00;constexpr uint32_t kLuaThrowMagic = 0xC0FFEE01;
constexpr uint32_t kLuaThrowPatchedEntry = 0x404DAB64;  // libParsons + 0x4DAB64
constexpr uint32_t kLuaThrowOrigPush = 0xE92D4070;      // PUSH {R4-R6,LR}

static const uint32_t kLuaThrowStub[] = {
    // W6: reached by an absolute literal jump from the patched luaD_throw
    // entry (BL cannot cover the 0x40000000..0x0065AB80 distance). Entry:
    // r0 = L (lua_State), r1 = errcode; LR = caller's return (untouched).
    0xE51FF004,  // 0x65AB80 LDR  pc, [pc, #-4]     ; jump to the dump body below
    0x404DAB6C,  // 0x65AB84 (literal) resume luaD_throw at +8
    0xE92D400F,  // 0x65AB88 PUSH {r0-r3, lr}
    0xE5902008,  // 0x65AB8C LDR  r2, [r0, #8]      ; top
    0xE2422010,  // 0x65AB90 SUB  r2, r2, #16       ; top-1 TValue slot
    0xE5923008,  // 0x65AB94 LDR  r3, [r2, #8]      ; tt
    0xE5920000,  // 0x65AB98 LDR  r0, [r2]          ; value (TString* when tt==4)
    EncodeMOVW(1, 0xAC00),  // 0x65AB9C MOVW r1, #0xAC00
    EncodeMOVT(1, 0x65),    // 0x65ABA0 MOVT r1, #0x65     ; r1 = 0x0065AC00 (scratch)
    0xE881000D,  // 0x65ABA4 STMIA r1!, {r0, r2, r3}
    EncodeMOVW(2, 0xEE01),  // 0x65ABA8 MOVW r2, #0xEE01 (W9: was MOVW r14)
    EncodeMOVT(2, 0xC0FF),  // 0x65ABAC MOVT r2, #0xC0FF      ; r2 = 0xC0FFEE01 (W9: was MOVT r12)
    0xE5812000,  // 0x65ABB0 STR  r2, [r1]          ; magic
    0xE8BD400F,  // 0x65ABB4 POP  {r0-r3, lr}
    0xE51FF004,  // 0x65ABB8 LDR  pc, [pc, #-4]     ; resume luaD_throw at +8
    0x404DAB6C,  // 0x65ABBC (literal) resume address
};

// Exported for jni_bridge.cpp: installs the trampoline after the guest image
// is loaded (once; safe before any guest code has executed).
static void EnsureLuaThrowDumper(DynarmicHost& host);
void InstallLuaThrowDumper(DynarmicHost& host) { EnsureLuaThrowDumper(host); }

static void EnsureLuaThrowDumper(DynarmicHost& host) {
    static std::once_flag once;
    std::call_once(once, [&host] {
        constexpr size_t kCount = sizeof(kLuaThrowStub) / sizeof(kLuaThrowStub[0]);
        for (size_t i = 0; i < kCount; ++i) {
            host.MemoryWrite32(kLuaThrowStubAddr + static_cast<uint32_t>(i * 4), kLuaThrowStub[i]);
        }
        // Overwrite the patched entry only if it still holds the expected
        // PUSH -- the opcode assertion required for in-memory guest patches.
        const uint32_t original = host.MemoryRead32(kLuaThrowPatchedEntry);
        if (original != kLuaThrowOrigPush) {
            LOGE("[luaD_throw] unexpected entry word 0x%08X -- dump patch skipped", original);
            return;
        }
        // W6: the stub now lives at 0x65AB80 -- far outside the BL ±32MB
        // range from 0x4DAB64 -- so patch with an absolute literal jump:
        //   0x4DAB64: LDR pc, [pc, #-4]   ; pc reads 0x4DAB6C -> literal
        //   0x4DAB68: 0x0065AB80          ; stub address
        //   0x4DAB6C..0x4DAB74: re-emitted MOV R4,R0 / LDR R3,[R0,#0x70] /
        //   MOV R5,R1; execution naturally continues at 0x4DAB78 (CMP).
        host.MemoryWrite32(kLuaThrowPatchedEntry, 0xE51FF004u);
        host.MemoryWrite32(kLuaThrowPatchedEntry + 4, kLuaThrowStubAddr);
        host.MemoryWrite32(kLuaThrowPatchedEntry + 8, 0xE1A04000u);
        host.MemoryWrite32(kLuaThrowPatchedEntry + 12, 0xE5903070u);
        host.MemoryWrite32(kLuaThrowPatchedEntry + 16, 0xE1A05001u);
        host.InvalidateGuestCode(kLuaThrowPatchedEntry, 20);
        LOGI("[luaD_throw] stack dump trampoline installed (patched 0x%08X -> 0x%08X)",
             kLuaThrowPatchedEntry, kLuaThrowStubAddr);
    });
}

// W7: Android_fopen (0x3F2928) path-dump trampoline. The terminate at
// boot+3s is std::length_error from the filename construction inside this
// function; the trampoline snapshots the path argument (r0) before any
// string work so the diag dump shows the corrupted path.
constexpr uint32_t kFopenDiagStubAddr = 0x0065ACC0;
constexpr uint32_t kFopenDiagScratchAddr = 0x0065AD00;
constexpr uint32_t kFopenDiagPatchedEntry = 0x403F2928;  // libParsons + 0x3F2928
constexpr uint32_t kFopenDiagOrigPush = 0xE92D4FF0;      // PUSH {R4-R11,LR}
constexpr uint32_t kFopenDiagMagic = 0xF1EEF1EE;

static const uint32_t kFopenDiagStub[] = {
    0xE92D000F,  // 0x65ACC0 PUSH {r0-r3, lr}
    EncodeMOVW(1, 0xAD00),  // 0x65ACC4 MOVW r1, #0xAD00
    EncodeMOVT(1, 0x65),    // 0x65ACC8 MOVT r1, #0x65     ; r1 = 0x0065AD00
    0xE5810004,  // 0x65ACCC STR  r0, [r1, #4]      ; path pointer
    EncodeMOVW(2, 0xF1EE),  // 0x65ACD0 MOVW r2, #0xF1EE (W9: was MOVW r15 = the boot halt)
    EncodeMOVT(2, 0xF1EE),  // 0x65ACD4 MOVT r2, #0xF1EE      ; r2 = 0xF1EEF1EE (W9: was MOVT r15)
    0xE5812000,  // 0x65ACD8 STR  r2, [r1]          ; magic
    0xE8BD000F,  // 0x65ACDC POP  {r0-r3, lr}
    0xE92D4FF0,  // 0x65ACE0 PUSH {R4-R11, LR}      ; displaced prologue
    0xE1A08001,  // 0x65ACE4 MOV  R8, R1            ; displaced prologue
    0xE51FF004,  // 0x65ACE8 LDR  pc, [pc, #-4]     ; resume at +8
    0x403F2930,  // 0x65ACEC (literal) resume address (W11: was 0x003F2930 -- missing the 0x40000000 load base, sent the resume into the RUNAWAY trap)
};

static void EnsureFopenDiagDumper(DynarmicHost& host);
void InstallFopenDiagDumper(DynarmicHost& host) { EnsureFopenDiagDumper(host); }

static void EnsureFopenDiagDumper(DynarmicHost& host) {
    static std::once_flag once;
    std::call_once(once, [&host] {
        constexpr size_t kCount = sizeof(kFopenDiagStub) / sizeof(kFopenDiagStub[0]);
        for (size_t i = 0; i < kCount; ++i) {
            host.MemoryWrite32(kFopenDiagStubAddr + static_cast<uint32_t>(i * 4), kFopenDiagStub[i]);
        }
        const uint32_t original = host.MemoryRead32(kFopenDiagPatchedEntry);
        if (original != kFopenDiagOrigPush) {
            LOGE("[Android_fopen] unexpected entry word 0x%08X -- diag patch skipped", original);
            return;
        }
        // Absolute literal jump (same as the luaD_throw W6 patch):
        //   0x3F2928: LDR pc, [pc, #-4]
        //   0x3F292C: 0x0065ACC0
        host.MemoryWrite32(kFopenDiagPatchedEntry, 0xE51FF004u);
        host.MemoryWrite32(kFopenDiagPatchedEntry + 4, kFopenDiagStubAddr);
        host.InvalidateGuestCode(kFopenDiagPatchedEntry, 8);
        LOGI("[Android_fopen] path dump trampoline installed (patched 0x%08X)",
             kFopenDiagPatchedEntry);
    });
}

// W7: __cxa_throw (0x58E014) catch-all dump trampoline. Fired for EVERY
// guest C++ throw; snapshots the throw site (LR), the exception object and
// the type_info name pointer into scratch 0x65AD80 before resuming.
constexpr uint32_t kCxaThrowStubAddr = 0x0065AD40;
constexpr uint32_t kCxaThrowScratchAddr = 0x0065AD80;
constexpr uint32_t kCxaThrowPatchedEntry = 0x4058E014;  // libParsons + 0x58E014
constexpr uint32_t kCxaThrowOrigPush = 0xE92D48F0;      // PUSH {R4-R7,R11,LR}
constexpr uint32_t kCxaThrowMagic = 0x71EE71EE;

// W10b causal repair: android_getCpuCount (0x17C72C) returns
// dword_67CCA0, which stays 0 because its pthread_once initializer is a
// no-op under the bridge (the SVC continuation cannot preserve a
// handler-written PC, so the init routine never runs). TaskManager::Start
// then computes cores-1 = -1 (0xFFFFFFFF) worker threads and
// vector::_M_fill_insert throws std::length_error("vector::_M_fill_insert")
// -> std::terminate -> the boot dies at +3s (proven in run28: throw site
// lr=0x40411E50 inside vector<long>::_M_fill_insert, message ptr
// 0x5F4058). Replace the function entirely: constant 4 cores, no
// MOVW/MOVT (undefined under the JIT arch config), no resume needed.
constexpr uint32_t kCpuCountStubAddr = 0x0065AC70;
constexpr uint32_t kCpuCountPatchedEntry = 0x4017C72C;  // libParsons + 0x17C72C
constexpr uint32_t kCpuCountOrigPush = 0xE92D4010;      // PUSH {R4,R12,LR}

static const uint32_t kCpuCountStub[] = {
    0xE3A00004,  // 0x65AC70 MOV r0, #4             ; 4 cores
    0xE12FFF1E,  // 0x65AC74 BX lr                  ; return to the caller
};

static void EnsureCpuCountStub(DynarmicHost& host);
void InstallCpuCountStub(DynarmicHost& host) { EnsureCpuCountStub(host); }

// W20 diagnostic: execution markers for the WAD parse tail. Evidence (run47):
// both parse printfs fire, the 88864-byte directory read succeeds, yet the
// "WAD file stats" print at 0x4145B8 never executes while the thread lives.
// Counter stubs at SetupWadDirPointers entry and at the parse tail (0x4145A0,
// right after it returns) split the divert point.
constexpr uint32_t kWadDirEntryMarkerStub = 0x0065AE00;
constexpr uint32_t kWadDirEntryPatched = 0x404140B0;  // libParsons + 0x4140B0
constexpr uint32_t kWadDirEntryOrig = 0xE92D47F0;     // PUSH {r4-r10,lr}
constexpr uint32_t kWadParseTailMarkerStub = 0x0065AE40;
constexpr uint32_t kWadParseTailPatched = 0x404145A0;  // libParsons + 0x4145A0
constexpr uint32_t kWadParseTailOrig = 0xE1D620B0;     // LDRH R2,[R6]
constexpr uint32_t kWadMarkerScratch = 0x0065AE80;     // [0] dir-entry count
                                                       // [1] tail count
                                                       // [2] tail LR

static const uint32_t kWadDirEntryMarkerStubCode[] = {
    EncodeMOVW(12, 0xAE80),  // MOVW r12, #0xAE80
    EncodeMOVT(12, 0x65),    // MOVT r12, #0x65     ; r12 = scratch
    0xE59C3000,              // LDR  r3, [r12]
    0xE2833001,              // ADD  r3, r3, #1
    0xE58C3000,              // STR  r3, [r12]      ; ++dir-entry count
    // W30: record buffer-B base (gAAFDirectoryBuffer at first dir entry) --
    // needed post-mortem because the runaway loop zeroes the global.
    EncodeMOVW(3, 0xB100),   // MOVW r3, #0xB100
    EncodeMOVT(3, 0x65),     // MOVT r3, #0x65      ; r3 = 0x65B100
    0xE5932000,              // LDR  r2, [r3]
    0xE3520000,              // CMP  r2, #0
    0x1A000003,              // BNE  +3 (skip record)
    EncodeMOVW(2, 0x0E60),   // MOVW r2, #0x0E60
    EncodeMOVT(2, 0x70),     // MOVT r2, #0x70      ; r2 = 0x700E60
    0xE5922000,              // LDR  r2, [r2]       ; base of buffer B
    0xE5832000,              // STR  r2, [r3]       ; record base_b
    0xE92D47F0,              // PUSH {r4-r10,lr}    ; displaced prologue
    0xE51FF004,              // LDR  pc, [pc, #-4]
    0x404140B4,              // resume SetupWadDirPointers at +4
};

static const uint32_t kWadParseTailMarkerStubCode[] = {
    EncodeMOVW(12, 0xAE80),  // 0x65AE40 MOVW r12, #0xAE80
    EncodeMOVT(12, 0x65),    // 0x65AE44 MOVT r12, #0x65     ; r12 = scratch
    0xE59C3004,              // 0x65AE48 LDR  r3, [r12, #4]
    0xE2833001,              // 0x65AE4C ADD  r3, r3, #1
    0xE58C3004,              // 0x65AE50 STR  r3, [r12, #4]  ; ++tail count
    0xE58CE000,              // 0x65AE54 STR  lr, [r12, #8]  ; tail LR
    0xE1D620B0,              // 0x65AE58 LDRH R2, [R6]       ; displaced
    0xE51FF004,              // 0x65AE5C LDR  pc, [pc, #-4]
    0x404145A4,              // 0x65AE60 resume parse at 0x4145A4
};

// W20b: SetupWadFilePointers entry marker. Run49 evidence: dir_entries=2
// ('DATA' + 'SETUP') and tail=0 -- the flow diverts inside 'SETUP's
// file-count loop, i.e. the first SetupWadFilePointers calls. Its first
// instruction is a PC-relative literal load (word 0x0025C814 pooled at
// 0x4140AC), so the stub embeds that literal and re-issues it.
constexpr uint32_t kWadFileEntryMarkerStub = 0x0065AF00;
constexpr uint32_t kWadFileEntryPatched = 0x40414024;  // libParsons + 0x414024
constexpr uint32_t kWadFileEntryOrig = 0xE59F3080;     // LDR R3,[PC,#0x80]
constexpr uint32_t kWadFileEntryLiteral = 0x0025C814;  // pooled at 0x4140AC
constexpr uint32_t kWadMarkerFileScratch = 0x0065AF80;

static const uint32_t kWadFileEntryMarkerStubCode[] = {
    EncodeMOVW(12, 0xAF80),  // MOVW r12, #0xAF80
    EncodeMOVT(12, 0x65),    // MOVT r12, #0x65     ; r12 = scratch2
    0xE59C2000,              // LDR  r2, [r12]
    0xE2822001,              // ADD  r2, r2, #1
    0xE58C2000,              // STR  r2, [r12]      ; ++file-entry count
    0xE58C100C,              // STR  r1, [r12, #12] ; a2 address
    0xE5912000,              // LDR  r2, [r1]
    0xE58C2010,              // STR  r2, [r12, #16] ; A-cursor value
    0xE58CD024,              // STR  r13, [r12, #36] ; entry SP
    // W31: capture the 16-byte node the reader is about to consume
    // (at the current gAAFDirectoryBuffer cursor, runtime address).
    EncodeMOVW(3, 0x0E60),   // MOVW r3, #0x0E60
    EncodeMOVT(3, 0x4070),  // MOVT r3, #0x4070     ; r3 = 0x40700E60
    0xE5932000,              // LDR  r2, [r3]        ; r2 = B cursor (node address)
    0xE5923000,              // LDR  r3, [r2]
    0xE58C3028,              // STR  r3, [r12, #40]  ; node w0
    0xE5923004,              // LDR  r3, [r2, #4]
    0xE58C302C,              // STR  r3, [r12, #44]  ; node w1 (fileCount)
    0xE5923008,              // LDR  r3, [r2, #8]
    0xE58C3030,              // STR  r3, [r12, #48]  ; node w2 (dirCount)
    0xE592300C,              // LDR  r3, [r2, #12]
    0xE58C3034,              // STR  r3, [r12, #52]  ; node w3
    0xE59F300C,              // LDR  r3, [pc, #12]  ; pooled literal
    0xE92D41F0,              // PUSH {r4-r8,lr}     ; displaced prologue
    0xE51FF004,              // LDR  pc, [pc, #-4]
    0x4041402C,              // resume SetupWadFilePointers at +4
    0x00000000,              // pad
    kWadFileEntryLiteral,    // pooled literal (was at 0x4140AC)
};

// W21: parse-entry + recursion-seam markers. Parse-entry counts
// _WAD_ParseWADFile invocations (the game retries: 3 AOPENs) and captures
// the file-name pointer. The seam marker counts returns into DATA's
// recursion loop at 0x414154 (first instruction after the recursive BL at
// 0x414150) -- run50: dir_entries=2 file_entries=5 tail=0 means the flow
// vanished exactly in this seam.
constexpr uint32_t kWadParseEntryMarkerStub = 0x0065AEC0;
constexpr uint32_t kWadParseEntryPatched = 0x4041442C;  // libParsons + 0x41442C
constexpr uint32_t kWadParseEntryOrig = 0xE92D47F0;     // PUSH {r4-r10,lr}
constexpr uint32_t kWadSeamMarkerStub = 0x0065AFC0;
constexpr uint32_t kWadSeamPatched = 0x40414154;        // libParsons + 0x414154
constexpr uint32_t kWadSeamOrig = 0xE5943004;           // LDR R3,[R4,#4]
constexpr uint32_t kWadMarkerScratch2 = 0x0065AF80;     // [4] attempts [8] name ptr
constexpr uint32_t kWadMarkerScratch3 = 0x0065B000;     // [0] seam returns
constexpr uint32_t kWadParseProbeSite = 0x4041442C;
constexpr uint32_t kWadParseProbeStub = 0x8F11E000;
constexpr uint32_t kWadParseProbeScratch = 0x93001A00;
static const uint32_t kWadParseProbeCode[] = {
    EncodeMOVW(12, 0x1A00), EncodeMOVT(12, 0x9300), // r12 = probe cells
    0xE58CE000,                                    // str lr,[r12]
    0xE58CD004,                                    // str sp,[r12,#4]
    0xE24D3004,                                    // sub r3,sp,#4 (saved-LR slot)
    0xE58C3008,                                    // str r3,[r12,#8]
    0xE3A03001,                                    // mov r3,#1
    0xE58C300C,                                    // str r3,[r12,#12] (active)
    0xE92D47F0,                                    // displaced push {r4-r10,lr}
    0xE1A04001,                                    // displaced mov r4,r1
    0xE51FF004, 0x40414434,                        // resume at original +8
};

static const uint32_t kWadParseEntryMarkerStubCode[] = {
    EncodeMOVW(12, 0xAF80),  // 0x65AEC0 MOVW r12, #0xAF80
    EncodeMOVT(12, 0x65),    // 0x65AEC4 MOVT r12, #0x65
    0xE59C2004,              // 0x65AEC8 LDR  r2, [r12, #4]
    0xE2822001,              // 0x65AECC ADD  r2, r2, #1
    0xE58C2004,              // 0x65AED0 STR  r2, [r12, #4]  ; ++attempts
    0xE58C0008,              // 0x65AED4 STR  r0, [r12, #8]  ; file-name ptr
    0xE92D47F0,              // 0x65AED8 PUSH {r4-r10,lr}    ; displaced prologue
    0xE51FF004,              // 0x65AEDC LDR  pc, [pc, #-4]
    0x40414430,              // 0x65AEE0 resume _WAD_ParseWADFile at +8 (MOV R4,R0)
};

static const uint32_t kWadSeamMarkerStubCode[] = {
    EncodeMOVW(12, 0xB000),  // 0x65AFC0 MOVW r12, #0xB000
    EncodeMOVT(12, 0x65),    // 0x65AFC4 MOVT r12, #0x65
    0xE59C2000,              // 0x65AFC8 LDR  r2, [r12]
    0xE2822001,              // 0x65AFCC ADD  r2, r2, #1
    0xE58C2000,              // 0x65AFD0 STR  r2, [r12]      ; ++seam returns
    0xE5943004,              // 0x65AFD4 LDR  R3, [R4, #4]   ; displaced
    0xE51FF004,              // 0x65AFD8 LDR  pc, [pc, #-4]
    0x40414158,              // 0x65AFDC resume SetupWadDirPointers at 0x414158
};

// W22d: file-loop exit counter at 0x414168 (CMP R5,#0 -- reached when the
// file-pointer loop of the current node has finished, right before the
// epilogue). Scratch 0x65B010[0].
constexpr uint32_t kWadFileLoopExitStub = 0x0065B0C0;
constexpr uint32_t kWadFileLoopExitPatched = 0x40414168;  // libParsons + 0x414168
constexpr uint32_t kWadFileLoopExitOrig = 0xE3550000;     // CMP R5,#0
constexpr uint32_t kWadFileLoopExitScratch = 0x0065B010;

static const uint32_t kWadFileLoopExitStubCode[] = {
    EncodeMOVW(12, 0xB010),  // 0x65B0C0 MOVW r12, #0xB010
    EncodeMOVT(12, 0x65),    // 0x65B0C4 MOVT r12, #0x65
    0xE59C2000,              // 0x65B0C8 LDR  r2, [r12]
    0xE2822001,              // 0x65B0CC ADD  r2, r2, #1
    0xE58C2000,              // 0x65B0D0 STR  r2, [r12]      ; ++file-loop exits
    0xE3550000,              // 0x65B0D4 CMP  R5, #0         ; displaced
    0xE51FF004,              // 0x65B0D8 LDR  pc, [pc, #-4]
    0x4041416C,              // 0x65B0DC resume at 0x41416C
};

// W22: dir-EPILOGUE marker at loc_414190 (LDR R3,[R7,#8] = --gDepth head;
// return PC sits at [SP+8] here). Splits "epilogue never ran" from "POP
// returned elsewhere" for the run49/50 dir_entries=2 file_entries=5 tail=0
// divert.
constexpr uint32_t kWadDirEpilogueMarkerStub = 0x0065B040;
constexpr uint32_t kWadDirEpiloguePatched = 0x40414190;  // libParsons + 0x414190
constexpr uint32_t kWadDirEpilogueOrig = 0xE5973000;     // LDR R3,[R7] (W22: real word, IDA showed [R7,#8] frame-addressed)

static const uint32_t kWadDirEpilogueMarkerStubCode[] = {
    // W26 CAUSAL FIX: the epilogue's saved-LR slot arrives corrupted with the
    // parse's own cursor pointer (&var_4) after SETUP's file loop. If the
    // saved return PC is not one of the two legitimate return addresses
    // (0x40414154 = back into SetupWadDirPointers, 0x404145A0 = back into
    // _WAD_ParseWADFile), rewrite it to 0x40414154 so the tree walk continues
    // in the parent frame instead of diverging onto the stack.
    EncodeMOVW(12, 0xB000),  // MOVW r12, #0xB000
    EncodeMOVT(12, 0x65),    // MOVT r12, #0x65      ; r12 = 0x65B000
    0xE59C2004,              // LDR  r2, [r12, #4]
    0xE2822001,              // ADD  r2, r2, #1
    0xE58C2004,              // STR  r2, [r12, #4]   ; ++epilogue count
    0xE59D2008,              // LDR  r2, [r13, #8]   ; saved return PC
    0xE59F3040,              // LDR  r3, [pc, #64]   ; =0x40414154
    0xE1520003,              // CMP  r2, r3
    0x13520450,              // CMPNE r2, #0x404145A0
    0x058D3008,              // STREQ r3, [r13, #8]  ; keep legit
    0x158D3008,              // STRNE r3, [r13, #8]  ; fix garbage -> DATA return
    0xE58C2010,              // STR  r2, [r12, #16]  ; remember raw value
    0xE58CD00C,              // STR  r13, [r12, #12] ; SP at epilogue
    0xE5973000,              // LDR  r3, [r7]        ; displaced (real word)
    0xE51FF004,              // LDR  pc, [pc, #-4]
    0x40414194,              // resume at 0x414194
    0x40414154,              // literal: return into SetupWadDirPointers
    0x404145A0,              // literal: return into _WAD_ParseWADFile
};

// W28: file-pointer EXIT counter at 0x41417C (first instruction after the
// BL SetupWadFilePointers inside the file loop). Counts successful returns;
// compared against file_entries it localizes the non-returning invocation.
constexpr uint32_t kWadFileExitMarkerStub = 0x0065B500;
constexpr uint32_t kWadFileExitPatched = 0x4041417C;  // libParsons + 0x41417C
constexpr uint32_t kWadFileExitOrig = 0xE594300C;     // LDR R3,[R4,#0xC]
constexpr uint32_t kWadFileExitScratch = 0x0065B030;

static const uint32_t kWadFileExitMarkerStubCode[] = {
    EncodeMOVW(12, 0xB030),  // MOVW r12, #0xB030
    EncodeMOVT(12, 0x65),    // MOVT r12, #0x65
    0xE59C2000,              // LDR  r2, [r12]
    0xE2822001,              // ADD  r2, r2, #1
    0xE58C2000,              // STR  r2, [r12]      ; ++file-exit count
    0xE594300C,              // LDR  R3, [R4, #12]  ; displaced
    0xE51FF004,              // LDR  pc, [pc, #-4]
    0x40414180,              // resume at 0x414180
};

// W32: micro-probes after each of the three bz_Mem_ReadU32 calls inside
// SetupWadDirPointers (0x4140FC/0x414108/0x414114) -- counts c1/c2/c3
// localize the exact stopping instruction of 'DATA' (run61: dir=1, no
// progress for minutes).
constexpr uint32_t kWadR32S1Stub = 0x0065B600;   // after 1st ReadU32 (ADD R9,R9,R0)
constexpr uint32_t kWadR32S1Patched = 0x404140FC;
constexpr uint32_t kWadR32S1Orig = 0xE0899000;
constexpr uint32_t kWadR32S2Stub = 0x0065B640;   // after 2nd ReadU32 (MOV R5,R0)
constexpr uint32_t kWadR32S2Patched = 0x40414108;
constexpr uint32_t kWadR32S2Orig = 0xE1A05000;
constexpr uint32_t kWadR32S3Stub = 0x0065B680;   // after 3rd ReadU32 (MOV R3,#0)
constexpr uint32_t kWadR32S3Patched = 0x40414114;
constexpr uint32_t kWadR32S3Orig = 0xE3A03000;
constexpr uint32_t kWadR32Scratch = 0x0065B700;  // [0]=c1 [4]=c2 [8]=c3

static const uint32_t kWadR32S1StubCode[] = {
    EncodeMOVW(12, 0xB700), EncodeMOVT(12, 0x65),
    0xE59C2000, 0xE2822001, 0xE58C2000,   // ++c1
    0xE0899000,                            // ADD R9,R9,R0 (displaced)
    0xE51FF004, 0x40414100,
};
static const uint32_t kWadR32S2StubCode[] = {
    EncodeMOVW(12, 0xB704), EncodeMOVT(12, 0x65),
    0xE59C2000, 0xE2822001, 0xE58C2004,   // ++c2
    0xE1A05000,                            // MOV R5,R0 (displaced)
    0xE51FF004, 0x4041410C,
};
static const uint32_t kWadR32S3StubCode[] = {
    EncodeMOVW(12, 0xB708), EncodeMOVT(12, 0x65),
    0xE59C2000, 0xE2822001, 0xE58C2008,   // ++c3
    0xE3A03000,                            // MOV R3,#0 (displaced)
    0xE51FF004, 0x40414118,
};

// W33 CAUSAL FIX: bridge-assisted directory walk. SetupWadDirPointers/
// SetupWadFilePointers hang/diverge under specific JIT block layouts
// (W22e-W32: 4 different stop points for the same valid input). The tree
// is fully known: 5554 sequential 16-byte nodes in buffer B. A host-side
// builder reproduces SetupWadDirPointers/SetupWadFilePointers semantics
// exactly (register-frame slots in buffer A, linked lists, gDepth), never
// executing the guest bodies.

static uint32_t kWad33Strbase() { return 0; }

static uint32_t HostWadBuildFile(DynarmicHost& host, uint32_t details,
                                 uint32_t& slotCur, uint32_t& rawCur,
                                 uint32_t strbase, uint32_t flags) {
    uint32_t nameOff = host.MemoryRead32(rawCur);
    uint32_t offset  = host.MemoryRead32(rawCur + 4);
    uint32_t size    = host.MemoryRead32(rawCur + 8);
    host.MemoryWrite32(0x40700E60, rawCur + 16);   // advance B cursor (mimic)
    rawCur += 16;                                  // guest shares this cursor
    uint32_t name = strbase + nameOff;
    host.MemoryWrite32(slotCur, 0);                // v2[0]
    host.MemoryWrite32(slotCur + 4, name);         // v2[1]
    host.MemoryWrite32(slotCur + 8, size);         // v2[2]
    uint32_t stored = offset;
    if (flags & 2) stored = offset - 4;
    host.MemoryWrite32(slotCur + 12, stored);      // v2[3]
    uint32_t r = slotCur;
    slotCur += 16;
    return r;
}

static uint32_t HostWadBuildDir(DynarmicHost& host, uint32_t details,
                                uint32_t& slotCur, uint32_t& rawCur,
                                uint32_t strbase, uint32_t flags, int depth) {
    uint32_t nameOff = host.MemoryRead32(rawCur);
    uint32_t fCount  = host.MemoryRead32(rawCur + 4);
    uint32_t dCount  = host.MemoryRead32(rawCur + 8);
    host.MemoryWrite32(0x40700E60, rawCur + 16);   // advance B cursor (mimic)
    rawCur += 16;                                  // guest shares this cursor
    uint32_t name = strbase + nameOff;
    uint32_t slot = slotCur; slotCur += 16;
    host.MemoryWrite32(slot, name);                // v3[0]
    host.MemoryWrite32(slot + 4, 0);               // v3[1] child-dirs
    host.MemoryWrite32(slot + 8, 0);               // v3[2]
    host.MemoryWrite32(slot + 12, 0);              // v3[3] files
    if (depth < 64) {
        for (uint32_t d = 0; d < dCount; ++d) {
            uint32_t child = HostWadBuildDir(host, details, slotCur, rawCur,
                                             strbase, flags, depth + 1);
            // child[8] = slot[4]; slot[4] = child   (prepend dir list)
            host.MemoryWrite32(child + 8, host.MemoryRead32(slot + 4));
            host.MemoryWrite32(slot + 4, child);
        }
    }
    for (uint32_t f = 0; f < fCount; ++f) {
        uint32_t fp = HostWadBuildFile(host, details, slotCur, rawCur,
                                       strbase, flags);
        // fp[0] = slot[12]; slot[12] = fp          (prepend file list)
        host.MemoryWrite32(fp, host.MemoryRead32(slot + 12));
        host.MemoryWrite32(slot + 12, fp);
    }
    return slot;
}

// Host handler behind SVC in the dir-entry stub: builds the whole tree,
// returns the root slot in r0.
static void W33BuildWadTreeHandler(Dynarmic::A32::Jit& jit, DynarmicHost& host) {
    uint32_t details = jit.Regs()[0];
    uint32_t a2      = jit.Regs()[1];
    const uint32_t parse_sp = jit.Regs()[13];
    const uint32_t parse_saved_lr_before = host.MemoryRead32(parse_sp + 0x24u);
    const uint32_t parse_entry_lr = host.MemoryRead32(kWadParseProbeScratch);
    const uint32_t parse_entry_sp = host.MemoryRead32(kWadParseProbeScratch + 4);
    const uint32_t parse_saved_lr_slot = host.MemoryRead32(kWadParseProbeScratch + 8);
    uint32_t slotCur = host.MemoryRead32(a2);          // var_4 = X-buffer cursor
    uint32_t strbase = host.MemoryRead32(details + 0x114);
    uint32_t flags   = host.MemoryRead32(details + 0x104);
    uint32_t rawCur  = host.MemoryRead32(0x40700E60);  // buffer B base (pre-walk)
    uint32_t root = HostWadBuildDir(host, details, slotCur, rawCur, strbase, flags, 0);
    host.MemoryWrite32(a2, slotCur);                   // store updated X cursor
    jit.Regs()[0] = root;                              // SetupWadDirPointers return
    host.MemoryWrite32(kWadParseProbeScratch + 12, 0);
    char b[224];
    snprintf(b, sizeof(b),
             "W33TREE root=%08X rawEnd=%08X slots=%u entry_lr=%08X entry_sp=%08X saved_slot=%08X saved_lr=%08X->%08X",
             root, rawCur, (slotCur - host.MemoryRead32(details + 0x110)) / 16,
             parse_entry_lr, parse_entry_sp, parse_saved_lr_slot,
             parse_saved_lr_before, host.MemoryRead32(parse_saved_lr_slot));
    DiagTrace::Note(b);
    LOGI("%s", b);
}

// W36: entry counters for the three NovaFile_Initialise registration calls.
constexpr uint32_t kW36FeStub = 0x0065C800;    // bz_FileExists entry probe
constexpr uint32_t kW36FePatched = 0x404083FC;
constexpr uint32_t kW36FeOrig = 0xE3500000;    // CMP R0,#0
constexpr uint32_t kW36WadStub = 0x0065C900;   // AddWADContent entry probe
constexpr uint32_t kW36WadPatched = 0x404040C8;
constexpr uint32_t kW36WadOrig = 0xE1A03001;   // MOV R3,R1
constexpr uint32_t kW36RiStub = 0x0065CA00;    // ReadAppInfo entry probe
constexpr uint32_t kW36RiPatched = 0x404035CC;
constexpr uint32_t kW36RiOrig = 0xE59F3010;    // LDR R3,[R0,#0x10]
constexpr uint32_t kW36CntBase = 0x0065CC00;   // [0]=fe [4]=wad [8]=ri

static const uint32_t kW36FeStubCode[] = {
    EncodeMOVW(12, 0xCC00), EncodeMOVT(12, 0x65),
    0xE59C2000, 0xE2822001, 0xE58C2000,   // ++c_fe
    0xE3500000,                            // CMP R0,#0 (displaced)
    0xE51FF004, 0x40408400,                // resume entry+4 (keep BEQ)
};
static const uint32_t kW36WadStubCode[] = {
    EncodeMOVW(12, 0xCC04), EncodeMOVT(12, 0x65),
    0xE59C2000, 0xE2822001, 0xE58C2004,   // ++c_wad
    0xE1A03001,                            // MOV R3,R1 (displaced)
    0xE51FF004, 0x404040CC,                // resume entry+4 (keep MOV r1,#0)
};
static const uint32_t kW36RiStubCode[] = {
    EncodeMOVW(12, 0xCC08), EncodeMOVT(12, 0x65),
    0xE59C2000, 0xE2822001, 0xE58C2008,   // ++c_ri
    0xE59F3010,                            // LDR R3,[R0,#0x10] (displaced)
    0xE51FF004, 0x404035D0,                // resume entry+4 (keep MOV r1,r0)
};

// W38: probes for PDAds_Init and AddDirectoryContent (the early-exit zone).
constexpr uint32_t kW38AdsStub = 0x8F114F00;    // PDAds_Init entry probe
constexpr uint32_t kW38AdsPatched = 0x40551418;
constexpr uint32_t kW38AdsOrig = 0xE59F3030;    // LDR R3,[R0,#0x30]
constexpr uint32_t kW38AdsResume = 0x4055141C;
constexpr uint32_t kW38AdcStub = 0x8F114F40;    // AddDirectoryContent entry probe
constexpr uint32_t kW38AdcPatched = 0x4040372C;
constexpr uint32_t kW38AdcOrig = 0xE1A03002;    // MOV R3,R2
constexpr uint32_t kW38AdcResume = 0x40403730;
constexpr uint32_t kW38CntBase = 0x0065CC10;    // [0]=ads [4]=adc [8]=exit code

static const uint32_t kW38AdsStubCode[] = {
    EncodeMOVW(12, 0xCC10), EncodeMOVT(12, 0x65),
    0xE59C2000, 0xE2822001, 0xE58C2000,   // ++ads count
    0xE59F3030,                            // LDR R3,[R0,#0x30] (displaced)
    0xE51FF004, 0x4055141C,                // resume
};
static const uint32_t kW38AdcStubCode[] = {
    EncodeMOVW(12, 0xCC14), EncodeMOVT(12, 0x65),
    0xE59C2000, 0xE2822001, 0xE58C2004,   // ++adc count
    0xE1A03002,                            // MOV R3,R2 (displaced)
    0xE51FF004, 0x40403730,                // resume
};

static void EnsureWadParseMarkers(DynarmicHost& host);
void InstallWadParseMarkers(DynarmicHost& host) { EnsureWadParseMarkers(host); }

static void EnsureWadParseMarkers(DynarmicHost& host) {
    host.MemoryWrite32(kWadParseProbeScratch + 12, 0);
    // W412 (run553): state-based one-shot gate. std::call_once survives the
    // process, but the guest TEXT does not -- an in-process activity relaunch
    // re-copies the ELF image and every patch silently vanished (the ~50%
    // installer-skip race). Gate on this function's own sentinel instead:
    // the W394b NOP head at 0x4040D9F8 goes in with the rest of the patch
    // set and is wiped together with it.
    if (host.MemoryRead32(0x4040D9F8u) == 0xE1A00000u) {
        host.MemoryWrite32(0x93001790u, 119);  // W447P W412
        LOGI("[W412] markers live (0x4040D9F8==E1A00000) -- skip reinstall");
        return;
    }
    [&host] {
        // W433: boot ordinal -- increments every time the installer actually
        // runs; lives OUTSIDE the W429 per-boot zero range (0x93001500-740)
        // so it separates boot1/boot2 within one process lifetime.
        host.MemoryWrite32(0x93001780u, host.MemoryRead32(0x93001780u) + 1u);
        host.MemoryWrite32(0x93001790u, 999u);  // W450: 999 = installer started; breadcrumbs overwrite downward to 0
        // W35 CAUSAL FIX v2: instead of the stack-based SVC stub at 0x65AE00
        // (whose saved-LR slot was corrupted by host-side execution between
        // PUSH and POP -- run64/65), patch SetupWadDirPointers' ENTRY itself
        // to jump to the W33BuildWadTree thunk TRAMPOLINE (SVC #id; BX lr).
        // This uses the standard bridge dispatch path: the thunk handler
        // builds the tree host-side, returns, and BX lr sends control back
        // to the parse at 0x4145A0 with the stack untouched.
        auto& tm = host.GetThunkManager();
        for (size_t i = 0; i < sizeof(kWadParseProbeCode) / sizeof(uint32_t); ++i) {
            host.MemoryWrite32(kWadParseProbeStub + static_cast<uint32_t>(i * 4),
                               kWadParseProbeCode[i]);
        }
        const uint32_t probe_word = host.MemoryRead32(kWadParseProbeSite);
        const uint32_t probe_word2 = host.MemoryRead32(kWadParseProbeSite + 4);
        if (probe_word == 0xE92D47F0u && probe_word2 == 0xE1A04001u) {
            host.MemoryWrite32(kWadParseProbeSite, 0xE51FF004u);
            host.MemoryWrite32(kWadParseProbeSite + 4, kWadParseProbeStub);
            host.InvalidateGuestCode(kWadParseProbeSite, 8);
            host.InvalidateGuestCode(kWadParseProbeStub,
                                     sizeof(kWadParseProbeCode));
        } else if (probe_word != 0xE51FF004u || probe_word2 != kWadParseProbeStub) {
            LOGE("[WAD-ENTRY] unexpected words at %08X: %08X/%08X",
                 kWadParseProbeSite, probe_word, probe_word2);
        }
        const uint32_t w33addr = tm.RegisterThunk("W33BuildWadTree",
            [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
                W33BuildWadTreeHandler(jit, h);
            });
        const uint32_t w33id = tm.GetThunkSvcId("W33BuildWadTree");
        if (!w33id || !w33addr) {
            LOGE("[W33] tree-builder thunk not registered -- abort");
            return;
        }
        // Patch SetupWadDirPointers entry (0x404140B0): LDR pc,[pc,#-4] +
        // literal = W33 thunk trampoline address.
        host.MemoryWrite32(kWadDirEntryPatched, 0xE51FF004u);
        host.MemoryWrite32(kWadDirEntryPatched + 4, w33addr);
        host.InvalidateGuestCode(kWadDirEntryPatched, 8);
        host.MemoryWrite32(0x93001790u, 118);  // W447P W33
        LOGI("[W33] SetupWadDirPointers entry redirected to W33BuildWadTree "
             "trampoline 0x%08X (SVC #%u)", w33addr, w33id);
        // W42: preserve the requested asset-relative directory. Returning
        // the APK root for every scan makes the guest recursively enumerate
        // the same entries as if each were a directory; the old length-based
        // cutoff merely hid that bug and could also truncate legitimate paths.
        {
            const uint32_t w42entry = 0x403F1FF8;
            const uint32_t w42addr = tm.RegisterThunk("W42ScanStart",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
                    const uint32_t fd = jit.Regs()[0];
                    char p[256] = {};
                    uint32_t len = 0;
                    for (; len < sizeof(p) - 1; ++len) {
                        const char c = static_cast<char>(h.MemoryRead8(fd + len));
                        if (!c) break;
                        p[len] = c;
                    }
                    const bool terminated = len < sizeof(p) - 1;
                    p[len] = 0;
                    char asset_path[sizeof(p)] = {};
                    size_t out = 0;
                    bool previous_slash = false;
                    for (size_t i = 0; terminated && p[i] && out < sizeof(asset_path) - 1; ++i) {
                        char c = p[i] == '\\' ? '/' : p[i];
                        if (c == '/' && (out == 0 || previous_slash)) continue;
                        asset_path[out++] = c;
                        previous_slash = c == '/';
                    }
                    while (out && asset_path[out - 1] == '/') asset_path[--out] = 0;
                    asset_path[out] = 0;
                    if (out == 1 && asset_path[0] == '.') asset_path[0] = 0;
                    static std::atomic<uint32_t> w42n{0};
                    const uint32_t scan_index = w42n.fetch_add(1);
                    uint32_t dir_handle = 0;
                    AAssetManager* mgr = terminated ? BridgeGetAssetManager() : nullptr;
                    if (mgr) {
                        AAssetDir* dir = AAssetManager_openDir(mgr, asset_path);
                        if (dir) dir_handle = GuestHandleFor(dir);
                    }
                    if (scan_index < 32) {
                        char b[384];
                        snprintf(b, sizeof(b),
                                 "W42SCAN fd=0x%08X len=%u path=%s asset=%s mgr=%u dir=0x%08X",
                                 fd, len, p, asset_path, mgr != nullptr, dir_handle);
                        DiagTrace::NotePersist(b);
                        LOGI("%s", b);
                    }
                    h.MemoryWrite32(fd + 0x228, dir_handle);
                    jit.Regs()[0] = 0;
                });
            const uint32_t w42id = tm.GetThunkSvcId("W42ScanStart");
            host.MemoryWrite32(w42entry, 0xE51FF004u);
            host.MemoryWrite32(w42entry + 4, w42addr);
            host.InvalidateGuestCode(w42entry, 8);
            host.MemoryWrite32(0x93001790u, 117);  // W447P W42
            LOGI("[W42] PDStartScanningForFiles replaced by W42ScanStart "
                 "trampoline 0x%08X (SVC #%u)", w42addr, w42id);
        }
        // W54: skip SetupWadFilePointers entirely. The guest WAD parse reads
        // the string table + directory structure fine, W33 builds the whole
        // tree host-side (5554 = 373 dirs + 5181 files), but the parse then
        // walks SetupWadFilePointers' file-entry loop -- the same JIT-fragile
        // region that ran away in W28 -- and the game thread's PC ends up in
        // zero-filled memory, where runaway-PC containment silently ends the
        // RunFunction (thread vanishes, no exception/exit -- run102). The
        // file pointers are already covered by the host-built tree, so the
        // walk is redundant: entry -> SVC trampoline whose handler does
        // nothing (BX lr returns to the caller with regs intact).
        {
            const uint32_t w54tgt = 0x40414028;
            if (host.MemoryRead32(w54tgt) == 0xE92D41F0u) {
                const uint32_t w54addr = tm.RegisterThunk("W54SkipFilePtr",
                    [](Dynarmic::A32::Jit&, DynarmicHost&) {
                        static std::atomic<uint32_t> w54n{0};
                        if (w54n.fetch_add(1) == 0) {
                            DiagTrace::NotePersist("W54 SetupWadFilePointers walk skipped");
                        }
                    });
                host.MemoryWrite32(w54tgt, 0xE51FF004u);
                host.MemoryWrite32(w54tgt + 4, w54addr);
                host.InvalidateGuestCode(w54tgt, 8);
                host.MemoryWrite32(0x93001790u, 116);  // W447P W54
                LOGI("[W54] SetupWadFilePointers at 0x%08X replaced by no-op "
                     "trampoline 0x%08X", w54tgt, w54addr);
            } else {
                LOGE("[W54] unexpected word at 0x%08X: 0x%08X", w54tgt,
                     host.MemoryRead32(w54tgt));
            }
        }
        // W61b: clamp the LLMemMakeChildOf pool-init fill loop. The loop at
        // 0x4040D634 re-loads its bound from [r4] every iteration and ran
        // with a ~4.29G count (3+ billion iterations = ~6 min per pool),
        // starving every init attempt. The clamp stub re-issues the bound
        // load and the overwritten ADD, caps the bound, then resumes at +8.
        {
            const uint32_t w61b_site = 0x4040D63C;
            const uint32_t w61b_stub = 0x8F114E00;   // W280 (run379): relocated from the stomped 0x65D2xx gap
            const uint32_t w61b_code[] = {
                0xE5942000u,          // ldr r2,[r4]        (displaced)
                0xE3003000u,          // movw r3,#0x0000
                0xE3403010u,          // movt r3,#0x0010    ; r3 = 1 MB
                0xE1520003u,          // cmp r2,r3
                0x82A02003u,          // movhi r2,r3
                0xE2811001u,          // add r1,r1,#1       (displaced site+4)
                0xE51FF004u,          // ldr pc,[pc,#-4]
                w61b_site + 8,        // resume after both displaced instructions
            };
            for (size_t i = 0; i < sizeof(w61b_code) / sizeof(uint32_t); ++i)
                host.MemoryWrite32(w61b_stub + static_cast<uint32_t>(i * 4), w61b_code[i]);
            if (host.MemoryRead32(w61b_site) == 0xE5942000u) {
                host.MemoryWrite32(w61b_site, 0xE51FF004u);
                host.MemoryWrite32(w61b_site + 4, w61b_stub);
                host.InvalidateGuestCode(w61b_site, 8);
                host.InvalidateGuestCode(w61b_stub, 32);
                host.MemoryWrite32(0x93001790u, 115);  // W447P W61b
                LOGI("[W61b] MakeChildOf fill-loop bound clamp at 0x%08X -> stub 0x%08X",
                     w61b_site, w61b_stub);
            } else {
                LOGE("[W61b] unexpected word at 0x%08X: 0x%08X", w61b_site,
                     host.MemoryRead32(w61b_site));
            }
        }
        // W59: bz_StartInternal + AndroidProcessSystemMessages entry
        // counters. Keep the original bz_StartInternal prologue intact:
        // Init_BZ constructs and passes its real stack-local bzStartInput.
        {
            struct W59Probe { uint32_t tgt, cnt, disp; };
            const W59Probe w59[] = {};
            uint32_t stub = 0x0065D140;
            for (const auto& pr : w59) {
                if (host.MemoryRead32(pr.tgt) != pr.disp) {
                    LOGE("[W59] unexpected word at 0x%08X: 0x%08X", pr.tgt,
                         host.MemoryRead32(pr.tgt));
                    continue;
                }
                const uint32_t code[] = {
                    EncodeMOVW(12, pr.cnt & 0xFFFFu),
                    EncodeMOVT(12, pr.cnt >> 16),
                    0xE59C3000,       // ldr r3,[r12]
                    0xE2833001,       // add r3,r3,#1
                    0xE58C3000,       // str r3,[r12]
                    0xE58C000C,       // str r0,[r12,#12]  (W59b: arg0 snapshot at cnt+12)
                    pr.disp,          // displaced
                    0xE51FF004,       // ldr pc,[pc,#-4]
                    pr.tgt + 4,       // resume
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(pr.tgt, 0xE51FF004u);
                host.MemoryWrite32(pr.tgt + 4, stub);
                host.InvalidateGuestCode(pr.tgt, 8);
                stub += 0x40;
            }
            host.MemoryWrite32(0x93001790u, 111);  // W447P W59
            LOGI("[W59] StartInternal/APS probes installed");
        }
        // W69: PDStartup_0 arg0 snapshot -- is IT also called with NULL?
        {
            const uint32_t w69cnt  = 0x0065CDB4;
            const uint32_t w69stub = 0x0065D240;
            const uint32_t w69tgt  = 0x403DA314;
            const uint32_t w69code[] = {
                EncodeMOVW(12, 0xCDB4), EncodeMOVT(12, 0x65),
                0xE59C3000,           // ldr r3,[r12]
                0xE2833001,           // add r3,r3,#1
                0xE58C3000,           // str r3,[r12]
                0xE58C000C,           // str r0,[r12,#12]  (arg0 snapshot)
                0xE92D4FF0u,          // push {r4-r11,lr}  (displaced)
                0xE1A04000u,          // mov r4,r0         (W112: displaced site+4 --
                                      // the 8-byte entry patch destroyed it and
                                      // PDStartup_0's bzStartInput pointer was
                                      // garbage for every run since W43!)
                0xE51FF004,           // ldr pc,[pc,#-4]
                w69tgt + 8,           // resume PAST the displaced pair
            };
            for (size_t i = 0; i < sizeof(w69code) / sizeof(uint32_t); ++i)
                host.MemoryWrite32(w69stub + static_cast<uint32_t>(i * 4), w69code[i]);
            if (host.MemoryRead32(w69tgt) == 0xE92D4FF0u) {
                host.MemoryWrite32(w69tgt, 0xE51FF004u);
                host.MemoryWrite32(w69tgt + 4, w69stub);
                host.InvalidateGuestCode(w69tgt, 8);
                host.MemoryWrite32(0x93001790u, 110);  // W447P W69
                LOGI("[W69] PDStartup_0 probe at 0x%08X -> stub 0x%08X",
                     w69tgt, w69stub);
            } else {
                LOGE("[W69] unexpected word at 0x%08X: 0x%08X", w69tgt,
                     host.MemoryRead32(w69tgt));
            }
        }
        // W127 (run174): W72 RETIRED. The constant 0x40000 bound made EVERY
        // pool fill iterate 1M slots regardless of the real count -- for the
        // 20-element [Dyn] pools that is 32 MB of free-list writes 32 MB
        // past a 640-byte block, annihilating the guest heap at the FIRST
        // pool creation (measured: D_InitialiseDynamicsController's first
        // LLMemCreateNewPool(0xB8,0x20,0x14) returned 0 -> bzd returned 14
        // -> infinite init retry). The 4.29G-count descriptor garbage that
        // originally motivated W72 came from the W112 probe corruption,
        // since fixed. Restore the count-based bound.
        {
            const uint32_t w72site = 0x4040D64C;
            if (host.MemoryRead32(w72site) == 0xE3510077u) {
                host.MemoryWrite32(w72site, 0xE1510002u);  // cmp r1,r2 (original)
                host.InvalidateGuestCode(w72site, 4);
                host.MemoryWrite32(0x93001790u, 109);  // W447P W127
                LOGI("[W127] W72 constant cap removed; count-based bound restored at 0x%08X",
                     w72site);
            } else if (host.MemoryRead32(w72site) == 0xE1510002u) {
                host.MemoryWrite32(0x93001790u, 108);  // W447P W127
                LOGI("[W127] count-based bound already in place at 0x%08X", w72site);
            } else {
                LOGE("[W127] unexpected word at 0x%08X: 0x%08X", w72site,
                     host.MemoryRead32(w72site));
            }
        }
        // W73 retired: its guard veneer replaced the original BLX, clobbered
        // r1 (the callback's second argument), and skipped the call-site's
        // normal continuation. android_app_entry installs this source with a
        // verified guest process callback, so retain the original ABI here.
        // W77 retired: its NOP broke PDStartup_0's readiness loop after one
        // AndroidProcessSystemMessages pass. That let android_app_entry
        // return while lifecycle callbacks still waited for command ACKs.
        // Preserve the original conditional branch so the guest message pump
        // owns readiness and callback completion.
        // W78: full JIT cache invalidation of the PDStartup_0 region AFTER
        // all patches are installed. Without this, the JIT may hold cached
        // translations of pre-patch guest code in the spin loop.
        host.InvalidateGuestCode(0x403DA000u, 0x1000u);
        host.MemoryWrite32(0x93001790u, 105);  // W447P W78
        LOGI("[W78] full invalidation of 0x403DA000..0x403DB000 after all patches");
        // W79: guest .text write/readback test. Verifies that
        // MemoryWrite32 + MemoryRead32 work correctly for guest .text
        // addresses at install time. If readback != written value, the
        // ELF loader or the bridge's memory mapping has a fundamental issue
        // with writes to the guest code region.
        {
            const uint32_t test_addr = 0x4040D64C;
            const uint32_t orig = host.MemoryRead32(test_addr);
            host.MemoryWrite32(test_addr, 0xDEADBEEFu);
            const uint32_t rb = host.MemoryRead32(test_addr);
            host.MemoryWrite32(test_addr, orig);
            const uint32_t rb2 = host.MemoryRead32(test_addr);
            host.MemoryWrite32(0x93001790u, 104);  // W447P W79
            LOGI("[W79] .text write test @0x%08X: orig=0x%08X wrote=0xDEADBEEF "
                 "readback=0x%08X restored readback=0x%08X %s",
                 test_addr, orig, rb, rb2,
                 (rb == 0xDEADBEEFu) ? "OK" : "FAILED");
            if (rb != 0xDEADBEEFu) {
                DiagTrace::NotePersist("W79 .text WRITE FAILED — guest patches will be wiped!");
            }
        }
        // W80 retired: it removed the AndroidProcessSystemMessages call and
        // forged the window-ready flag, so PDStartup_0 could skip the real
        // lifecycle/event path. Keep the guest instructions intact; this
        // controlled run tests the message pump with W77 unchanged.
        // W82 retired: bz_TestBuildSettings validates the matching build
        // constants and emits diagnostics. Init_BZ discards its return value
        // immediately before calling bz_StartInternal, so replacing this BL
        // with MOV R0,#0 had no valid control-flow rationale and hid logger
        // failures instead of fixing them. Leave the guest call intact.
        // The bridge page is live thunk storage. The old W131/W292 relaunch
        // scrub erased the SVC veneers already registered by RegisterAllThunks
        // and then flooded logcat while doing so. A fresh DynarmicHost starts
        // with zeroed diagnostic cells; an in-process relaunch does not rerun
        // this installer because its patch sentinel is retained. Do not clear
        // executable thunk memory or guest-visible diagnostic storage here.
        LOGI("[W292] retained thunk page and diagnostic cells");
        // W361 retired: this installer runs after .init_array has already
        // created live guest JIT workers. Clearing 0x7E3FE000..0x7E400000
        // here overwrote the active first worker stack (captured crash SP
        // 0x7E3FFEC8). CurrentJit/W372 already zeros the full 4 MiB slab
        // when a worker claims it; never scrub a guest stack after launch.
        // W351b: ONLY the W100 boot counters (0x93001500). The earlier
        // W351 also zeroed 0x93000040-0x93000200 -- which holds the
        // RUNTIME cells (0x93000160 live-app, cond, ack, WAD name) that
        // the W292/W301 replay machinery reads back -- wiping them broke
        // the pipe wake chain (run463-465).
        // W100 (run155): progress probes inside bz_StartInternal between
        // InitMemorySystem (reached, qsort=6) and PDStartup_1 (print never
        // seen). Each probe bumps a counter, executes the original call, and
        // resumes. The counters live in bridge-allocated guest memory (the
        // first attempt used static 0x65CE00 and the guest's own data
        // overwrote it), and the W40PCS line prints them verbatim.
        {
            struct W100Probe { uint32_t site, target; const char* name; };
            // NOTE: sites must not be adjacent -- the 8-byte probe patch at
            // `site` overwrites site+4 (run157: the InitFileSystem probe at
            // 0x403DBEB0 clobbered the Content::Startup BL at 0x403DBEB4).
            const W100Probe w100[] = {
                { 0x403DBE38, 0x40411B30, "TaskManagerStart" },
                { 0x403DBE7C, 0x4040F7BC, "InitMemorySystem" },
                { 0x403DBE94, 0x4027EDD4, "MaterialInit" },
                { 0x403DBEB4, 0x404012A0, "ContentStartup" },
                { 0x403DBF3C, 0x403DAB14, "PDStartup_1" },
                { 0x403DBF50, 0x402DD110, "InitViewports" },
                { 0x403DBF58, 0x403DB0FC, "PDStartup_2" },
                { 0x403DBFAC, 0x4030956C, "AsciiTranslator" },
                { 0x403DBFB8, 0x4024006C, "BeelzebubInit" },
                { 0x403DBFD4, 0x401E41BC, "LogManagerCtor" },
                { 0x403DC008, 0x401E2888, "SetDefaultDir" },
                { 0x403DC028, 0x401E3F78, "CreateDebugLog" },
                { 0x403DC038, 0x403DB1AC, "PDShowOSCursor" },
                { 0x403DC060, 0x403D7A08, "SoundSystemCtor" },
                { 0x403DC070, 0x403F3CE8, "ReleaseGraphics" },
            };
            const uint32_t cnt_base = 0x93001500u;  // W252: safe block, outside the worker-stack reach  // W251 (run353): 0x93000xxx sits inside the worker-stack region and gets stomped  // W211 (run294): relocated out of the 0x9000 window -- the boot counters there read 0
                                          // while imgdir (0x93000404) survives: something zeroes low 0x9000 during the boot
            g_w100_counter_addr = cnt_base;
            // W382 (run513): the W100 stub block is DISABLED. Its mission
            // (locating the boot stall) is complete: the full 15-marker pass
            // is proven, and runs 506-512 proved the freeze is the probe
            // infrastructure itself -- the guest allocator reuses the stub
            // block as a descriptor pool ({rodata ptr, canary, zeros} at
            // every window base 0x9000/0xB000/0x9800), so marker 15 executes
            // wiped words and bz_StartInternal never returns (w377c=0). With
            // the sites unpatched the guest runs its own code; W377 (kept --
            // single 44-byte stub far from this block) still captures the
            // true return value.
            host.MemoryWrite32(0x93001790u, 100);  // W447P W382
            LOGI("[W382] W100 stub probes disabled (mission complete)");
            // W408 (run546): W100 marker stubs RETIRED. Their mission
            // (locating the boot stall) is complete -- the full 15-marker
            // pass is proven. The guest allocator hands the stub-window
            // addresses out as data (the descriptor/log aliasing), so any
            // stub there eventually gets scribbled and freezes the game
            // thread at marker 15. Without the stubs the guest runs its
            // own unmodified init code and bz_StartInternal completes.
            // W165: relocated out of the gap dead-zone (~0x65D780+); window is guest-executable
            // W408: W100 stub installs RETIRED (mission complete - 15 markers proven;
            // the guest allocator scribbles the stub block, freezing the game thread).
            // uint32_t stub = 0x00011400u;  // retired
            for (size_t idx = 0; false && idx < sizeof(w100) / sizeof(w100[0]); ++idx) { // W408: retired
                uint32_t stub = 0x8F111400u;  // (dead code - loop disabled)
                stub += 0;
                const uint32_t site = w100[idx].site;
                const uint32_t target = w100[idx].target;
                const uint32_t cnt = cnt_base + static_cast<uint32_t>(idx) * 4;
                const uint32_t orig = host.MemoryRead32(site);
                const uint32_t expect = 0xEB000000u | (((target - site - 8) >> 2) & 0x00FFFFFFu);
                if (orig != expect) {
                    LOGE("[W100] unexpected word at 0x%08X: 0x%08X (want 0x%08X)",
                         site, orig, expect);
                    continue;
                }
                // W112: the old single-displacement pattern resumed at site+4
                // AFTER overwriting it with the stub address -- the guest then
                // executed the data word as an instruction. Displace site+4 as
                // well and resume at site+8.
                const uint32_t w2 = host.MemoryRead32(site + 4);
                const bool w2_is_bl = (w2 & 0x0F000000u) == 0x0B000000u;
                const bool w2_pc_rel =
                    ((w2 & 0x0F7FF000u) == 0xE59FF000u) ||
                    ((w2 & 0x0F7F0000u) == 0x028F0000u) ||
                    ((w2 & 0x0F7F0000u) == 0x024F0000u) ||
                    ((w2 & 0x0E000000u) == 0x0A000000u);
                if (!w2_is_bl && w2_pc_rel) {
                    LOGE("[W112] site+4 at 0x%08X is PC-relative (0x%08X) -- probe skipped",
                         site + 4, w2);
                    continue;
                }
                uint32_t code[14];
                size_t n = 0;
                code[n++] = EncodeMOVW(12, cnt & 0xFFFFu);
                code[n++] = EncodeMOVT(12, cnt >> 16);
                code[n++] = 0xE59C3000u;          // ldr r3,[r12]
                code[n++] = 0xE2833001u;          // add r3,r3,#1
                code[n++] = 0xE58C3000u;          // str r3,[r12]
                if (w2_is_bl) {
                    const uint32_t tgt1 = site + 4 + 8 +
                        ((static_cast<int32_t>(w2 << 8) >> 6));
                    code[n++] = 0xE59F3010u;      // ldr r3,[pc,#16] -> tgt0
                    code[n++] = 0xE12FFF33u;      // blx r3         ; lr = S+28
                    code[n++] = 0xE59F300Cu;      // ldr r3,[pc,#12] -> tgt1
                    code[n++] = 0xE12FFF33u;      // blx r3         ; lr = S+36
                    code[n++] = 0xE51FF004u;      // ldr pc,[pc,#-4] -> resume
                    code[n++] = site + 8;
                    code[n++] = target;
                    code[n++] = tgt1;
                } else {
                    code[n++] = 0xE59F300Cu;      // ldr r3,[pc,#12] -> tgt0
                    code[n++] = 0xE12FFF33u;      // blx r3         ; lr = S+28
                    code[n++] = w2;               // displaced site+4
                    code[n++] = 0xE51FF004u;      // ldr pc,[pc,#-4] -> resume
                    code[n++] = site + 8;
                    code[n++] = target;
                }
                for (size_t i = 0; i < n; ++i)
                    host.MemoryWrite32(stub + static_cast<uint32_t>(i * 4), code[i]);
                // W393 (run525): the site+4 literal no longer holds the stub
                // address (LogManager entries were derived from it and
                // scribbled the stubs). It points at a bridge veneer cell
                // [E51FF004; stub_addr] in the 0x8F012000 page -- any
                // data-like reuse lands in bridge-owned memory, and the
                // stub block stays pristine.
                const uint32_t w393veneer = 0x8F012000u + static_cast<uint32_t>(idx) * 8u;
                host.MemoryWrite32(w393veneer, 0xE51FF004u);
                host.MemoryWrite32(w393veneer + 4, stub);
                host.MemoryWrite32(site, 0xE51FF004u);
                host.MemoryWrite32(site + 4, w393veneer);
                host.InvalidateGuestCode(site, 8);
                host.InvalidateGuestCode(stub, 64);  // W165: drop stale JIT blocks
                stub += 64;
                host.MemoryWrite32(0x93001790u, 99);  // W447P W100
                LOGI("[W100] probe %s installed at 0x%08X -> stub 0x%08X (cnt 0x%08X)",
                     w100[idx].name, site, stub - 64, cnt);
                // W399 (run540): per-iteration snapshot of the JUST-INSTALLED
                // stub (12 words from the stub base) -- A/B vs the tick-time
                // W379STUB proves whether the bytes are born wrong or
                // corrupted later.
                {
                    char sb9[300];
                    int sn9 = snprintf(sb9, sizeof(sb9), "W399I %s:", w100[idx].name);
                    for (int w = 0; w < 11 && sn9 > 0; ++w)
                        sn9 += snprintf(sb9 + sn9, sizeof(sb9) - (size_t)sn9, " %08X",
                                        host.MemoryRead32(stub - 64 + (uint32_t)w * 4u));
                    DiagTrace::NotePersist(std::string(sb9, (size_t)sn9));
                }
            }
        }

        // W101 (run157): the PDStartup_0 pause loop kept spinning even with
        // m_startup_game_thread_paused verifiably 0 (W96), starving the whole
        // boot behind it. Same class of broken round-trip as the W80 window
        // spin: NOP the loop-back branch so the loop runs at most one flip
        // and falls through to the rest of PDStartup_0.
        {
            const uint32_t w101site = 0x403DA9C0;  // bne pause_body
            const uint32_t orig = host.MemoryRead32(w101site);
            if ((orig & 0x00010000u) == 0x1A000000u) {
                host.MemoryWrite32(w101site, 0xE1A00000u);  // bne -> nop
                host.InvalidateGuestCode(w101site, 4);
                host.MemoryWrite32(0x93001790u, 98);  // W447P W101
                LOGI("[W101] pause loop-back NOP-ed at 0x%08X (was 0x%08X)",
                     w101site, orig);
            } else {
                LOGE("[W101] unexpected word at 0x%08X: 0x%08X", w101site, orig);
            }
        }
        // W103 (run159): bz_Threading_AcquireGraphicsSystem switches the
        // calling thread onto a guest-managed "graphics stack" (measured:
        // the whole boot ran at sp=0xC77D169E with PDStartup_0's frame
        // residue), and the matching Release restores a ZERO saved context
        // under the bridge -- POP of zeros, PC slides into the exit trap,
        // R4-R11=0, R0=-3 (W84APP). Force both to plain returns so the boot
        // stays on its own stack; the engine serialised graphics access
        // around these calls anyway.
        {
            const uint32_t w103a = 0x403F3C4C;  // bz_Threading_AcquireGraphicsSystem
            const uint32_t w103b = 0x403F3CE8;  // bz_Threading_ReleaseGraphicsSystem
            host.MemoryWrite32(0x93001790u, 97);  // W447P W103
            LOGI("[W103] Acquire@0x%08X=0x%08X Release@0x%08X=0x%08X -> BX LR",
                 w103a, host.MemoryRead32(w103a), w103b, host.MemoryRead32(w103b));
            host.MemoryWrite32(w103a, 0xE1A0F00Eu);  // mov pc, lr
            host.MemoryWrite32(w103b, 0xE1A0F00Eu);
            host.InvalidateGuestCode(w103a, 4);
            host.InvalidateGuestCode(w103b, 4);
        }
        // W110 removed (W112): its site+4 displacement broke the PC-relative
        // banner literal load at 0x403DA31C.
        // W114 (run164): Init_BZ spills "Aug 11 2017"/"09:47:54" pointers
        // (0x405F3EC4/0x4061E398) into its frame at [sp+0x10]/[sp+0x14] for
        // the W82-NOP-ed bz_TestBuildSettings call. A later same-depth frame
        // read that stale slot as a function pointer and CALLED into the
        // string constant (wild call target 0x4061E398 measured; the guest
        // then executed rodata as code until an undefined instruction).
        // Redirect both spills to nullsub_21 (0x40543A00, an empty function):
        // the stale call becomes a harmless no-op.
        {
            const uint32_t w114a = 0x40543B68;  // ldr lr,[pc,#..] delta for "Aug 11 2017"
            const uint32_t w114b = 0x40543B6C;  // ldr r12,[pc,#..] delta for "09:47:54"
            const uint32_t olda = host.MemoryRead32(w114a);
            const uint32_t oldb = host.MemoryRead32(w114b);
            if (olda == 0x000B0444u && oldb == 0x000DA910u) {
                // deltas re-based to nullsub_21 (0x40543A00): 0x543A00-0x543A80
                // and 0x543A00-0x543A88
                host.MemoryWrite32(w114a, 0xFFFFFF80u);
                host.MemoryWrite32(w114b, 0xFFFFFF78u);
                host.InvalidateGuestCode(w114a, 8);
                // W117 (run165): the wild call ALSO hits 0x4061E394/8 with the
                // spills redirected -- the remaining producer of that address
                // is bzStartInput[0] ("CARMAGEDDON GIZMONDO" ptr, stored by
                // STR R2,[SP,#var_58] at 0x40543A44). A mismatched-struct
                // callback read of slot[0] would call into the name string.
                // Redirect this literal to nullsub_21 as well (0x543A00-
                // 0x543A3C).
                const uint32_t w117 = 0x40543B60;
                const uint32_t oldc = host.MemoryRead32(w117);
                if (oldc == 0x000DA944u) {
                    host.MemoryWrite32(w117, 0xFFFFFFC4u);
                    host.InvalidateGuestCode(w117, 4);
                } else {
                    LOGE("[W117] unexpected literal at 0x%08X: 0x%08X", w117, oldc);
                }
                host.MemoryWrite32(0x93001790u, 96);  // W447P W114
                LOGI("[W114] build-string spills redirected to nullsub_21");
            } else {
                LOGE("[W114] unexpected literals at 0x%08X/0x%08X: 0x%08X/0x%08X",
                     w114a, w114b, olda, oldb);
            }
        }
        // W196 (run273): CLEAN-SLATE bisect. The boot thread returns cleanly
        // from android_app_entry before probe 9 (boot=[1x9,0x6]) while every
        // stub readback verifies correct -- so ONE of the dozen patches in
        // the dynamics region may itself be the killer. Disable EVERY
        // probe/patch in the bz_StartInternal chain (W122/W125/W124/W156/
        // W158/W160/W167/W176/W172/W188/W132). If the boot STILL dies at the
        // same place with zero guest-code patches there, the probes are
        // exonerated and the death is the engine's own early-return path.
        constexpr bool kW196CleanSlate = true;
        // W197 (run275): stage probes around the Init_BZ tail and ActualMain.
        // S1's manual call trampoline has been retired; the original direct
        // BL to bz_StartInternal remains in place. Other probes below remain
        // temporary stage counters until the complete native path is verified.
        {
            struct W197Site { uint32_t site, target, disp; uint32_t cnt; };
            const W197Site w197[] = {
                { 0x4054E090u, 0x4040CB1Cu, 0xE1A01000u, 0x93000408u },  // LLMemFreeSpace; disp MOV R1,R0
                { 0x4054E0A8u, 0x405694ACu, 0xE8BD4010u, 0x93000414u },  // DoInitInOneGo; disp POP {R4,LR}
            };
            // S1 (W212) is deliberately no longer detoured. The original
            // ARM BL at 0x40543AB8 already reaches bz_StartInternal directly;
            // replacing it with a hand-built BLX trampoline only creates a
            // second, less trustworthy calling convention. Keep the native
            // call intact and let the BSI entry/return probes observe it.
            {
                const uint32_t s1 = 0x40543AB8u;
                const uint32_t o1 = host.MemoryRead32(s1);
                const uint32_t i1 = ((0x403DBCB0u - s1 - 8) >> 2) & 0x00FFFFFFu;
                if (o1 == (0xEB000000u | i1)) {
                    LOGI("[W212] leaving original bz_StartInternal BL intact at 0x%08X", s1);
                } else {
                    LOGE("[W212] S1 unexpected word at 0x%08X: 0x%08X", s1, o1);
                }
            }
            // S4: PrintToDebugger probe that CHAINS the displaced BL
            // Init_PostBZ (W173: BL cannot imm24-relocate into 0x9000xxxx).
            {
                const uint32_t s4 = 0x4054E0A0u;
                const uint32_t s4stub = 0x8F113040u;
                const uint32_t o4 = host.MemoryRead32(s4);
                const uint32_t i4 = ((0x401E6AFCu - s4 - 8) >> 2) & 0x00FFFFFFu;
                if (o4 == (0xEB000000u | i4)) {
                    const uint32_t code[] = {
                        EncodeMOVW(12, 0x040Cu), EncodeMOVT(12, 0x9300u),
                        0xE59C3000u,          // ldr r3,[r12]
                        0xE2833001u,          // add r3,r3,#1
                        0xE58C3000u,          // str r3,[r12]        print called++
                        EncodeMOVW(3, 0x6AFCu), EncodeMOVT(3, 0x401Eu),
                        0xE12FFF33u,          // blx PrintToDebugger
                        EncodeMOVW(3, 0x3B88u), EncodeMOVT(3, 0x4054u),
                        0xE12FFF33u,          // blx Init_PostBZ     (displaced)
                        0xE51FF004u,          // ldr pc,[pc,#-4]
                        0x4054E0A8u,           // resume
                    };
                    for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                        host.MemoryWrite32(s4stub + static_cast<uint32_t>(i * 4), code[i]);
                    host.MemoryWrite32(s4, 0xE51FF004u);
                    host.MemoryWrite32(s4 + 4, s4stub);
                    host.InvalidateGuestCode(s4, 8);
                    host.InvalidateGuestCode(s4stub, 48);
                    host.MemoryWrite32(0x93001790u, 94);  // W447P W197
                    LOGI("[W197] S4 print+Init_PostBZ chain at 0x%08X", s4);
                } else {
                    LOGE("[W197] S4 unexpected word at 0x%08X: 0x%08X", s4, o4);
                }
            }
            // S6: the tail-B into StateMachine_Enter (no resume, W172 law).
            {
                const uint32_t s6 = 0x4054E0B0u;
                const uint32_t s6stub = 0x8F113090u;
                const int32_t oimm6 = static_cast<int32_t>(host.MemoryRead32(s6) << 8) >> 6;
                const uint32_t otgt6 = s6 + 8 + static_cast<uint32_t>(oimm6);
                if ((host.MemoryRead32(s6) & 0x00010000u) == 0xEA000000u && otgt6 == 0x40569B8Cu) {
                    const uint32_t code[] = {
                        EncodeMOVW(12, 0x0418u), EncodeMOVT(12, 0x9300u),
                        0xE59C3000u,          // ldr r3,[r12]
                        0xE2833001u,          // add r3,r3,#1
                        0xE58C3000u,          // str r3,[r12]        enter called++
                        EncodeMOVW(3, 0x9B8Cu), EncodeMOVT(3, 0x4056u),
                        0xE12FFF13u,          // bx StateMachine_Enter
                    };
                    for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                        host.MemoryWrite32(s6stub + static_cast<uint32_t>(i * 4), code[i]);
                    host.MemoryWrite32(s6, 0xE51FF004u);
                    host.MemoryWrite32(s6 + 4, s6stub);
                    host.InvalidateGuestCode(s6, 8);
                    host.InvalidateGuestCode(s6stub, 28);
                    host.MemoryWrite32(0x93001790u, 93);  // W447P W197
                    LOGI("[W197] S6 enter probe at 0x%08X", s6);
                } else {
                    LOGE("[W197] S6 unexpected word at 0x%08X: 0x%08X (tgt %08X)",
                         s6, host.MemoryRead32(s6), otgt6);
                }
            }
            // S3/S5: generic count-and-resume probes (register-only
            // displaced-next, W112-safe). Init_BZ's image/material directory
            // calls remain original guest BL instructions.
            for (const auto& pr : w197) {
                uint32_t stub = 0x8F113100u +
                    static_cast<uint32_t>(&pr - &w197[0]) * 0x40u;
                const uint32_t orig = host.MemoryRead32(pr.site);
                const uint32_t imm24 = ((pr.target - pr.site - 8) >> 2) & 0x00FFFFFFu;
                if (orig != (0xEB000000u | imm24)) {
                    LOGE("[W197] unexpected BL at 0x%08X: 0x%08X (want %08X)",
                         pr.site, orig, 0xEB000000u | imm24);
                    continue;
                }
                const uint32_t code[] = {
                    EncodeMOVW(12, (pr.cnt & 0xFFFFu)), EncodeMOVT(12, pr.cnt >> 16),
                    0xE59C3000u,          // ldr r3,[r12]
                    0xE2833001u,          // add r3,r3,#1
                    0xE58C3000u,          // str r3,[r12]
                    EncodeMOVW(3, pr.target & 0xFFFFu), EncodeMOVT(3, pr.target >> 16),
                    0xE12FFF33u,          // blx target
                    pr.disp,              // displaced site+4 (register-only)
                    0xE51FF004u,          // ldr pc,[pc,#-4]
                    pr.site + 8u,         // resume site+8 (site+4 travels in slot 8)
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(pr.site, 0xE51FF004u);
                host.MemoryWrite32(pr.site + 4, stub);
                host.InvalidateGuestCode(pr.site, 8);
                host.InvalidateGuestCode(stub, 44);
                host.MemoryWrite32(0x93001790u, 92);  // W447P W197
                LOGI("[W197] probe at 0x%08X cnt 0x%08X", pr.site, pr.cnt);
            }
        }
        // W199 retired for a controlled native-path test. Keep the guest's
        // CBNode::Find implementation intact; the last captured run showed
        // zero null-child bailouts, so the synthetic traversal has no proven
        // need and can no longer be justified as a correctness fix.
        // W200 RETIRED (run287): the entry-capture stub at 0x403F7038 killed
        // the SECOND FindImpl entry (reason=0x1000000 halt inside its
        // ldm/stm capture, exit pc=0x00013344) -- that second entry is the
        // LEGITIMATE Content::Startup tree walk, which must run natively.
        // W201 retired: the null-tree guard had zero hits on the populated
        // Content::Find path. Keep the original two-instruction guest thunk;
        // the former LDR-PC veneer changed this hot control-flow edge without
        // evidence that this call needed a workaround.
        // W202 (run286): CINodeTree::Find(char*) THUNK guard. The null-tree
        // Find reached FindImpl WITHOUT passing W201 (the 0x9000 capture
        // cells are stomped by the game arena mmap, so paths are murky) --
        // guard the tree thunk itself: tree==0 (r0) -> return 0 immediately.
        // Catches ReplaceSearch/RemoveSearchGroup/AddSearchGroup/PushCWD on
        // an uninitialised system. Count at 0x00010404 (best-effort).
        {
            const uint32_t w202site = 0x403FE010u;
            const uint32_t w202stub = 0x8F113500u;
            const int32_t w202imm =
                static_cast<int32_t>(0x403FDF08u - w202site - 8) >> 2;
            const uint32_t o2 = host.MemoryRead32(w202site);
            if (o2 == (0xEA000000u |
                       (static_cast<uint32_t>(w202imm) & 0x00FFFFFFu))) {
                // W173 law: the displaced tail B cannot imm24-relocate into
                // the 0x9000 stub window -- target travels as immediates.
                const uint32_t code[] = {
                    0xE3500000u,                          // S+0 cmp r0,#0  (tree)
                    0x1A000006u,                          // S+1 bne S+9 (tail)
                    EncodeMOVW(3, 0x0404u),               // S+2 null: count it
                    EncodeMOVT(3, 0x9000u),
                    0xE5932000u,                          // S+4 ldr r2,[r3]
                    0xE2822001u,                          // S+5 add r2,r2,#1
                    0xE5832000u,                          // S+6 str r2,[r3]
                    0xE12FFF1Eu,                          // S+7 bx lr (return 0)
                    0xE1A00000u,                          // S+8 nop
                    EncodeMOVW(3, 0xDF08u),               // S+9 tail: r3 = 0x403FDF08
                    EncodeMOVT(3, 0x403Fu),
                    0xE12FFF13u,                          // S+11 bx r3
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w202stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w202site, 0xE51FF004u);
                host.MemoryWrite32(w202site + 4, w202stub);
                host.InvalidateGuestCode(w202site, 8);
                host.InvalidateGuestCode(w202stub, 48);
                host.MemoryWrite32(0x93001790u, 88);  // W447P W202
                LOGI("[W202] CINodeTree::Find null guard at 0x%08X (tail %08X)",
                     w202site, 0x403FDF08u);
            } else {
                LOGE("[W202] unexpected thunk word at 0x%08X: %08X (want %08X)",
                     w202site, o2, 0xEA000000u |
                                       (static_cast<uint32_t>(w202imm) & 0x00FFFFFFu));
            }
        }
        // W204 (run289): content-init chain bisect. The single FindImpl
        // entry has tree=0 and Content::Startup (boot[3]) fires -- so the
        // tree build dies inside the CINodeSystem chain. Probe:
        //   A 0x4040120C BL WADSimple::Startup (inside CINodeSystem::Startup)
        //   B 0x40400F68 BL operator new(0x74) (inside InitialiseContentTree)
        // A fired + B not -> the death is between (ctor/file hooks).
        {
            struct W204Site { uint32_t site, target, disp, cnt; };
            const W204Site w204[] = {
                { 0x4040120Cu, 0x403F7D0Cu, 0xE1A00006u, 0x930004A0u },  // WADSimple::Startup; disp MOV R0,R6
                { 0x40400F68u, 0x4040D03Cu, 0xE1A05000u, 0x930004A4u },  // new(0x74); disp MOV R5,R0
            };
            for (const auto& pr : w204) {
                const uint32_t stub = 0x8F113700u +
                    static_cast<uint32_t>(&pr - &w204[0]) * 0x40u;
                const uint32_t orig = host.MemoryRead32(pr.site);
                const uint32_t imm24 = ((pr.target - pr.site - 8) >> 2) & 0x00FFFFFFu;
                if (orig != (0xEB000000u | imm24)) {
                    LOGE("[W204] unexpected BL at 0x%08X: %08X (want %08X)",
                         pr.site, orig, 0xEB000000u | imm24);
                    continue;
                }
                const uint32_t code[] = {
                    EncodeMOVW(12, pr.cnt & 0xFFFFu), EncodeMOVT(12, pr.cnt >> 16u),
                    0xE59C3000u,          // ldr r3,[r12]
                    0xE2833001u,          // add r3,r3,#1
                    0xE58C3000u,          // str r3,[r12]
                    EncodeMOVW(3, pr.target & 0xFFFFu), EncodeMOVT(3, pr.target >> 16u),
                    0xE12FFF33u,          // blx target
                    pr.disp,              // displaced site+4 (register-only)
                    0xE51FF004u,          // ldr pc,[pc,#-4]
                    pr.site + 8u,         // resume
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(pr.site, 0xE51FF004u);
                host.MemoryWrite32(pr.site + 4, stub);
                host.InvalidateGuestCode(pr.site, 8);
                host.InvalidateGuestCode(stub, 44);
                host.MemoryWrite32(0x93001790u, 87);  // W447P W204
                LOGI("[W204] probe at 0x%08X cnt 0x%08X", pr.site, pr.cnt);
            }
        }
        // W206 (run291): CINodeSystem::Startup early bisect. Startup died
        // before WADSimple (W204a=0): its only preceding calls are
        // LLMemFill(this+0x2C,0,0x8C) and bz_RetrieveFileIOHooks.
        //   A 0x404011F0 BL LLMemFill        disp ADD R6,R4,#0xB8
        //   B 0x404011FC BL bz_RetrieveFileIOHooks  disp MOV R1,R5
        // A=0 -> the thread dies in LLMemFill itself; A=1,B=0 -> in
        // RetrieveFileIOHooks.
        {
            struct W206Site { uint32_t site, target, disp, cnt; };
            const W206Site w206[] = {
                { 0x404011F0u, 0x40409CC0u, 0xE28460B8u, 0x930004A8u },  // LLMemFill
                { 0x404011FCu, 0x404082CCu, 0xE1A01005u, 0x930004ACu },  // RetrieveFileIOHooks
            };
            for (const auto& pr : w206) {
                const uint32_t stub = 0x8F113780u +
                    static_cast<uint32_t>(&pr - &w206[0]) * 0x40u;
                const uint32_t orig = host.MemoryRead32(pr.site);
                const uint32_t imm24 = ((pr.target - pr.site - 8) >> 2) & 0x00FFFFFFu;
                if (orig != (0xEB000000u | imm24)) {
                    LOGE("[W206] unexpected BL at 0x%08X: %08X (want %08X)",
                         pr.site, orig, 0xEB000000u | imm24);
                    continue;
                }
                const uint32_t code[] = {
                    EncodeMOVW(12, pr.cnt & 0xFFFFu), EncodeMOVT(12, pr.cnt >> 16u),
                    0xE59C3000u,          // ldr r3,[r12]
                    0xE2833001u,          // add r3,r3,#1
                    0xE58C3000u,          // str r3,[r12]
                    EncodeMOVW(3, pr.target & 0xFFFFu), EncodeMOVT(3, pr.target >> 16u),
                    0xE12FFF33u,          // blx target
                    pr.disp,              // displaced site+4 (register-only)
                    0xE51FF004u,          // ldr pc,[pc,#-4]
                    pr.site + 8u,         // resume
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(pr.site, 0xE51FF004u);
                host.MemoryWrite32(pr.site + 4, stub);
                host.InvalidateGuestCode(pr.site, 8);
                host.InvalidateGuestCode(stub, 44);
                host.MemoryWrite32(0x93001790u, 86);  // W447P W206
                LOGI("[W206] probe at 0x%08X cnt 0x%08X", pr.site, pr.cnt);
            }
        }
        // W207 (run292): Content::Startup NULL-path bisect. Startup was never
        // called (W206=0/0) -- the death is in the null branch:
        //   A 0x404012EC BL operator new(0x170)   disp MOV R5,R0
        //   B 0x404012F4 BL CINodeSystem ctor     disp MOV R0,R5
        // A=1,B=0 -> death inside new(0x170) or the ctor never entered.
        // A=1,B=1 -> death inside the CINodeSystem ctor.
        {
            struct W207Site { uint32_t site, target, disp, cnt; };
            const W207Site w207[] = {
                { 0x404012ECu, 0x4040D03Cu, 0xE1A05000u, 0x930004B0u },  // new(0x170)
                { 0x404012F4u, 0x403FBFE8u, 0xE1A00005u, 0x930004B4u },  // CINodeSystem ctor
            };
            for (const auto& pr : w207) {
                const uint32_t stub = 0x8F113800u +
                    static_cast<uint32_t>(&pr - &w207[0]) * 0x40u;
                const uint32_t orig = host.MemoryRead32(pr.site);
                const uint32_t imm24 = ((pr.target - pr.site - 8) >> 2) & 0x00FFFFFFu;
                if (orig != (0xEB000000u | imm24)) {
                    LOGE("[W207] unexpected BL at 0x%08X: %08X (want %08X)",
                         pr.site, orig, 0xEB000000u | imm24);
                    continue;
                }
                const uint32_t code[] = {
                    EncodeMOVW(12, pr.cnt & 0xFFFFu), EncodeMOVT(12, pr.cnt >> 16u),
                    0xE59C3000u,          // ldr r3,[r12]
                    0xE2833001u,          // add r3,r3,#1
                    0xE58C3000u,          // str r3,[r12]
                    EncodeMOVW(3, pr.target & 0xFFFFu), EncodeMOVT(3, pr.target >> 16u),
                    0xE12FFF33u,          // blx target
                    pr.disp,              // displaced site+4 (register-only)
                    0xE51FF004u,          // ldr pc,[pc,#-4]
                    pr.site + 8u,         // resume
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(pr.site, 0xE51FF004u);
                host.MemoryWrite32(pr.site + 4, stub);
                host.InvalidateGuestCode(pr.site, 8);
                host.InvalidateGuestCode(stub, 44);
                host.MemoryWrite32(0x93001790u, 85);  // W447P W207
                LOGI("[W207] probe at 0x%08X cnt 0x%08X", pr.site, pr.cnt);
            }
        }
        // W208 (run294): Content::Startup -- force the creation path. The
        // content system never initialises (W204/W206/W207 all zero) and
        // Init_BZ's tail then crashes on a NULL sNode_system. Make the
        // sNode_system==NULL branch UNCONDITIONAL so every Content::Startup
        // call creates a fresh CINodeSystem (once per boot -- no leak risk).
        {
            const uint32_t w208site = 0x404012B4u;
            const uint32_t orig = host.MemoryRead32(w208site);
            if (false && orig == 0x0A00000Bu) {   // W278 (run379) DISABLED: with the real data folder (W276) the content system should initialise naturally; the force-create hijacked it and left the 17 search dirs unfilled.
                host.MemoryWrite32(w208site, 0xEA00000Bu);  // B (unconditional)
                host.InvalidateGuestCode(w208site, 4);
                host.MemoryWrite32(0x93001790u, 84);  // W447P W208
                LOGI("[W208] Content::Startup forced-create at 0x%08X", w208site);
            } else {
                LOGE("[W208] unexpected word at 0x%08X: %08X (want 0A00000B)",
                     w208site, orig);
            }
        }
        // W209 retired: its alleged BXEQ was encoded as unconditional BX LR
        // (E12FFF1E), returning the CINodeTree as if it were a search node.
        // AddSearchEntry then rejected that non-search object. Runtime evidence:
        // 5,565 indexed nodes and 102 AddSearch calls, but zero search nodes;
        // all [#DATA] script lookups failed despite existing WAD members.
        // Keep the original AddSearchMount, including its own null-name branch.
        // W429 (run577): W213/W214/W217 RETIRED. These run299-302-era
        // probes sit INSIDE Init_BZ / bz_StartInternal, clobber r2/r3/r12
        // without full restoration, and their cells (0x93001550,
        // 0x93001560-5C0) collide with the W425/W420/W424 counter map.
        // Their stack dumps were the entire "smear" mystery, and their
        // register clobbers are a live corruption source in the exact
        // window where the game thread disappears.
        if (false) {
        // W213 (run298): SoapRequestManager creation bisect. After the S1
        // fix the boot completes (s1ret=0) but the thread freezes before
        // the Image-dir call (imgdir=0) -- the only code between is the
        // SoapRequestManager creation:
        //   A 0x40543B40 BL operator new(0x28)   disp MOV R1,R5
        //   B 0x40543B4C BL SoapRequestManager ctor, then BX 0x40543AD4
        {
            // A: count-and-resume (register-only displaced-next).
            {
                const uint32_t site = 0x40543B40u;
                const uint32_t stub = 0x8F113B00u;
                const uint32_t orig = host.MemoryRead32(site);
                const uint32_t imm24 = ((0x4040D03Cu - site - 8) >> 2) & 0x00FFFFFFu;
                if (orig == (0xEB000000u | imm24)) {
                    const uint32_t code[] = {
                        EncodeMOVW(12, 0x0548u), EncodeMOVT(12, 0x9300u),
                        0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // cnt++
                        EncodeMOVW(3, 0xD03Cu), EncodeMOVT(3, 0x4040u),
                        0xE12FFF33u,                          // blx operator new
                        0xE1A01005u,                          // disp MOV R1,R5
                        0xE51FF004u,
                        site + 8u,                            // resume 0x40543B48
                    };
                    for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                        host.MemoryWrite32(stub + static_cast<uint32_t>(i * 4), code[i]);
                    host.MemoryWrite32(site, 0xE51FF004u);
                    host.MemoryWrite32(site + 4, stub);
                    host.InvalidateGuestCode(site, 8);
                    host.InvalidateGuestCode(stub, 44);
                    host.MemoryWrite32(0x93001790u, 82);  // W447P W213
                    LOGI("[W213] A new(0x28) probe at 0x%08X", site);
                } else {
                    LOGE("[W213] A unexpected word at 0x%08X: %08X", site, orig);
                }
            }
            // B: count, call the ctor, then BX to the merge (W173 law).
            {
                const uint32_t site = 0x40543B4Cu;
                const uint32_t stub = 0x8F113B40u;
                const uint32_t orig = host.MemoryRead32(site);
                const uint32_t imm24 = ((0x40380AB0u - site - 8) >> 2) & 0x00FFFFFFu;
                if (orig == (0xEB000000u | imm24)) {
                    const uint32_t code[] = {
                        EncodeMOVW(12, 0x054Cu), EncodeMOVT(12, 0x9300u),
                        0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // cnt++
                        EncodeMOVW(3, 0x0AB0u), EncodeMOVT(3, 0x4038u),
                        0xE12FFF33u,                          // blx SoapRequestManager ctor
                        EncodeMOVW(3, 0x3AD4u), EncodeMOVT(3, 0x4054u),
                        0xE12FFF13u,                          // bx merge 0x40543AD4
                    };
                    for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                        host.MemoryWrite32(stub + static_cast<uint32_t>(i * 4), code[i]);
                    host.MemoryWrite32(site, 0xE51FF004u);
                    host.MemoryWrite32(site + 4, stub);
                    host.InvalidateGuestCode(site, 8);
                    host.InvalidateGuestCode(stub, 48);
                    host.MemoryWrite32(0x93001790u, 81);  // W447P W213
                    LOGI("[W213] B ctor probe at 0x%08X", site);
                } else {
                    LOGE("[W213] B unexpected word at 0x%08X: %08X", site, orig);
                }
            }
        }
        // W214 (run299): capture the ms_Singleton GOT load. The thread
        // vanishes between the S1 resume (0x40543AC0) and both successor
        // probes (new(0x28) and Image-dir never fire) -- 5 instructions.
        // The suspicious load is LDR R3,[R3] off the GOT slot: a garbage
        // slot would DataAbort inside a nested access. Capture the loaded
        // pointer into 0x93001550 and continue.
        {
            const uint32_t w214site = 0x40543AC0u;
            const uint32_t w214stub = 0x8F113C00u;
            const uint32_t o0 = host.MemoryRead32(w214site);
            // original: LDR R3,[PC,R3] -- encoding E59F3000-class? It is
            // LDR R3, [PC, R3] = register+PC form: 0xE79F3003? verify both.
            if (o0 == 0xE79F3003u || o0 == 0xE59F3000u) {
                const uint32_t code[] = {
                    EncodeMOVW(2, 0x3AC8u), EncodeMOVT(2, 0x4054u),
                    0xE7933002u,                          // ldr r3,[r2,r3] (= [PC+R3])
                    EncodeMOVW(12, 0x0550u), EncodeMOVT(12, 0x9300u),
                    0xE58C3000u,                          // str r3,[r12]  captured
                    0xE5933000u,                          // ldr r3,[r3] (DISPLACED 0x40543AC4: r3 = ms_Singleton)
                    0xE51FF004u,                          // ldr pc -> resume
                    w214site + 8u,                        // resume 0x40543AC8
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w214stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(0x93001550u, 0xDEADBEADu);  // disambiguate
                host.MemoryWrite32(w214site, 0xE51FF004u);
                host.MemoryWrite32(w214site + 4, w214stub);
                host.InvalidateGuestCode(w214site, 8);
                host.InvalidateGuestCode(w214stub, 48);
                host.MemoryWrite32(0x93001790u, 80);  // W447P W214
                LOGI("[W214] GOT-load capture at 0x%08X (orig %08X)", w214site, o0);
            } else {
                LOGE("[W214] unexpected word at 0x%08X: %08X", w214site, o0);
            }
        }
        // W217 (run302): bz_StartInternal epilogue freeze bisect. After the
        // boot[14] probe the thread vanished without reaching 0x40543AC0
        // (W214 DEADBEAD), with no RUNAWAY/EXCEPTION/W84APP. Probe BOTH
        // epilogue instructions of the success return:
        //   P2 installs FIRST: its verify expects the ORIGINAL POP word at
        //   0x403DC07C, which P1's install would overwrite. Then P1:
        //   0x403DC078 ADD SP,SP,#0x10 -- dump sp, r4-r10, 8 stack words
        //   P2 0x403DC07C POP {R4-R10,PC} -- dump sp + the first 8 popped
        //      words (the LAST one is the PC the POP loads!).
        // Cells: P1 0x93001560(sp) 564-7C(r4-r10) 580-9C(stack);
        //        P2 0x930015A0(sp) 5A4-C0(stack words).
        {
            // P2
            {
                const uint32_t p2 = 0x403DC07Cu;
                const uint32_t p2stub = 0x8F113E00u;   // W221: moved — P1 grew to 156B and overlapped 0x00013D80
                const uint32_t o = host.MemoryRead32(p2);
                if (o == 0xE8BD87F0u) {                     // POP {R4-R10,PC}
                    const uint32_t code[] = {
                        0xE92D0003u,                        // push {r0,r1}
                        // W220-M2: prove P2 entered.
                        EncodeMOVW(12, 0x05A8u), EncodeMOVT(12, 0x9300u),
                        EncodeMOVW(3, 0xEE03u), EncodeMOVT(3, 0xC0FFu),
                        0xE58C3000u,                        // str r3,[r12] M2
                        EncodeMOVW(12, 0x05A0u), EncodeMOVT(12, 0x9300u),
                        0xE1A0200Du,                        // mov r2,sp
                        0xE2822008u,                        // add r2,r2,#8
                        0xE4C21004u,                        // str r2,[r12],#4
                        0xE4D33004u, 0xE4C13004u,           // 8 popped words
                        0xE4D33004u, 0xE4C13004u,           // (word 7 = the PC
                        0xE4D33004u, 0xE4C13004u,           //  the POP will load!)
                        0xE4D33004u, 0xE4C13004u,
                        0xE8BD0003u,                        // pop {r0,r1}
                        0xE8BD87F0u,                        // pop {R4-R10,PC} (displaced)
                    };
                    for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                        host.MemoryWrite32(p2stub + static_cast<uint32_t>(i * 4), code[i]);
                    host.MemoryWrite32(p2, 0xE51FF004u);
                    host.MemoryWrite32(p2 + 4, p2stub);
                    host.InvalidateGuestCode(p2, 8);
                    host.InvalidateGuestCode(p2stub, 64);
                    host.MemoryWrite32(0x93001790u, 79);  // W447P W217
                    LOGI("[W217] P2 pop dump at 0x%08X", p2);
                } else {
                    LOGE("[W217] P2 unexpected word at 0x%08X: %08X", p2, o);
                }
            }
        }
            // P1
            {
                const uint32_t p1 = 0x403DC078u;
                const uint32_t p1stub = 0x8F113D00u;
                const uint32_t o = host.MemoryRead32(p1);
                if (o == 0xE28DD010u) {
                    const uint32_t code[] = {
                        // W223 (run327): SHORT stub. The previous 156-byte
                        // stub "stopped" between its stmia and the extension
                        // (hypothesis: Dynarmic truncates long guest-block
                        // translation). 18 words: entry magic, CAPTURE
                        // r4-r10 then restore, skip the dead frame, jump to
                        // the S1 stub's post-call.
                        0xE92D0003u,                        // push {r0,r1}
                        EncodeMOVW(12, 0x0700u), EncodeMOVT(12, 0x9300u),
                        EncodeMOVW(3, 0xEE01u), EncodeMOVT(3, 0xC0FFu),
                        0xE58C3000u,                        // str r3,[r12]  far magic
                        EncodeMOVW(12, 0x0564u), EncodeMOVT(12, 0x9300u),
                        0xE1A0200Du,                        // mov r2,sp
                        0xE2822008u,                        // add r2,r2,#8 (entry sp)
                        0xE8AC07F0u,                        // stmia r12!,{r4-r10} capture
                        0xE8BC07F0u,                        // ldmia r12!,{r4-r10} restore
                        0xE8BD0003u,                        // pop {r0,r1}
                        0xE28DD010u,                        // add sp,sp,#0x10 (locals; displaced)
                        0xE28DD020u,                        // add sp,sp,#0x20 (saved regs)
                        0xE3A00000u,                        // mov r0,#0 (bz_StartInternal return)
                        0xE51FF004u,                        // ldr pc -> S1 post-call
                        0x8F113A30u,
                    };
                    for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                        host.MemoryWrite32(p1stub + static_cast<uint32_t>(i * 4), code[i]);
                    host.MemoryWrite32(p1, 0xE51FF004u);
                    host.MemoryWrite32(p1 + 4, p1stub);
                    host.InvalidateGuestCode(p1, 8);
                    host.InvalidateGuestCode(p1stub, 128);
                    host.MemoryWrite32(0x93001790u, 78);  // W447P W217
                    LOGI("[W217] P1 epilogue-entry dump at 0x%08X", p1);
                } else {
                    LOGE("[W217] P1 unexpected word at 0x%08X: %08X", p1, o);
                }
            }
        }  // W429 end retired W213/W214/W217
        // W221 (run322): ReleaseGraphicsSystem ENTRY counter. boot[14]
        // proves the call was ISSUED; this proves whether the function was
        // ENTERED and captures the graphics-lock count. PC-relative pair
        // reproduced with absolute arithmetic (W112 law).
        // Cells: 0x93000604=entries, 608=&count, 60C=count-at-entry.
        {
            const uint32_t w221site = 0x403F3CE8u;
            const uint32_t w221stub = 0x8F113F00u;
            const uint32_t o0 = host.MemoryRead32(w221site);
            const uint32_t o1 = host.MemoryRead32(w221site + 4);
            if (o0 == 0xE59F2034u && o1 == 0xE08F2002u) {
                const uint32_t code[] = {
                    EncodeMOVW(2, 0x3D24u), EncodeMOVT(2, 0x403Fu),
                    0xE5922000u,                        // ldr r2,[r2]  (lit)
                    EncodeMOVW(3, 0x3CF4u), EncodeMOVT(3, 0x403Fu),
                    0xE0822003u,                        // add r2,r2,r3 (= &count)
                    0xE5923004u,                        // ldr r3,[r2,#4] (displaced)
                    EncodeMOVW(12, 0x0604u), EncodeMOVT(12, 0x9300u),
                    0xE59C1000u,                        // ldr r1,[r12]
                    0xE2811001u,                        // add r1,r1,#1
                    0xE58C1000u,                        // str r1,[r12]  entries++
                    EncodeMOVW(1, 0x0608u), EncodeMOVT(1, 0x9300u),
                    0xE58C2000u,                        // str r2,[r1]   &count
                    EncodeMOVW(1, 0x060Cu), EncodeMOVT(1, 0x9300u),
                    0xE58C3000u,                        // str r3,[r1]   count
                    0xE51FF004u,                        // ldr pc -> resume
                    w221site + 8u,                      // resume 0x403F3CF4 (CMP R3,#0)
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w221stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w221site, 0xE51FF004u);
                host.MemoryWrite32(w221site + 4, w221stub);
                host.InvalidateGuestCode(w221site, 8);
                host.InvalidateGuestCode(w221stub, 96);
                host.MemoryWrite32(0x93001790u, 77);  // W447P W221
                LOGI("[W221] ReleaseGraphicsSystem entry capture at 0x%08X", w221site);
            } else {
                LOGE("[W221] unexpected words at 0x%08X: %08X/%08X", w221site, o0, o1);
            }
        }
        // W226 (run330): AddSearchEntry + RemoveSearchGroup entry
        // counters. The boot+content init complete, Image-dir passes, but
        // the vanish happens inside CINode::AddSearchEntry (0x403F7824) at
        // its call 0x403F784C. Count entries: 0x93000630 = AddSearchEntry,
        // 0x93000634 = RemoveSearchGroup. Stack-safe counter pattern
        // (push args+scratch, count, pop, displaced prologue).
        {
            // W226a: AddSearchEntry (0x403F7824): PUSH {r4-r8,lr}; CMP R1,#0
            {
                const uint32_t site = 0x403F7824u;
                const uint32_t stub = 0x8F114080u;
                const uint32_t o0 = host.MemoryRead32(site);
                const uint32_t o1 = host.MemoryRead32(site + 4);
                if (o0 == 0xE92D41F0u && o1 == 0xE3510000u) {
                    const uint32_t code[] = {
                        0xE92D100Fu,                    // push {r0-r3,r12}
                        EncodeMOVW(0, 0x005Cu), EncodeMOVT(0, 0x9300u),
                        0xE5901000u, 0xE2811001u, 0xE5801000u,
                        0xE8BD100Fu,                    // pop {r0-r3,r12}
                        0xE92D41F0u,                    // push {r4-r8,lr} (displaced)
                        0xE3510000u,                    // cmp r1,#0 (displaced)
                        0xE51FF004u,                    // ldr pc -> resume
                        site + 8u,                      // resume 0x403F782C
                    };
                    for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                        host.MemoryWrite32(stub + static_cast<uint32_t>(i * 4), code[i]);
                    host.MemoryWrite32(site, 0xE51FF004u);
                    host.MemoryWrite32(site + 4, stub);
                    host.InvalidateGuestCode(site, 8);
                    host.InvalidateGuestCode(stub, 48);
                    host.MemoryWrite32(0x93001790u, 75);  // W447P W226
                    LOGI("[W226] AddSearchEntry probe at 0x%08X", site);
                } else {
                    LOGE("[W226] AddSearchEntry unexpected %08X/%08X", o0, o1);
                }
            }
            // W226b: RemoveSearchGroup (0x403FE684): PUSH {r3,lr}; BL Find
            {
                const uint32_t site = 0x403FE684u;
                const uint32_t stub = 0x8F114100u;
                const uint32_t o0 = host.MemoryRead32(site);
                const uint32_t o1 = host.MemoryRead32(site + 4);
                const uint32_t tgt = 0x403FE010u;
                if (o0 == 0xE92D4008u && o1 == (0xEB000000u | ((tgt - site - 8) >> 2 & 0x00FFFFFFu))) {
                    const uint32_t code[] = {
                        0xE92D100Fu,                    // push {r0-r3,r12}
                        EncodeMOVW(0, 0x0060u), EncodeMOVT(0, 0x9300u),
                        0xE5901000u, 0xE2811001u, 0xE5801000u,
                        0xE8BD100Fu,                    // pop {r0-r3,r12}
                        0xE92D3008u,                    // push {r3,lr} (displaced)
                        EncodeMOVW(3, tgt & 0xFFFFu), EncodeMOVT(3, tgt >> 16),
                        0xE12FFF33u,                    // blx CINodeTree::Find
                        0xE51FF004u,                    // ldr pc -> resume
                        site + 8u,                      // resume 0x403FE68C
                    };
                    for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                        host.MemoryWrite32(stub + static_cast<uint32_t>(i * 4), code[i]);
                    host.MemoryWrite32(site, 0xE51FF004u);
                    host.MemoryWrite32(site + 4, stub);
                    host.InvalidateGuestCode(site, 8);
                    host.InvalidateGuestCode(stub, 56);
                    host.MemoryWrite32(0x93001790u, 74);  // W447P W226
                    LOGI("[W226] RemoveSearchGroup probe at 0x%08X", site);
                } else {
                    LOGE("[W226] RemoveSearchGroup unexpected %08X/%08X", o0, o1);
                }
            }
        }
        // W227 (run330): BL CleanPath probe (0x403FE9F4 in Init_BZ tail →
        // SetCommonMaterialDir's string prep — the vanish site). Captures
        // count + &string + the first 16 bytes of the string object into
        // far cells 0x93000720-73C. Displaced-next is PC-relative
        // (LDR R3,[PC,#0x104] at 0x403FE9F8) — reproduced absolutely.
        {
            const uint32_t w227site = 0x403FE9F4u;
            const uint32_t w227stub = 0x8F114200u;
            const uint32_t o227 = host.MemoryRead32(w227site);
            const uint32_t i227 = ((0x403FC8ECu - w227site - 8) >> 2) & 0x00FFFFFFu;
            if (o227 == (0xEB000000u | i227)) {
                const uint32_t code[] = {
                    EncodeMOVW(12, 0x0720u), EncodeMOVT(12, 0x9300u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // count++
                    0xE58C0004u,                        // str r0,[r12,#4]  &string
                    0xE5903000u, 0xE58C3008u,           // [r0] -> 0x93000728
                    0xE5903004u, 0xE58C300Cu,           // [r0+4]
                    0xE5903010u, 0xE58C3010u,           // [r0+8]
                    0xE5903014u, 0xE58C3014u,           // [r0+12]
                    EncodeMOVW(3, 0xC8ECu), EncodeMOVT(3, 0x403Fu),
                    0xE12FFF33u,                        // blx CleanPath
                    EncodeMOVW(2, 0xEB04u), EncodeMOVT(2, 0x403Fu),   // W266: FIXED was 0xEB00 (off-by-4!) -- the literal sits at 0x403FEB04; the wrong delta gave ReplaceSearch a garbage node-system
                    0xE5923000u,                        // ldr r3,[r2]  (displaced LDR R3,[PC,#0x104])
                    0xE51FF004u,                        // ldr pc -> resume
                    w227site + 8u,                      // resume 0x403FE9FC
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w227stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w227site, 0xE51FF004u);
                host.MemoryWrite32(w227site + 4, w227stub);
                host.InvalidateGuestCode(w227site, 8);
                host.InvalidateGuestCode(w227stub, 128);
                host.MemoryWrite32(0x93001790u, 73);  // W447P W227
                LOGI("[W227] CleanPath BL probe at 0x%08X", w227site);
            } else {
                LOGE("[W227] unexpected word at 0x%08X: %08X (want %08X)",
                     w227site, o227, 0xEB000000u | i227);
            }
        }
        // W228 (run330): Material::SetCommonLoadingDirectory string-copy
        // LLMemAllocate probe. Captures the size arg and the RESULT:
        // cell 0x93000628=count, 0x93000618=size, 0x9300062C=result ptr.
        // A zero/garbage result = the string rep allocation failing.
        {
            const uint32_t w228site = 0x4027F64Cu;
            const uint32_t w228stub = 0x8F114280u;
            const uint32_t o228 = host.MemoryRead32(w228site);
            const uint32_t i228 = ((0x4040DE74u - w228site - 8) >> 2) & 0x00FFFFFFu;
            if (o228 == (0xEB000000u | i228)) {
                const uint32_t code[] = {
                    // W287 (run387): SHRUNK below the ~100B translation-truncation
                    // line (was 33 words/132B -- the tail was cut and the flow slid).
                    // Keeps: the state heal (0/3 -> 2) and the result capture.
                    EncodeMOVW(12, 0x3DC4u), EncodeMOVT(12, 0x406Eu),
                    0xE59D2000u,                        // r2 = bzgMemory_system_state
                    0xE3520001u,                        // cmp r2,#1
                    0x13520002u,                        // cmpne r2,#2
                    0x0A000001u,                        // beq healed
                    0xE3A02002u,                        // mov r2,#2
                    0xE58C2000u,                        // str r2,[r12] healed
                    EncodeMOVW(3, 0x0040u), EncodeMOVT(3, 0x9300u),
                    0xE5932000u, 0xE2822001u, 0xE5832000u,   // count++ @0x93000040
                    EncodeMOVW(3, 0xDE74u), EncodeMOVT(3, 0x4040u),   // LLMemAllocate (W257 fixed)
                    0xE12FFF33u,                        // blx LLMemAllocate
                    EncodeMOVW(12, 0x0044u), EncodeMOVT(12, 0x9300u),
                    0xE58C0000u,                        // str r0,[r12] result @0x93000044
                    0xE3550001u,                        // displaced CMP R5,#1
                    0xE51FF004u,                        // ldr pc -> resume
                    w228site + 8u,                      // resume 0x4027F654
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w228stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w228site, 0xE51FF004u);
                host.MemoryWrite32(w228site + 4, w228stub);
                host.InvalidateGuestCode(w228site, 8);
                host.InvalidateGuestCode(w228stub, 96);
                host.MemoryWrite32(0x93001790u, 72);  // W447P W228
                LOGI("[W228] Material string-alloc probe at 0x%08X", w228site);
            } else {
                LOGE("[W228] unexpected word at 0x%08X: %08X (want %08X)",
                     w228site, o228, 0xEB000000u | i228);
            }
        }
        // W238 (run348): BL SetCommonMaterialDir probe at the Material body
        // tail (0x4027F628). Fires when the body reaches dir registration;
        // captures the string arg ptr + the rep length field.
        {
            const uint32_t w238site = 0x4027F628u;
            const uint32_t w238stub = 0x8F114600u;
            const uint32_t o238 = host.MemoryRead32(w238site);
            if (o238 == 0xEB05FCE1u) {
                const uint32_t code[] = {
                    EncodeMOVW(12, 0x0754u), EncodeMOVT(12, 0x9300u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // count++
                    0xE58C0004u,                        // str r0,[r12,#4] string ptr
                    0xE5903008u,                        // ldr r3,[r0,#8] rep field
                    0xE58C3008u,                        // str r3,[r12,#8]
                    EncodeMOVW(3, 0xE9B4u), EncodeMOVT(3, 0x403Fu),
                    0xE12FFF33u,                        // blx SetCommonMaterialDir
                    0xE59D3004u,                        // displaced LDR R3,[SP,#4]
                    0xE51FF004u,                        // ldr pc -> resume
                    w238site + 8u,                      // resume 0x4027F634
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w238stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w238site, 0xE51FF004u);
                host.MemoryWrite32(w238site + 4, w238stub);
                host.InvalidateGuestCode(w238site, 8);
                host.InvalidateGuestCode(w238stub, 64);
                host.MemoryWrite32(0x93001790u, 71);  // W447P W238
                LOGI("[W238] SetCommonMaterialDir BL probe at 0x%08X", w238site);
            } else {
                LOGE("[W238] unexpected word at 0x%08X: %08X (want EB05FCE1)",
                     w238site, o238);
            }
        }
        // W239 (run348): Init_BZ error-path probe (0x40543B10 BL
        // ErrorMarkSourcePoition). Non-zero = R6 error -> the Init_BZ
        // error branch fired after the dir registration.
        {
            const uint32_t w239site = 0x40543B10u;
            const uint32_t w239stub = 0x8F114840u;
            const uint32_t o239 = host.MemoryRead32(w239site);
            if (o239 == 0xEBF29124u) {
                const uint32_t code[] = {
                    // W374 (run503): counter moved to the fresh 0x9300 bank
                    // (0x93000764 was arena-stomped) + capture r6 = the
                    // 'started' error code at the Init_BZ error branch.
                    EncodeMOVW(12, 0x0564u), EncodeMOVT(12, 0x9300u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // count++
                    0xE58C6004u,                        // str r6,[r12,#4] started
                    EncodeMOVW(3, 0x7FA8u), EncodeMOVT(3, 0x401Eu),
                    0xE12FFF33u,                        // blx ErrorMarkSourcePoition
                    0xE3500000u,                        // displaced CMP R0,#0
                    0xE51FF004u,                        // ldr pc -> resume
                    w239site + 8u,                      // resume 0x40543B18
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w239stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w239site, 0xE51FF004u);
                host.MemoryWrite32(w239site + 4, w239stub);
                host.InvalidateGuestCode(w239site, 8);
                host.InvalidateGuestCode(w239stub, 48);
                host.MemoryWrite32(0x93001790u, 70);  // W447P W239
                LOGI("[W239] Init_BZ error-path probe at 0x%08X", w239site);
            } else {
                LOGE("[W239] unexpected word at 0x%08X: %08X (want EBF29124)",
                     w239site, o239);
            }
        }
        // W240 (run348): Init_BZ LLError probe (0x40543B30). Fires on the
        // fatal "ERROR" log right before Init_BZ returns.
        {
            const uint32_t w240site = 0x40543B30u;
            const uint32_t w240stub = 0x8F114880u;
            const uint32_t o240 = host.MemoryRead32(w240site);
            if (o240 == 0xEBF29123u) {
                const uint32_t code[] = {
                    EncodeMOVW(12, 0x0768u), EncodeMOVT(12, 0x9300u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // count++
                    EncodeMOVW(3, 0x7FC4u), EncodeMOVT(3, 0x401Eu),
                    0xE12FFF33u,                        // blx LLError
                    0xE28DD074u,                        // displaced ADD SP,SP,#0x74
                    0xE51FF004u,                        // ldr pc -> resume
                    w240site + 8u,                      // resume 0x40543B38
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w240stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w240site, 0xE51FF004u);
                host.MemoryWrite32(w240site + 4, w240stub);
                host.InvalidateGuestCode(w240site, 8);
                host.InvalidateGuestCode(w240stub, 48);
                host.MemoryWrite32(0x93001790u, 69);  // W447P W240
                LOGI("[W240] Init_BZ LLError probe at 0x%08X", w240site);
            } else {
                LOGE("[W240] unexpected word at 0x%08X: %08X (want EBF29123)",
                     w240site, o240);
            }
        }
        // W241 (run348): SetCommonMaterialDir entry probe (0x403FE9B4).
        // W238=1 + W241=1 + rsg(W226b)=0 => death INSIDE
        // SetCommonMaterialDir, before RemoveSearchGroup.
        {
            const uint32_t w241site = 0x403FE9B4u;
            const uint32_t w241stub = 0x8F1148C0u;
            const uint32_t o241a = host.MemoryRead32(w241site);
            const uint32_t o241b = host.MemoryRead32(w241site + 4);
            if (o241a == 0xE92D40F0u && o241b == 0xE24DD014u) {
                const uint32_t code[] = {
                    0xE92D100Fu,                    // push {r0-r3,r12}
                    EncodeMOVW(12, 0x076Cu), EncodeMOVT(12, 0x9300u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // count++
                    0xE58C0000u,                        // str r0,[r12] arg string
                    0xE8BD100Fu,                    // pop {r0-r3,r12}
                    0xE92D40F0u,                    // displaced push {r4-r7,lr}
                    0xE24DD014u,                    // displaced sub sp,sp,#0x14
                    0xE51FF004u,                    // ldr pc -> resume
                    w241site + 8u,                  // resume 0x403FE9BC
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w241stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w241site, 0xE51FF004u);
                host.MemoryWrite32(w241site + 4, w241stub);
                host.InvalidateGuestCode(w241site, 8);
                host.InvalidateGuestCode(w241stub, 64);
                host.MemoryWrite32(0x93001790u, 68);  // W447P W241
                LOGI("[W241] SetCommonMaterialDir entry probe at 0x%08X", w241site);
            } else {
                LOGE("[W241] unexpected words at 0x%08X: %08X/%08X",
                     w241site, o241a, o241b);
            }
        }
        // W377 (run506): capture started (r0) at bz_StartInternal RETURN
        // (MOV r6,r0 at 0x40543ACC) into the fresh bank. W374 at the error
        // branch caught r6=0 which is impossible via the CMP r6/BNE flow --
        // evidence of a W371 bounce-wander, not a real init failure. This
        // probe sits BEFORE any branch and sees the true return value.
        {
            const uint32_t w377site = 0x40543ACCu;
            const uint32_t w377stub = 0x8F114900u;
            const uint32_t o377 = host.MemoryRead32(w377site);
            if (false && o377 == 0xE1A06000u) {  // W432: replaced by the SVC-trampoline probe below
                const uint32_t code[] = {
                    EncodeMOVW(12, 0x1728u), EncodeMOVT(12, 0x9300u),  // W428: cell 0x93001728 (0x0570 was W217-collided)
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // count++
                    0xE58C0004u,                        // str r0,[r12,#4] started
                    0xE1A06000u,                        // displaced MOV R6,R0
                    0xE51FF004u,                        // ldr pc -> resume
                    w377site + 4u,                      // resume 0x40543AD0
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w377stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w377site, 0xE51FF004u);
                host.MemoryWrite32(w377site + 4, w377stub);
                host.InvalidateGuestCode(w377site, 8);
                host.InvalidateGuestCode(w377stub, 44);
                host.MemoryWrite32(0x93001790u, 67);  // W447P W377
                LOGI("[W377] bz_StartInternal return capture at 0x%08X -> stub 0x%08X",
                     w377site, w377stub);
            } else {
                LOGE("[W377] unexpected word at 0x%08X: %08X (want E1A06000)",
                     w377site, o377);
            }

        // W394b (run529): take the LLMem auto-init under control.
        // LLMemAllocateV's auto-init (BL InitMemorySystem(0); state=1)
        // wins the init race, so the game's own InitMemorySystem(a1)
        // takes the SHORT path and silently drops ALL configured pool
        // parameters (alignment, heap limit, temp stack) -- the pool
        // table stays empty and pool items alias. NOP the five words so
        // the auto-init becomes a no-op and the game's own
        // InitMemorySystem(a1) performs the LONG init with real inputs.
        {
            const uint32_t w394b_site = 0x4040D9F8u;  // W412: was 0x40D9F8 -- IDB paste missed +0x40000000 base
            const uint32_t want[5] = {0, 0, 0, 0, 0};
            uint32_t orig[5];
            bool pristine = true;
            for (int k = 0; k < 5; ++k) {
                orig[k] = host.MemoryRead32(w394b_site + static_cast<uint32_t>(k) * 4u);
                (void)want[0];
            }
            // Expected: BL InitMemorySystem; LDR r3,=ptr; MOV r2,#1;
            //           LDR r3,[r5,r3]; STR r2,[r3]
            pristine = (orig[0] & 0x00010000u) == 0xEB000000u &&
                       orig[2] == 0xE3A02001u && orig[4] == 0xE5832000u;  // W412: MOV r2,#1 (was r1 -- never matched)
            if (pristine) {
                for (int k = 0; k < 5; ++k)
                    host.MemoryWrite32(w394b_site + static_cast<uint32_t>(k) * 4u,
                                       0xE1A00000u);  // nop
                host.InvalidateGuestCode(w394b_site, 20);
                host.MemoryWrite32(0x93001790u, 66);  // W447P W394b
                LOGI("[W394b] LLMem auto-init NOPped at 0x40D9F8 (5 words)");
            } else {
                LOGE("[W394b] unexpected words at 0x40D9F8: %08X %08X %08X %08X %08X",
                     orig[0], orig[1], orig[2], orig[3], orig[4]);
            }

        // W397 (run532): the SECOND auto-init copy lives in
        // bz_Mem_NewDoAlloc (0x410080): loc_410118 = BL InitMemorySystem(0)
        // then STR r2,[r3] (state=1) at 0x41012C. NOP both (keep
        // MOV R7,#0xD at 0x410124 -- r7 feeds the allocation tag). With
        // W394b this removes every premature state=1 write, letting the
        // game's own InitMemorySystem(a1) run the LONG init with the real
        // pool parameters (alignment, heap limit, temp stack).
        {
            const uint32_t w397a = 0x40410118u;  // BL InitMemorySystem (W412: +base)
            const uint32_t w397b = 0x4041012Cu;  // STR r2,[r3] (state=1) (W412: +base)
            const uint32_t oa = host.MemoryRead32(w397a);
            const uint32_t ob = host.MemoryRead32(w397b);
            const bool bl_ok = (oa & 0x00010000u) == 0xEB000000u;
            const bool str_ok = ob == 0xE5832000u;
            if (bl_ok && str_ok) {
                host.MemoryWrite32(w397a, 0xE1A00000u);  // nop
                host.MemoryWrite32(w397b, 0xE1A00000u);  // nop
                host.InvalidateGuestCode(w397a, 8);
                host.InvalidateGuestCode(w397b, 8);
                host.MemoryWrite32(0x93001790u, 65);  // W447P W397
                LOGI("[W397] bz_Mem_NewDoAlloc auto-init NOPped (0x410118 BL, 0x41012C STR)");
            } else {
                LOGE("[W397] unexpected words at 0x410118=%08X 0x41012C=%08X", oa, ob);
            }

        // W404b (run544): probe the bzgLogManager STORE site (0x403DBFE8,
        // STR r7,[r8] where r8 = &bzgLogManager) to capture the LogManager
        // object pointer AT WRITE TIME -- the W403C tick dump read zero and
        // the store-time value survives rotation via NotePersist.
        {
            const uint32_t w404bsite = 0x403DBFE8u;
            const uint32_t w404bstub = 0x98001980u;
            const uint32_t w404btramp = host.GetThunkManager().GetOrCreateThunkAddress("w398_poolitem_log");
            const uint32_t o404 = host.MemoryRead32(w404bsite);
            if (false && o404 == 0xE5887000u) {  // W412: RETIRED -- stub literal was 0x98001980 (typo for 0x00011980): RUNAWAY on the live bzgLogManager store, W371 BX LR recovery skipped the store itself (LM@00000000 in run544-552)
                const uint32_t code[] = {
                    0xE5887000u,                        // displaced STR r7,[r8]
                    0xE92D0007u,                        // push {r0-r2}
                    0xE59F300Cu,                        // ldr r3,[pc,#12]
                    0xE12FFF33u,                        // blx r3 (log thunk)
                    0xE8BD0007u,                        // pop {r0-r2}
                    0xE51FF004u,                        // ldr pc,[pc,#-4]
                    0x403DBFECu,                        // resume
                    w404btramp,                         // W398 log thunk
                };
                for (size_t i2 = 0; i2 < sizeof(code) / sizeof(uint32_t); ++i2)
                    host.MemoryWrite32(w404bstub + static_cast<uint32_t>(i2 * 4), code[i2]);
                host.MemoryWrite32(w404bsite, 0xE51FF004u);
                host.MemoryWrite32(w404bsite + 4, w404bstub);
                host.InvalidateGuestCode(w404bsite, 8);
                host.InvalidateGuestCode(w404bstub, 36);
                host.MemoryWrite32(0x93001790u, 64);  // W447P W404b
                LOGI("[W404b] bzgLogManager store probe at 0x%08X -> stub 0x%08X",
                     w404bsite, w404bstub);
            } else {
                LOGE("[W404b] unexpected word at 0x%08X: %08X (want E5887000)",
                     w404bsite, o404);
            }

        // W409 (run546b): restore the ORIGINAL ActualMain code at
        // 0x4054E0A0-0x4054E0AC, removing all veneer patches from earlier
        // probes. Then NOP the diagnostic print (BL bz_Debug_PrintToDebugger)
        // so the flow goes: Init_BZ returns -> (skip print) -> Init_PostBZ
        // -> StateMachine_DoInit -> StateMachine_Enter -> render loop.
        {
            const uint32_t w409_orig[] = {
                0xE1A00000u,  // NOP (was BL bz_Debug_PrintToDebugger)
                0xEBFFD6B7u,  // BL Init_PostBZ (original)
                0xEB006CFFu,  // BL StateMachine_DoInitialisationInOneGo (original)
            };
            for (int k = 0; k < 3; ++k)
                host.MemoryWrite32(0x4054E0A0u + static_cast<uint32_t>(k) * 4u, w409_orig[k]);
            host.InvalidateGuestCode(0x4054E0A0u, 12);
            host.MemoryWrite32(0x93001790u, 63);  // W447P W409
            LOGI("[W409] ActualMain restored: print NOPped, Init_PostBZ + StateMachine_DoInit restored");
        }
        // Leave StateMachine_DoInitialisationInOneGo's original prologue
        // intact.  The old W410 diagnostic veneer overwrote entry+4 with its
        // literal target, then resumed at entry+4.  That literal decodes as
        // a conditional SVC and killed android_main before the first frame.
        }
        // W398 (run533): catch the allocation that hands out stub-window
        // addresses. Every LLMemAllocatePoolItemV RETURN (site 0x40DC1C)
        // passes a logging thunk that records the returned pointer; the
        // log names the pool-item path if it ever returns an address in
        // the W100 stub window [0x00011400,0x00011800).
        {
            host.GetThunkManager().RegisterThunk("w398_poolitem_log",
                [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
                    static std::atomic<uint32_t> w398n{0};
                    const uint32_t r0v = jit.Regs()[0];
                    const uint32_t n398 = w398n.fetch_add(1);
                    // W402 (run536): log EVERY pool-item return (capped) to
                    // see the item-address pattern and catch the aliasing
                    // with the DebugLog sink callback fields.
                    if (n398 < 64) {
                        char tb[160];
                        snprintf(tb, sizeof(tb),
                                 "W402 POOLITEM ret=%08X lr=%08X n=%u",
                                 r0v, jit.Regs()[14], static_cast<unsigned>(n398));
                        DiagTrace::NotePersist(std::string(tb));
                        LOGE("%s", tb);  // W415: survive ring rotation
                    }
                });
            const uint32_t w398tramp =
                host.GetThunkManager().GetOrCreateThunkAddress("w398_poolitem_log");
            const uint32_t w398site = 0x4040DC1Cu;  // W412: was 0x40DC1C -- +base
            const uint32_t w398stub = 0x8F111980u;
            const uint32_t o398 = host.MemoryRead32(w398site);
            if (false && o398 == 0xE1A04000u && w398tramp) {  // W483 (run639): RETIRED -- 113M events per boot flooded the diag ring and burned CPU
                const uint32_t code[] = {
                    0xE1A04000u,                        // displaced mov r4,r0
                    0xE92D100Fu,                        // push {r0-r3,r12}
                    0xE59F300Cu,                        // ldr r3,[pc,#12]
                    0xE12FFF33u,                        // blx r3 (log thunk)
                    0xE8BD100Fu,                        // pop {r0-r3,r12}
                    0xE51FF004u,                        // ldr pc,[pc,#-4]
                    0x4040DC20u,                        // resume: B loc_4040DC30 (W412: +base)
                    w398tramp,                          // literal: log thunk
                };
                for (size_t i2 = 0; i2 < sizeof(code) / sizeof(uint32_t); ++i2)
                    host.MemoryWrite32(w398stub + static_cast<uint32_t>(i2 * 4), code[i2]);
                host.MemoryWrite32(w398site, 0xE51FF004u);
                host.MemoryWrite32(w398site + 4, w398stub);
                host.InvalidateGuestCode(w398site, 8);
                host.InvalidateGuestCode(w398stub, 40);
                host.MemoryWrite32(0x93001790u, 61);  // W447P W398
                LOGI("[W398] pool-item return probe at 0x%08X -> stub 0x%08X",
                     w398site, w398stub);
            } else {
                LOGE("[W398] unexpected word at 0x%08X: %08X (want E1A04000)",
                     w398site, o398);
            }
        }        }        }        }
        // W484 (run640): call-granular trace of the first StateMachine_Process
        // tick. The game thread parks at the bridge page (pc=8, lr=40569B9C,
        // r0=-8) within ~1s of Enter (W481) and the W478 display-init stub
        // never runs. Five once-logging veneers on the exact BL sites name
        // the surviving call: A=Enter->BeforeMainLoop, C=Enter->Process,
        // D=Process->GetFramePeriod, E=Process->GetRenderTime,
        // F=Process->IsAppInBackground. The stub preserves the BL semantics
        // (lr := site+4, pc := absolute target) and restores r0-r3/r12/lr
        // around the one-shot log thunk.
        if (false)  // W490 (run657): RETIRED -- the a-probe (B94) wrote its literal into B98 (adjacent!), destroying the original BL Process; the c/d/e/f/u/g/h probes clobbered their neighbors the same way. Self-inflicted spin.
        {
            struct W484Probe { const char* tag; uint32_t site; uint32_t stub; uint32_t lr_in; };
            const W484Probe probes[] = {
                {"w484a", 0x40569B94u, 0x8F118800u, 0x40569B98u},
                {"w484c", 0x40569B98u, 0x8F118828u, 0x40569B9Cu},
                {"w484d", 0x405694F8u, 0x8F118850u, 0x40569B9Cu},
                {"w484e", 0x40569500u, 0x8F118878u, 0x405694FCu},
                {"w484f", 0x40569508u, 0x8F1188A0u, 0x40569504u},
                {"w484u", 0x405695DCu, 0x8F1188C8u, 0x405695E0u},
                {"w484g", 0x40569730u, 0x8F1188F0u, 0x40569734u},
                {"w484h", 0x40569624u, 0x8F118918u, 0x40569628u},
                {"w484i", 0x403DB7E8u, 0x8F118940u, 0x403DB7ECu},
                {"w484j", 0x403DB7F8u, 0x8F118968u, 0x403DB7FCu},
                {"w484k", 0x403DB7FCu, 0x8F118990u, 0x403DB800u},
                {"w484l", 0x403DB800u, 0x8F1189B8u, 0x403DB804u},
                {"w484m", 0x403DB81Cu, 0x8F1189E0u, 0x403DB820u},
            };
            for (const W484Probe& pr : probes) {
                char tname[32];
                snprintf(tname, sizeof(tname), "%s_log", pr.tag);
                const char* tag = pr.tag;
                host.GetThunkManager().RegisterThunk(
                    tname, [tag](Dynarmic::A32::Jit&, DynarmicHost&) {
                        // W488: per-tag gate -- a plain local static in this
                        // lambda is shared by every probe (one lambda class),
                        // which silenced c/d/e/f after a fired first.
                        static std::mutex m484;
                        static std::unordered_map<std::string, uint32_t> hits;
                        std::lock_guard<std::mutex> lk(m484);
                        const uint32_t n = hits[tag]++;
                        if (n < 3 || (n % 5000) == 0)
                            LOGE("[W484] %s HIT n=%u", tag, n);
                    });
                const uint32_t tramp =
                    host.GetThunkManager().GetOrCreateThunkAddress(tname);
                const uint32_t orig = host.MemoryRead32(pr.site);
                if ((orig & 0x0F000000u) != 0x0B000000u) {
                    LOGE("[W484] %s: site %08X not a BL (%08X)", pr.tag, pr.site, orig);
                    continue;
                }
                const int32_t off =
                    static_cast<int32_t>(orig << 8) >> 8;  // sign-extend imm24
                const uint32_t target = pr.site + 8u +
                    static_cast<uint32_t>(off << 2);
                const uint32_t code[10] = {
                    0xE92D500Fu,        // push {r0-r3, r12, lr}
                    0xE59F300Cu,        // ldr r3, [pc, #12]   -> [6] tramp
                    0xE12FFF33u,        // blx r3              (log; clobbers lr)
                    0xE8BD500Fu,        // pop {r0-r3, r12, lr}
                    0xE59FE008u,        // ldr lr, [pc, #8]    -> [8] resume
                    0xE59FF008u,        // ldr pc, [pc, #8]    -> [9] target
                    tramp,
                    0u,
                    pr.site + 4u,       // lr value the original BL would set
                    target,
                };
                for (size_t i2 = 0; i2 < 10; ++i2)
                    host.MemoryWrite32(pr.stub + static_cast<uint32_t>(i2) * 4u, code[i2]);
                host.MemoryWrite32(pr.site, 0xE51FF004u);
                host.MemoryWrite32(pr.site + 4, pr.stub);
                host.InvalidateGuestCode(pr.site, 8);
                host.InvalidateGuestCode(pr.stub, 40);
                LOGE("[W484] %s veneer site=%08X stub=%08X target=%08X resume=%08X",
                     pr.tag, pr.site, pr.stub, target, pr.site + 4u);
            }
        }
        // W413 RETIRED: its veneer occupied 0x403F7050/54, overlapping the
        // W199 null-guard installed at 0x403F7054. That diagnostic-only patch
        // turned the valid empty-tree return path back into a self-loop.
        // W420 (run558b): init-flow progress tracer. The game thread
        // reaches bz_StartInternal (LM set) but something drops it before
        // the render loop. One 2-word veneer per stage entry, displacing
        // BOTH prologue words; PC-rel LDRs are re-emitted as MOVW/MOVT
        // with the literal value read at install time. Counters:
        // 0x930015A0=PDStartup_1, A4=PDStartup_2, A8=PDStartup_3.
        {
            struct W420Site { uint32_t site; uint32_t lit_off; uint32_t push;
                              uint32_t extra; bool has_extra; uint32_t cell;
                              uint32_t stub; const char* name; };
            const W420Site w420[] = {
                {0x403DAB14u, 0x550u, 0xE92D41F0u, 0, false, 0x93001700u, 0x8F117200u, "PS1"},
                {0x403DB0FCu, 0x010u, 0xE92D4008u, 0, false, 0x93001704u, 0x8F117240u, "PS2"},
                {0x403DB118u, 0x010u, 0xE92D4008u, 0, false, 0x93001708u, 0x8F117280u, "PS3"},
                // W423: the game-main chain. android_main prints its banner
                // then tail-Bs into ActualMain; ActualMain calls Init_PostBZ
                // then StateMachine_DoInit then tail-Bs StateMachine_Enter.
                {0x4054E0B8u, 0,     0xE1A07000u, 0, false, 0x93001710u, 0x8F117300u, "AM"},
                {0x4054E078u, 0,     0xE1A04000u, 0, false, 0x93001714u, 0x8F117340u, "AM2"},
                {0x40543B88u, 0,     0xE24DD034u, 0, false, 0x93001718u, 0x8F117380u, "IPBZ"},
                // W424: Init_BZ message path (prints the status string after
                // bz_StartInternal returns) and the Init_BZ epilogue. If MSG
                // counts but EPI does not, the drop is inside the print path;
                // if both count but W258 does not, the drop is in the return
                // to ActualMain.
                {0x40543B04u, 0x06Cu, 0xE30011AEu, 0, false, 0x9300171Cu, 0x8F1173C0u, "MSG"},
                {0x40543B38u, 0,     0xE8BD80F0u, 0, false, 0x93001720u, 0x8F117400u, "EPI"},
                // W434: glue bracket -- android_app_entry entry and the
                // instruction after the pipe-setup call (0x4017C814). If GAE
                // counts but Piped does not, the glue dies inside its own
                // pipe/looper setup, before android_main is ever called.
                {0x4017CA38u, 0,     0xE24DD008u, 0, false, 0x93001738u, 0x8F117540u, "GAE"},
                {0x4017CA74u, 0x0F4u, 0xE5844058u, 0, false, 0x9300173Cu, 0x8F117580u, "Piped"},
                // W461: InitViewports entry -- the pass dies between PDStartup_1's
                // return (0x403DBF40) and PDStartup_2's call (0x403DBF58); the only
                // code in that window is BL InitViewports (0x403DBF50). If iv
                // counts but ps2 never fires, InitViewports itself wedges.
                {0x402DD110u, 0x00Cu, 0xE3A02000u, 0, false, 0x93001560u, 0x8F117600u, "IV"},
                // W462: PDStartup_1 return-site probes -- count COMPLETED
                // internal calls; the last fired site before the pass death
                // brackets the killing call. Cells 0x93001564-0x93001570.
                {0x403DAB4Cu, 0,     0xE5952034u, 0, false, 0x93001564u, 0x8F117740u, "P1a"},
                // W462b P1d/P1e RETIRED: their veneers moved PC-relative
                // loads to low stub addresses without preserving the original
                // PC, corrupting PDStartup_1's context/Java environment before
                // the very call they were meant to diagnose.
                {0x403DAB60u, 0,     0xE1A01008u, 0, false, 0x93001568u, 0x8F117780u, "P1b"},
                // P1c RETIRED: its displaced second instruction is BEQ with
                // a PC-relative destination. Replaying it from the low
                // diagnostic stub branches into stub space instead of the
                // original PDStartup_1 target at 0x403DAD78.
                // Trace the native-app-glue poll-source callback itself. Its
                // address is populated into android_app.cmdPollSource.process
                // by android_app_entry; the following command read is logged
                // independently in the read thunk.
                {0x4017D9ACu, 0,     0xE1A04000u, 0, false, 0x93001744u, 0x8F117940u, "CMDPROC"},
            };
                host.MemoryWrite32(0x93001744u, 0u);
                for (size_t wi = 0; wi < sizeof(w420) / sizeof(w420[0]); ++wi) {
                const W420Site& s = w420[wi];
                const uint32_t o0 = host.MemoryRead32(s.site);
                const uint32_t o1 = host.MemoryRead32(s.site + 4u);
                if (o1 != s.push) {
                    LOGE("[W420] %s word1 %08X != %08X", s.name, o1, s.push);
                    continue;
                }
                std::vector<uint32_t> code;
                auto enc = [&code](uint32_t v) { code.push_back(v); };
                enc(EncodeMOVW(12, s.cell & 0xFFFFu));
                enc(EncodeMOVT(12, s.cell >> 16));
                enc(0xE59C3000u); enc(0xE2833001u); enc(0xE58C3000u);
                if (s.lit_off) {
                    const uint32_t lit = host.MemoryRead32(s.site + 8u + s.lit_off);
                    // Re-emit the displaced PC-relative LDR into its original
                    // destination register. Hard-coding r0 silently skipped
                    // loads into callee-saved registers (P1d: r5), corrupting
                    // PDStartup_1's context base and the JNIEnv it reads from it.
                    const uint32_t rd = (o0 >> 12) & 0xFu;
                    enc(EncodeMOVW(rd, lit & 0xFFFFu));
                    enc(EncodeMOVT(rd, lit >> 16));
                } else {
                    enc(o0);
                }
                enc(s.push);
                if (s.has_extra) enc(s.extra);
                const size_t ldr_idx = code.size();
                enc(0xE51FF004u);
                enc(s.site + 8u);
                (void)ldr_idx;
                for (size_t i = 0; i < code.size(); ++i)
                    host.MemoryWrite32(s.stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(s.site, 0xE51FF004u);
                host.MemoryWrite32(s.site + 4u, s.stub);
                host.InvalidateGuestCode(s.site, 8);
                host.InvalidateGuestCode(s.stub, 48);
                host.MemoryWrite32(0x93001790u, 59);  // W447P W420
                LOGI("[W420] %s entry probe 0x%08X -> 0x%08X", s.name, s.site, s.stub);
                {   // W428b: survive logcat throttling -- the install record
                    // must be provable in the diag file.
                    char ib[96];
                    snprintf(ib, sizeof(ib), "W420INST %s site=%08X stub=%08X",
                             s.name, s.site, s.stub);
                    DiagTrace::NotePersist(std::string(ib));
                }
            }
        }
        // W561: bracket the exact indirect poll-source dispatch. The
        // returned source and its process pointer can be valid while guest
        // control flow still fails before entering process_cmd; this veneer
        // records the target and then replays both displaced instructions.
        {
            const uint32_t site = 0x403DA2A0u;
            const uint32_t stub = 0x8F117980u;
            const uint32_t cell = 0x9300174Cu;
            const uint32_t o0 = host.MemoryRead32(site);
            const uint32_t o1 = host.MemoryRead32(site + 4u);
            if (o0 == 0xE5913008u && o1 == 0xE1A00006u) {
                std::vector<uint32_t> code = {
                    EncodeMOVW(12, cell & 0xFFFFu),
                    EncodeMOVT(12, cell >> 16),
                    0xE59C2000u,  // LDR r2,[r12]
                    0xE2822001u,  // ADD r2,r2,#1
                    0xE58C2000u,  // STR r2,[r12]
                    0xE5912008u,  // LDR r2,[r1,#8] -- selected process callback
                    0xE58C2004u,  // STR r2,[r12,#4]
                    o0, o1,       // displaced LDR r3,[r1,#8]; MOV r0,r6
                    0xE51FF004u,
                    site + 8u,
                };
                host.MemoryWrite32(cell, 0u);
                host.MemoryWrite32(cell + 4u, 0u);
                for (size_t i = 0; i < code.size(); ++i)
                    host.MemoryWrite32(stub + static_cast<uint32_t>(i * 4u), code[i]);
                host.MemoryWrite32(site, 0xE51FF004u);
                host.MemoryWrite32(site + 4u, stub);
                host.InvalidateGuestCode(site, 8);
                host.InvalidateGuestCode(stub, 48);
                DiagTrace::NotePersist("W561 installed poll-source dispatch probe");
            } else {
                char b[112];
                snprintf(b, sizeof(b), "W561 gate failed site=%08X words=%08X/%08X",
                         site, o0, o1);
                DiagTrace::NotePersist(b);
            }
        }
        // W432 (run578): SVC-trampoline flow probes -- NO guest stub memory
        // at all (the old 0x8DB0 stubs were scribbled by the wild writer).
        // Each probe: 2-word veneer at the site + the 8-byte [SVC; BX lr]
        // trampoline in the proven 0x11938 region; the HOST handler does the
        // counting and the displaced-instruction effects, then sets LR to
        // the resume address so the trampoline's BX lr continues the flow.
        //   W432A: Init_BZ return into ActualMain (0x4054E094, after the
        //          BL LLMemFreeSpace): r1 = r0, r0 = [0x4054E0B4], lr = resume.
        {
            auto& tm432 = host.GetThunkManager();
            host.MemoryWrite32(0x93001724u, 0u);
            tm432.RegisterThunk("w432a_initbz_ret",
                [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
                    uint32_t c = h.MemoryRead32(0x93001724u);
                    h.MemoryWrite32(0x93001724u, c + 1u);
                    jit.Regs()[1] = jit.Regs()[0];
                    jit.Regs()[0] = h.MemoryRead32(0x4054E0B4u);
                    jit.Regs()[14] = 0x4054E09Cu;
                });
            // W432A site: the MOV r1,r0 after the BL LLMemFreeSpace
            const uint32_t a432 = 0x4054E094u;
            const uint32_t oa432 = host.MemoryRead32(a432);
            if (oa432 == 0xE1A01000u) {
                const uint32_t t432a = tm432.GetOrCreateThunkAddress("w432a_initbz_ret");
                host.MemoryWrite32(a432, 0xE51FF004u);
                host.MemoryWrite32(a432 + 4u, t432a);
                host.InvalidateGuestCode(a432, 8);
                DiagTrace::NotePersist("W432A installed at 0x4054E094");
            } else {
                LOGE("[W432A] unexpected word at 0x4054E094: %08X", oa432);
                DiagTrace::NotePersist("W432A GATE FAIL 0x4054E094");
            }
        }
        // W258 (run364): ActualMain return-of-Init_BZ probe (0x4054E090 BL
        // LLMemFreeSpace). If this fires, Init_BZ's POP returned correctly
        // and the death is inside LLMemFreeSpace; if not, Init_BZ's stack
        // frame was smashed and the POP jumped to garbage (thread at 0x8).
        {
            const uint32_t w258site = 0x4054E090u;
            const uint32_t w258stub = 0x8F114A00u;
            const uint32_t o258 = host.MemoryRead32(w258site);
            if (false && o258 == 0xEBFAFAA1u) {  // W432: replaced by the SVC-trampoline probe below (old stub got scribbled)
                const uint32_t code[] = {
                    EncodeMOVW(12, 0x1724u), EncodeMOVT(12, 0x9300u),  // W428: cell 0x93001724 (0x1550 was W214-collided)
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // count++
                    EncodeMOVW(3, 0xCB1Cu), EncodeMOVT(3, 0x4040u),
                    0xE12FFF33u,                        // blx LLMemFreeSpace
                    0xE1A01000u,                        // displaced MOV R1,R0
                    0xE51FF004u,                        // ldr pc -> resume
                    w258site + 8u,                      // resume 0x4054E098
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w258stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w258site, 0xE51FF004u);
                host.MemoryWrite32(w258site + 4, w258stub);
                host.InvalidateGuestCode(w258site, 8);
                host.InvalidateGuestCode(w258stub, 48);
                host.MemoryWrite32(0x93001790u, 58);  // W447P W258
                LOGI("[W258] Init_BZ return probe at 0x%08X", w258site);
            } else {
                LOGE("[W258] unexpected word at 0x%08X: %08X (want EBFAFAA1)",
                     w258site, o258);
            }
        }
        // W259 (run364): LLMemFreeSpace entry probe (0x4040CB1C).
        {
            const uint32_t w259site = 0x4040CB1Cu;
            const uint32_t w259stub = 0x8F114A40u;
            const uint32_t o259a = host.MemoryRead32(w259site);
            const uint32_t o259b = host.MemoryRead32(w259site + 4);
            if (o259a == 0xE92D4070u && o259b == 0xE24DD008u) {
                const uint32_t code[] = {
                    0xE92D100Fu,                    // push {r0-r3,r12}
                    EncodeMOVW(12, 0x0054u), EncodeMOVT(12, 0x9300u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // count++
                    0xE8BD100Fu,                    // pop {r0-r3,r12}
                    0xE92D4070u,                    // displaced push {r4-r6,lr}
                    0xE24DD008u,                    // displaced sub sp,sp,#8
                    0xE51FF004u,                    // ldr pc -> resume
                    w259site + 8u,                  // resume 0x4040CB24
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w259stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w259site, 0xE51FF004u);
                host.MemoryWrite32(w259site + 4, w259stub);
                host.InvalidateGuestCode(w259site, 8);
                host.InvalidateGuestCode(w259stub, 48);
                host.MemoryWrite32(0x93001790u, 57);  // W447P W259
                LOGI("[W259] LLMemFreeSpace entry probe at 0x%08X", w259site);
            } else {
                LOGE("[W259] unexpected words at 0x%08X: %08X/%08X",
                     w259site, o259a, o259b);
            }
        }
        // W268 (run370): GetWADAppData entry probe (0x403F8328). The mount
        // path during ReplaceSearch reads WAD app-data by name; captures
        // the name pointer + first word, the app-data out pointer, and LR.
        {
            const uint32_t w268site = 0x403F8328u;
            const uint32_t w268stub = 0x8F114B40u;
            const uint32_t o268a = host.MemoryRead32(w268site);
            const uint32_t o268b = host.MemoryRead32(w268site + 4);
            if (o268a == 0xE92D4070u && o268b == 0xE1A06001u) {
                const uint32_t code[] = {
                    0xE92D100Fu,                    // push {r0-r3,r12}
                    EncodeMOVW(12, 0x0080u), EncodeMOVT(12, 0x9300u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // count++
                    0xE58C0004u,                        // str r0,[r12,#4] name
                    0xE58C1008u,                        // str r1,[r12,#8] appdata
                    0xE58CE00Cu,                        // str lr,[r12,#0xC] caller
                    0xE5903000u,                        // ldr r3,[r0]
                    0xE58C3010u,                        // str r3,[r12,#0x10] name[0]
                    0xE8BD100Fu,                    // pop {r0-r3,r12}
                    0xE92D4070u,                    // displaced push {r4-r6,lr}
                    0xE1A06001u,                    // displaced MOV R6,R1
                    0xE51FF004u,                    // ldr pc -> resume
                    w268site + 8u,                  // resume 0x403F8330
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w268stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w268site, 0xE51FF004u);
                host.MemoryWrite32(w268site + 4, w268stub);
                host.InvalidateGuestCode(w268site, 8);
                host.InvalidateGuestCode(w268stub, sizeof(code));
                host.MemoryWrite32(0x93001790u, 54);  // W447P W268
                LOGI("[W268] GetWADAppData entry probe at 0x%08X", w268site);
            } else {
                LOGE("[W268] unexpected words at 0x%08X: %08X/%08X",
                     w268site, o268a, o268b);
            }
        }
        // W270 (run372): bz_fread entry probe (0x40408824, after its GOT
        // literal load). Captures the bzFile handle, AAsset*, and FILE*
        // fields to distinguish the two native-backed stream modes. The displaced
        // pair reserves 16 stack bytes and loads the global file-hook root through
        // its original GOT slot.
        {
            const uint32_t w270site = 0x40408824u;
            const uint32_t w270stub = 0x8F114BC0u;
            const uint32_t o270a = host.MemoryRead32(w270site);
            const uint32_t o270b = host.MemoryRead32(w270site + 4);
            if (o270a == 0xE24DD010u && o270b == 0xE79FC00Cu) {
                const uint32_t code[] = {
                    0xE92D100Fu,                    // push {r0-r3,r12}
                    EncodeMOVW(12, 0x0620u), EncodeMOVT(12, 0x9000u),
                    0xE59C0000u, 0xE2800001u, 0xE58C0000u,   // count++ @0x90000620
                    0xE50C3010u,                        // str r3,[r12,#-0x10] bzFile
                    0xE5930000u,                        // ldr r0,[r3]
                    0xE50C000Cu,                        // str r0,[r12,#-0xC] AAsset*
                    0xE5930004u,                        // ldr r0,[r3,#4]
                    0xE50C0008u,                        // str r0,[r12,#-8] FILE*
                    0xE5130010u,                        // ldr r0,[r3,#-0x10]
                    0xE58C0078u,                        // str r0,[r12,#0x78] magic @0x90000698
                    0xE513000Cu,                        // ldr r0,[r3,#-0xC]
                    0xE58C007Cu,                        // str r0,[r12,#0x7C] base @0x9000069C
                    0xE58CE080u,                        // str lr,[r12,#0x80] caller @0x900006A0
                    0xE8BD100Fu,                    // pop {r0-r3,r12}
                    0xE24DD010u,                    // displaced sub sp,sp,#0x10
                    EncodeMOVW(12, 0xF1A4u), EncodeMOVT(12, 0x4066u),
                    0xE59CC000u,                        // displaced LDR r12,[PC,r12] via original GOT slot
                    0xE51FF004u,                        // ldr pc -> resume
                    w270site + 8u,                  // resume 0x4040882C
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w270stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w270site, 0xE51FF004u);
                host.MemoryWrite32(w270site + 4, w270stub);
                host.InvalidateGuestCode(w270site, 8);
                host.InvalidateGuestCode(w270stub, sizeof(code));
                host.MemoryWrite32(0x93001790u, 53);  // W447P W270
                LOGI("[W270] bz_fread entry probe at 0x%08X", w270site);
            } else {
                LOGE("[W270] unexpected words at 0x%08X: %08X/%08X",
                     w270site, o270a, o270b);
            }
        }
        // W272 (run374): WADSimple::fopen(CINode*) entry (0x403F7DD8) --
        // the lazy WAD opener for mounted nodes. Captures the node pointer,
        // LR, and node[0..2] so the name/handle field layout is visible.
        {
            const uint32_t w272site = 0x403F7DD8u;
            const uint32_t w272stub = 0x8F114C40u;
            const uint32_t o272a = host.MemoryRead32(w272site);
            const uint32_t o272b = host.MemoryRead32(w272site + 4);
            if (o272a == 0xE92D43F0u && o272b == 0xE1A05000u) {
                const uint32_t code[] = {
                    0xE92D100Fu,                    // push {r0-r3,r12}
                    EncodeMOVW(12, 0x00C0u), EncodeMOVT(12, 0x9300u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // count++
                    0xE58C0004u,                        // str r0,[r12,#4] node
                    0xE58CE008u,                        // str lr,[r12,#8] caller
                    0xE5903000u, 0xE58C300Cu,           // node[0] -> 0xC
                    0xE5903004u, 0xE58C3010u,           // node[1] -> 0x10
                    0xE5903008u, 0xE58C3014u,           // node[2] -> 0x14
                    0xE8BD100Fu,                    // pop {r0-r3,r12}
                    0xE92D43F0u,                    // displaced push {r4-r9,lr}
                    0xE1A05000u,                    // displaced MOV R5,R0
                    0xE51FF004u,                    // ldr pc -> resume
                    w272site + 8u,                  // resume 0x403F7DE0
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w272stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w272site, 0xE51FF004u);
                host.MemoryWrite32(w272site + 4, w272stub);
                host.InvalidateGuestCode(w272site, 8);
                host.InvalidateGuestCode(w272stub, 80);
                host.MemoryWrite32(0x93001790u, 52);  // W447P W272
                LOGI("[W272] WADSimple::fopen entry probe at 0x%08X", w272site);
            } else {
                LOGE("[W272] unexpected words at 0x%08X: %08X/%08X",
                     w272site, o272a, o272b);
            }
        }
        // W273 (run374): CINodeTree::AddEntry probe (0x403FC3A4). The mount
        // path calls AddEntry(name, 4); captures the name pointer, type and
        // the first name word.
        {
            const uint32_t w273site = 0x403FC3A4u;
            const uint32_t w273stub = 0x8F114CC0u;
            const uint32_t o273a = host.MemoryRead32(w273site);
            const uint32_t o273b = host.MemoryRead32(w273site + 4);
            if (o273a == 0xE92D4FF0u && o273b == 0xE2807058u) {
                const uint32_t code[] = {
                    0xE92D100Fu,                    // push {r0-r3,r12}
                    EncodeMOVW(12, 0x00D8u), EncodeMOVT(12, 0x9300u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // count++
                    0xE58C1004u,                        // str r1,[r12,#4] name
                    0xE58C2008u,                        // str r2,[r12,#8] type
                    0xE5913000u, 0xE58C300Cu,           // name[0] -> 0xC
                    0xE8BD100Fu,                    // pop {r0-r3,r12}
                    0xE92D4FF0u,                    // displaced push {r4-r10,lr}
                    0xE2807058u,                    // displaced add r7,r0,#0x58
                    0xE51FF004u,                    // ldr pc -> resume
                    w273site + 8u,                  // resume 0x403FC3AC
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w273stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w273site, 0xE51FF004u);
                host.MemoryWrite32(w273site + 4, w273stub);
                host.InvalidateGuestCode(w273site, 8);
                host.InvalidateGuestCode(w273stub, 72);
                host.MemoryWrite32(0x93001790u, 51);  // W447P W273
                LOGI("[W273] AddEntry probe at 0x%08X", w273site);
            } else {
                LOGE("[W273] unexpected words at 0x%08X: %08X/%08X",
                     w273site, o273a, o273b);
            }
        }
        // W274 (run376): CINodeTree::AddSearch entry probe (0x403FE744).
        // The last link between ReplaceSearch and the Add chain: captures
        // the group/dir/tag string pointers.
        {
            const uint32_t w274site = 0x403FE744u;
            const uint32_t w274stub = 0x8F114D40u;
            const uint32_t o274a = host.MemoryRead32(w274site);
            const uint32_t o274b = host.MemoryRead32(w274site + 4);
            if (o274a == 0xE92D41F0u && o274b == 0xE24DD008u) {
                const uint32_t code[] = {
                    0xE92D100Fu,                    // push {r0-r3,r12}
                    EncodeMOVW(12, 0x00E8u), EncodeMOVT(12, 0x9300u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // count++
                    0xE58C1004u,                        // str r1,[r12,#4] group
                    0xE58C2008u,                        // str r2,[r12,#8] dir
                    0xE58C300Cu,                        // str r3,[r12,#0xC] tag
                    0xE8BD100Fu,                    // pop {r0-r3,r12}
                    0xE92D41F0u,                    // displaced push {r4-r8,lr}
                    0xE24DD008u,                    // displaced sub sp,sp,#8
                    0xE51FF004u,                    // ldr pc -> resume
                    w274site + 8u,                  // resume 0x403FE74C
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w274stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w274site, 0xE51FF004u);
                host.MemoryWrite32(w274site + 4, w274stub);
                host.InvalidateGuestCode(w274site, 8);
                host.InvalidateGuestCode(w274stub, 64);
                host.MemoryWrite32(0x93001790u, 50);  // W447P W274
                LOGI("[W274] CINodeTree::AddSearch probe at 0x%08X", w274site);
            } else {
                LOGE("[W274] unexpected words at 0x%08X: %08X/%08X",
                     w274site, o274a, o274b);
            }
        }
        // W312 (run414): stub-claim ledger -- two probes sharing one
        // stub address silently overwrite each other (W275/W279 both
        // landed on 0x00014DC0 and shipped a CConfigFile->bz_WAD_Open
        // teleport; W297/W300A shared 0x00015280). LOGE on any overlap
        // so the next address drift is caught at boot instead of after
        // a week of phantom spins.
        static struct { uint32_t a, b; const char* n; } g_claims[96];
        static uint32_t g_claims_n = 0;
        auto ClaimStub = [](uint32_t addr, uint32_t bytes, const char* name) {
            for (uint32_t i = 0; i < g_claims_n; ++i)
                if (addr < g_claims[i].b && g_claims[i].a < addr + bytes)
                    LOGE("[W312] STUB OVERLAP %s@%08X+%u vs %s[%08X,%08X)",
                         name, addr, bytes, g_claims[i].n, g_claims[i].a, g_claims[i].b);
            if (g_claims_n < 96) {
                g_claims[g_claims_n] = {addr, addr + bytes, name};
                ++g_claims_n;
            }
        };
        // W275 (run377): CConfigFile ctor entry probe (0x401A0D90). The
        // config load is the prime suspect for the 17 unfilled dir strings:
        // CConfigFile ctor does bz_File_Read on its name; if fopen failed
        // the read dereferences a zero/garbage handle. Captures the name
        // pointer + first word + the object pointer.
        {
            const uint32_t w275site = 0x401A0D90u;
            const uint32_t w275stub = 0x8F116000u;
            ClaimStub(w275stub, 64, "W275");
            const uint32_t o275a = host.MemoryRead32(w275site);
            const uint32_t o275b = host.MemoryRead32(w275site + 4);
            if (o275a == 0xE92D43F0u && o275b == 0xE3A02000u) {
                const uint32_t code[] = {
                    0xE92D100Fu,                    // push {r0-r3,r12}
                    EncodeMOVW(12, 0x00F8u), EncodeMOVT(12, 0x9300u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // count++ @0x930000F8
                    0xE58C0004u,                        // str r0,[r12,#4] object @FC
                    0xE58C1008u,                        // str r1,[r12,#8] name @100
                    0xE5913000u, 0xE58C300Cu,           // name[0] -> @104
                    0xE8BD100Fu,                    // pop {r0-r3,r12}
                    0xE92D43F0u,                    // displaced push {r4-r9,lr}
                    0xE3A02000u,                    // displaced mov r2,#0
                    0xE51FF004u,                    // ldr pc -> resume
                    w275site + 8u,                  // resume 0x401A0D98
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w275stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w275site, 0xE51FF004u);
                host.MemoryWrite32(w275site + 4, w275stub);
                host.InvalidateGuestCode(w275site, 8);
                host.InvalidateGuestCode(w275stub, 72);
                host.MemoryWrite32(0x93001790u, 49);  // W447P W275
                LOGI("[W275] CConfigFile ctor probe at 0x%08X", w275site);
            } else {
                LOGE("[W275] unexpected words at 0x%08X: %08X/%08X",
                     w275site, o275a, o275b);
            }
        }
        // W279 (run379): bz_WAD_Open entry probe (0x404169D8) + parse side.
        // Answers whether the boot ever opens DATA_ANDROID.WAD and with what
        // path, and whether _WAD_ParseWADFile / SetupWadDirPointers run.
        {
            const uint32_t w279site = 0x404169D8u;
            const uint32_t w279stub = 0x8F114DC0u;
            ClaimStub(w279stub, 64, "W279");
            const uint32_t o279a = host.MemoryRead32(w279site);
            const uint32_t o279b = host.MemoryRead32(w279site + 4);
            if (o279a == 0xE92D4038u && o279b == 0xE1A05000u) {
                const uint32_t code[] = {
                    0xE92D100Fu,                    // push {r0-r3,r12}
                    EncodeMOVW(12, 0x0108u), EncodeMOVT(12, 0x9300u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // count++
                    0xE58C0004u,                        // str r0,[r12,#4] name
                    0xE58C2008u,                        // str r2,[r12,#8] flag
                    0xE5913000u, 0xE58C300Cu,           // name[0] -> 0xC
                    0xE8BD100Fu,                    // pop {r0-r3,r12}
                    0xE92D4038u,                    // displaced push {r3-r5,lr}
                    0xE1A05000u,                    // displaced MOV R5,R0
                    0xE51FF004u,                    // ldr pc -> resume
                    w279site + 8u,                  // resume 0x404169E0
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w279stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w279site, 0xE51FF004u);
                host.MemoryWrite32(w279site + 4, w279stub);
                host.InvalidateGuestCode(w279site, 8);
                host.InvalidateGuestCode(w279stub, 64);
                host.MemoryWrite32(0x93001790u, 48);  // W447P W279
                LOGI("[W279] bz_WAD_Open entry probe at 0x%08X", w279site);
            } else {
                LOGE("[W279] unexpected words at 0x%08X: %08X/%08X",
                     w279site, o279a, o279b);
            }
        }
        // W281 (run380): BZ::Content::fread entry probe (0x403F7F80).
        // Captures the file handle,
        // the buffer, the size and LR -- identifies who feeds a string as the
        // bzFile during Init_BZ.
        {
            const uint32_t w281site = 0x403F7F84u;
            const uint32_t w281stub = 0x8F115100u;
            ClaimStub(w281stub, 80, "W281");
            const uint32_t o281 = host.MemoryRead32(w281site);
            if (o281 == 0xE92D4010u) {
                const uint32_t code[] = {
                    0xE92D100Fu,                    // push {r0-r3,r12}
                    EncodeMOVW(12, 0x0118u), EncodeMOVT(12, 0x9300u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // count++
                    0xE59D300Cu,                        // ldr r3,[sp,#12] original r3/file
                    0xE58C3004u,                        // str r3,[r12,#4] file
                    0xE58C0008u,                        // str r0,[r12,#8] buf
                    0xE58C200Cu,                        // str r2,[r12,#0xC] n
                    0xE58CE010u,                        // str lr,[r12,#0x10] caller
                    0xE8BD100Fu,                    // pop {r0-r3,r12}
                    0xE92D4010u,                    // displaced push {r4,lr}
                    0xE24DD008u,                    // displaced sub sp,sp,#8
                    0xE51FF004u,                    // ldr pc -> resume
                    w281site + 8u,                  // resume 0x403F7F8C
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w281stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w281site, 0xE51FF004u);
                host.MemoryWrite32(w281site + 4, w281stub);
                host.InvalidateGuestCode(w281site, 8);
                host.InvalidateGuestCode(w281stub, 80);
                host.MemoryWrite32(0x93001790u, 47);  // W447P W281
                LOGI("[W281] Content::fread entry probe at 0x%08X", w281site);
            } else {
                LOGE("[W281] unexpected word at 0x%08X: %08X (want E92D4010)",
                     w281site, o281);
            }
        }
        // W284 (run384): bz_File_ReadU16 entry probe (0x403F3DEC). The fatal
        // 2-byte read (r2=2 in the W84 dump) comes from here; captures the
        // file handle and the CALLER (LR) to identify the parser that reads
        // a string as a file.
        {
            const uint32_t w284site = 0x403F3DECu;
            const uint32_t w284stub = 0x8F115180u;
            ClaimStub(w284stub, 64, "W284");
            const uint32_t o284a = host.MemoryRead32(w284site);
            const uint32_t o284b = host.MemoryRead32(w284site + 4);
            if (o284a == 0xE52DE004u && o284b == 0xE24DD00Cu) {
                const uint32_t code[] = {
                    0xE92D1001u,                    // push {r0,r12}
                    EncodeMOVW(12, 0x0138u), EncodeMOVT(12, 0x9300u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // count++
                    0xE58C0004u,                        // str r0,[r12,#4] file
                    0xE58CE008u,                        // str lr,[r12,#8] caller
                    0xE8BD1001u,                    // pop {r0,r12}
                    0xE52DE004u,                    // displaced push {lr}
                    0xE24DD00Cu,                    // displaced sub sp,sp,#0xC
                    0xE51FF004u,                    // ldr pc -> resume
                    w284site + 8u,                  // resume 0x403F3DF4
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w284stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w284site, 0xE51FF004u);
                host.MemoryWrite32(w284site + 4, w284stub);
                host.InvalidateGuestCode(w284site, 8);
                host.InvalidateGuestCode(w284stub, 64);
                host.MemoryWrite32(0x93001790u, 46);  // W447P W284
                LOGI("[W284] bz_File_ReadU16 probe at 0x%08X", w284site);
            } else {
                LOGE("[W284] unexpected words at 0x%08X: %08X/%08X",
                     w284site, o284a, o284b);
            }
        }
        // W563: trace the exact first WAD verification transaction. These
        // probes observe entry and the return edges after ftell/fseek while
        // replaying every displaced instruction unchanged. This avoids
        // inferring parser progress from the older W281/W284 probes, whose
        // installation was not independently verified in the stalled run.
        {
            const uint32_t site = 0x404142ECu;
            const uint32_t stub = 0x8F117800u;
            ClaimStub(stub, 64, "W563-verify");
            const uint32_t a = host.MemoryRead32(site);
            const uint32_t b = host.MemoryRead32(site + 4u);
            if (a == 0xE92D4070u && b == 0xE1A04000u) {
                const uint32_t code[] = {
                    0xE92D500Fu,                    // push {r0-r3,r12,lr}
                    EncodeMOVW(12, 0x0300u), EncodeMOVT(12, 0x9300u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u, // entry count
                    0xE58C0004u,                    // file handle
                    0xE58C1008u,                    // verify flag
                    0xE58CE00Cu,                    // caller LR
                    0xE8BD500Fu,                    // pop {r0-r3,r12,lr}
                    0xE92D4070u,                    // displaced push {r4-r6,lr}
                    0xE1A04000u,                    // displaced mov r4,r0
                    0xE51FF004u, site + 8u,
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(stub + static_cast<uint32_t>(i * 4u), code[i]);
                host.MemoryWrite32(site, 0xE51FF004u);
                host.MemoryWrite32(site + 4u, stub);
                host.InvalidateGuestCode(site, 8u);
                host.InvalidateGuestCode(stub, 64u);
                LOGI("[W563] WAD verify entry probe at 0x%08X", site);
            } else {
                LOGE("[W563] verify entry mismatch at %08X: %08X/%08X",
                     site, a, b);
            }
        }
        {
            const uint32_t site = 0x404142FCu;
            const uint32_t stub = 0x8F117840u;
            ClaimStub(stub, 48, "W563-ftell-return");
            const uint32_t a = host.MemoryRead32(site);
            const uint32_t b = host.MemoryRead32(site + 4u);
            if (a == 0xE3A01000u && b == 0xE1A02001u) {
                const uint32_t code[] = {
                    EncodeMOVW(12, 0x0310u), EncodeMOVT(12, 0x9300u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u, // tell-return count
                    0xE58C0004u,                    // tell result
                    0xE58C4008u,                    // file handle
                    0xE3A01000u,                    // displaced mov r1,#0
                    0xE1A02001u,                    // displaced mov r2,r1
                    0xE51FF004u, site + 8u,
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(stub + static_cast<uint32_t>(i * 4u), code[i]);
                host.MemoryWrite32(site, 0xE51FF004u);
                host.MemoryWrite32(site + 4u, stub);
                host.InvalidateGuestCode(site, 8u);
                host.InvalidateGuestCode(stub, 48u);
                LOGI("[W563] WAD ftell return probe at 0x%08X", site);
            } else {
                LOGE("[W563] ftell return mismatch at %08X: %08X/%08X",
                     site, a, b);
            }
        }
        {
            const uint32_t site = 0x403F2420u;
            const uint32_t stub = 0x8F1178C0u;
            ClaimStub(stub, 48, "W563-android-ftell");
            const uint32_t a = host.MemoryRead32(site);
            const uint32_t b = host.MemoryRead32(site + 4u);
            if (a == 0xE5900014u && b == 0xE12FFF1Eu) {
                const uint32_t code[] = {
                    0xE92D500Fu,                    // push {r0-r3,r12,lr}
                    EncodeMOVW(12, 0x0340u), EncodeMOVT(12, 0x9300u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u, // callback count
                    0xE58C0004u,                    // bzFile pointer
                    0xE5903014u, 0xE58C3008u,       // incoming position
                    0xE8BD500Fu,                    // pop {r0-r3,r12,lr}
                    0xE5900014u,                    // displaced ldr r0,[r0,#20]
                    0xE12FFF1Eu,                    // displaced bx lr
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(stub + static_cast<uint32_t>(i * 4u), code[i]);
                host.MemoryWrite32(site, 0xE51FF004u);
                host.MemoryWrite32(site + 4u, stub);
                host.InvalidateGuestCode(site, 8u);
                host.InvalidateGuestCode(stub, 48u);
                LOGI("[W563] Android_ftell entry probe at 0x%08X", site);
            } else {
                LOGE("[W563] Android_ftell mismatch at %08X: %08X/%08X",
                     site, a, b);
            }
        }
        {
            const uint32_t site = 0x40414310u;
            const uint32_t stub = 0x8F117880u;
            ClaimStub(stub, 48, "W563-fseek-return");
            const uint32_t a = host.MemoryRead32(site);
            const uint32_t b = host.MemoryRead32(site + 4u);
            if (a == 0xE1A01005u && b == 0xE1A00004u) {
                const uint32_t code[] = {
                    EncodeMOVW(12, 0x0320u), EncodeMOVT(12, 0x9300u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u, // seek-return count
                    0xE58C0004u,                    // seek result
                    0xE58C4008u,                    // file handle
                    0xE1A01005u,                    // displaced mov r1,r5
                    0xE1A00004u,                    // displaced mov r0,r4
                    0xE51FF004u, site + 8u,
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(stub + static_cast<uint32_t>(i * 4u), code[i]);
                host.MemoryWrite32(site, 0xE51FF004u);
                host.MemoryWrite32(site + 4u, stub);
                host.InvalidateGuestCode(site, 8u);
                host.InvalidateGuestCode(stub, 48u);
                LOGI("[W563] WAD fseek return probe at 0x%08X", site);
            } else {
                LOGE("[W563] fseek return mismatch at %08X: %08X/%08X",
                     site, a, b);
            }
        }
        {
            const uint32_t site = 0x4041431Cu;
            const uint32_t stub = 0x8F117900u;
            ClaimStub(stub, 48, "W563-u16-return");
            const uint32_t a = host.MemoryRead32(site);
            const uint32_t b = host.MemoryRead32(site + 4u);
            if (a == 0xE3A01001u && b == 0xE1A05000u) {
                const uint32_t code[] = {
                    EncodeMOVW(12, 0x0350u), EncodeMOVT(12, 0x9300u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u, // read-return count
                    0xE58C0004u,                    // U16 result
                    0xE58C4008u,                    // file handle
                    0xE3A01001u,                    // displaced mov r1,#1
                    0xE1A05000u,                    // displaced mov r5,r0
                    0xE51FF004u, site + 8u,
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(stub + static_cast<uint32_t>(i * 4u), code[i]);
                host.MemoryWrite32(site, 0xE51FF004u);
                host.MemoryWrite32(site + 4u, stub);
                host.InvalidateGuestCode(site, 8u);
                host.InvalidateGuestCode(stub, 48u);
                LOGI("[W563] WAD first U16 return probe at 0x%08X", site);
            } else {
                LOGE("[W563] U16 return mismatch at %08X: %08X/%08X",
                     site, a, b);
            }
        }
        // W294 (run394): CINodeSystem::fopen entry probe (0x404006D4). The
        // lazy open of a file under a mounted directory: captures the name
        // pointer, its first two words, and the caller.
        {
            const uint32_t w294site = 0x404006D4u;
            const uint32_t w294stub = 0x8F115200u;
            ClaimStub(w294stub, 80, "W294");
            const uint32_t o294a = host.MemoryRead32(w294site);
            const uint32_t o294b = host.MemoryRead32(w294site + 4);
            if (o294a == 0xE92D4FF0u && o294b == 0xE24DDFD5u) {
                const uint32_t code[] = {
                    0xE92D100Fu,                    // push {r0-r3,r12}
                    EncodeMOVW(12, 0x0148u), EncodeMOVT(12, 0x9300u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // count++
                    0xE58C1004u,                        // str r1,[r12,#4] name
                    0xE58CE008u,                        // str lr,[r12,#8] caller
                    0xE5913000u, 0xE58C300Cu,           // name[0] -> 0xC
                    0xE5913004u, 0xE58C3010u,           // name[1] -> 0x10
                    0xE8BD100Fu,                    // pop {r0-r3,r12}
                    0xE92D4FF0u,                    // displaced push {r4-r10,lr}
                    0xE24DDFD5u,                    // displaced sub sp,sp,#0xFD5
                    0xE51FF004u,                    // ldr pc -> resume
                    w294site + 8u,                  // resume 0x404006DC
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w294stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w294site, 0xE51FF004u);
                host.MemoryWrite32(w294site + 4, w294stub);
                host.InvalidateGuestCode(w294site, 8);
                host.InvalidateGuestCode(w294stub, 72);
                host.MemoryWrite32(0x93001790u, 45);  // W447P W294
                LOGI("[W294] CINodeSystem::fopen entry probe at 0x%08X", w294site);
            } else {
                LOGE("[W294] unexpected words at 0x%08X: %08X/%08X",
                     w294site, o294a, o294b);
            }
        }
        // W297 (run401): android_handle_cmd entry probe (0x403D9FDC).
        // Counts every command delivery and captures the cmd id (R1) so the
        // W292 pipe-posted commands (9/8/6/1) are verifiable end-to-end.
        {
            const uint32_t w297site = 0x403D9FDCu;
            const uint32_t w297stub = 0x8F115280u;
            ClaimStub(w297stub, 64, "W297");
            const uint32_t o297a = host.MemoryRead32(w297site);
            const uint32_t o297b = host.MemoryRead32(w297site + 4);
            if (o297a == 0xE92D4010u && o297b == 0xE1A04000u) {
                const uint32_t code[] = {
                    0xE92D100Fu,                    // push {r0-r3,r12}
                    EncodeMOVW(12, 0x0168u), EncodeMOVT(12, 0x9300u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // count++
                    0xE58C1004u,                        // str r1,[r12,#4] cmd
                    0xE58C0008u,                        // str r0,[r12,#8] app
                    0xE8BD100Fu,                    // pop {r0-r3,r12}
                    0xE92D4010u,                    // displaced push {r4,lr}
                    0xE1A04000u,                    // displaced MOV R4,R0
                    0xE51FF004u,                    // ldr pc -> resume
                    w297site + 8u,                  // resume 0x403D9FE4
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w297stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w297site, 0xE51FF004u);
                host.MemoryWrite32(w297site + 4, w297stub);
                host.InvalidateGuestCode(w297site, 8);
                host.InvalidateGuestCode(w297stub, 64);
                host.MemoryWrite32(0x93001790u, 44);  // W447P W297
                LOGI("[W297] android_handle_cmd entry probe at 0x%08X", w297site);
            } else {
                LOGE("[W297] unexpected words at 0x%08X: %08X/%08X",
                     w297site, o297a, o297b);
            }
        }
        // W300 (run402b): bz_StartInternal EXIT-path counters.
        // A: the 0x403DBF64 return (R0 = PDStartup_2's result) -- the POP is
        // re-emitted in the stub so the function returns normally.
        // B: the 0x403DC080 return (R0 = 0x1E) -- displaces MOV+ADD+POP.
        {
            const uint32_t w300a = 0x403DBF64u;
            const uint32_t w300astub = 0x8F115300u;
            ClaimStub(w300astub, 40, "W300A");
            if (host.MemoryRead32(w300a) == 0xE8BD87F0u) {
                const uint32_t code[] = {
                    EncodeMOVW(3, 0x0180u), EncodeMOVT(3, 0x9300u),
                    0xE5932000u, 0xE2822001u, 0xE5832000u,   // count++ @0x93000180
                    0xE5830004u,                        // str r0,[r3,#4] retval @184
                    0xE8BD87F0u,                        // displaced POP {R4-R10,PC}
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w300astub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w300a, 0xE51FF004u);
                host.MemoryWrite32(w300a + 4, w300astub);
                host.InvalidateGuestCode(w300a, 8);
                host.InvalidateGuestCode(w300astub, 40);
                host.MemoryWrite32(0x93001790u, 43);  // W447P W300
                LOGI("[W300] bz_StartInternal exit-A probe at 0x%08X", w300a);
            } else {
                LOGE("[W300] unexpected word at 0x%08X: %08X (want E8BD87F0)",
                     w300a, host.MemoryRead32(w300a));
            }
        }
        {
            const uint32_t w300bsite = 0x403DC080u;
            const uint32_t w300bstub = 0x8F1152C0u;
            ClaimStub(w300bstub, 48, "W300B");
            if (host.MemoryRead32(w300bsite) == 0xE3A0001Eu) {
                const uint32_t code[] = {
                    EncodeMOVW(3, 0x0188u), EncodeMOVT(3, 0x9300u),
                    0xE5932000u, 0xE2822001u, 0xE5832000u,   // count++ @0x93000188
                    0xE3A0001Eu,                        // displaced MOV R0,#0x1E
                    0xE28DD010u,                        // displaced ADD SP,SP,#0x10
                    0xE8BD87F0u,                        // displaced POP {R4-R10,PC}
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w300bstub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w300bsite, 0xE51FF004u);
                host.MemoryWrite32(w300bsite + 4, w300bstub);
                host.InvalidateGuestCode(w300bsite, 8);
                host.InvalidateGuestCode(w300bstub, 48);
                host.MemoryWrite32(0x93001790u, 42);  // W447P W300
                LOGI("[W300] bz_StartInternal exit-B probe at 0x%08X", w300bsite);
            } else {
                LOGE("[W300] unexpected word at 0x%08X: %08X (want E3A0001E)",
                     w300bsite, host.MemoryRead32(w300bsite));
            }
        }
        // W491: inspect bz_StartInternal's third (normal-success) epilogue.
        // W300 only covered the PDStartup_2 error return and null-argument
        // return; the successful path at 0x403DC074 was unobserved. Capture
        // its saved LR and callee-saved frame before POP so an unexpected
        // top-level guest-thread return can be distinguished from a bad
        // return address in bz_StartInternal's own frame.
        {
            const uint32_t site = 0x403DC074u;
            const uint32_t stub = 0x8F118100u;
            const uint32_t cell = 0x930018A0u;
            ClaimStub(stub, 192, "W491");
            if (host.MemoryRead32(site) == 0xE3A00000u) {
                for (uint32_t off = 0; off <= 0x2Cu; off += 4u)
                    host.MemoryWrite32(cell + off, 0u);
                host.MemoryWrite32(cell + 0x40u, 0u);
                host.MemoryWrite32(cell + 0x44u, 0u);
                const uint32_t code[] = {
                    EncodeMOVW(12, cell & 0xFFFFu), EncodeMOVT(12, cell >> 16),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u, // count++
                    0xE58CD004u,                           // SP before epilogue
                    0xE59D202Cu, 0xE58C2008u,               // saved LR
                    0xE1A0200Eu, 0xE58C200Cu,               // live LR
                    0xE59D2010u, 0xE58C2010u,               // saved R4
                    0xE59D2014u, 0xE58C2014u,               // saved R5
                    0xE59D2018u, 0xE58C2018u,               // saved R6
                    0xE59D201Cu, 0xE58C201Cu,               // saved R7
                    0xE59D2020u, 0xE58C2020u,               // saved R8
                    0xE59D2024u, 0xE58C2024u,               // saved R9
                    0xE59D2028u, 0xE58C2028u,               // saved R10
                    0xE1A02000u, 0xE58C202Cu,               // R0 before replay
                    0xE3530001u,                           // first epilogue?
                    EncodeMOVW(12, 0x18E0u), EncodeMOVT(12, 0x9300u),
                    0xE59D202Cu, 0x058C2000u,               // first saved LR
                    0xE3530002u,                           // second epilogue?
                    EncodeMOVW(12, 0x18E4u), EncodeMOVT(12, 0x9300u),
                    0xE59D202Cu, 0x058C2000u,               // second saved LR
                    0xE3A00000u,                           // displaced MOV R0,#0
                    0xE28DD010u,                           // displaced ADD SP,SP,#0x10
                    0xE51FF004u, site + 8u,                 // resume at POP
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(stub + static_cast<uint32_t>(i * 4u), code[i]);
                host.MemoryWrite32(site, 0xE51FF004u);
                host.MemoryWrite32(site + 4u, stub);
                host.InvalidateGuestCode(site, 8u);
                host.InvalidateGuestCode(stub, sizeof(code));
                host.MemoryWrite32(0x93001790u, 115); // W447P W491
                LOGI("[W491] bz_StartInternal success epilogue probe at 0x%08X", site);
            } else {
                LOGE("[W491] unexpected word at 0x%08X: %08X (want E3A00000)",
                     site, host.MemoryRead32(site));
            }
        }
        // W491-entry: record the *incoming* LR at bz_StartInternal before
        // the guest body or any host thunk can touch its frame. Replay the
        // exact two-word prologue in the trampoline; R2/R3/R12 and flags are
        // caller-clobbered by AAPCS, so this leaves the function contract
        // unchanged while separating bad entry state from later stack damage.
        {
            const uint32_t site = 0x403DBCB0u;
            const uint32_t stub = 0x8F118200u;
            const uint32_t cell = 0x93001900u;
            ClaimStub(stub, 80, "W491-entry");
            host.MemoryWrite32(cell, 0u);
            host.MemoryWrite32(cell + 4u, 0u);
            host.MemoryWrite32(cell + 8u, 0u);
            if (host.MemoryRead32(site) == 0xE92D47F0u &&
                host.MemoryRead32(site + 4u) == 0xE24DD010u) {
                const uint32_t code[] = {
                    EncodeMOVW(12, 0x1900u), EncodeMOVT(12, 0x9300u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u, // entry count++
                    0xE3530001u,
                    EncodeMOVW(2, 0x1904u), EncodeMOVT(2, 0x9300u),
                    0x0582E000u,                           // first incoming LR
                    0xE3530002u,
                    EncodeMOVW(2, 0x1908u), EncodeMOVT(2, 0x9300u),
                    0x0582E000u,                           // second incoming LR
                    0xE92D47F0u,                           // original PUSH
                    0xE24DD010u,                           // original SUB SP,#0x10
                    0xE51FF004u, site + 8u,                // resume after prologue
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(stub + static_cast<uint32_t>(i * 4u), code[i]);
                host.MemoryWrite32(site, 0xE51FF004u);
                host.MemoryWrite32(site + 4u, stub);
                host.InvalidateGuestCode(site, 8u);
                host.InvalidateGuestCode(stub, sizeof(code));
                host.MemoryWrite32(0x93001790u, 116); // W447P W491-entry
                LOGI("[W491-entry] bz_StartInternal entry probe at 0x%08X", site);
            } else {
                LOGE("[W491-entry] unexpected prologue at 0x%08X: %08X/%08X",
                     site, host.MemoryRead32(site), host.MemoryRead32(site + 4u));
            }
        }
        // W229 (run331): Material::SetCommonLoadingDirectory BODY entry
        // counter (0x4027F50C, target of the 0x402857BC tail-B thunk).
        // Distinguishes "body not entered" vs "body died before its
        // string LLMemAllocate" (W228 cnt=0). Cell 0x93000638.
        {
            const uint32_t w229site = 0x4027F50Cu;
            const uint32_t w229stub = 0x8F114400u;
            const uint32_t o0 = host.MemoryRead32(w229site);
            const uint32_t o1 = host.MemoryRead32(w229site + 4);
            if (o0 == 0xE92D43F0u && o1 == 0xE3510000u) {
                const uint32_t code[] = {
                    0xE92D100Fu,                    // push {r0-r3,r12}
                    EncodeMOVW(12, 0x0638u), EncodeMOVT(12, 0x9300u),
                    0xE59C0000u, 0xE2800001u, 0xE58C0000u,
                    // W230-dump REMOVED: mCl dump exceeded the safe
                    // translation-block size and killed the thread
                    // (W84APP pc=9000442C in run333).
                    0xE8BD100Fu,                    // pop {r0-r3,r12}
                    // W234: capture s (r0) into the far zone.
                    0xE92D0003u,                    // push {r0,r1}
                    EncodeMOVW(12, 0x0658u), EncodeMOVT(12, 0x9300u),
                    0xE58C0000u,                    // str r0,[r12]  s ptr
                    0xE8BD0003u,                    // pop {r0,r1}
                    0xE92D43F0u,                    // push {r4-r9,lr} (displaced)
                    0xE3510000u,                    // cmp r1,#0 (displaced)
                    0xE51FF004u,                    // ldr pc -> resume
                    w229site + 8u,                  // resume 0x4027F514
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w229stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w229site, 0xE51FF004u);
                host.MemoryWrite32(w229site + 4, w229stub);
                host.InvalidateGuestCode(w229site, 8);
                host.InvalidateGuestCode(w229stub, 56);
                host.MemoryWrite32(0x93001790u, 41);  // W447P W229
                LOGI("[W229] body entry probe at 0x%08X", w229site);
            } else {
                LOGE("[W229] unexpected words at 0x%08X: %08X/%08X", w229site, o0, o1);
            }
        }
        // Keep native LLMemFill semantics for stack buffers too. The old W231
        // size/address guard skipped Race_ScanForCheckpoints' legitimate
        // 8204-byte local initialization, leaving stale counts/model pointers
        // and causing WRONG CHECKPOINT even after the qsort repair.
        // W232 (run335): the 5 internal BLs of Material::SetCommonLoading
        // Directory body (0x4027F50C), counted to find the exact death site:
        // the flow enters the body (W229=1) but never reaches the string
        // alloc BL at 0x4027F5DC. All displaced words are register-only.
        {
            struct W232Site { uint32_t site, target, disp, cnt; const char* name; };
            const W232Site w232[] = {
                { 0x4027F53Cu, 0x40166C0Cu, 0xE3550000u, 0x93001550u, "strlen1" },
                { 0x4027F550u, 0x4016645Cu, 0xE1A01005u, 0x93001554u, "f1" },
                { 0x4027F564u, 0x40166FCCu, 0xE0843007u, 0x93001558u, "memcpy" },
                { 0x4027F588u, 0x4016645Cu, 0xE0840000u, 0x9300155Cu, "f2" },
                { 0x4027F5DCu, 0x4040DE74u, 0xE3A02000u, 0x93001560u, "alloc" },
            };
            for (const auto& pr : w232) {
                const uint32_t stub = 0x8F114700u +
                    static_cast<uint32_t>(&pr - &w232[0]) * 0x40u;
                const uint32_t orig = host.MemoryRead32(pr.site);
                const uint32_t imm24 = ((pr.target - pr.site - 8) >> 2) & 0x00FFFFFFu;
                if (orig != (0xEB000000u | imm24)) {
                    LOGE("[W232] unexpected BL at 0x%08X: %08X (want %08X)",
                         pr.site, orig, 0xEB000000u | imm24);
                    continue;
                }
                const uint32_t code[] = {
                    EncodeMOVW(12, pr.cnt & 0xFFFFu), EncodeMOVT(12, pr.cnt >> 16),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // cnt++
                    EncodeMOVW(3, pr.target & 0xFFFFu), EncodeMOVT(3, pr.target >> 16),
                    0xE12FFF33u,                        // blx target
                    pr.disp,                            // displaced site+4
                    0xE51FF004u,                        // ldr pc -> resume
                    pr.site + 8u,                       // resume
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(pr.site, 0xE51FF004u);
                host.MemoryWrite32(pr.site + 4, stub);
                host.InvalidateGuestCode(pr.site, 8);
                host.InvalidateGuestCode(stub, 48);
                host.MemoryWrite32(0x93001790u, 39);  // W447P W232
                LOGI("[W232] %s probe at 0x%08X cnt 0x%08X", pr.name, pr.site, pr.cnt);
            }
        }
        // W246/W62 were retired: Init_BZ passes its initialized bzStartInput
        // directly. Keep the guest's BSI prologue and caller-owned stack intact.
        // W247 (run351): InitMemorySystem entry probe (0x4040F7BC). The
        // call site 0x403DBE7C is already owned by the W100 boot probe, so
        // capture at the callee entry instead: count, the input pointer,
        // input[2] (offset 8 - the alignment field whose garbage forces
        // the error-101 bail) and the memory state at entry.
        {
            const uint32_t w247site = 0x4040F7BCu;
            const uint32_t w247stub = 0x8F114900u;
            const uint32_t o247a = host.MemoryRead32(w247site);
            const uint32_t o247b = host.MemoryRead32(w247site + 4);
            if (o247a == 0xE92D47F0u && o247b == 0xE24DD080u) {
                const uint32_t code[] = {
                    0xE92D100Fu,                    // push {r0-r3,r12}
                    EncodeMOVW(12, 0x0070u), EncodeMOVT(12, 0x9300u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // count++ @0x7DF00070
                    0xE58C0000u,                        // str r0,[r12] input ptr (overwrites count)
                    0xE5903008u,                        // ldr r3,[r0,#8]
                    0xE58C3008u,                        // str r3,[r12,#8] @0x7DF00078 input[2]
                    EncodeMOVW(3, 0x3DC4u), EncodeMOVT(3, 0x406Eu),
                    0xE5933000u,                        // r3 = bzgMemory_system_state
                    0xE58C300Cu,                        // str r3,[r12,#0xC] @0x7DF0007C state-in
                    0xE8BD100Fu,                    // pop {r0-r3,r12}
                    0xE92D47F0u,                    // displaced push {r4-r7,lr}
                    0xE24DD080u,                    // displaced sub sp,sp,#0x80
                    0xE51FF004u,                    // ldr pc -> resume
                    w247site + 8u,                  // resume 0x4040F7C4
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w247stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w247site, 0xE51FF004u);
                host.MemoryWrite32(w247site + 4, w247stub);
                host.InvalidateGuestCode(w247site, 8);
                host.InvalidateGuestCode(w247stub, 96);
                host.MemoryWrite32(0x93001790u, 38);  // W447P W247
                LOGI("[W247] InitMemorySystem entry probe at 0x%08X", w247site);
            } else {
                LOGE("[W247] unexpected words at 0x%08X: %08X/%08X",
                     w247site, o247a, o247b);
            }
        }
        // W245 (run349): force bzgMemory_system_state = 1. The boot sets
        // gBeelzebub_Initialised=1 before ANY LLMemAllocate call, so the
        // allocator's early check (state==0 -> return NULL) fired and every
        // LLMemAllocate returned NULL (W237: mstate=0 res=00000000 while the
        // malloc-based trace allocs kept working). With state=1 and the
        // zero-initialised pool tables, every size takes the proven
        // LABEL_22 malloc fallback (the same path all >0x1FF allocs use).
        {
            host.MemoryWrite32(0x406E3DC4u, 1u);
            host.InvalidateGuestCode(0x406E3DC4u, 4);
            host.MemoryWrite32(0x93001790u, 37);  // W447P W245
            LOGI("[W245] bzgMemory_system_state forced to 1");
        }
        // W313 (run415): install the default file-IO hooks BEFORE any
        // WAD/config read. bz_fread (0x40881C) calls the read hook at
        // 0x6DA9D4 UNCONDITIONALLY; the slot is zero until
        // InitFileSystem (0x4082E0) copies the default table from
        // 0x406732A0 -- and under the bridge the first bz_fread inside
        // the bz_StartInternal chain ran BEFORE that (run414: BLX 0
        // walked into the trap page and the game thread "cleanly"
        // returned PC=0x8 200 ms after launch, W84APP lr=40408844).
        // Call InitFileSystem directly: it also clears the AllFiles
        // list and inits the file-system mutex, all safe pre-thread.
        // W313c (run415b): the full InitFileSystem run died inside
        // PDFileSystemInit under the bridge (hooks stayed zero), so
        // replicate its two data steps host-side: copy the default
        // hook table (0x406732A0, 35 relocated pointers) over the
        // slot globals 0x6DA980..0x6DAA08 exactly the way
        // bz_InstallFileIOHooks would (non-zero members only). A zero
        // read hook made the first bz_fread BLX into the trap page.
        {
            for (int i = 0; i < 35; ++i) {
                const uint32_t v = host.MemoryRead32(0x406732A0u + static_cast<uint32_t>(i) * 4u);
                if (v) host.MemoryWrite32(0x406DA980u + static_cast<uint32_t>(i) * 4u, v);
            }
            const uint32_t hook_read = host.MemoryRead32(0x406DA9D4u);
            host.MemoryWrite32(0x93001790u, 36);  // W447P W313
            LOGI("[W313] default hooks copied: read=%08X open=%08X",
                 hook_read, host.MemoryRead32(0x6DA984u));
            if (!hook_read)
                LOGE("[W313] read hook zero after table copy!");
        }
        // W314 (run416): guard the bz_fread read-hook call itself.
        // bz_WADFile_SysClose / ~CINodeSystem re-run bz_InstallFileIOHooks
        // with empty tables and can zero 0x6DA9D4 mid-boot; the next
        // bz_fread then BLXes 0 and the thread walks into the trap page
        // (run414/415/416: W84APP lr=40408844, "clean" PC=0x8 exit).
        // Patch 0x408840 (BLX R12): skip the call and force R0=0 when the
        // hook is dead -- bz_fread then takes its own (always valid) read
        // path. Displaced CMP R0,#0 + BNE are re-emitted in the stub.
        {
            const uint32_t w314site = 0x40408840u;
            const uint32_t w314stub = 0x8F115380u;
            ClaimStub(w314stub, 40, "W314");
            if (host.MemoryRead32(w314site) == 0xE12FFF3Cu) {
                const uint32_t code[] = {
                    0xE35C0000u,                    // cmp r12,#0
                    0x0A000001u,                    // beq zero_path
                    0xE12FFF3Cu,                    // blx r12 (displaced)
                    0xEA000000u,                    // b converge
                    0xE3A00000u,                    // zero_path: mov r0,#0
                    0xE3500000u,                    // converge: cmp r0,#0 (displaced)
                    0x151FF004u,                    // ldrne pc,[pc,#-4]
                    0x404088F4u,                    //   taken -> 0x4088F4
                    0xE51FF004u,                    // ldr pc,[pc,#-4]
                    0x4040884Cu,                    //   not taken -> 0x40884C
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w314stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w314site, 0xE51FF004u);
                host.MemoryWrite32(w314site + 4, w314stub);
                host.InvalidateGuestCode(w314site, 8);
                host.InvalidateGuestCode(w314stub, sizeof(code));
                host.MemoryWrite32(0x93001790u, 35);  // W447P W314
                LOGI("[W314] bz_fread hook guard installed at 0x%08X", w314site);
            } else {
                LOGE("[W314] unexpected word at 0x%08X: %08X (want E12FFF3C)",
                     w314site, host.MemoryRead32(w314site));
            }
        }
        // W317 (run420): guard the loading-service callback call.
        // bz_LoadingScreen_LoadingService (0x4047CA58) does BLX R7 with
        // R7 = gLoading_service (0x407A955C); that .bss slot is found
        // (run418/419: 0x4066A5DC, a .data.rel.ro table address) and the
        // call executes pointer tables as code, killing the game thread
        // mid bz_File_Read. A legit service fn lives in main-image
        // .text (< 0x40600000); anything >= 0x40600000 is garbage --
        // skip the call. Displaced CMP R4,#0 + BNE re-emitted here.
        {
            const uint32_t w317site = 0x4047CAC4u;
            const uint32_t w317stub = 0x8F115400u;
            ClaimStub(w317stub, 48, "W317");
            if (host.MemoryRead32(w317site) == 0xE12FFF37u) {
                const uint32_t code[] = {
                    EncodeMOVW(3, 0x0000u), EncodeMOVT(3, 0x406u),   // r3 = 0x40600000
                    0xE1570003u,                    // cmp r7, r3
                    0x2A000000u,                    // bhs skip (service ptr is garbage)
                    0xE12FFF37u,                    // blx r7 (displaced)
                    0xE3540000u,                    // skip: cmp r4,#0 (displaced)
                    0x151FF004u,                    // ldrne pc,[pc,#-4]
                    0x4047CADCu,                    //   taken -> 0x4047CADC
                    0xE51FF004u,                    // ldr pc,[pc,#-4]
                    0x4047CAC8u,                    //   not taken -> 0x4047CAC8
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w317stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w317site, 0xE51FF004u);
                host.MemoryWrite32(w317site + 4, w317stub);
                host.InvalidateGuestCode(w317site, 8);
                host.InvalidateGuestCode(w317stub, 48);
                host.MemoryWrite32(0x93001790u, 34);  // W447P W317
                LOGI("[W317] loading-service guard installed at 0x%08X", w317site);
            } else {
                LOGE("[W317] unexpected word at 0x%08X: %08X (want E12FFF37)",
                     w317site, host.MemoryRead32(w317site));
            }
        }
        // W318 retired: this throw suppressor hid failed file callbacks and
        // returned an uninitialized U16. Preserve the original error path.
        // bz_fread throws when the 1-byte probe read fails with
        // ftell != GetLength
        // (inconsistent stream) -- and the guest C++ unwind under the JIT
        // POPs a garbage PC and kills the whole game thread
        // (run418-420: pc=0x4066A5DC). Patch the throw entry (0x40408908,
        // MOV R0,#4) into a stub that captures the bzFile state and
        // returns 0 quietly -- the exact loc_4088FC epilogue.
        if (false) { // retired diagnostic stub; never patch __cxa_throw
            const uint32_t w318site = 0x40408908u;
            const uint32_t w318stub = 0x8F115600u;
            ClaimStub(w318stub, 128, "W318");
            if (host.MemoryRead32(w318site) == 0xE3A00004u) {
                const uint32_t code[] = {
                    0xE92D100Fu,                    // push {r0-r3,r12}
                    EncodeMOVW(12, 0x06D0u), EncodeMOVT(12, 0x9000u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // count++ @0x93000210
                    0xE58C5004u,                    // str r5,[r12,#4] bzFile (a4)
                    0xE59A3000u, 0xE58C3008u,       // f[0x00] -> 0x93000218
                    0xE59A3004u, 0xE58C300Cu,       // f[0x04] -> 0x9300021C
                    0xE59A3008u, 0xE58C3010u,       // f[0x08] -> 0x93000220
                    0xE59A300Cu, 0xE58C3014u,       // f[0x0C] -> 0x93000224
                    0xE59A3010u, 0xE58C3018u,       // f[0x10] -> 0x93000228
                    0xE59A3014u, 0xE58C301Cu,       // f[0x14] -> 0x9300022C
                    0xE59A3018u, 0xE58C3020u,       // f[0x18] -> 0x93000230
                    0xE59A301Cu, 0xE58C3024u,       // f[0x1C] -> 0x93000234
                    0xE59D3024u, 0xE58C3028u,       // [sp+0x24] caller LR -> 0x93000238
                    0xE59A3020u, 0xE58C3030u,       // f[0x20] -> 0x93000240
                    0xE59A3024u, 0xE58C3034u,       // f[0x24] -> 0x93000244
                    0xE59A3028u, 0xE58C3038u,       // f[0x28] -> 0x93000248
                    0xE59A302Cu, 0xE58C303Cu,       // f[0x2C] -> 0x9300024C
                    0xE59A3030u, 0xE58C3040u,       // f[0x30] -> 0x93000250
                    0xE59A3034u, 0xE58C3044u,       // f[0x34] -> 0x93000254
                    0xE59A3038u, 0xE58C3048u,       // f[0x38] -> 0x93000258
                    0xE59A303Cu, 0xE58C304Cu,       // f[0x3C] -> 0x9300025C
                    0xE28CC070u,                    // add r12,r12,#0x70 -> 0x93000280
                    0xE3A02014u,                    // mov r2,#20
                    0xE49D3004u,                    // loop: ldr r3,[sp],#4
                    0xE48C3004u,                    // str r3,[r12],#4
                    0xE2522001u,                    // subs r2,r2,#1
                    0x1AFFFFFCu,                    // bne loop
                    0xE8BD100Fu,                    // pop {r0-r3,r12}
                    0xE3A00000u,                    // mov r0,#0 (quiet EOF)
                    0xE28DD010u,                    // add sp,sp,#0x10
                    0xE8BD81F0u,                    // pop {r4-r8,pc}
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w318stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w318site, 0xE51FF004u);
                host.MemoryWrite32(w318site + 4, w318stub);
                host.InvalidateGuestCode(w318site, 8);
                host.InvalidateGuestCode(w318stub, 224);
                host.MemoryWrite32(0x93001790u, 33);  // W447P W318
                LOGI("[W318] throw-guard installed at 0x%08X", w318site);
            } else {
                LOGE("[W318] unexpected word at 0x%08X: %08X (want E3A00004)",
                     w318site, host.MemoryRead32(w318site));
            }
        }
        // W319 (run422): name the WAD member that fails to open.
        // BZ::Content::GetWADAppData (0x403F8328) does
        // bz_File_Open(name,"rb") and got 0xFFFFFFFF -- a non-NULL
        // garbage handle that flows into bz_File_Seek/ReadU16 and dies
        // in the read hooks. Capture the requested name at entry.
        {
            const uint32_t w319site = 0x403F8328u;
            const uint32_t w319stub = 0x8F115500u;
            ClaimStub(w319stub, 64, "W319");
            const uint32_t o319a = host.MemoryRead32(w319site);
            const uint32_t o319b = host.MemoryRead32(w319site + 4);
            if (o319a == 0xE92D4070u && o319b == 0xE1A06001u) {
                const uint32_t code[] = {
                    0xE92D100Fu,                    // push {r0-r3,r12}
                    EncodeMOVW(12, 0x0790u), EncodeMOVT(12, 0x9000u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // count++ @0x90000790
                    0xE58C0004u,                    // str r0,[r12,#4] name ptr
                    0xE5903000u, 0xE58C3008u,       // name[0..3]
                    0xE5903004u, 0xE58C300Cu,       // name[4..7]
                    0xE8BD100Fu,                    // pop {r0-r3,r12}
                    0xE92D4070u,                    // displaced push {r4-r6,lr}
                    0xE1A06001u,                    // displaced mov r6,r1
                    0xE51FF004u,                    // ldr pc -> resume
                    w319site + 8u,                  // resume 0x403F8330
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w319stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w319site, 0xE51FF004u);
                host.MemoryWrite32(w319site + 4, w319stub);
                host.InvalidateGuestCode(w319site, 8);
                host.InvalidateGuestCode(w319stub, 64);
                host.MemoryWrite32(0x93001790u, 32);  // W447P W319
                LOGI("[W319] GetWADAppData entry probe at 0x%08X", w319site);
            } else {
                LOGE("[W319] unexpected words at 0x%08X: %08X/%08X",
                     w319site, o319a, o319b);
            }
        // W323 (run428): name the WAD whose parse dies.
        // _WAD_ParseWADFile (0x4041442C) is the ReadU16 caller whose
        // member descriptor fills with trap-page words. Capture the path.
        {
            const uint32_t w323site = 0x4041442Cu;
            const uint32_t w323stub = 0x8F115700u;
            ClaimStub(w323stub, 64, "W323");
            const uint32_t o323a = host.MemoryRead32(w323site);
            const uint32_t o323b = host.MemoryRead32(w323site + 4);
            if (o323a == 0xE92D47F0u && o323b == 0xE1A04001u) {
                const uint32_t code[] = {
                    0xE92D100Fu,                    // push {r0-r3,r12}
                    EncodeMOVW(12, 0x07C0u), EncodeMOVT(12, 0x9000u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // count++ @0x900007C0
                    0xE58C0004u,                    // str r0,[r12,#4] path
                    0xE5903000u, 0xE58C3008u,       // path[0..3]
                    0xE5903004u, 0xE58C300Cu,       // path[4..7]
                    0xE8BD100Fu,                    // pop {r0-r3,r12}
                    0xE92D4FF0u,                    // displaced push {r4-r10,lr}
                    0xE1A04001u,                    // displaced mov r4,r1
                    0xE51FF004u,                    // ldr pc -> resume
                    w323site + 8u,                  // resume 0x40414434
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w323stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w323site, 0xE51FF004u);
                host.MemoryWrite32(w323site + 4, w323stub);
                host.InvalidateGuestCode(w323site, 8);
                host.InvalidateGuestCode(w323stub, 64);
                host.MemoryWrite32(0x93001790u, 31);  // W447P W323
                LOGI("[W323] ParseWADFile entry probe at 0x%08X", w323site);
            } else {
                LOGE("[W323] unexpected words at 0x%08X: %08X/%08X",
                     w323site, o323a, o323b);
            }
        // W324 (run429): capture bz_File_Open's result INSIDE the WAD
        // parse (0x40414448, SUBS R5,R0,#0). The parser's member
        // descriptor held reads from [NULL+4]/[NULL+8] (trap words), i.e.
        // the WAD context is NULL -- this names the open that failed.
        {
            const uint32_t w324site = 0x40414448u;
            const uint32_t w324stub = 0x8F115800u;
            ClaimStub(w324stub, 48, "W324");
            if (host.MemoryRead32(w324site) == 0xE2505000u) {
                const uint32_t code[] = {
                    0xE92D100Fu,                    // push {r0-r3,r12}
                    EncodeMOVW(12, 0x07A0u), EncodeMOVT(12, 0x9000u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // count++ @0x900007A0
                    0xE58C0004u,                    // str r0,[r12,#4] opened file
                    0xE8BD100Fu,                    // pop {r0-r3,r12}
                    0xE2505000u,                    // displaced rsbs r5,r0,#0
                    0x01A00005u,                    // displaced moveq r0,r5
                    0xE51FF004u,                    // ldr pc -> resume
                    w324site + 8u,                  // resume after both displaced instructions
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w324stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w324site, 0xE51FF004u);
                host.MemoryWrite32(w324site + 4, w324stub);
                host.InvalidateGuestCode(w324site, 8);
                host.InvalidateGuestCode(w324stub, 48);
                host.MemoryWrite32(0x93001790u, 30);  // W447P W324
                LOGI("[W324] ParseWADFile open-result probe at 0x%08X", w324site);
            } else {
                LOGE("[W324] unexpected word at 0x%08X: %08X (want E2505000)",
                     w324site, host.MemoryRead32(w324site));
            }
        // W326 (run434): retain a bounded ring of bz_File_Open path pointers.
        // The single last-path cell often gets overwritten by unrelated UI
        // loads before the diagnostic sampler runs; this ring lets us see
        // which guest content requests actually occurred without changing
        // guest file lookup or return values.
        {
            const uint32_t w326site = 0x40407ACCu;
            const uint32_t w326stub = 0x8F115900u;
            ClaimStub(w326stub, 80, "W326");
            const uint32_t o326a = host.MemoryRead32(w326site);
            const uint32_t o326b = host.MemoryRead32(w326site + 4);
            if (o326a == 0xE92D4070u && o326b == 0xE24DDF42u) {
                const uint32_t code[] = {
                    0xE92D100Fu,                    // push {r0-r3,r12}
                    EncodeMOVW(12, 0x07B0u), EncodeMOVT(12, 0x9000u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // count++ @0x900007B0
                    0xE59C2000u,                    // ldr r2,[r12] count
                    0xE202200Fu,                    // and r2,r2,#15
                    0xE28C1040u,                    // add r1,r12,#64 (ring @0x900007F0)
                    0xE7810102u,                    // str r0,[r1,r2,lsl #2]
                    0xE58C0004u,                    // str r0,[r12,#4] path ptr
                    0xE5903000u, 0xE58C3008u,       // path[0..3]
                    0xE5903004u, 0xE58C300Cu,       // path[4..7]
                    0xE8BD100Fu,                    // pop {r0-r3,r12}
                    0xE92D4070u,                    // displaced push {r4-r6,lr}
                    0xE24DDF42u,                    // displaced sub sp,sp,#0x108
                    0xE51FF004u,                    // ldr pc -> resume
                    w326site + 8u,                  // resume 0x40407AD4
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w326stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w326site, 0xE51FF004u);
                host.MemoryWrite32(w326site + 4, w326stub);
                host.InvalidateGuestCode(w326site, 8);
                host.InvalidateGuestCode(w326stub, 80);
                host.MemoryWrite32(0x93001790u, 29);  // W447P W326
                LOGI("[W326] bz_File_Open entry probe at 0x%08X", w326site);
            } else {
                LOGE("[W326] unexpected words at 0x%08X: %08X/%08X",
                     w326site, o326a, o326b);
            }
        // W364 (run488): patch GOT base 0x4066E988 with BX LR.
        // The glue wild-jumps here (a DRO callback pointer holds
        // &GOT instead of *GOT); the GOT data as ARM code is UNDEF,
        // killing the thread. Patch = any jump there returns with
        // R0=0 immediately.
        host.MemoryWrite32(0x4066E988u, 0xE3A00000u);
        host.MemoryWrite32(0x4066E98Cu, 0xE12FFF1Eu);
        host.InvalidateGuestCode(0x4066E988u, 8);

        // W329 (run440): capture the WAD member-open hook's name struct.
        // The WAD read hook (sub_415858) falls back to Android_fread when
        // file->[24] (the WAD entry ptr) is NULL = the member lookup
        // failed; the member descriptor then serves trap-page words and
        // every read throws. sub_414F84 (slot+2, the open hook) receives
        // the name struct in R0 and checks byte [0x10] first.
        {
            const uint32_t w329site = 0x40414F84u;
            const uint32_t w329stub = 0x8F115A00u;
            ClaimStub(w329stub, 64, "W329");
            const uint32_t o329a = host.MemoryRead32(w329site);
            const uint32_t o329b = host.MemoryRead32(w329site + 4);
            if (o329a == 0xE5D02010u && o329b == 0xE3520000u) {
                const uint32_t code[] = {
                    0xE92D100Fu,                    // push {r0-r3,r12}
                    EncodeMOVW(12, 0x07D0u), EncodeMOVT(12, 0x9000u),
                    0xE59C3000u, 0xE2833001u, 0xE58C3000u,   // count++ @0x900007D0
                    0xE58C0004u,                    // str r0,[r12,#4] struct ptr
                    0xE5903000u, 0xE58C3008u,       // s[0]
                    0xE5903004u, 0xE58C300Cu,       // s[4]
                    0xE5903010u, 0xE58C3010u,       // s[0x10]
                    0xE5903014u, 0xE58C3014u,       // s[0x14]
                    0xE8BD100Fu,                    // pop {r0-r3,r12}
                    0xE5D02010u,                    // displaced ldrb r2,[r0,#0x10]
                    0xE3520000u,                    // displaced cmp r2,#0
                    0xE51FF004u,                    // ldr pc -> resume
                    w329site + 8u,                  // resume 0x40414F8C
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w329stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w329site, 0xE51FF004u);
                host.MemoryWrite32(w329site + 4, w329stub);
                host.InvalidateGuestCode(w329site, 8);
                host.InvalidateGuestCode(w329stub, 72);
                host.MemoryWrite32(0x93001790u, 24);  // W447P W329
                LOGI("[W329] WAD open-hook probe at 0x%08X", w329site);
            } else {
                LOGE("[W329] unexpected words at 0x%08X: %08X/%08X",
                     w329site, o329a, o329b);
            }
        // W334 (run447): guard bz_fread's FILE POINTER. AllocateFile()
        // hands out slots ONLY from AllFiles (0x406D9780..+0x1180). A
        // call with file=NULL/garbage (W270: r3=0; its fields read trap
        // words) previously walked hook-fallback chains into wild jumps.
        // Intercept at the entry: implausible file -> quiet return 0.
        {
            const uint32_t w334site = 0x4040881Cu;
            const uint32_t w334stub = 0x8F115B00u;
            ClaimStub(w334stub, 64, "W334");
            const uint32_t o334 = host.MemoryRead32(w334site + 4);
            if (o334 == 0xE92D41F0u) {
                const uint32_t code[] = {
                    EncodeMOVW(12, 0x9780u), EncodeMOVT(12, 0x406Du), // r12=0x406D9780
                    0xE153000Cu,                    // cmp r3,r12
                    0x3A000001u,                    // blo fail
                    EncodeMOVW(12, 0xA900u), EncodeMOVT(12, 0x406Eu), // r12=0x406EA900
                    0xE153000Cu,                    // cmp r3,r12
                    0x3A000001u,                    // blo ok
                    0xE3A00000u,                    // fail: mov r0,#0
                    0xE12FFF1Eu,                    // bx lr (caller sees 0)
                    EncodeMOVW(12, 0x6974u), EncodeMOVT(12, 0x26u),   // ok: r12=delta 0x266974
                    0xE92D41F0u,                    // displaced push {r4-r8,lr}
                    0xE51FF004u,                    // ldr pc -> resume
                    w334site + 8u,                  // resume 0x40408824 (W270 probe)
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w334stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w334site, 0xE51FF004u);
                host.MemoryWrite32(w334site + 4, w334stub);
                host.InvalidateGuestCode(w334site, 8);
                host.InvalidateGuestCode(w334stub, 64);
                host.MemoryWrite32(0x93001790u, 23);  // W447P W334
                LOGI("[W334] bz_fread file-pointer guard installed at 0x%08X", w334site);
            } else {
                LOGE("[W334] unexpected word at 0x%08X+4: %08X (want E92D41F0)",
                     w334site, o334);
            }
        }
        }
        }
        }
        }
        }
        // W233 (run340): pre-fill BZ::Material::mCommon_loading_directory
        // (0x406C876C) with "Textures\\". The Material-dir body reads this
        // static buffer for its strlen; without a prior build the buffer is
        // empty, strlen=0, and the whole dir registration degenerates into
        // an empty string (the CleanPath/ReplaceSearch cascade death).
        {
            const uint32_t mcl = 0x406C876Cu;
            host.MemoryWrite32(mcl, 0x74786554u);        // "Text"
            host.MemoryWrite32(mcl + 4, 0x73657275u);    // "ures"
            host.MemoryWrite32(mcl + 8, 0x0000005Cu);    // "\0\0\0"
            host.InvalidateGuestCode(mcl, 16);
            host.MemoryWrite32(0x93001790u, 22);  // W447P W233
            LOGI("[W233] mCommon_loading_directory pre-filled with Textures\\");
        }
        // W122 (run170): the boot quits cleanly ~6 ms after PDStartup_3 with
        // R0=0x30; the W120 probes bracket it to the bzd_InitEntireDynamics
        // System call (0x403DC0B8 BL 0x402160C4, result-checked at 0x403DC0BC
        // CMP R0,#0). Probe the call and CAPTURE ITS RETURN VALUE; the
        // W40PCS line also prints the W51b pool-arg snapshots.
        {
            const uint32_t w122site = 0x403DC0B8;
            const uint32_t w122stub = 0x8F111800u;  // W166: gap (0x65E4xx) gets stomped with float constants by guest init; bridge window is safe
            const uint32_t cnt_called = 0x00010040u;  // W131 fixed window
            const uint32_t cnt_ret = 0x00010044u;
            g_w122_counter_addr = cnt_called;
            const uint32_t orig = host.MemoryRead32(w122site);
            if (!kW196CleanSlate && orig == 0xEBF8E801u) {
                // W169 (run229): store the blx target (r3) into 0x00010048
                // immediately before the jump. The W124 probe-0 stub showed
                // the same pattern (literal correct at all ticks, blx still
                // went to 0x00E59F30) -- this names the real jump target at
                // execution time. Array grew to 14 words; the tgt literal
                // moved to idx 14 (S+56), ldr offset 24->28.
                // W171 (run233): NO PC-relative literal at all. The literal
                // loads were observed returning byte-shifted stub-encoding
                // garbage on first execution (0x49C000E3 = reversed
                // EncodeMOVW bytes; 0x00E59F30 earlier). The target now
                // travels as MOVW/MOVT immediates -- nothing to misread.
                const uint32_t code[] = {
                    EncodeMOVW(12, cnt_called & 0xFFFFu), EncodeMOVT(12, cnt_called >> 16),
                    0xE59C3000u,          // ldr r3,[r12]
                    0xE2833001u,          // add r3,r3,#1
                    0xE58C3000u,          // str r3,[r12]
                    EncodeMOVW(3, 0x60C4u), EncodeMOVT(3, 0x4021u),
                                          // r3 = 0x402160C4 (bzd) as immediates
                    0xE58C3008u,          // str r3,[r12,#8]  W169: blx target
                    0xE12FFF33u,          // blx r3
                    EncodeMOVW(12, cnt_ret & 0xFFFFu), EncodeMOVT(12, cnt_ret >> 16),
                    0xE58C0000u,          // str r0,[r12]      ; bzd return value
                    0xE3500000u,          // cmp r0,#0         (displaced site+4)
                    0xE51FF004u,          // ldr pc,[pc,#-4]   -> resume
                    w122site + 8,         // resume
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w122stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w122site, 0xE51FF004u);
                host.MemoryWrite32(w122site + 4, w122stub);
                host.InvalidateGuestCode(w122site, 8);
                host.InvalidateGuestCode(w122stub, 64);  // W170: drop stale JIT blocks over the freshly written stub
                host.MemoryWrite32(0x93001790u, 21);  // W447P W122
                LOGI("[W122] bzd call probe at 0x%08X -> stub 0x%08X", w122site, w122stub);
            } else {
                LOGE("[W122] unexpected word at 0x%08X: 0x%08X", w122site, orig);
            }
        }
        // W124 (run172): bzd_InitEntireDynamicsSystem returns 14 and the
        // guest retries it billions of times. Probe each D_* call site
        // (site=BL D_x, site+4=CMP R0,#0, site+8=BEQ): the counter that
        // stops advancing names the failing step. Counters are u32 and wrap
        // (fine -- the zero-or-low one is the answer).
        {
            struct W124Site { uint32_t site, target; };
            const W124Site w124[] = {
                { 0x402160EC, 0x40222FD0, },  // D_InitialiseDynamicsObjectManager
                { 0x402160F8, 0x401F7680, },  // D_InitCoreMechanics
                { 0x40216104, 0x4023D1BC, },  // D_InitVolumes
                { 0x40216110, 0x4022DC50, },  // D_InitMediums
                { 0x4021611C, 0x4022A668, },  // D_InitProgrammedBehaviours
                { 0x40216128, 0x402289E0, },  // D_InitPredefinedBehaviours
                { 0x40216134, 0x40230188, },  // D_InitSubstances
                { 0x40216140, 0x40220FA0, },  // D_InitObjectPool
                { 0x4021614C, 0x40235788, },  // D_InitVehicleModule
            };
            const uint32_t cnt_base = 0x00010050u;  // W131 fixed window
            g_w124_counter_addr = cnt_base;
            // W155 (run203): each stub also snapshots the first NONZERO
            // return of its D_* into 0x000100C0 + i*8 ([ret, hit]). bzd's
            // fail epilogue passes r0 through, so the returning-14 step is
            // named directly. 17 words per stub now (step 72).
            uint32_t stub = 0x8F111000u;  // W162: relocated out of the 0x65D8xx gap (guest copy-stomps it); 9*88=792
            // W164 (run224): probe 0 DISABLED for this run -- the D_1 site
            // stays UNPATCHED. If the glue-thread death at 0xE59F30 persists
            // without any probe on the D_1 call site, the probe infra is
            // exonerated and D_1's body genuinely dies; if it vanishes, the
            // W124 stub machinery itself is implicated.
            bool w164_skip_probe0 = true;
            uint32_t w155_idx = 0;
            for (const auto& pr : w124) {
                if (w164_skip_probe0 || kW196CleanSlate) {
                    host.MemoryWrite32(0x93001790u, 20);  // W447P W164
                    LOGI("[W164] probe %u (site 0x%08X) left UNPATCHED",
                         w155_idx, pr.site);
                    stub += 88;
                    ++w155_idx;
                    continue;
                }
                const uint32_t orig = host.MemoryRead32(pr.site);
                const uint32_t imm24 = ((pr.target - pr.site - 8) >> 2) & 0x00FFFFFFu;
                const uint32_t next = host.MemoryRead32(pr.site + 4);
                if (orig != (0xEB000000u | imm24) || next != 0xE3500000u) {
                    LOGE("[W124] unexpected words at 0x%08X: 0x%08X/0x%08X",
                         pr.site, orig, next);
                    continue;
                }
                const uint32_t w155cells =
                    0x000100C0u + w155_idx * 8u;
                // W171 retrofit: targets travel as MOVW/MOVT immediates --
                // NO PC-relative literal loads (they returned byte-shifted
                // garbage on first execution). 22 words, stride 88 kept.
                const uint32_t code[] = {
                    EncodeMOVW(12, (cnt_base + static_cast<uint32_t>(&pr - &w124[0]) * 4) & 0xFFFFu),
                    EncodeMOVT(12, (cnt_base + static_cast<uint32_t>(&pr - &w124[0]) * 4) >> 16),
                    0xE59C3000u,          // ldr r3,[r12]
                    0xE2833001u,          // add r3,r3,#1
                    0xE58C3000u,          // str r3,[r12]
                    EncodeMOVW(3, pr.target & 0xFFFFu), EncodeMOVT(3, pr.target >> 16),
                    0xE1A01003u,          // mov r1,r3       W161b: save blx target
                    0xE12FFF33u,          // blx r3            ; lr = S+36
                    0xE3500000u,          // cmp r0,#0         W155: failure?
                    0x0A000008u,          // beq -> idx 19
                    EncodeMOVW(3, w155cells & 0xFFFFu), EncodeMOVT(3, w155cells >> 16),
                    0xE5830000u,          // str r0,[r3]       last nonzero ret
                    0xE3A0C001u,          // mov r12,#1
                    0xE58C1004u,          // str r12,[r3,#4]   hit flag
                    EncodeMOVW(3, 0x035Cu), EncodeMOVT(3, 0x9000u),
                    0xE5831000u,          // str r1,[r3]       W161b: blx target seen
                    next,                 // cmp r0,#0         (displaced site+4)
                    0xE51FF004u,          // ldr pc,[pc,#-4]   -> resume site+8
                    pr.site + 8,          // resume (BEQ stays in place)
                };
                static_assert(sizeof(code) == 88, "W124-v4 stub layout drift");
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(pr.site, 0xE51FF004u);
                host.MemoryWrite32(pr.site + 4, stub);
                // W161: the stub region held zeros (file gap) that the JIT may
                // have already translated from an earlier stray fetch -- drop
                // any cached block covering the freshly written stub.
                host.InvalidateGuestCode(stub, 88);
                host.InvalidateGuestCode(pr.site, 8);
                stub += 88;
                ++w155_idx;
            }
            host.MemoryWrite32(0x93001790u, 19);  // W447P W124
            LOGI("[W124] %zu dynamics probes installed, counters at 0x%08X",
                 sizeof(w124) / sizeof(w124[0]), cnt_base);
            // W162 (run221): 50 ms host watcher on both the OLD literal cell
            // (0x65D850, the stomp victim) and the NEW one (0x00011050). Logs
            // every value transition into the persist ring so the stomp
            // window and its author can be timed against boot markers.
            {
                DynarmicHost* h = &host;
                std::thread([h] {
                    // W163 v2: heal the WHOLE JUMP_SLOT GOT region
                    // (0x66E988..0x66EFA8 = 392 function pointers incl.
                    // malloc_ptr/free_ptr/memset_ptr and the PD table
                    // siblings). Snapshot is taken here, after relocation;
                    // any later divergence (the 0x00E59F30 byte-shifted
                    // garbage that kills the boot thread's indirect calls)
                    // is restored within 50 ms. Function-pointer-only region:
                    // healing can never corrupt mutable globals.
                    constexpr uint32_t kGotBase = 0x66E988u;
                    constexpr size_t kGotWords = 392;
                    static uint32_t got_snap[kGotWords];
                    for (size_t i = 0; i < kGotWords; ++i)
                        got_snap[i] = h->MemoryRead32(kGotBase + 4u * i);

                    // W348 (run458): the REAL guest GOT lives at
                    // 0x4066E988 (= 0x66E988 + 0x40000000 image base); the
                    // got_snap above reads the BASELESS 0x66E988 (low
                    // bridge page, zeros) so the actual import slots were
                    // never healed. Snapshot the true GOT + the
                    // .data.rel.ro function-pointer region; restore any
                    // drift every 50 ms tick (the 500 ms W336 tick was too
                    // slow: the glue died BETWEEN ticks jumping INTO the
                    // AAsset_close GOT slot, run447/457 W84APP
                    // pc=0x4066E98C).
                    constexpr uint32_t kTrueGotBase = 0x4066E988u;
                    static uint32_t true_got_snap[kGotWords];
                    for (size_t i = 0; i < kGotWords; ++i)
                        true_got_snap[i] = h->MemoryRead32(kTrueGotBase + 4u * i);
                    constexpr uint32_t kDroBase = 0x4066A000u;
                    constexpr size_t kDroWords = 0x2400u;
                    static uint32_t dro_snap[kDroWords];
                    for (size_t i = 0; i < kDroWords; ++i)
                        dro_snap[i] = h->MemoryRead32(kDroBase + 4u * i);
                    static const uint32_t slots[5][2] = {
                        {0x40673334u, 0x403F5FD4u}, {0x40673338u, 0x403F5FD8u},
                        {0x4067333Cu, 0x403F5FE0u}, {0x40673340u, 0x403F5FE4u},
                        {0x40673344u, 0x403F5FE8u},
                    };
                    uint32_t po = 0, pn = 0;
                    bool w178_done = false;
                    for (int i = 0; i < 2400; ++i) {  // 120 s at 50 ms
                        // W178: pre-create fast-path pool 76 (0x4C) once the
                        // guest memory system is up. bz_AR_AddSessionType's
                        // allocation fast-path needs [0x406DC988] != 0; the
                        // lazy fallback never succeeds under the bridge.
                        // W182: pool 76 (0x4C) never gets created under the
                        // bridge (the guest's lazy creation deadlocks on
                        // alloc_critical_section against the spinning boot
                        // thread). Construct the descriptor + bunch entirely
                        // HOST-side (no guest execution, no locks) and
                        // publish: fast-path entry 0x406DC988 + id-slot
                        // 0x406DB210. Trigger: 50 s into the hang with the
                        // entry still zero.
                        if (!w178_done) {
                            const uint32_t st = h->MemoryRead32(0x406E3DC4u);
                            const uint32_t ent = h->MemoryRead32(0x406DC928u);
                            if (st >= 1 && ent == 0) {
                                // fire AS SOON as the memory system is up --
                                // bz_AR_AddSessionType needs the pool by ~15 s
                                w178_done = true;
                                const uint32_t elem = 0x4Cu, align = 0x20u, count = 64u;
                                const uint32_t aelem = (elem + align - 1) & ~(align - 1);   // 0x60
                                const uint32_t stride = (((align + 7 + aelem) & ~(align - 1)) + 3u) & ~3u; // 0x80
                                const uint32_t bunch = h->GuestAlloc(stride * count, align);
                                const uint32_t desc = h->GuestAlloc(0x2Cu, 4u);
                                for (uint32_t k = 0; k + 1 < count; ++k)
                                    h->MemoryWrite32(bunch + k * stride, bunch + (k + 1) * stride);
                                h->MemoryWrite32(bunch + (count - 1) * stride, 0);
                                h->MemoryWrite32(desc + 0x00u, count);
                                h->MemoryWrite32(desc + 0x04u, aelem);
                                h->MemoryWrite32(desc + 0x08u, stride);
                                h->MemoryWrite32(desc + 0x0Cu, count);
                                h->MemoryWrite32(desc + 0x10u, 0u);
                                h->MemoryWrite32(desc + 0x14u, bunch);
                                h->MemoryWrite32(desc + 0x18u, bunch);
                                h->MemoryWrite32(desc + 0x1Cu, 0u);
                                h->MemoryWrite32(desc + 0x20u, 0u);
                                h->MemoryWrite32(desc + 0x24u, align);
                                h->MemoryWrite32(desc + 0x28u, 0u);
                                h->MemoryWrite32(0x406DC928u, desc);
                                h->MemoryWrite32(0x406DB210u, desc);
                                char wb[160];
                                snprintf(wb, sizeof(wb),
                                         "W182 pool 76 built: desc=%08X bunch=%08X "
                                         "(elem=%u align=%u count=%u stride=%u)",
                                         desc, bunch, elem, align, count, stride);
                                DiagTrace::NotePersist(wb);
                                LOGE("%s", wb);
                            }
                        }
                        const uint32_t vo = h->MemoryRead32(0x65D850u);
                        const uint32_t vn = h->MemoryRead32(0x8F111050u);
                        if (vo != po || vn != pn) {
                            char b[112];
                            snprintf(b, sizeof(b),
                                     "W162 t=%dms old:%08X->%08X new:%08X->%08X",
                                     i * 50, po, vo, pn, vn);
                            DiagTrace::NotePersist(b);
                            po = vo;
                            pn = vn;
                        }
                        // W210 (run294): every 5 s mirror the W100 boot
                        // counters + verify the probe sites are still
                        // patched (detect counter smashing / un-patching).
                        if (i % 100 == 50) {
                            char b[220];
                            int n = snprintf(b, sizeof(b), "W210 t=%dms boot:", i * 50);
                            for (int k = 0; k < 15 && n > 0; ++k)
                                n += snprintf(b + n, sizeof(b) - static_cast<size_t>(n),
                                              " %u", h->MemoryRead32(0x93001500u +
                                                                     static_cast<uint32_t>(k) * 4));
                            snprintf(b + n, sizeof(b) - static_cast<size_t>(n),
                                     " | site0=%08X s1=%08X w214site=%08X",
                                     h->MemoryRead32(0x403DBE38u),
                                     h->MemoryRead32(0x40543AB8u),
                                     h->MemoryRead32(0x40543AC0u));
                            DiagTrace::NotePersist(b);
                        }
                        // W198 (run276): every 500 ms sample the live guest
                        // PC of every JIT context; persist on transitions.
                        // The game thread spins one full core somewhere
                        // after bz_Material_SetCommonLoadingDirectory
                        // entered -- this names the exact spinning PC.
                        if (i % 10 == 0) {
                            static std::string w198_prev;
                            std::string s = h->DiagSamplePCs();
                            if (!s.empty() && s != w198_prev) {
                                char b[1280];
                                snprintf(b, sizeof(b), "W198 t=%dms%s", i * 50, s.c_str());
                                DiagTrace::NotePersist(b);
                                LOGE("%s", b);
                                w198_prev = std::move(s);
                            }
                        }
                        // W348: fast heal of the REAL guest GOT and the
                        // .data.rel.ro function-pointer region every 50 ms.
                        for (size_t i = 0; false && i < kGotWords; ++i) {  // W498: retired
                            const uint32_t slot = kTrueGotBase + 4u * i;
                            const uint32_t cur = h->MemoryRead32(slot);
                            if (cur != true_got_snap[i]) {
                                h->MemoryWrite32(slot, true_got_snap[i]);
                                char hb[128];
                                snprintf(hb, sizeof(hb),
                                         "W348GOTFIX slot=%08X poisoned=%08X restored=%08X",
                                         slot, cur, true_got_snap[i]);
                                DiagTrace::NotePersist(std::string(hb));
                                LOGE("%s", hb);
                            }
                        }
                        if (false) for (size_t i = 0; i < kDroWords; ++i) {
                            const uint32_t slot = kDroBase + 4u * i;
                            // W511 (run690): the game located its bzgAndroidInfo
                            // struct at 0x405DBE60 (0x36C bytes) -- INSIDE the
                            // DRO region. The healer was reverting the game's own
                            // struct writes (mini/env/cell/init outputs) every
                            // 50 ms. Exempt that range.
                            if (slot >= 0x405DBE60u && slot < 0x405DBE60u + 0x36Cu)
                                continue;
                            const uint32_t cur = h->MemoryRead32(slot);
                            if (cur != dro_snap[i]) {
                                h->MemoryWrite32(slot, dro_snap[i]);
                                char hb2[128];
                                snprintf(hb2, sizeof(hb2),
                                         "W348DROFIX addr=%08X poisoned=%08X restored=%08X",
                                         slot, cur, dro_snap[i]);
                                DiagTrace::NotePersist(std::string(hb2));
                                LOGE("%s", hb2);
                            }
                        }
                        // W357 (run472): glue worker-stack-top smear scan.
                        // The fclose epilogue POP pulled 0x4066E98C (a
                        // .data.rel.ro literal address) from the stack --
                        // caught the smear here instead: any DRO-range value
                        // in the glue stack's top 128 words is reported.
                        {
                            // W362 (run486): scan-and-CLEAR. The smear
                            // 0x4067D168 at 0x7E3FFF0C is written by the
                            // CConfigFile ctor as a legit local but is later
                            // read by Android_fclose's POP {PC} as a return
                            // address. Zero ALL DRO-range values in the
                            // glue stack's top 4KB every 50 ms tick -- this
                            // includes the 0x7E3FFF0C slot and any other
                            // leftover DRO pointers from dead frames.
                            const uint32_t stack_top = 0x7E3FFF00u;
                            uint32_t w362_fixed = 0;
                            for (uint32_t a = stack_top; a < 0x7E400000u; a += 4) {
                                const uint32_t v = h->MemoryRead32(a);
                                if (false && v >= 0x40660000u && v < 0x40680000u) {
                                    h->MemoryWrite32(a, 0);
                                    if (w362_fixed < 4) {
                                        char sb2[128];
                                        snprintf(sb2, sizeof(sb2),
                                                 "W362 CLEAR addr=%08X val=%08X",
                                                 a, v);
                                        DiagTrace::NotePersist(std::string(sb2));
                                    }
                                    ++w362_fixed;
                                }
                            }
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(50));
                    }
                }).detach();
                // W355 (run471): 2 ms micro-guard on the PLT JUMP_SLOT
                // region (0x4066E988..0x4066F000). run468/469: the glue
                // died jumping to 0x4066E98C THROUGH AAsset_close's
                // JUMP_SLOT (0x4066EA58, patched with a neighbour slot's
                // address) inside ONE 50 ms watcher window -- the poison
                // and the call are adjacent. Heal every 2 ms and log the
                // drift with the guest thread id.
                // W384 (run515): the JSFIX perpetual healer is DISABLED.
                // It re-froze the GOT region [0x4066E988,0x4066F000) to a
                // snapshot taken at install time every 2 ms -- fighting
                // W336 DRO-heal (the heal war) and overwriting runtime
                // re-pointed import slots with stale/instruction words
                // (E3A00000/E12FFF1E restored into jump slots). Post-release
                // import calls then died on poisoned GOT words (run514:
                // exceptions at 0x40667260 / 0x4055FB34 right after the
                // pause release). GOT healing now belongs to W336 alone.
                if (false) std::thread([h] {
                    constexpr uint32_t kJsBase = 0x4066E988u;
                    constexpr size_t kJsWords = (0x4066F000u - 0x4066E988u) / 4u;
                    static uint32_t js_snap[kJsWords];
                    for (size_t i = 0; i < kJsWords; ++i)
                        js_snap[i] = h->MemoryRead32(kJsBase + 4u * i);
                    for (;;) {
                        for (size_t i = 0; i < kJsWords; ++i) {
                            const uint32_t slot = kJsBase + 4u * i;
                            const uint32_t cur = h->MemoryRead32(slot);
                            if (cur != js_snap[i]) {
                                h->MemoryWrite32(slot, js_snap[i]);
                                char hb3[128];
                                snprintf(hb3, sizeof(hb3),
                                         "W355 JSFIX slot=%08X poisoned=%08X restored=%08X",
                                         slot, cur, js_snap[i]);
                                DiagTrace::NotePersist(std::string(hb3));
                                LOGE("%s", hb3);
                            }
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(2));
                    }
                }).detach();
            }
            // W159 (run213): the D_1 stub's tgt literal at 0x65D840 was found
            // holding 0x00E59F30 at first execution though install wrote
            // 0x40222FD0. Verify every probe's words immediately.
            for (const auto& pr : w124) {
                if (kW196CleanSlate) break;  // sites unpatched, nothing to verify
                // stub addresses are internal; re-derive from the site patch
                const uint32_t s = host.MemoryRead32(pr.site + 4);
                const uint32_t tgt_word = host.MemoryRead32(s + 80u);  // idx 20 in v3
                if (tgt_word != pr.target) {
                    LOGE("[W159] probe tgt already wrong at 0x%08X: lit=0x%08X want=0x%08X",
                         pr.site, tgt_word, pr.target);
                }
            }
        }
        // W125: bzd ENTRY probe -- counts entries into
        // bzd_InitEntireDynamicsSystem itself (the W122 call-site counter is
        // guest-corrupted, and W124's D_* sites only fire past the entry).
        {
            const uint32_t w125site = 0x402160C4;
            const uint32_t w125stub = 0x8F111900u;  // W166: relocated to the safe bridge window  // was 0x65DA00: inside relocated W124-v2 range
            const uint32_t w125cnt = 0x00010080u;  // W131 fixed window
            g_w125_counter_addr = w125cnt;
            const uint32_t w0 = host.MemoryRead32(w125site);
            const uint32_t w1 = host.MemoryRead32(w125site + 4);
            if (!kW196CleanSlate && w0 == 0xE92D43F0u && (w1 & 0x0F7FF000u) != 0xE59FF000u &&
                (w1 & 0x0F7F0000u) != 0x028F0000u && (w1 & 0x0F7F0000u) != 0x024F0000u) {
                const uint32_t code[] = {
                    EncodeMOVW(12, w125cnt & 0xFFFFu), EncodeMOVT(12, w125cnt >> 16),
                    0xE59C3000u,          // ldr r3,[r12]
                    0xE2833001u,          // add r3,r3,#1
                    0xE58C3000u,          // str r3,[r12]
                    w0,                   // push {r4-r10,lr}   (displaced w0)
                    w1,                   // sub sp,sp,#0xC     (displaced w1)
                    0xE51FF004u,          // ldr pc,[pc,#-4]
                    w125site + 8,         // resume
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w125stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w125site, 0xE51FF004u);
                host.MemoryWrite32(w125site + 4, w125stub);
                host.InvalidateGuestCode(w125site, 8);
                host.MemoryWrite32(0x93001790u, 18);  // W447P W125
                LOGI("[W125] bzd entry probe at 0x%08X -> stub 0x%08X (cnt 0x%08X)",
                     w125site, w125stub, w125cnt);
            } else {
                LOGE("[W125] unexpected entry words at 0x%08X: 0x%08X/0x%08X",
                     w125site, w0, w1);
            }
        }
        // W137 (run183 v2): capture the LLMemAllocate result at 0x4040E00C
        // AND preserve the failure branch (0x4040E010 was BEQ 0x40E224 --
        // the old stub silently swallowed alloc failures). Also capture the
        // LLMemCreateNewPool RETURN (R5) at its epilogue 0x4040E14C.
        {
            const uint32_t w128cnt = 0x00010090u;  // W131 fixed window
            g_w128_counter_addr = w128cnt;
            const uint32_t a0 = host.MemoryRead32(0x4040E00Cu);
            const uint32_t a1 = host.MemoryRead32(0x4040E010u);
            if (a0 == 0xE3500000u && (a1 & 0x00010000u) == 0x0A000000u) {
                const int32_t beq_imm = static_cast<int32_t>(a1 << 8) >> 6;
                const uint32_t fail_tgt = 0x4040E010u + 8 + static_cast<uint32_t>(beq_imm);
                const uint32_t s = 0x0065DB80u;
                const uint32_t code[] = {
                    EncodeMOVW(12, (w128cnt + 20) & 0xFFFFu), EncodeMOVT(12, (w128cnt + 20) >> 16),
                    0xE58C0000u,          // str r0,[r12]      alloc result
                    a0,                   // cmp r0,#0         (displaced)
                    0x0A000002u,          // beq +2            -> fail cont
                    0xE51FF004u,          // ldr pc,[pc,#-4]   -> 0x4040E014
                    0x4040E014u,          // success resume
                    0xE51FF004u,          // fail: ldr pc,[pc,#-4] -> 0x4040E224
                    fail_tgt,
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(s + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(0x4040E00C, 0xE51FF004u);
                host.MemoryWrite32(0x4040E010, s);
                host.InvalidateGuestCode(0x4040E00C, 8);
                host.MemoryWrite32(0x93001790u, 17);  // W447P W137
                LOGI("[W137] alloc-result probe v2 at 0x4040E00C (fail->0x%08X)",
                     fail_tgt);
            } else {
                LOGE("[W137] unexpected words at 0x4040E00C: 0x%08X/0x%08X", a0, a1);
            }
            // W137b: LLMemCreateNewPool RETURN capture at the epilogue
            // 0x4040E14C (MOV R0,R5) + 0x4040E150 (ADD SP,SP,#0x1C).
            const uint32_t w137site = 0x4040E14Cu;
            const uint32_t w137stub = 0x0065DC00u;
            const uint32_t m0 = host.MemoryRead32(w137site);
            const uint32_t m1 = host.MemoryRead32(w137site + 4);
            if (m0 == 0xE1A00005u && m1 == 0xE28DD01Cu) {
                const uint32_t code[] = {
                    EncodeMOVW(12, (w128cnt + 24) & 0xFFFFu), EncodeMOVT(12, (w128cnt + 24) >> 16),
                    0xE58C5000u,          // str r5,[r12]      pool creator return
                    m0,                   // mov r0,r5         (displaced)
                    m1,                   // add sp,sp,#0x1C   (displaced)
                    0xE51FF004u,          // ldr pc,[pc,#-4]
                    w137site + 8,         // resume (POP)
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w137stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w137site, 0xE51FF004u);
                host.MemoryWrite32(w137site + 4, w137stub);
                host.InvalidateGuestCode(w137site, 8);
                host.MemoryWrite32(0x93001790u, 16);  // W447P W137
                LOGI("[W137] pool-return probe at 0x%08X", w137site);
            } else {
                LOGE("[W137] unexpected epilogue words at 0x%08X: 0x%08X/0x%08X",
                     w137site, m0, m1);
            }
        }
        // W142b (run190b): the LLMem alignment global dword_67332C (read by
        // LLMemCreateNewPool to compute the bunch slot size) reads
        // 0x90F36D08 under the bridge (measured W141c) -- garbage geometry
        // -> runaway free-list fills -> the whole data-segment stomping.
        // Initialize it to a sane 0x20 alignment at patch install.
        {
            const uint32_t w142bsite = 0x4067332Cu;
            const uint32_t oldv = host.MemoryRead32(w142bsite);
            host.MemoryWrite32(w142bsite, 0x20u);
            host.InvalidateGuestCode(w142bsite, 4);
            host.MemoryWrite32(0x93001790u, 15);  // W447P W142b
            LOGI("[W142b] LLMem alignment 0x%08X -> 0x20 at 0x%08X", oldv, w142bsite);
        }
        // W148 (run196b): LLMemCreateNewPool's bunch fill loop at 0x40E038
        // re-reads the descriptor count [R4] and stride [R4,#8] EVERY
        // iteration and loops while i < count-1 unsigned. Any concurrent
        // mutation (the lock-free sub_40D4A0 fast path, the descriptor slot
        // reuse window, an earlier overrunning bunch) that flips count to 0
        // makes the bound 0xFFFFFFFF and the loop never terminates -- the
        // exact main-thread freeze sampled at 0x4040E038 in the run196b PC
        // ring. Snapshot bound+stride at loop entry (LR is scratch: the
        // prologue saved it) and guard count==0; the loop then always
        // terminates and writes stay inside the block handed out for it.
        {
            const uint32_t w148site = 0x4040E02Cu;
            const uint32_t w148stub = 0x0065DD00u;
            const uint32_t c0 = host.MemoryRead32(w148site);       // ldr r3,[r4,#8]
            const uint32_t c1 = host.MemoryRead32(w148site + 4);   // mov r2,r0
            const uint32_t c2 = host.MemoryRead32(w148site + 8);   // mov r12,#0
            if (c0 == 0xE5943008u && c1 == 0xE1A02000u && c2 == 0xE3A0C000u) {
                // W152 v2 ring append, same layout as the W149 stub.
                                const uint32_t code[] = {
                    0xE594B000u,          // ldr r11,[r4]        bound = count
                    0xE1A02000u,          // mov r2,r0           cursor
                    0xE25BB001u,          // subs r11,r11,#1
                    0x3A000019u,          // bcc done
                    0xE594E008u,          // ldr lr,[r4,#8]      stride
                    0xE3CEE003u,          // bic lr,lr,#3
                    0xE35B001Eu,          // cmp r11,#30
                    0x9A000009u,          // bls skip
                    0xE59F3016u,          // ldr r3,[pc,#88]     -> lit ctrl (idx 32)
                    0xE5931000u,          // ldr r1,[r3]         seq
                    0xE201100Fu,          // and r1,r1,#15
                    0xE2833004u,          // add r3,r3,#4
                    0xE0833101u,          // add r3,r3,r1,lsl#3
                    0xE2811001u,          // add r1,r1,#1
                    0xE5831000u,          // str r1,[r3]         seq++
                    0xE28B1001u,          // add r1,r11,#1       count
                    0xE5831000u,          // str r1,[r3]
                    0xE583E004u,          // str lr,[r3,#4]
                    0xE3A0C000u,          // skip: mov r12,#0    i = 0
                    0xE082300Eu,          // body: add r3,r2,lr
                    0xE5823000u,          // str r3,[r2]
                    0xE082200Eu,          // add r2,r2,lr
                    0xE28CC001u,          // add r12,r12,#1
                    0xE15C000Bu,          // cmp r12,r11
                    0x2A000004u,          // bhs done
                    0xE59F3006u,          // ldr r3,[pc,#24]     -> lit end (idx 33)
                    0xE5933000u,          // ldr r3,[r3]
                    0xE1520003u,          // cmp r2,r3
                    0x2A000000u,          // bhs done            cursor past own block end
                    0xEAFFFFF4u,          // b body
                    0xE51FF004u,          // done: ldr pc,[pc,#-4]
                    w148site + 0x34u,     // resume 0x4040E060
                    0x00010200u,          // lit: W152 ring ctrl
                    0x00010280u,          // lit: W153 alloc end cell
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w148stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w148site, 0xE51FF004u);
                host.MemoryWrite32(w148site + 4, w148stub);
                host.InvalidateGuestCode(w148site, 0x38);
                host.MemoryWrite32(0x93001790u, 14);  // W447P W148
                LOGI("[W148] bunch fill snapshot patch at 0x%08X -> stub 0x%08X",
                     w148site, w148stub);
            } else {
                LOGE("[W148] unexpected fill loop words at 0x%08X: %08X/%08X/%08X",
                     w148site, c0, c1, c2);
            }
        }
        // W149 (run197): same class as W148 for the FAST-path bunch filler
        // sub_40D4A0 -- its loop at 0x40D634 re-reads the descriptor count and
        // stride every iteration. The C1 canary report shows its overruns:
        // freelist links from one bunch land in the tails of adjacent blocks
        // (and in the run197 sentinel, across the guest data segment around
        // the descriptor table). Snapshot bound+stride, guard count==0. R1/R2
        // are safe: the original loop itself used them as counter/scratch, so
        // no live value (a2 flags included) lives there across the loop.
        {
            const uint32_t w149site = 0x4040D628u;
            const uint32_t w149stub = 0x0065DE00u;
            const uint32_t d0 = host.MemoryRead32(w149site);       // ldr r3,[r4,#8]
            const uint32_t d1 = host.MemoryRead32(w149site + 4);   // mov r12,r0
            const uint32_t d2 = host.MemoryRead32(w149site + 8);   // mov r1,#0
            if (d0 == 0xE5943008u && d1 == 0xE1A0C000u && d2 == 0xE3A01000u) {
                // W152 v2: after the bound/stride snapshot, fills with
                // count >= 31 append [count, stride] to the host-readable
                // ring at 0x00010200 (16 x 8 bytes, ctrl word = seq). Paired
                // against the alloc heap events (size = count*stride+40)
                // this exposes the alloc->fill descriptor mutation with both
                // sides' values. Append clobbers only r1/r3 (re-init after).
                                const uint32_t code[] = {
                    0xE5942000u,          // ldr r2,[r4]         bound = count
                    0xE1A0C000u,          // mov r12,r0          cursor
                    0xE2522001u,          // subs r2,r2,#1
                    0x3A000019u,          // bcc done
                    0xE594E008u,          // ldr lr,[r4,#8]      stride
                    0xE3CEE003u,          // bic lr,lr,#3
                    0xE352001Eu,          // cmp r2,#30
                    0x9A000009u,          // bls skip
                    0xE59F3016u,          // ldr r3,[pc,#88]     -> lit ctrl (idx 32)
                    0xE5931000u,          // ldr r1,[r3]         seq
                    0xE201100Fu,          // and r1,r1,#15
                    0xE2833004u,          // add r3,r3,#4
                    0xE0833101u,          // add r3,r3,r1,lsl#3
                    0xE2811001u,          // add r1,r1,#1
                    0xE5831000u,          // str r1,[r3]         seq++
                    0xE2811001u,          // add r1,r2,#1        count
                    0xE5831000u,          // str r1,[r3]
                    0xE583E004u,          // str lr,[r3,#4]
                    0xE3A01000u,          // skip: mov r1,#0     i = 0
                    0xE08C300Eu,          // body: add r3,r12,lr
                    0xE58C3000u,          // str r3,[r12]
                    0xE08CC00Eu,          // add r12,r12,lr
                    0xE2811001u,          // add r1,r1,#1
                    0xE1510002u,          // cmp r1,r2
                    0x2A000004u,          // bhs done
                    0xE59F3006u,          // ldr r3,[pc,#24]     -> lit end (idx 33)
                    0xE5933000u,          // ldr r3,[r3]
                    0xE15C0003u,          // cmp r12,r3
                    0x2A000000u,          // bhs done            cursor past own block end
                    0xEAFFFFF4u,          // b body
                    0xE51FF004u,          // done: ldr pc,[pc,#-4]
                    w149site + 0x34u,     // resume 0x4040D65C
                    0x00010200u,          // lit: W152 ring ctrl
                    0x00010280u,          // lit: W153 alloc end cell
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w149stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w149site, 0xE51FF004u);
                host.MemoryWrite32(w149site + 4, w149stub);
                host.InvalidateGuestCode(w149site, 0x38);
                host.MemoryWrite32(0x93001790u, 13);  // W447P W149
                LOGI("[W149] fast-path bunch fill snapshot patch at 0x%08X -> stub 0x%08X",
                     w149site, w149stub);
            } else {
                LOGE("[W149] unexpected fill loop words at 0x%08X: %08X/%08X/%08X",
                     w149site, d0, d1, d2);
            }
        }
        // W151 (run199): the SECOND re-reading fill loop inside
        // LLMemCreateNewPool -- the a3-bunches loop at 0x40E0F0. The W150
        // trail dumps show the remaining overruns stamp *cursor = cursor+elem
        // while advancing +4, the fingerprint of a stride flicker between the
        // link-add and the advance that only these re-reading loops can
        // amplify. Same snapshot treatment as W148 (R11 free in the loop
        // window; the prologue saved it).
        {
            const uint32_t w151site = 0x4040E0E4u;
            const uint32_t w151stub = 0x0065DF00u;
            const uint32_t e0 = host.MemoryRead32(w151site);       // ldr r3,[r4,#8]
            const uint32_t e1 = host.MemoryRead32(w151site + 4);   // mov r2,r0
            const uint32_t e2 = host.MemoryRead32(w151site + 8);   // mov r12,#0
            if (e0 == 0xE5943008u && e1 == 0xE1A02000u && e2 == 0xE3A0C000u) {
                                const uint32_t code[] = {
                    0xE594B000u,          // ldr r11,[r4]        bound = count
                    0xE1A02000u,          // mov r2,r0           cursor
                    0xE25BB001u,          // subs r11,r11,#1
                    0x3A000019u,          // bcc done
                    0xE594E008u,          // ldr lr,[r4,#8]      stride
                    0xE3CEE003u,          // bic lr,lr,#3
                    0xE35B001Eu,          // cmp r11,#30
                    0x9A000009u,          // bls skip
                    0xE59F3016u,          // ldr r3,[pc,#88]     -> lit ctrl (idx 32)
                    0xE5931000u,          // ldr r1,[r3]         seq
                    0xE201100Fu,          // and r1,r1,#15
                    0xE2833004u,          // add r3,r3,#4
                    0xE0833101u,          // add r3,r3,r1,lsl#3
                    0xE2811001u,          // add r1,r1,#1
                    0xE5831000u,          // str r1,[r3]         seq++
                    0xE28B1001u,          // add r1,r11,#1       count
                    0xE5831000u,          // str r1,[r3]
                    0xE583E004u,          // str lr,[r3,#4]
                    0xE3A0C000u,          // skip: mov r12,#0    i = 0
                    0xE082300Eu,          // body: add r3,r2,lr
                    0xE5823000u,          // str r3,[r2]
                    0xE082200Eu,          // add r2,r2,lr
                    0xE28CC001u,          // add r12,r12,#1
                    0xE15C000Bu,          // cmp r12,r11
                    0x2A000004u,          // bhs done
                    0xE59F3006u,          // ldr r3,[pc,#24]     -> lit end (idx 33)
                    0xE5933000u,          // ldr r3,[r3]
                    0xE1520003u,          // cmp r2,r3
                    0x2A000000u,          // bhs done            cursor past own block end
                    0xEAFFFFF4u,          // b body
                    0xE51FF004u,          // done: ldr pc,[pc,#-4]
                    w151site + 0x34u,     // resume 0x4040E118
                    0x00010200u,          // lit: W152 ring ctrl
                    0x00010280u,          // lit: W153 alloc end cell
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w151stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w151site, 0xE51FF004u);
                host.MemoryWrite32(w151site + 4, w151stub);
                host.InvalidateGuestCode(w151site, 0x38);
                host.MemoryWrite32(0x93001790u, 12);  // W447P W151
                LOGI("[W151] a3-bunch fill snapshot patch at 0x%08X -> stub 0x%08X",
                     w151site, w151stub);
            } else {
                LOGE("[W151] unexpected fill loop words at 0x%08X: %08X/%08X/%08X",
                     w151site, e0, e1, e2);
            }
        }
        // W154 (run202): the elem-4 pool grabs a 104025300-byte bunch because
        // its count argument is 26006323 (0x18CFBB3) -- garbage-scale for this
        // engine (largest legit pool: CHILD POOL count 700, auto-count cap
        // 0xBB8/elem). Snapshot the arguments of any LLMemCreateNewPool call
        // whose count exceeds 10M into 0x00010300, so the diag names the
        // caller (lr) and the requested geometry at the moment the monster
        // pool is born. Three such pools exhausted the 736MB guest heap.
        {
            const uint32_t w154site = 0x4040DEA4u;
            const uint32_t w154stub = 0x0065E600u;  // was 0x65E000: suspect guest-stomp zone
            const uint32_t f0 = host.MemoryRead32(w154site);       // push {r4-r11,lr}
            const uint32_t f1 = host.MemoryRead32(w154site + 4);   // sub sp,sp,#0x1C
            if (f0 == 0xE92D4FF0u && f1 == 0xE24DD01Cu) {
                const uint32_t code[] = {
                    0xE3510A0Au,          // cmp r1,#0xA00000    count > 10M?
                    0x9A000004u,          // bls skip            -> idx 7
                    0xE59F3008u,          // ldr r3,[pc,#32]     -> cells (idx 12)
                    0xE8A31007u,          // stmib r3,{r0,r1,r2,r12}
                    0xE583E014u,          // str lr,[r3,#20]
                    0xE3A0C001u,          // mov r12,#1
                    0xE583C000u,          // str r12,[r3]        flag
                    0xE92D4FF0u,          // skip: push {r4-r11,lr} (displaced)
                    0xE24DD01Cu,          // sub sp,sp,#0x1C     (displaced)
                    0xE51FF004u,          // ldr pc,[pc,#-4]
                    w154site + 8u,        // resume
                    0x00000000u,          // (pad)
                    0x00010300u,          // cells
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w154stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w154site, 0xE51FF004u);
                host.MemoryWrite32(w154site + 4, w154stub);
                host.InvalidateGuestCode(w154site, 8);
                host.MemoryWrite32(0x93001790u, 11);  // W447P W154
                LOGI("[W154] big-pool arg snapshot at 0x%08X -> stub 0x%08X",
                     w154site, w154stub);
            } else {
                LOGE("[W154] unexpected entry words at 0x%08X: %08X/%08X",
                     w154site, f0, f1);
            }
        }
        // W156 (run206): the boot thread dies inside D_InitialiseDynamicsObjectManager
        // with a corrupted saved PC (W84APP pc=0xE59F34, r3=0x00E59F30 -- a garbage
        // function pointer). Count entries into each of D_1's three callees to name
        // the one that kills the thread: counters at 0x00010340 + i*4.
        {
            struct W156Site { uint32_t site, target; };
            const W156Site w156[] = {
                { 0x40223008u, 0x40222FC0u },  // BL bzd_StartProcessingSet(gMain_set)
                { 0x4022300Cu, 0x402127Cu  },  // BL sub_22127C(started)
                { 0x4022303Cu, 0x40473B40u },  // BL bz_AR_AddSessionType(...) (target typo fixed: was 0x4073B40)
            };
            uint32_t w156stub = 0x8F111A00u;   // W166: relocated from the gap; 80-byte stride
            for (const auto& pr : w156) {
                if (kW196CleanSlate) { LOGI("[W196] W156 site 0x%08X skipped", pr.site); continue; }
                const uint32_t orig = host.MemoryRead32(pr.site);
                const uint32_t imm24 = ((pr.target - pr.site - 8) >> 2) & 0x00FFFFFFu;
                if (orig != (0xEB000000u | imm24)) {
                    LOGE("[W156] unexpected BL at 0x%08X: 0x%08X", pr.site, orig);
                    continue;
                }
                const uint32_t next = host.MemoryRead32(pr.site + 4);
                const uint32_t cnt = 0x00010340u +
                    static_cast<uint32_t>(&pr - &w156[0]) * 4u;
                // W112 law, deeper clause: a displaced PC-relative LDR
                // (LDR Rt,[PC,#imm]) reads from the STUB's PC, not the
                // original site's -- relocate it to a literal slot
                // pre-filled with the original pool word.
                uint32_t reloc = 0;
                bool relocating = false;
                // A displaced BL/BL (relative) keeps its imm24, which was
                // computed for the ORIGINAL site -- from the stub it lands
                // ~1MB away into stub garbage (run207-210's 0x00E59F30 jump).
                // Recompute the offset for the stub slot-7 address.
                uint32_t disp = next;
                uint32_t disp_tgt = 0;
                bool disp_is_bl = false;
                if ((next & 0x0F000000u) == 0x0B000000u) {
                    // W173-style: a displaced BL cannot be imm24-relocated
                    // into the 0x9000xxxx window (range violation). Convert
                    // it to MOVW/MOVT r3 + BLX r3 with the ORIGINAL target.
                    const int32_t imm = static_cast<int32_t>(next << 8) >> 6;
                    disp_tgt = pr.site + 12 + static_cast<uint32_t>(imm);
                    disp_is_bl = true;
                }
                std::vector<uint32_t> code = {
                    EncodeMOVW(12, cnt & 0xFFFFu), EncodeMOVT(12, cnt >> 16),
                    0xE59C3000u,          // ldr r3,[r12]
                    0xE2833001u,          // add r3,r3,#1
                    0xE58C3000u,          // str r3,[r12]
                    EncodeMOVW(3, pr.target & 0xFFFFu), EncodeMOVT(3, pr.target >> 16),
                    0xE12FFF33u,          // blx r3            ; lr = S+32
                };
                if (disp_is_bl) {
                    code.push_back(EncodeMOVW(3, disp_tgt & 0xFFFFu));
                    code.push_back(EncodeMOVT(3, disp_tgt >> 16));
                    code.push_back(0xE12FFF33u);  // blx r3        ; lr = S+48
                    code.push_back(0xE51FF004u);  // ldr pc -> slot 13 (resume)
                    code.push_back(pr.site + 12u);
                } else {
                    code.push_back(disp);
                    code.push_back(0xE51FF004u);
                    code.push_back(pr.site + 8u);
                }
                if (relocating) code.push_back(reloc);  // slot 11
                for (size_t i = 0; i < code.size(); ++i)
                    host.MemoryWrite32(w156stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(pr.site, 0xE51FF004u);
                host.MemoryWrite32(pr.site + 4, w156stub);
                host.InvalidateGuestCode(pr.site, 8);
                host.InvalidateGuestCode(w156stub, 80);
                w156stub += 80;
                host.MemoryWrite32(0x93001790u, 10);  // W447P W156
                LOGI("[W156] callee probe at 0x%08X cnt 0x%08X reloc=%u",
                     pr.site, cnt, relocating ? reloc : 0);
            }
        }
        // W158 v2 (run214): the real BL is at 0x40222FF8 (next word is a
        // PC-relative LDR R3,[PC,#0x6C] whose literal lives at 0x40223070 --
        // relocated into the stub). Caller's R3 saved/restored across the stub.
        {
            const uint32_t w158site = 0x40222FF8u;
            const uint32_t w158stub = 0x8F111C00u;  // W166: relocated from the gap
            const uint32_t orig = host.MemoryRead32(w158site);
            const uint32_t imm24 = ((0x40222F58u - w158site - 8) >> 2) & 0x00FFFFFFu;
            if (!kW196CleanSlate && orig == (0xEB000000u | imm24)) {
                const uint32_t reloc = host.MemoryRead32(0x40223070u);
                const uint32_t code[] = {
                    0xE92D0008u,          // push {r3}          caller's gMain_set ptr
                    EncodeMOVW(12, 0x0350u), EncodeMOVT(12, 0x9000u),
                    0xE59C3000u,          // ldr r3,[r12]
                    0xE2833001u,          // add r3,r3,#1
                    0xE58C3000u,          // str r3,[r12]       called++
                    EncodeMOVW(3, 0x2F58u), EncodeMOVT(3, 0x4022u),
                    0xE12FFF33u,          // blx r3
                    EncodeMOVW(3, 0x0354u), EncodeMOVT(3, 0x9000u),
                    0xE5830000u,          // str r0,[r3]        last ret
                    0xE49D0008u,          // pop {r3}
                    0xE59F3001u,          // ldr r3,[pc,#4]     -> reloc (slot 16)
                    0xE51FF004u,          // ldr pc,[pc,#-4]    -> slot 14
                    w158site + 8u,        // resume
                    reloc,                // relocated 0x40223070 word
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w158stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w158site, 0xE51FF004u);
                host.MemoryWrite32(w158site + 4, w158stub);
                host.InvalidateGuestCode(w158site, 8);
                host.InvalidateGuestCode(w158stub, 128);
                host.MemoryWrite32(0x93001790u, 9);  // W447P W158
                LOGI("[W158] CreateObjectSet return capture at 0x%08X reloc=%08X",
                     w158site, reloc);
            } else {
                LOGE("[W158] unexpected word at 0x%08X: 0x%08X (want 0xEBFFFFD6)", w158site, orig);
            }
        }
        // W160 (run215): bisect D_1's death -- count entries into its FIRST
        // call (BL LLMemFill at 0x40222FF0; displaced-next 0xE1A00004
        // MOV R0,R4 is register-only, no relocation needed). Counter at
        // 0x00010358: called=1 -> the death is inside LLMemFill's memset
        // chain; called=0 -> it dies in D_1's prologue or the W124 stub
        // never reached D_1 at all.
        {
            const uint32_t w160site = 0x40222FF0u;
            const uint32_t w160tgt = 0x40409CC0u;
            const uint32_t w160stub = 0x8F111D00u;  // W166: relocated from the gap
            const uint32_t orig = host.MemoryRead32(w160site);
            const uint32_t imm24 = ((w160tgt - w160site - 8) >> 2) & 0x00FFFFFFu;
            if (!kW196CleanSlate && orig == (0xEB000000u | imm24)) {
                const uint32_t code[] = {
                    EncodeMOVW(12, 0x0358u), EncodeMOVT(12, 0x9000u),
                    0xE59C3000u,          // ldr r3,[r12]
                    0xE2833001u,          // add r3,r3,#1
                    0xE58C3000u,          // str r3,[r12]
                    EncodeMOVW(3, w160tgt & 0xFFFFu), EncodeMOVT(3, w160tgt >> 16),
                    0xE12FFF33u,          // blx r3
                    0xE1A00004u,          // mov r0,r4       (displaced site+4)
                    0xE51FF004u,          // ldr pc,[pc,#-4] -> slot 9
                    w160site + 8u,        // resume
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w160stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w160site, 0xE51FF004u);
                host.MemoryWrite32(w160site + 4, w160stub);
                host.InvalidateGuestCode(w160site, 8);
                host.InvalidateGuestCode(w160stub, 64);
                host.MemoryWrite32(0x93001790u, 8);  // W447P W160
                LOGI("[W160] LLMemFill entry probe at 0x%08X", w160site);
            } else {
                LOGE("[W160] unexpected word at 0x%08X: 0x%08X", w160site, orig);
            }
        }
        // W167 (run228): bisect the silent clean return after bzd success --
        // count entries into BL operator new (0x403DBFCC -> _Znwj) and
        // capture its returned r0. entered=1 && r0=0 => operator new FAILED
        // (bad_alloc unwind confirmed); entered=0 => the death is earlier
        // (inside the W122/bzd return path). Counter 0x00010360, ret
        // 0x00010364. Displaced-next = MOV R7,R0 (register-only, safe).
        {
            const uint32_t w167site = 0x403DBFCCu;
            const uint32_t w167tgt = 0x4040D03Cu;  // W412: +base
            const uint32_t w167stub = 0x8F111E00u;  // W166: relocated from the gap
            const uint32_t orig = host.MemoryRead32(w167site);
            const uint32_t imm24 = ((w167tgt - w167site - 8) >> 2) & 0x00FFFFFFu;
            if (!kW196CleanSlate && orig == (0xEB000000u | imm24)) {
                const uint32_t code[] = {
                    EncodeMOVW(12, 0x0360u), EncodeMOVT(12, 0x9000u),
                    0xE59C3000u,          // ldr r3,[r12]
                    0xE2833001u,          // add r3,r3,#1
                    0xE58C3000u,          // str r3,[r12]
                    EncodeMOVW(3, w167tgt & 0xFFFFu), EncodeMOVT(3, w167tgt >> 16),
                    0xE12FFF33u,          // blx r3
                    0xE58C0004u,          // str r0,[r12,#4]  last ret
                    0xE1A07000u,          // mov r7,r0       (displaced site+4)
                    0xE51FF004u,          // ldr pc,[pc,#-4] -> slot 9
                    w167site + 8u,        // resume
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w167stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w167site, 0xE51FF004u);
                host.MemoryWrite32(w167site + 4, w167stub);
                host.InvalidateGuestCode(w167site, 8);
                host.InvalidateGuestCode(w167stub, 48);
                host.MemoryWrite32(0x93001790u, 7);  // W447P W167
                LOGI("[W167] operator new entry probe at 0x%08X", w167site);
            } else {
                LOGE("[W167] unexpected word at 0x%08X: 0x%08X (want 0xEB013C18)", w167site, orig);
            }
        }
        // W176 (run241): probe `MOV R0,#0x28; BL operator new` at 0x403DBFC8
        // (the LogManager allocation after bzd success). entered=0 means the
        // death is between the bzd resume and this MOV; entered>=1 with
        // ret=0 means operator new/LLMemAllocate(pool 231) failed. The
        // displaced BL is converted to MOVW/MOVT+BLX (32MB range rule).
        // Counters: entered 0x0001036C, ret r0 0x00010370.
        {
            const uint32_t w176site = 0x403DBFCCu;
            const uint32_t w176tgt = 0x4040D03Cu;  // W412: +base
            const uint32_t w176stub = 0x8F112100u;
            const uint32_t orig = host.MemoryRead32(w176site);
            const uint32_t imm24 = ((w176tgt - w176site - 8) >> 2) & 0x00FFFFFFu;
            if (!kW196CleanSlate && orig == (0xEB000000u | imm24)) {
                const uint32_t code[] = {
                    EncodeMOVW(12, 0x036Cu), EncodeMOVT(12, 0x9000u),
                    0xE59C3000u,          // ldr r3,[r12]
                    0xE2833001u,          // add r3,r3,#1
                    0xE58C3000u,          // str r3,[r12]
                    EncodeMOVW(12, 0x0370u), EncodeMOVT(12, 0x9000u),
                    EncodeMOVW(3, w176tgt & 0xFFFFu), EncodeMOVT(3, w176tgt >> 16),
                    0xE12FFF33u,          // blx r3            ; lr = S+40
                    0xE58C0000u,          // str r0,[r12]      ret r0
                    0xE3A00028u,          // mov r0,#0x28      (displaced site+4)
                    0xE51FF004u,          // ldr pc,[pc,#-4]   -> slot 13
                    w176site + 8u,        // resume
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w176stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w176site, 0xE51FF004u);
                host.MemoryWrite32(w176site + 4, w176stub);
                host.InvalidateGuestCode(w176site, 8);
                host.InvalidateGuestCode(w176stub, 56);
                host.MemoryWrite32(0x93001790u, 6);  // W447P W176
                LOGI("[W176] operator-new call probe at 0x%08X", w176site);
            } else {
                LOGE("[W176] unexpected word at 0x%08X: 0x%08X (want 0xEB013C18)", w176site, orig);
            }
        }
        // W172 (run234): count entries into LLMemFill's dispatch target
        // 0x403F5FE8 (a tail-branch thunk `B 0x4016AE40`). The displaced
        // word IS an unconditional branch: recompute its imm24 relative to
        // the stub slot so the jump lands on 0x4016AE40 from the stub too.
        // No resume: the B is the whole tail. Counter 0x00010368.
        {
            const uint32_t w172site = 0x403F5FE8u;
            const uint32_t w172stub = 0x8F111F00u;
            const uint32_t orig = host.MemoryRead32(w172site);
            // original: B 0x4016AE40 = EAxxxxxx (decode imm to verify target)
            const int32_t oimm = static_cast<int32_t>(orig << 8) >> 6;
            const uint32_t otgt = w172site + 8 + static_cast<uint32_t>(oimm);
            if (!kW196CleanSlate && (orig & 0x00010000u) == 0xEA000000u && otgt == 0x40166AE0u) {
                // W173: the original tail-B cannot be imm24-relocated into
                // the 0x9000xxxx window (range +-32MB) -- the wrapped imm24
                // produced the 0x90166AF8 garbage jump. Replace with a
                // register-indirect BX: target travels as immediates.
                const uint32_t code[] = {
                    EncodeMOVW(12, 0x0368u), EncodeMOVT(12, 0x9000u),
                    0xE59C3000u,          // ldr r3,[r12]
                    0xE2833001u,          // add r3,r3,#1
                    0xE58C3000u,          // str r3,[r12]
                    EncodeMOVW(3, 0x6AE0u), EncodeMOVT(3, 0x4016u),
                    0xE12FFF13u,          // BX r3   -> 0x40166AE0
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w172stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w172site, 0xE51FF004u);
                host.MemoryWrite32(w172site + 4, w172stub);
                host.InvalidateGuestCode(w172site, 8);
                host.InvalidateGuestCode(w172stub, 24);
                host.MemoryWrite32(0x93001790u, 5);  // W447P W172
                LOGI("[W172] fill-dispatch entry probe at 0x%08X", w172site);
            } else {
                LOGE("[W172] unexpected word at 0x%08X: 0x%08X (tgt %08X)", w172site, orig, otgt);
            }
        }
        // W188 (run260): entry probes inside bz_AR_AddSessionType to find
        // the exact call where the boot thread disappears after
        // CreateObjectSet. Two sites, counters 0x00010370 (LLMemAllocateV)
        // and 0x00010374 (map insert). Both have safe displaced-next.
        {
            struct W188Site { uint32_t site, target, disp; };
            const W188Site w188[] = {
                { 0x40473B7Cu, 0x4040D8B8u, 0xE2504000u },  // BL LLMemAllocateV; SUBS R4,R0,#0
                { 0x40473BCCu, 0x4040D05Cu, 0xE1A00000u },  // BL 0x4040D05C; NOP (skip PC-rel next)
            };
            uint32_t w188stub = 0x8F112100u;
            for (const auto& pr : w188) {
                if (kW196CleanSlate) { LOGI("[W196] W188 site 0x%08X skipped", pr.site); continue; }
                const uint32_t orig = host.MemoryRead32(pr.site);
                const uint32_t imm24 = ((pr.target - pr.site - 8) >> 2) & 0x00FFFFFFu;
                if (orig != (0xEB000000u | imm24)) {
                    LOGE("[W188] unexpected BL at 0x%08X: 0x%08X", pr.site, orig);
                    continue;
                }
                const uint32_t cnt = 0x00010370u +
                    static_cast<uint32_t>(&pr - &w188[0]) * 4u;
                const uint32_t code[] = {
                    EncodeMOVW(12, cnt & 0xFFFFu), EncodeMOVT(12, cnt >> 16),
                    0xE59C3000u,          // ldr r3,[r12]
                    0xE2833001u,          // add r3,r3,#1
                    0xE58C3000u,          // str r3,[r12]
                    0xE58D0004u,          // str r0,[sp,#4]   W189: capture pool id
                    EncodeMOVW(3, pr.target & 0xFFFFu), EncodeMOVT(3, pr.target >> 16),
                    0xE12FFF33u,          // blx r3            ; lr = S+36
                    pr.disp,              // displaced-next
                    0xE51FF004u,          // ldr pc,[pc,#-4]   -> slot 11
                    pr.site + 8u,         // resume
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w188stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(pr.site, 0xE51FF004u);
                host.MemoryWrite32(pr.site + 4, w188stub);
                host.InvalidateGuestCode(pr.site, 8);
                host.InvalidateGuestCode(w188stub, 40);
                w188stub += 48;
                host.MemoryWrite32(0x93001790u, 4);  // W447P W188
                LOGI("[W188] internal probe at 0x%08X cnt 0x%08X", pr.site, cnt);
            }
        }
        // W177b: capture D_1's returned r0 at its result-check BNE
        // (0x402160F4 -> 0x402160E4 early-return). Cell 0x00010378.
        {
            const uint32_t w177b_site = 0x402160F4u;
            const uint32_t w177b_stub = 0x8F112200u;
            const uint32_t orig = host.MemoryRead32(w177b_site);
            if (false && orig == 0x1AFFFFFAu) {  // W177b DISABLED: inverted beq killed android_app_entry on every D_1 pass (run261)
                const uint32_t code[] = {
                    EncodeMOVW(12, 0x0378u), EncodeMOVT(12, 0x9000u),
                    0xE58C0000u,          // str r0,[r12]     D_1's returned r0
                    0x0A000002u,          // beq -> idx 6 (D_1 ok, continue)
                    EncodeMOVW(3, 0x60E4u), EncodeMOVT(3, 0x4021u),
                    0xE12FFF13u,          // bx r3            -> early return
                    0xE51FF004u,          // ldr pc -> slot 8 (resume)
                    w177b_site + 8u,      // resume = 0x402160FC
                };
                for (size_t i = 0; i < sizeof(code) / sizeof(uint32_t); ++i)
                    host.MemoryWrite32(w177b_stub + static_cast<uint32_t>(i * 4), code[i]);
                host.MemoryWrite32(w177b_site, 0xE51FF004u);
                host.MemoryWrite32(w177b_site + 4, w177b_stub);
                host.InvalidateGuestCode(w177b_site, 8);
                host.InvalidateGuestCode(w177b_stub, 36);
                host.MemoryWrite32(0x93001790u, 3);  // W447P W177b
                LOGI("[W177b] D_1 return capture at 0x%08X", w177b_site);
            } else {
                LOGE("[W177b] unexpected word at 0x%08X: 0x%08X (want 0x1AFFFFFA)", w177b_site, orig);
            }
        }
        // W129 (run176): LLMemAllocate returned a garbage map-region pointer
        // (0xA1103FF0) for the [Dyn] Dynamic element pool -- the LLMem arena
        // sized by bzStartInput+0x4C (0x1000000 = 16 MB, Init_BZ
        // MOV R1,#0x1000000 at 0x40543A38) is exhausted by the time the
        // dynamics pools are created. Enlarge the arena to 64 MB.
        {
            const uint32_t w129site = 0x40543A38;
            const uint32_t oldr = host.MemoryRead32(w129site);
            // W145 (run192): W143 reverted W129's 64MB arena to 16MB, but
            // the 16MB arena stalled the boot EARLIER (boot=[0...] -- the
            // init pools don't fit). The 64MB arena (W129) let the boot
            // progress further (boot=[1 1 1 1 1 1 1 1 1]). Restore 64MB.
            if (oldr == 0xE3A01401u) {
                host.MemoryWrite32(w129site, 0xE3A01101u);  // mov r1,#0x04000000 (64MB)
                host.InvalidateGuestCode(w129site, 4);
                host.MemoryWrite32(0x93001790u, 2);  // W447P W145
                LOGI("[W145] LLMem arena restored to 64MB at 0x%08X", w129site);
            } else {
                LOGE("[W145] unexpected word at 0x%08X: 0x%08X", w129site, oldr);
            }
        }
        // W132 (run171): bzd_InitEntireDynamicsSystem returns 14 and the
        // failure branch (0x403DC0C4 B 0x403DBF64) re-runs the whole init
        // FOREVER -- billions of retries, the boot never advances. Route
        // the failure into the success continuation instead: the game then
        // boots WITHOUT dynamics (degraded physics) and reaches the menu,
        // while the underlying LLMemCreateNewPool failure is chased
        // separately with the W122/W128 captures.
        {
            const uint32_t w132site = 0x403DC0C4;
            const uint32_t orig = host.MemoryRead32(w132site);
            // expect B 0x403DBF64
            const int32_t imm = static_cast<int32_t>(0x403DBF64u - w132site - 8) >> 2;
            if (!kW196CleanSlate && orig == (0xEA000000u | (static_cast<uint32_t>(imm) & 0x00FFFFFFu))) {
                const int32_t new_imm = static_cast<int32_t>(0x403DC0E4u - w132site - 8) >> 2;
                host.MemoryWrite32(w132site, 0xEA000000u | (static_cast<uint32_t>(new_imm) & 0x00FFFFFFu));
                host.InvalidateGuestCode(w132site, 4);
                host.MemoryWrite32(0x93001790u, 1);  // W447P W132
                LOGI("[W132] bzd-failure retry branch redirected to success "
                     "continuation at 0x%08X (was 0x%08X)", w132site, orig);
            } else {
                LOGE("[W132] unexpected word at 0x%08X: 0x%08X", w132site, orig);
            }
        }
        // W83: invalidate patched code on ALL JIT contexts (not just the
        // calling thread's) so the game thread sees the patches.
        host.InvalidateGuestCodeAll(0x403DA000u, 0x3000u);
        host.MemoryWrite32(0x93001790u, 0);  // W447P W83
        LOGI("[W83] global JIT invalidation 0x403DA000+0x3000");
        // W52: state-cascade stage counters. The cascade is
        // CGameLube::Load -> ChangeSubState(3) -> Load_Phase2, Init_Stage2 ->
        // ChangeSubState(4) -> Init_Stage3, Init_Stage4, ... -- the last
        // counter >0 names the stage where the init thread dies.
        // W112: W52 cascade-stage probes RETIRED -- their single-displacement
        // stubs destroyed each site+4 instruction (CGameLube::Load /
        // Init_Stage2/3/4 ran with a data word patched over real code).
        LOGI("[W52] retired (site+4 clobber class, see W112)");
        {
            struct W52Stage { uint32_t tgt, cnt, disp, orig; };
            const W52Stage w52[] = {};
            (void)w52;
            uint32_t stub = 0x0065CF00;
            (void)stub;
            for (const auto& st : w52) {
                (void)st;
                LOGE("[W52] unexpected word at 0x%08X: 0x%08X", st.tgt,
                     host.MemoryRead32(st.tgt));
            }
        }
        // W51b: LLMemCreateNewPool entry probe (0x40DEA4). The dying thread's
        // last LR sits inside the allocator chain; this counts pool creations
        // and snapshots the requested size args (r0,r1,r2) at 0x65CD70.. so
        // the watchdog can read the LAST pool request before the exit.
        {
            const uint32_t w51cnt  = 0x0065CD60;
            const uint32_t w51args = 0x0065CD70;
            const uint32_t w51stub = 0x0065CE00;
            const uint32_t w51tgt  = 0x4040DEA4;
            const uint32_t w51next = host.MemoryRead32(w51tgt + 4);
            const uint32_t w51code[] = {
                EncodeMOVW(12, 0xCD70), EncodeMOVT(12, 0x65),
                0xE58C0000u,          // str r0,[r12]
                0xE58C1004u,          // str r1,[r12,#4]
                0xE58C2008u,          // str r2,[r12,#8]
                // W123 (run171): the W61 clamp (pool args <= 1 MB each) is
                // REMOVED. With the W112-era root causes fixed, the clamped
                // geometry broke bzd_InitEntireDynamicsSystem's physics
                // pools: bzd returned 14 and the guest looped the call 2.17
                // billion times (W122 counter) instead of finishing. The
                // original 3-billion-iteration fill hang is bounded by W72's
                // fill-loop cap, and an oversized allocation now fails
                // gracefully in GuestAlloc.
                EncodeMOVW(12, 0xCD60), EncodeMOVT(12, 0x65),
                0xE59C1000u,          // ldr r1,[r12]
                0xE2811001u,          // add r1,r1,#1
                0xE58C1000u,          // str r1,[r12]
                0xE92D4FF0u,          // push {r4-r11,lr}  (displaced)
                w51next,              // W112: displaced tgt+4 (was clobbered)
                0xE51FF004u,          // ldr pc,[pc,#-4]
                w51tgt + 8,           // resume (W112: was tgt+4)
            };
            for (size_t i = 0; i < sizeof(w51code) / sizeof(uint32_t); ++i)
                host.MemoryWrite32(w51stub + static_cast<uint32_t>(i * 4), w51code[i]);
            if (false && host.MemoryRead32(w51tgt) == 0xE92D4FF0u &&  // W487 (run644): RETIRED -- stub window 0x65CDxx was overwritten by guest data expansion
                (w51next & 0x0E000000u) != 0x0A000000u) {
                host.MemoryWrite32(w51tgt, 0xE51FF004u);
                host.MemoryWrite32(w51tgt + 4, w51stub);
                host.InvalidateGuestCode(w51tgt, 8);
                LOGI("[W51] LLMemCreateNewPool probe at 0x%08X -> stub 0x%08X",
                     w51tgt, w51stub);
            } else {
                LOGE("[W51] unexpected word at 0x%08X: 0x%08X", w51tgt,
                     host.MemoryRead32(w51tgt));
            }
        }
        // W48: StateMachine_Enter entry counter -- settles whether the loop
        // function is entered at all (proc=0 while enter>0 would mean the
        // exit happens between Enter's entry and its first Process call).
        {
            const uint32_t w48cnt  = 0x0065CD5C;
            const uint32_t w48stub = 0x0065CDE0;
            const uint32_t w48tgt  = 0x40569B8C;
            const uint32_t w48code[] = {
                EncodeMOVW(12, 0xCD5C), EncodeMOVT(12, 0x65),
                0xE59C1000u,          // ldr r1,[r12]
                0xE2811001u,          // add r1,r1,#1
                0xE58C1000u,          // str r1,[r12]
                0xE92D4008u,          // push {r3,lr}  (displaced)
                0xE51FF004u,          // ldr pc,[pc,#-4]
                w48tgt + 4,           // resume
            };
            for (size_t i = 0; i < sizeof(w48code) / sizeof(uint32_t); ++i)
                host.MemoryWrite32(w48stub + static_cast<uint32_t>(i * 4), w48code[i]);
            if (false && host.MemoryRead32(w48tgt) == 0xE92D4008u) {  // W487: RETIRED (corrupted stub window)
                host.MemoryWrite32(w48tgt, 0xE51FF004u);
                host.MemoryWrite32(w48tgt + 4, w48stub);
                host.InvalidateGuestCode(w48tgt, 8);
                LOGI("[W48] StateMachine_Enter probe at 0x%08X -> stub 0x%08X",
                     w48tgt, w48stub);
            } else {
                LOGE("[W48] unexpected word at 0x%08X: 0x%08X", w48tgt,
                     host.MemoryRead32(w48tgt));
            }
        }
        // W47: StateMachine_Process entry counter. If proc>0 the game loop
        // runs at all; combined with the W45 patch readback (w45=) this
        // settles whether the clean game-thread exit bypasses the loop.
        {
            const uint32_t w47cnt  = 0x0065CD58;
            const uint32_t w47stub = 0x0065CDA0;
            const uint32_t w47tgt  = 0x405694E4;
            const uint32_t w47code[] = {
                EncodeMOVW(12, 0xCD58), EncodeMOVT(12, 0x65),
                0xE59C1000u,          // ldr r1,[r12]
                0xE2811001u,          // add r1,r1,#1
                0xE58C1000u,          // str r1,[r12]
                0xE92D47F0u,          // push {r4-r10,lr}  (displaced)
                0xED2D8B02u,          // vpush {d8}        (displaced)
                0xE51FF004u,          // ldr pc,[pc,#-4]
                w47tgt + 8,           // resume
            };
            for (size_t i = 0; i < sizeof(w47code) / sizeof(uint32_t); ++i)
                host.MemoryWrite32(w47stub + static_cast<uint32_t>(i * 4), w47code[i]);
            if (false && host.MemoryRead32(w47tgt) == 0xE92D47F0u) {  // W487: RETIRED (corrupted stub window) -- Process entry jumped into guest data
                host.MemoryWrite32(w47tgt, 0xE51FF004u);
                host.MemoryWrite32(w47tgt + 4, w47stub);
                host.InvalidateGuestCode(w47tgt, 8);
                LOGI("[W47] StateMachine_Process probe at 0x%08X -> stub 0x%08X",
                     w47tgt, w47stub);
            } else {
                LOGE("[W47] unexpected word at 0x%08X: 0x%08X", w47tgt,
                     host.MemoryRead32(w47tgt));
            }
        }
        // W46 retired: the probe rewrote the live ARM EHABI entry and changed
        // R1 before the guest unwinder saved its initial register context.
        // Keep the native guest prologue intact; Find_exidx records lookups
        // without interposing on the exception state.
        // W45: StateMachine_Enter's loop exits when StateMachine_Process
        // returns nonzero (the guest reached its quit state). Under the
        // bridge the states advance without a visible movie/render, so the
        // game quit cleanly seconds after boot (run87/88/91: clean
        // exit-trap RET of android_app_entry, zero eglSwapBuffers ever).
        // Patch the loop's `beq` (0x569BA0) to `b` -- the loop keeps
        // ticking no matter what Process returns, so the renderer keeps
        // running while the real quit cause is investigated.
        {
            const uint32_t w45loop = 0x40569BA0;
            if (host.MemoryRead32(w45loop) == 0x0AFFFFFCu) {
                host.MemoryWrite32(w45loop, 0xEAFFFFFCu);  // beq -> b
                host.InvalidateGuestCode(w45loop, 4);
                LOGI("[W45] StateMachine_Enter loop forced infinite at 0x%08X", w45loop);
            } else {
                LOGE("[W45] unexpected word at 0x%08X: 0x%08X", w45loop,
                     host.MemoryRead32(w45loop));
            }
        }
        // Retired W39: its two-word tail-jump patch replaced BL call sites
        // without setting LR, and P1's target literal was missing a hex digit.
        // Keep the original guest BL instructions and their ABI semantics.
        // W36: registration diagnostics -- entry probes on the three
        // NovaFile_Initialise registration calls.
        auto write_probe = [&host](uint32_t stub_addr, const uint32_t* code,
                                   size_t words, uint32_t patch_addr,
                                   uint32_t orig) {
            for (size_t i = 0; i < words; ++i)
                host.MemoryWrite32(stub_addr + static_cast<uint32_t>(i * 4), code[i]);
            if (host.MemoryRead32(patch_addr) != orig) return false;
            host.MemoryWrite32(patch_addr, 0xE51FF004u);
            host.MemoryWrite32(patch_addr + 4, stub_addr);
            host.InvalidateGuestCode(patch_addr, 8);
            return true;
        };
        // W112: W36/W38 probes RETIRED -- single-displacement stubs destroyed
        // each site+4 instruction. bz_FileExists / AddWADContent /
        // ReadAppInfo / PDAds_Init / AddDirectoryContent all ran with a data
        // word patched over their second instruction.
        (void)write_probe;
        LOGI("[W36] retired (site+4 clobber class, see W112)");
    }();
}

static void EnsureCpuCountStub(DynarmicHost& host) {
    static std::once_flag once;
    std::call_once(once, [&host] {
        constexpr size_t kCount = sizeof(kCpuCountStub) / sizeof(kCpuCountStub[0]);
        for (size_t i = 0; i < kCount; ++i) {
            host.MemoryWrite32(kCpuCountStubAddr + static_cast<uint32_t>(i * 4), kCpuCountStub[i]);
        }
        const uint32_t original = host.MemoryRead32(kCpuCountPatchedEntry);
        if (original != kCpuCountOrigPush) {
            LOGE("[android_getCpuCount] unexpected entry word 0x%08X -- patch skipped", original);
            return;
        }
        host.MemoryWrite32(kCpuCountPatchedEntry, 0xE51FF004u);
        host.MemoryWrite32(kCpuCountPatchedEntry + 4, kCpuCountStubAddr);
        host.InvalidateGuestCode(kCpuCountPatchedEntry, 8);
        LOGI("[android_getCpuCount] constant-4 stub installed (patched 0x%08X)",
             kCpuCountPatchedEntry);
    });
}

static const uint32_t kCxaThrowStub[] = {
    0xE92D000F,  // 0x65AD40 PUSH {r0-r3, lr}
    0xE5912004,  // 0x65AD44 LDR  r2, [r1, #4]     ; typeinfo->__name
    EncodeMOVW(1, 0xD80),   // 0x65AD48 MOVW r1, #0xD80
    EncodeMOVT(1, 0x65),    // 0x65AD4C MOVT r1, #0x65     ; r1 = 0x0065AD80
    EncodeMOVW(3, 0x71EE),  // 0x65AD50 MOVW r3, #0x71EE
    EncodeMOVT(3, 0x71EE),  // 0x65AD54 MOVT r3, #0x71EE      ; r3 = 0x71EE71EE (W9: was MOVT r7)
    0xE5813000,  // 0x65AD58 STR  r3, [r1]         ; magic
    0xE5811004,  // 0x65AD5C STR  lr, [r1, #4]     ; throw site
    0xE5810008,  // 0x65AD60 STR  r0, [r1, #8]     ; exception object
    0xE581200C,  // 0x65AD64 STR  r2, [r1, #12]    ; name pointer
    0xE8BD000F,  // 0x65AD68 POP  {r0-r3, lr}
    0xE92D48F0,  // 0x65AD6C PUSH {R4-R7, R11, LR} ; displaced prologue
    0xE51FF004,  // 0x65AD70 LDR  pc, [pc, #-4]    ; resume at +4
    0x4058E018,  // 0x65AD74 (literal) resume address
};

static void EnsureCxaThrowDumper(DynarmicHost& host);
void InstallCxaThrowDumper(DynarmicHost& host) { EnsureCxaThrowDumper(host); }

static void EnsureCxaThrowDumper(DynarmicHost& host) {
    static std::once_flag once;
    std::call_once(once, [&host] {
        constexpr size_t kCount = sizeof(kCxaThrowStub) / sizeof(kCxaThrowStub[0]);
        for (size_t i = 0; i < kCount; ++i) {
            host.MemoryWrite32(kCxaThrowStubAddr + static_cast<uint32_t>(i * 4), kCxaThrowStub[i]);
        }
        const uint32_t original = host.MemoryRead32(kCxaThrowPatchedEntry);
        if (original != kCxaThrowOrigPush) {
            LOGE("[__cxa_throw] unexpected entry word 0x%08X -- diag patch skipped", original);
            return;
        }
        host.MemoryWrite32(kCxaThrowPatchedEntry, 0xE51FF004u);
        host.MemoryWrite32(kCxaThrowPatchedEntry + 4, kCxaThrowStubAddr);
        host.InvalidateGuestCode(kCxaThrowPatchedEntry, 8);
        LOGI("[__cxa_throw] dump trampoline installed (patched 0x%08X)",
             kCxaThrowPatchedEntry);
    });
}

// W10: std::__throw_length_error (sub_5D82D4, guest entry 0x405D82D4) dump
// trampoline. The boot terminate is std::length_error thrown through this
// systemic helper (393 xrefs); the stub snapshots the message pointer (r0)
// and the throw site (lr) before resuming. Encodings use the CORRECTED
// MOVW/MOVT layout: imm4 = high nibble in bits 19:16, Rd in bits 15:12.
constexpr uint32_t kThrowLenStubAddr = 0x0065AC20;
constexpr uint32_t kThrowLenScratchAddr = 0x0065AC60;
constexpr uint32_t kThrowLenPatchedEntry = 0x405D82D4;  // libParsons + 0x5D82D4
constexpr uint32_t kThrowLenOrigPush = 0xE92D48F0;      // PUSH {R4-R7,R11,LR}
constexpr uint32_t kThrowLenMagic = 0x71EE71EE;

static const uint32_t kThrowLenStub[] = {
    0xE92D000F,  // 0x65AC20 PUSH {r0-r3, lr}
    EncodeMOVW(1, 0xC60),   // 0x65AC24 MOVW r1, #0xC60
    EncodeMOVT(1, 0x6),     // 0x65AC28 MOVT r1, #0x6      ; r1 = 0x0065AC60 (scratch)
    EncodeMOVW(2, 0x71EE),  // 0x65AC2C MOVW r2, #0x71EE
    EncodeMOVT(2, 0x71EE),  // 0x65AC30 MOVT r2, #0x71EE      ; r2 = 0x71EE71EE (W9: was MOVT r7)
    0xE5812000,  // 0x65AC34 STR  r2, [r1]          ; magic
    0xE5810004,  // 0x65AC38 STR  r0, [r1, #4]      ; message pointer (const char*)
    0xE581E008,  // 0x65AC3C STR  lr, [r1, #8]      ; throw site
    0xE8BD000F,  // 0x65AC40 POP  {r0-r3, lr}
    0xE92D48F0,  // 0x65AC44 PUSH {R4-R7, R11, LR}  ; displaced prologue word 1
    0xE1A07000,  // 0x65AC48 MOV  R7, R0            ; displaced prologue word 2
    0xE28DB014,  // 0x65AC4C ADD  R11, SP, #0x14    ; displaced prologue word 3
    0xE51FF004,  // 0x65AC50 LDR  pc, [pc, #-4]     ; resume at entry+8
    0x405D82DC,  // 0x65AC54 (literal) resume address
};

static void EnsureThrowLenDumper(DynarmicHost& host);
void InstallThrowLenDumper(DynarmicHost& host) { EnsureThrowLenDumper(host); }

static void EnsureThrowLenDumper(DynarmicHost& host) {
    static std::once_flag once;
    std::call_once(once, [&host] {
        constexpr size_t kCount = sizeof(kThrowLenStub) / sizeof(kThrowLenStub[0]);
        for (size_t i = 0; i < kCount; ++i) {
            host.MemoryWrite32(kThrowLenStubAddr + static_cast<uint32_t>(i * 4), kThrowLenStub[i]);
        }
        const uint32_t original = host.MemoryRead32(kThrowLenPatchedEntry);
        if (original != kThrowLenOrigPush) {
            LOGE("[__throw_length_error] unexpected entry word 0x%08X -- diag patch skipped", original);
            return;
        }
        // Absolute literal jump: LDR pc, [pc, #-4] at the entry, stub address
        // as the literal right behind it.
        host.MemoryWrite32(kThrowLenPatchedEntry, 0xE51FF004u);
        host.MemoryWrite32(kThrowLenPatchedEntry + 4, kThrowLenStubAddr);
        host.InvalidateGuestCode(kThrowLenPatchedEntry, 8);
        LOGI("[__throw_length_error] dump trampoline installed (patched 0x%08X)",
             kThrowLenPatchedEntry);
    });
}

// pthread_once return stub (guest ARM code, written once into the executable
// scratch region below the SVC trampoline area):
//   BLX r1              -- call the init routine (r1 = init_routine, bit0
//                          selects its mode); BLX sets lr = 0x1E804
//   LDR pc, [sp], #4    -- pop the saved pthread_once caller return and go there
constexpr uint32_t kOnceReturnStubAddr = 0x0065AB00;
static const uint32_t kOnceReturnStub[] = {
    0xE12FFF31,  // 0x65AB00 BLX  r1               ; call init_routine (lr←0x65AB04)
    0xE49DF004,  // 0x65AB04 LDR  pc, [sp], #4     ; return to caller's LR (pushed by the thunk)
};

static void EnsureOnceReturnStub(DynarmicHost& host) {
    static std::once_flag once;
    std::call_once(once, [&host] {
        constexpr size_t kCount = sizeof(kOnceReturnStub) / sizeof(kOnceReturnStub[0]);
        for (size_t i = 0; i < kCount; ++i) {
            host.MemoryWrite32(kOnceReturnStubAddr + static_cast<uint32_t>(i * 4), kOnceReturnStub[i]);
        }
        LOGI("[pthread_once] return stub installed at 0x%08X", kOnceReturnStubAddr);
    });
}

// Guest printf formatter
static std::string FormatGuestString(Dynarmic::A32::Jit& jit, DynarmicHost& host, const char* fmt, int first_arg_reg) {
    GuestWords32<Dynarmic::A32::Jit, DynarmicHost> words{
        jit, host, static_cast<uint32_t>(first_arg_reg), false};
    return GuestPrintf32::Format(host, fmt, words);
}

void GuestPthreadReleaseHeldMutexes() {
    for (auto& h : t_held_guest_mutexes) {
        for (uint32_t d = 0; d < h.depth; ++d) h.m->unlock();
    }
    t_held_guest_mutexes.clear();
}

void ThunkManager::RegisterLibcThunks() {
    uint8_t* mem = m_host.GetGuestMemoryBase();

    // W370 (run500): the guard storage NO LONGER lives at 0x100. run499:
    // 22 deaths, every one an UndefinedInstruction at PC=0x100 -- the old
    // __stack_chk_guard address smeared into return slots (glue POP {pc},
    // handle_cmd, thread-exit roots) and the canary value 0x00000AFF
    // executed as an unallocated word. Two changes: (1) the guard value
    // moves to the W325 data block at 0x8F010800 so both resolvers agree,
    // and (2) the word at 0x100 becomes a BX LR landing pad so any stray
    // control transfer lands, returns, and the caller completes instead
    // of killing the thread.
    *reinterpret_cast<uint32_t*>(mem + 0x100) = 0xE12FFF1Eu;  // BX LR
    *reinterpret_cast<uint32_t*>(mem + 0x8F010800u) = 0x6D4F5354u;
    memset(mem + 0x200, 0, 3 * 84);
    *reinterpret_cast<uint32_t*>(mem + 0x300) = 0;

    RegisterSymbol("__stack_chk_guard", 0x8F010800u);
    RegisterSymbol("__sF", 0x200);

    RegisterThunk("__errno", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0x300;
    });

    // -------------------------------------------------------------
    // Additional POSIX & Math Thunks for FMOD
    // -------------------------------------------------------------

    auto read_double_01 = [](const Dynarmic::A32::Jit& jit) -> double {
        uint64_t raw = (static_cast<uint64_t>(jit.Regs()[1]) << 32) | jit.Regs()[0];
        double val;
        memcpy(&val, &raw, sizeof(double));
        return val;
    };
    auto write_double_01 = [](Dynarmic::A32::Jit& jit, double val) {
        uint64_t raw;
        memcpy(&raw, &val, sizeof(double));
        jit.Regs()[0] = static_cast<uint32_t>(raw & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>((raw >> 32) & 0xFFFFFFFF);
    };

    RegisterThunk("sin", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, sin(read_double_01(jit)));
    });
    RegisterThunk("cos", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, cos(read_double_01(jit)));
    });
    RegisterThunk("tan", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, tan(read_double_01(jit)));
    });
    RegisterThunk("acos", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, acos(read_double_01(jit)));
    });
    RegisterThunk("atan2", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        double y = read_double_01(jit);
        uint64_t raw_x = (static_cast<uint64_t>(jit.Regs()[3]) << 32) | jit.Regs()[2];
        double x;
        memcpy(&x, &raw_x, sizeof(double));
        write_double_01(jit, atan2(y, x));
    });
    RegisterThunk("exp", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, exp(read_double_01(jit)));
    });
    RegisterThunk("log", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, log(read_double_01(jit)));
    });
    RegisterThunk("log10", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, log10(read_double_01(jit)));
    });
    RegisterThunk("log10f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float res = log10f(val);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });
    RegisterThunk("pow", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        double x = read_double_01(jit);
        uint64_t raw_y = (static_cast<uint64_t>(jit.Regs()[3]) << 32) | jit.Regs()[2];
        double y;
        memcpy(&y, &raw_y, sizeof(double));
        write_double_01(jit, pow(x, y));
    });
    RegisterThunk("sqrt", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, sqrt(read_double_01(jit)));
    });
    RegisterThunk("floor", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, floor(read_double_01(jit)));
    });
    RegisterThunk("rint", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, rint(read_double_01(jit)));
    });
    RegisterThunk("lrintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        jit.Regs()[0] = static_cast<uint32_t>(lrintf(val));
    });
    RegisterThunk("frexp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint64_t raw = (static_cast<uint64_t>(jit.Regs()[1]) << 32) | jit.Regs()[0];
        double val;
        memcpy(&val, &raw, sizeof(double));
        uint32_t exp_ptr = jit.Regs()[2];
        int exp_val = 0;
        double res = frexp(val, &exp_val);
        if (exp_ptr) host.MemoryWrite32(exp_ptr, static_cast<uint32_t>(exp_val));
        uint64_t res_raw;
        memcpy(&res_raw, &res, sizeof(double));
        jit.Regs()[0] = static_cast<uint32_t>(res_raw & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>((res_raw >> 32) & 0xFFFFFFFF);
    });
    RegisterThunk("ldexp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint64_t raw = (static_cast<uint64_t>(jit.Regs()[1]) << 32) | jit.Regs()[0];
        double val;
        memcpy(&val, &raw, sizeof(double));
        int exp_val = static_cast<int>(jit.Regs()[2]);
        double res = ldexp(val, exp_val);
        uint64_t res_raw;
        memcpy(&res_raw, &res, sizeof(double));
        jit.Regs()[0] = static_cast<uint32_t>(res_raw & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>((res_raw >> 32) & 0xFFFFFFFF);
    });

    // Memory & Strings
    RegisterThunk("memmove", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dst = jit.Regs()[0];
        uint32_t src = jit.Regs()[1];
        uint32_t n = jit.Regs()[2];
        void* h_dst = GuestToHost(host.GetGuestMemoryBase(), dst);
        const void* h_src = GuestToHost(host.GetGuestMemoryBase(), src);
        if (h_dst && h_src && n > 0) memmove(h_dst, h_src, n);
        jit.Regs()[0] = dst;
    });
    RegisterThunk("memmem", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t haystack = jit.Regs()[0];
        uint32_t hlen = jit.Regs()[1];
        uint32_t needle = jit.Regs()[2];
        uint32_t nlen = jit.Regs()[3];
        const void* h_hay = GuestToHost(host.GetGuestMemoryBase(), haystack);
        const void* h_nee = GuestToHost(host.GetGuestMemoryBase(), needle);
        if (h_hay && h_nee && hlen >= nlen) {
            const void* found = memmem(h_hay, hlen, h_nee, nlen);
            if (found) {
                uint32_t offset = static_cast<uint32_t>(reinterpret_cast<const uint8_t*>(found) - reinterpret_cast<const uint8_t*>(h_hay));
                jit.Regs()[0] = haystack + offset;
                return;
            }
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("strcat", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dst = jit.Regs()[0];
        uint32_t src = jit.Regs()[1];
        char* h_dst = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), dst));
        const char* h_src = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), src));
        if (h_dst && h_src) strcat(h_dst, h_src);
        jit.Regs()[0] = dst;
    });
    RegisterThunk("strncpy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dst = jit.Regs()[0];
        uint32_t src = jit.Regs()[1];
        uint32_t n = jit.Regs()[2];
        char* h_dst = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), dst));
        const char* h_src = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), src));
        if (h_dst && h_src && n > 0) strncpy(h_dst, h_src, n);
        jit.Regs()[0] = dst;
    });
    RegisterThunk("strncasecmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t s1 = jit.Regs()[0];
        uint32_t s2 = jit.Regs()[1];
        uint32_t n = jit.Regs()[2];
        const char* h_s1 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), s1));
        const char* h_s2 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), s2));
        jit.Regs()[0] = (h_s1 && h_s2) ? static_cast<uint32_t>(strncasecmp(h_s1, h_s2, n)) : 0;
    });
    RegisterThunk("strtol", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t nptr = jit.Regs()[0];
        uint32_t endptr = jit.Regs()[1];
        int base = static_cast<int>(jit.Regs()[2]);
        const char* h_nptr = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), nptr));
        if (!h_nptr) { jit.Regs()[0] = 0; return; }
        char* h_end = nullptr;
        long val = strtol(h_nptr, &h_end, base);
        if (endptr && h_end) {
            uint32_t offset = static_cast<uint32_t>(h_end - h_nptr);
            host.MemoryWrite32(endptr, nptr + offset);
        }
        jit.Regs()[0] = static_cast<uint32_t>(val);
    });
    RegisterThunk("puts", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t s = jit.Regs()[0];
        const char* str = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), s));
        if (str) LOGI("[puts] %s", str);
        jit.Regs()[0] = 1;
    });
    RegisterThunk("vsnprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t buf = jit.Regs()[0];
        uint32_t size = jit.Regs()[1];
        uint32_t fmt = jit.Regs()[2];
        char* h_buf = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), buf));
        const char* h_fmt = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), fmt));
        if (!h_buf || size == 0) { jit.Regs()[0] = 0; return; }
        if (!h_fmt) { h_buf[0] = 0; jit.Regs()[0] = 0; return; }
        strncpy(h_buf, h_fmt, size - 1);
        h_buf[size - 1] = 0;
        jit.Regs()[0] = static_cast<uint32_t>(strlen(h_buf));
    });

    // Time & Threading
    RegisterThunk("gettimeofday", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t tv_ptr = jit.Regs()[0];
        if (tv_ptr) {
            struct timeval tv;
            gettimeofday(&tv, nullptr);
            host.MemoryWrite32(tv_ptr + 0, static_cast<uint32_t>(tv.tv_sec));
            host.MemoryWrite32(tv_ptr + 4, static_cast<uint32_t>(tv.tv_usec));
        }
        jit.Regs()[0] = 0;
    });
    // Causal repair for the post-EGL gDynamic_vb_map corruption: the old usleep
    // thunk returned instantly, which collapsed the game's background-thread
    // timing. The image-processing thread (usleep 100 us), the TaskManager
    // workers (usleep 1 ms) and the loader rely on usleep yielding the CPU; with
    // a no-op they all spun at 100% CPU, and the game's pooled allocator (whose
    // LLMemFreePoolItem fast paths run outside alloc_critical_section, exactly as
    // on arm32) then saw truly concurrent alloc/free from 8+ guest threads during
    // the second init_display reload. Pool free-list races double-handed blocks
    // (the 0x18 Rb_tree nodes and the map object share that path) and corrupted
    // gDynamic_vb_map's tree links. Real sleeps restore the arm32 timing
    // separation the game was written against.
    RegisterThunk("usleep", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t usec = jit.Regs()[0];
        // W40: rate-limited caller-LR sample -- locates the guest loop the
        // game thread is spinning in (usleep-dominant stalls).
        static std::atomic<uint32_t> w40seq{0};
        if ((w40seq.fetch_add(1) & 0x7FFu) == 0) {
            char b[96];
            snprintf(b, sizeof(b), "W40USLEEP lr=0x%08X usec=%u sp=0x%08X "
                     "m0=0x%08X m4=0x%08X",
                     jit.Regs()[14], usec, jit.Regs()[13],
                     host.MemoryRead32(jit.Regs()[13]),
                     host.MemoryRead32(jit.Regs()[13] + 4));
            DiagTrace::Note(b);
        }
        if (usec == 0) {
            sched_yield();
        } else {
            // usleep's POSIX domain is [0, 1e6); clamp defensively.
            usleep(static_cast<useconds_t>(usec > 999999u ? 999999u : usec));
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("nanosleep", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t req = jit.Regs()[0];
        if (req) {
            timespec t{};
            t.tv_sec = static_cast<time_t>(host.MemoryRead32(req));
            t.tv_nsec = static_cast<long>(host.MemoryRead32(req + 4));
            // Clamp to 1 s: no guest waiter here is meant to block longer.
            if (t.tv_sec > 1 || (t.tv_sec == 1 && t.tv_nsec > 0)) {
                t.tv_sec = 1;
                t.tv_nsec = 0;
            }
            nanosleep(&t, nullptr);
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("lrand48", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = static_cast<uint32_t>(lrand48());
    });
    RegisterThunk("srand48", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        srand48(static_cast<long>(jit.Regs()[0]));
        jit.Regs()[0] = 0;
    });
    RegisterThunk("utime", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("unlink", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        jit.Regs()[0] = BridgeIsObbPath(path) ? static_cast<uint32_t>(-1) : 0u;
    });
    RegisterThunk("chown", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("fcntl", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });

    // Semaphores & Pthread
    RegisterThunk("sem_init", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sem_ptr = jit.Regs()[0];
        uint32_t val = jit.Regs()[2];
        if (sem_ptr) host.MemoryWrite32(sem_ptr, val);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("sem_destroy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("sem_wait", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sem_ptr = jit.Regs()[0];
        if (sem_ptr) {
            uint32_t val = host.MemoryRead32(sem_ptr);
            if (val > 0) {
                host.MemoryWrite32(sem_ptr, val - 1);
            }
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("sem_trywait", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sem_ptr = jit.Regs()[0];
        if (sem_ptr) {
            uint32_t val = host.MemoryRead32(sem_ptr);
            if (val > 0) {
                host.MemoryWrite32(sem_ptr, val - 1);
            }
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("sem_post", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sem_ptr = jit.Regs()[0];
        if (sem_ptr) {
            uint32_t val = host.MemoryRead32(sem_ptr);
            host.MemoryWrite32(sem_ptr, val + 1);
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("sem_post", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sem_ptr = jit.Regs()[0];
        if (sem_ptr) {
            uint32_t val = host.MemoryRead32(sem_ptr);
            host.MemoryWrite32(sem_ptr, val + 1);
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_self", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0x1001;
    });
    RegisterThunk("pthread_attr_init", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_attr_destroy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_attr_setdetachstate", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_attr_setstacksize", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_mutex_init", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t mtx = jit.Regs()[0];
        if (mtx) host.MemoryWrite32(mtx, 0);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_mutex_destroy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_mutexattr_init", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_mutexattr_settype", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_create", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t thread_out = jit.Regs()[0];
        uint32_t start_func = jit.Regs()[2];
        uint32_t arg = jit.Regs()[3];
        // W449: LOGE survives throttling -- every guest thread spawn must be
        // visible to correlate with the W435 RF log (the android_app_entry
        // spawn was suspected missing).
        LOGE("[W449] pthread_create func=0x%08X arg=0x%08X out=0x%08X",
             start_func, arg, thread_out);
        // W454: reach bit9 -- a guest pthread spawn was requested.
        host.MemoryWrite32(0x930017A4u, host.MemoryRead32(0x930017A4u) | (1u << 9));
        AddGuestThreadWorker(start_func, arg);
        if (arg) {
            // Set FMOD Thread / AsyncThread m_running flags to 1
            host.MemoryWrite8(arg + 0x10c, 1);
            host.MemoryWrite8(arg + 0x134, 1);
            uint32_t worker_func = host.MemoryRead32(arg + 0x120);
            uint32_t worker_arg = host.MemoryRead32(arg + 0x110);
            LOGI("pthread_create worker: func=0x%08X, arg=0x%08X", worker_func, worker_arg);
        }
        if (thread_out) host.MemoryWrite32(thread_out, 0x1000 + GetGuestThreadWorkers().size());
        host.SpawnGuestThread(start_func, arg);
        jit.Regs()[0] = 0; // Return OK
    });

    // Sockets & Net (Stubs)
    RegisterThunk("socket", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("bind", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("listen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("accept", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("connect", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("send", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("recv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("select", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("setsockopt", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("inet_addr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("gethostbyname", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });

    // Android & Runtime
    RegisterThunk("__android_log_write", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int prio = static_cast<int>(jit.Regs()[0]);
        uint32_t tag_ptr = jit.Regs()[1];
        uint32_t msg_ptr = jit.Regs()[2];
        const char* tag = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), tag_ptr));
        const char* msg = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), msg_ptr));
        if (tag && msg) __android_log_write(prio, tag, msg);
        jit.Regs()[0] = 1;
    });
    RegisterThunk("__aeabi_atexit", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__cxa_pure_virtual", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGE("__cxa_pure_virtual called!");
        jit.Regs()[0] = 0;
    });
    RegisterThunk("__cxa_type_match", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__cxa_begin_cleanup", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__cxa_call_unexpected", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    // Resolve each guest PC against the .ARM.exidx table of the ELF image
    // containing it. The table itself is located after most text, so comparing
    // pc against the table address is not a valid module-membership check.
    RegisterThunk("__gnu_Unwind_Find_exidx", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t pc = jit.Regs()[0];
        const uint32_t pcount = jit.Regs()[1];
        uint32_t start = 0;
        uint32_t end = 0;
        const bool has_image_table = host.GetExidxRangeForPc(pc, start, end);
        if (!has_image_table || start == 0 || end <= start) {
            if (pcount) host.MemoryWrite32(pcount, 0);
            jit.Regs()[0] = 0;
            static std::atomic<uint32_t> miss_count{0};
            if (miss_count.fetch_add(1) < 64) {
                char b[112];
                snprintf(b, sizeof(b), "FIND_EXIDX MISS pc=0x%08X (no image table)", pc);
                DiagTrace::NotePersist(b);
            }
            return;
        }
        const uint32_t table_bytes = end - start;
        const uint32_t n = table_bytes / 8;
        if ((table_bytes % 8) != 0 || !n) {
            if (pcount) host.MemoryWrite32(pcount, 0);
            jit.Regs()[0] = 0;
            static std::atomic<uint32_t> miss_count{0};
            if (miss_count.fetch_add(1) < 64) {
                char b[112];
                snprintf(b, sizeof(b), "FIND_EXIDX MISS pc=0x%08X (invalid table range)", pc);
                DiagTrace::NotePersist(b);
            }
            return;
        }
        // The guest's __gnu_Unwind_RaiseException calls sub_5F1064 to search
        // this table itself. Per the ARM EABI Find_exidx contract, return the
        // table base and its complete entry count; preselecting an entry here
        // causes the guest binary search to operate on a truncated/misaligned
        // suffix and can turn a valid C++ throw into an uncaught exception.
        if (pcount) host.MemoryWrite32(pcount, n);
        jit.Regs()[0] = start;
        static std::atomic<uint32_t> ok_count{0};
        if (ok_count.fetch_add(1) < 16) {
            char b[112];
            snprintf(b, sizeof(b), "FIND_EXIDX TABLE pc=0x%08X start=0x%08X count=%u",
                     pc, start, n);
            DiagTrace::NotePersist(b);
        }
    });

    RegisterThunk("__aeabi_unwind_cpp_pr0", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        // W2 diagnostic: ARM EABI personality routine level-0. The guest
        // unwinder calls this on every frame it walks; log the call sites so
        // the unwind chain is visible.
        static std::atomic<uint32_t> diag_calls{0};
        const uint32_t cnt = diag_calls.fetch_add(1);
        if (cnt < 64) {
            char b[128];
            snprintf(b, sizeof(b), "PR0 lr=0x%08X", jit.Regs()[14]);
            DiagTrace::Note(b);
        }
        jit.Regs()[0] = 0;  // _URC_CONTINUE_UNWIND
    });

    RegisterThunk("__aeabi_unwind_cpp_pr1", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::atomic<uint32_t> diag_calls{0};
        const uint32_t cnt = diag_calls.fetch_add(1);
        if (cnt < 64) {
            char b[128];
            snprintf(b, sizeof(b), "PR1 lr=0x%08X", jit.Regs()[14]);
            DiagTrace::Note(b);
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("dlopen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t name_ptr = jit.Regs()[0];
        const char* name = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), name_ptr));
        LOGI("dlopen('%s', %d)", name ? name : "NULL", jit.Regs()[1]);
        jit.Regs()[0] = 0x50005000; // Non-null handle
    });
    RegisterThunk("dlclose", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("dlsym", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sym_ptr = jit.Regs()[1];
        const char* sym = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), sym_ptr));
        LOGI("dlsym(handle, '%s')", sym ? sym : "NULL");
        if (sym) {
            if (strncmp(sym, "SL_IID_", 7) == 0) {
                uint32_t iid_ptr = GetOpenSLESInterfacePointer(sym);
                if (iid_ptr != 0) {
                    jit.Regs()[0] = iid_ptr;
                    return;
                }
            }
            if (strcmp(sym, "slCreateEngine") == 0) {
                jit.Regs()[0] = host.GetThunkManager().GetOrCreateThunkAddress("slCreateEngine");
                return;
            }
            const uint32_t registered = host.GetThunkManager().FindRegisteredSymbol(sym);
            if (registered) {
                jit.Regs()[0] = registered;
                return;
            }
            if (host.GetFmodEventLoader()) {
                uint32_t addr = host.GetFmodEventLoader()->GetSymbolAddress(sym);
                if (addr != 0) { jit.Regs()[0] = addr; return; }
            }
            if (host.GetFmodEventLLoader()) {
                uint32_t addr = host.GetFmodEventLLoader()->GetSymbolAddress(sym);
                if (addr != 0) { jit.Regs()[0] = addr; return; }
            }
            if (host.GetFmodExLoader()) {
                uint32_t addr = host.GetFmodExLoader()->GetSymbolAddress(sym);
                if (addr != 0) { jit.Regs()[0] = addr; return; }
            }
            if (host.GetFmodExLLoader()) {
                uint32_t addr = host.GetFmodExLLoader()->GetSymbolAddress(sym);
                if (addr != 0) { jit.Regs()[0] = addr; return; }
            }
            uint32_t addr = host.GetThunkManager().GetOrCreateThunkAddress(sym);
            jit.Regs()[0] = addr;
            return;
        }
        jit.Regs()[0] = 0;
    });

    // Real getauxval: the dlsym-created default stub returned 0 for AT_HWCAP,
    // so the game's CPU-feature probe fell back to parsing /proc/cpuinfo for
    // ARMv7 feature lines. On an arm64 host that parse never matches and the
    // probe retries forever (run5: 13M open("/proc/cpuinfo") in the
    // sub_17ADE8 reader, work/phase7_n5_route/run5). Report the arm32
    // HWCAP bits of a modern Cortex-A class core instead.
    RegisterThunk("getauxval", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t type = jit.Regs()[0];
        uint32_t value = 0;
        if (type == 6) {  // AT_PAGESZ
            value = 4096;
        } else if (type == 16) {  // AT_HWCAP (arm32 layout)
            value = (1u << 6)    // HWCAP_VFP
                  | (1u << 7)    // HWCAP_EDSP
                  | (1u << 12)   // HWCAP_NEON
                  | (1u << 13)   // HWCAP_VFPv3
                  | (1u << 15)   // HWCAP_TLS
                  | (1u << 16)   // HWCAP_VFPv4
                  | (1u << 17)   // HWCAP_IDIVA
                  | (1u << 18)   // HWCAP_IDIVT
                  | (1u << 19);  // HWCAP_VFPD32
        }
        // AT_HWCAP2 (26) and everything else: 0.
        jit.Regs()[0] = value;
    });

    RegisterThunk("__system_property_get", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* name = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        uint32_t val_ptr = jit.Regs()[1];
        LOGI("__system_property_get('%s')", name ? name : "null");
        if (name && val_ptr) {
            char* out = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), val_ptr));
            if (strcmp(name, "ro.build.version.sdk") == 0) {
                strcpy(out, "28");
                jit.Regs()[0] = 2;
                return;
            }
            strcpy(out, "");
        }
        jit.Regs()[0] = 0;
    });

    // C++ Memory Allocation operators
    RegisterThunk("_Znaj", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t size = jit.Regs()[0];
        jit.Regs()[0] = host.GuestAlloc(size, 8);
    });

    RegisterThunk("_Znwj", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t size = jit.Regs()[0];
        jit.Regs()[0] = host.GuestAlloc(size, 8);
    });

    RegisterThunk("_ZnajRKSt9nothrow_t", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t size = jit.Regs()[0];
        jit.Regs()[0] = host.GuestAlloc(size, 8);
    });

    RegisterThunk("_ZnwjRKSt9nothrow_t", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t size = jit.Regs()[0];
        jit.Regs()[0] = host.GuestAlloc(size, 8);
    });

    RegisterThunk("_ZdaPv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        host.GuestFree(jit.Regs()[0]);
    });

    RegisterThunk("_ZdlPv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        host.GuestFree(jit.Regs()[0]);
    });

    RegisterThunk("_ZNSt8ios_base4InitC1Ev", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("_ZNSt8ios_base4InitD1Ev", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});

    // Memory Allocation inside guest space
    RegisterThunk("malloc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t size = jit.Regs()[0];
        uint32_t addr = host.GuestAlloc(size, 8);
        // W50: big-malloc trace -- the guest pool-growth path
        // (LLMemCreateNewPool) retries forever; log every >=1 MB request
        // with the result.
        {
            static std::atomic<uint32_t> w50{0};
            if (w50.fetch_add(1) < 200) {
                char b[128];
                snprintf(b, sizeof(b), "W50 malloc size=%zu -> 0x%08X lr=0x%08X",
                         size, addr, jit.Regs()[14]);
                DiagTrace::NotePersist(b);
            }
        }
        // W254 (run359): trace small mallocs -- the LLMem string-rep
        // path (PDMalloc 30..64B) must show up here when it works.
        {
            static std::atomic<uint32_t> w254{0};
            if (size >= 24 && size <= 64 && w254.fetch_add(1) < 32) {
                char b[128];
                snprintf(b, sizeof(b), "W254 malloc size=%zu -> 0x%08X lr=0x%08X",
                         size, addr, jit.Regs()[14]);
                DiagTrace::NotePersist(b);
            }
        }
        jit.Regs()[0] = addr;
    });

    RegisterThunk("calloc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t num = jit.Regs()[0];
        size_t size = jit.Regs()[1];
        uint32_t addr = host.GuestAlloc(num * size, 8);
        if (addr) {
            memset(GuestToHost(host.GetGuestMemoryBase(), addr), 0, num * size);
        }
        jit.Regs()[0] = addr;
    });

    RegisterThunk("realloc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t old_addr = jit.Regs()[0];
        size_t new_size = jit.Regs()[1];
        uint32_t new_addr = host.GuestAlloc(new_size, 8);
        if (old_addr && new_addr) {
            memcpy(GuestToHost(host.GetGuestMemoryBase(), new_addr),
                   GuestToHost(host.GetGuestMemoryBase(), old_addr), new_size);
        }
        jit.Regs()[0] = new_addr;
    });

    RegisterThunk("free", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        host.GuestFree(jit.Regs()[0]);
    });

    RegisterThunk("memalign", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t alignment = jit.Regs()[0];
        size_t size = jit.Regs()[1];
        jit.Regs()[0] = host.GuestAlloc(size, alignment);
    });

    // Logging & Formatted output
    RegisterThunk("__android_log_print", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int prio = static_cast<int>(jit.Regs()[0]);
        const char* tag = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        const char* fmt = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2]));
        std::string formatted = FormatGuestString(jit, host, fmt, 3);
        __android_log_print(prio, tag ? tag : "Arm32Bridge_Guest", "[GUEST] %s", formatted.c_str());
        DiagTrace::GuestLog(formatted);
        jit.Regs()[0] = 0;
    });

    RegisterThunk("printf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* fmt = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        std::string formatted = FormatGuestString(jit, host, fmt, 1);
        LOGI("[printf] %s", formatted.c_str());
        DiagTrace::GuestLog(formatted);
        jit.Regs()[0] = formatted.length();
    });

    RegisterThunk("fprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* fmt = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        std::string formatted = FormatGuestString(jit, host, fmt, 2);
        LOGI("[fprintf] %s", formatted.c_str());
        jit.Regs()[0] = formatted.length();
    });

    RegisterThunk("sprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* str = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* fmt = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        std::string formatted = FormatGuestString(jit, host, fmt, 2);
        if (str) {
            strcpy(str, formatted.c_str());
            jit.Regs()[0] = formatted.length();
        } else {
            jit.Regs()[0] = 0;
        }
    });

    RegisterThunk("snprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* str = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        size_t size = jit.Regs()[1];
        const char* fmt = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2]));
        std::string formatted = FormatGuestString(jit, host, fmt, 3);
        if (str && size > 0) {
            strncpy(str, formatted.c_str(), size - 1);
            str[size - 1] = '\0';
            jit.Regs()[0] = formatted.length();
        } else {
            jit.Regs()[0] = 0;
        }
    });

    RegisterThunk("sscanf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        auto bounded = [&host](uint32_t address) -> const char* {
            if (!address || address >= host.GetGuestMemorySize()) return nullptr;
            const char* p = reinterpret_cast<const char*>(host.GetGuestMemoryBase() + address);
            return memchr(p, 0, host.GetGuestMemorySize() - address) ? p : nullptr;
        };
        const char* input = bounded(jit.Regs()[0]);
        const char* format = bounded(jit.Regs()[1]);
        GuestWords32<Dynarmic::A32::Jit, DynarmicHost> words{jit, host, 2, false};
        jit.Regs()[0] = static_cast<uint32_t>(GuestScan32::Scan(host, input, format, words));
    });
    RegisterThunk("vfprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("vasprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("putc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = jit.Regs()[0]; });
    RegisterThunk("fputc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = jit.Regs()[0]; });

    // fputs(const char *s, FILE *stream). Lesson 2.16: on Android fd 1 and 2 go nowhere, and
    // that is exactly where a C++ runtime writes the reason it is giving up. A stream the
    // guest really opened is written for real; anything else goes to the log instead of being
    // swallowed. In Angry Birds Go this was the last default stub still firing on a cold
    // start, and the first run with a real thunk printed what had been thrown away for
    // weeks: "io::IOException".
    RegisterThunk("fputs", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        if (!s) { jit.Regs()[0] = static_cast<uint32_t>(-1); return; }
        auto it = g_file_map.find(jit.Regs()[1]);
        if (it != g_file_map.end()) {
            jit.Regs()[0] = static_cast<uint32_t>(fputs(s, it->second));
            return;
        }
        // W2: the terminate handler prints the exception type through fputs
        // on the guest's stderr -- logcat throttling eats the LOGI, so also
        // route it into the notes ring. W18: persist it too.
        DiagTrace::Note(std::string("GUESTFPUTS ") + s);
        DiagTrace::NotePersist(std::string("GUESTFPUTS ") + s);
        LOGI("[guest fputs] %s", s);
        jit.Regs()[0] = static_cast<uint32_t>(strlen(s));
    });

    // Math functions
    RegisterThunk("sinf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float res = sinf(val);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });

    RegisterThunk("cosf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float res = cosf(val);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });

    RegisterThunk("sqrtf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float res = sqrtf(val);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });

    RegisterThunk("atanf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float res = atanf(val);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });

    RegisterThunk("acosf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float res = acosf(val);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });

    RegisterThunk("powf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float base = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float exp = *reinterpret_cast<float*>(&jit.Regs()[1]);
        float res = powf(base, exp);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });

    // String & Memory functions
    RegisterThunk("strcmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s1 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* s2 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = (s1 && s2) ? strcmp(s1, s2) : 0;
    });

    RegisterThunk("strncmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s1 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* s2 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        size_t n = jit.Regs()[2];
        jit.Regs()[0] = (s1 && s2) ? strncmp(s1, s2, n) : 0;
    });

    RegisterThunk("strcasecmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s1 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* s2 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = (s1 && s2) ? strcasecmp(s1, s2) : 0;
    });

    RegisterThunk("strlen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        jit.Regs()[0] = s ? static_cast<uint32_t>(strlen(s)) : 0;
    });

    RegisterThunk("strcpy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* dest = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* src = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        if (dest && src) strcpy(dest, src);
    });

    RegisterThunk("strdup", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* src = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        if (!src) { jit.Regs()[0] = 0; return; }
        size_t len = strlen(src) + 1;
        uint32_t dest_addr = host.GuestAlloc(len);
        memcpy(GuestToHost(host.GetGuestMemoryBase(), dest_addr), src, len);
        jit.Regs()[0] = dest_addr;
    });

    RegisterThunk("strrchr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        int c = static_cast<int>(jit.Regs()[1]);
        if (!s) { jit.Regs()[0] = 0; return; }
        const char* res = strrchr(s, c);
        jit.Regs()[0] = res ? static_cast<uint32_t>(reinterpret_cast<uintptr_t>(res) - reinterpret_cast<uintptr_t>(host.GetGuestMemoryBase())) : 0;
    });

    // strerror hands back storage the caller does not own and never frees, so a
    // fresh block per call is a block per failed open - and a guest that probes
    // for files that are not there does that constantly. One block per errno.
    RegisterThunk("strerror", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::mutex m;
        static std::unordered_map<int, uint32_t> cache;
        int err_no = static_cast<int>(jit.Regs()[0]);
        std::lock_guard<std::mutex> lock(m);
        auto it = cache.find(err_no);
        if (it == cache.end()) {
            const char* err = strerror(err_no);
            size_t len = strlen(err) + 1;
            uint32_t dest = host.GuestAlloc(len);
            if (dest) memcpy(GuestToHost(host.GetGuestMemoryBase(), dest), err, len);
            it = cache.emplace(err_no, dest).first;
        }
        jit.Regs()[0] = it->second;
    });

    RegisterThunk("strtoul", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* nptr = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        int base = static_cast<int>(jit.Regs()[2]);
        jit.Regs()[0] = nptr ? static_cast<uint32_t>(strtoul(nptr, nullptr, base)) : 0;
    });

    RegisterThunk("atoi", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* str = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        jit.Regs()[0] = str ? atoi(str) : 0;
    });

    RegisterThunk("islower", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = islower(static_cast<int>(jit.Regs()[0]));
    });

    RegisterThunk("isxdigit", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = isxdigit(static_cast<int>(jit.Regs()[0]));
    });

    RegisterThunk("memset", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* s = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        int c = static_cast<int>(jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        // W390 (run523): the stub-window scribbler is a guest bulk op --
        // MemoryWrite32 watchpoints saw NOTHING, so memset/memcpy thunks
        // (direct host writes) are the only unwatched writers. Log any
        // memset range overlapping the W100 stub window with exact args.
        if (s && jit.Regs()[0] < 0x8F111800u &&
            (jit.Regs()[0] + n) > 0x8F111400u) {
            char wb[160];
            snprintf(wb, sizeof(wb),
                     "W390 MEMSET-STUB dst=%08X c=%02X n=%zu lr=%08X",
                     jit.Regs()[0], jit.Regs()[1] & 0xFF, n, jit.Regs()[14]);
            DiagTrace::NotePersist(std::string(wb));
            LOGE("%s", wb);
        }
        // W407 (run540): the .text zeroing watch -- the LLMemAllocateV
        // auto-init region [0x40D9F0, 0x40DA20) was found ALL ZEROS at
        // tick time (W406AUTO). Any memset covering it names the zeroing
        // call with dst/len/lr.
        if (s && jit.Regs()[0] < 0x4040DA20u &&
            (jit.Regs()[0] + n) > 0x4040D9F0u) {
            char wb2[180];
            snprintf(wb2, sizeof(wb2),
                     "W407 MEMSET-AUTOINIT dst=%08X c=%02X n=%zu lr=%08X",
                     jit.Regs()[0], jit.Regs()[1] & 0xFF, n, jit.Regs()[14]);
            DiagTrace::NotePersist(std::string(wb2));
            LOGE("%s", wb2);
        }
        if (s) memset(s, c, n);
    });

    RegisterThunk("memcpy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* dest = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        const void* src = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        // W391 (run524): stub-window overlap probe (see memset W390).
        if (jit.Regs()[0] < 0x8F111800u &&
            (jit.Regs()[0] + jit.Regs()[2]) > 0x8F111400u) {
            char wb2[180];
            snprintf(wb2, sizeof(wb2),
                     "W391 memcpy-STUB dst=%08X src=%08X n=%zu lr=%08X",
                     jit.Regs()[0], jit.Regs()[1], static_cast<size_t>(jit.Regs()[2]), jit.Regs()[14]);
            DiagTrace::NotePersist(std::string(wb2));
            LOGE("%s", wb2);
        }
        if (dest && src) memcpy(dest, src, n);
    });

    RegisterThunk("memcmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t guest_s1 = jit.Regs()[0];
        const uint32_t guest_s2 = jit.Regs()[1];
        const void* s1 = GuestToHost(host.GetGuestMemoryBase(), guest_s1);
        const void* s2 = GuestToHost(host.GetGuestMemoryBase(), guest_s2);
        size_t n = jit.Regs()[2];
        // W577: observe the live CLubeProperyCollection tree walk without
        // changing guest state. Its memcmp call sites were the hot-loop
        // signature on ABB; capture node links and both key strings to tell a
        // malformed child cycle from repeated, distinct lookups.
        const uint32_t lr = jit.Regs()[14];
        if (lr == 0x40466730u || lr == 0x40466774u) {
            static std::atomic<uint32_t> samples{0};
            const uint32_t sample = samples.fetch_add(1);
            if (sample < 96 || (sample % 4096u) == 0) {
                const size_t guest_size = host.GetGuestMemorySize();
                auto readable = [guest_size](uint32_t address, size_t bytes) {
                    return static_cast<size_t>(address) <= guest_size &&
                           bytes <= guest_size - static_cast<size_t>(address);
                };
                const uint32_t node = lr == 0x40466730u ? jit.Regs()[4] : jit.Regs()[7];
                const uint32_t query_len = guest_s2 >= 12u && readable(guest_s2 - 12u, 4u)
                    ? host.MemoryRead32(guest_s2 - 12u) : 0;
                const uint32_t node_len = guest_s1 >= 12u && readable(guest_s1 - 12u, 4u)
                    ? host.MemoryRead32(guest_s1 - 12u) : 0;
                const uint32_t left = readable(node, 16u)
                    ? host.MemoryRead32(node + 8u) : 0;
                const uint32_t right = readable(node, 16u)
                    ? host.MemoryRead32(node + 12u) : 0;
                char key[25] = {};
                char query[25] = {};
                auto copy_preview = [&host, &readable](uint32_t address, uint32_t length, char* out) {
                    const uint32_t count = readable(address, 1u)
                        ? std::min<uint32_t>(std::min<uint32_t>(length, 24u),
                                             static_cast<uint32_t>(host.GetGuestMemorySize() - address))
                        : 0u;
                    for (uint32_t i = 0; i < count; ++i) {
                        const unsigned char c = host.MemoryRead8(address + i);
                        out[i] = c >= 0x20 && c <= 0x7E ? static_cast<char>(c) : '.';
                    }
                    out[count] = '\0';
                };
                copy_preview(guest_s1, node_len, key);
                copy_preview(guest_s2, query_len, query);
                char b[224];
                snprintf(b, sizeof(b),
                         "W577 #%u lr=%08X node=%08X L=%08X R=%08X key=%08X/%u \"%s\" query=%08X/%u \"%s\"",
                         sample, lr, node, left, right, guest_s1, node_len, key,
                         guest_s2, query_len, query);
                DiagTrace::NotePersist(b);
                if (sample < 16u || (sample % 65536u) == 0) LOGE("%s", b);

                // W579: capture the guest caller chain for the repeated Lua
                // property lookup observed on ABB. This is host-side tracing
                // only; no guest code or register state is modified.
                if (query_len == 20u && readable(guest_s2, 20u) && s2 &&
                    memcmp(s2, "tracks_unlock_bought", 20u) == 0) {
                    static std::atomic<uint32_t> target_samples{0};
                    const uint32_t target = target_samples.fetch_add(1);
                    if (target < 16u || (target % 262144u) == 0) {
                        const uint32_t sp = jit.Regs()[13];
                        auto stack_word = [&host, &readable, sp](uint32_t offset) {
                            if (sp > UINT32_MAX - offset) return 0u;
                            const uint32_t address = sp + offset;
                            return readable(address, 4u) ? host.MemoryRead32(address) : 0u;
                        };
                        const uint32_t saveSlotVariable = host.MemoryRead32(0x4067054Cu);
                        const uint32_t saveSlot = readable(saveSlotVariable, 4u)
                            ? host.MemoryRead32(saveSlotVariable) : 0u;
                        const uint32_t careerCountVariable = host.MemoryRead32(0x40670AE4u);
                        const uint32_t careerCount = readable(careerCountVariable, 4u)
                            ? host.MemoryRead32(careerCountVariable) : 0u;
                        const uint32_t subStateVariable = host.MemoryRead32(0x4067044Cu);
                        const uint32_t subState = readable(subStateVariable, 4u)
                            ? host.MemoryRead32(subStateVariable) : UINT32_MAX;
                        const uint32_t mainStateVariable = host.MemoryRead32(0x40670B38u);
                        const uint32_t mainState = readable(mainStateVariable, 4u)
                            ? host.MemoryRead32(mainStateVariable) : UINT32_MAX;
                        const uint32_t savedLevel = saveSlot && readable(saveSlot + 80u, 4u)
                            ? host.MemoryRead32(saveSlot + 80u) : 0u;
                        char trace[512];
                        int used = snprintf(trace, sizeof(trace),
                                            "W579 target=%u lr=%08X node=%08X sp=%08X savevar=%08X slot=%08X level=%08X careers=%u substate=%u mainstate=%u stack=",
                                            target, lr, node, sp, saveSlotVariable,
                                            saveSlot, savedLevel, careerCount,
                                            subState, mainState);
                        for (uint32_t offset = 28u; offset <= 128u &&
                             used > 0 && static_cast<size_t>(used) < sizeof(trace); offset += 4u) {
                            used += snprintf(trace + used, sizeof(trace) - static_cast<size_t>(used),
                                             "%s%08X", offset == 28u ? "" : ",",
                                             stack_word(offset));
                        }
                        DiagTrace::NotePersist(trace);
                        LOGE("%s", trace);
                    }
                }
            }
        }
        jit.Regs()[0] = (s1 && s2) ? memcmp(s1, s2, n) : 0;
    });

    RegisterThunk("memchr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const void* s = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        int c = static_cast<int>(jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        void* res = s ? const_cast<void*>(memchr(s, c, n)) : nullptr;
        jit.Regs()[0] = res ? HostToGuest(host.GetGuestMemoryBase(), res) : 0;
    });

    // The guest qsort comparator cannot run inside this SVC thunk. Match the
    // game's known comparators and sort their records on the host.
    RegisterThunk("qsort", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t base = jit.Regs()[0];
        const uint32_t n = jit.Regs()[1];
        const uint32_t width = jit.Regs()[2];
        const uint32_t compar = jit.Regs()[3];
#if BRIDGE_ENABLE_LOGS
        // Diagnostic builds retain the comparator and call site for triage.
        static std::atomic<uint32_t> diag_calls{0};
        if (diag_calls.fetch_add(1) < 4096) {
            char b[128];
            snprintf(b, sizeof(b), "QSORT base=0x%08X n=%u width=%u compar=0x%08X lr=0x%08X",
                     base, n, width, compar, jit.Regs()[14]);
            DiagTrace::Note(b);
        }
#endif
        // The SVC continuation cannot tail-call a guest comparator here.
        // Handle the game's known comparators with their exact record layouts.
        // Race_SortCheckpoints uses sub_55DDB0: float distance at byte 52 of
        // each 0xA4-byte checkpoint. Skipping this qsort leaves checkpoints in
        // model-enumeration order and makes the first gate report WRONG CHECKPOINT.
        if (compar == DynarmicHost::kGuestGameBase + 0x55DDB0u &&
            width == GuestCheckpointSort32::kRecordSize && n <= 4096 &&
            static_cast<uint64_t>(base) + static_cast<uint64_t>(n) * width <=
                host.GetGuestMemorySize()) {
            if (GuestCheckpointSort32::Sort(host.GetGuestMemoryBase() + base, n)) {
#if BRIDGE_ENABLE_LOGS
                float first_distance = 0.0f;
                if (n) std::memcpy(&first_distance,
                                   host.GetGuestMemoryBase() + base +
                                       GuestCheckpointSort32::kDistanceOffset,
                                   sizeof(first_distance));
                char b[112];
                snprintf(b, sizeof(b), "QSORT-CHECKPOINT n=%u base=0x%08X first_distance=%g",
                         n, base, first_distance);
                DiagTrace::Note(b);
#endif
                return;
            }
#if BRIDGE_ENABLE_LOGS
            DiagTrace::Note("QSORT-CHECKPOINT invalid distance; sort skipped");
#endif
        }
        // The pool comparator sub_409C7C compares the leading int32.
        if (compar == DynarmicHost::kGuestGameBase + 0x409C7C && n >= 2 &&
            width >= 4 && width <= 256 && n <= 65536 && n * width <= (1u << 20)) {
            uint8_t* mem = host.GetGuestMemoryBase() + base;
            std::vector<uint8_t> buf(static_cast<size_t>(n) * width);
            memcpy(buf.data(), mem, buf.size());
            const auto key = [width](const uint8_t* e) {
                int32_t v;
                memcpy(&v, e, 4);
                return v;
            };
            for (uint32_t i = 1; i < n; ++i) {
                for (uint32_t j = i;
                     j > 0 && key(&buf[static_cast<size_t>(j) * width]) <
                                  key(&buf[static_cast<size_t>(j - 1) * width]);
                     --j) {
                    std::swap_ranges(buf.begin() + static_cast<size_t>(j) * width,
                                     buf.begin() + static_cast<size_t>(j + 1) * width,
                                     buf.begin() + static_cast<size_t>(j - 1) * width);
                }
            }
            memcpy(mem, buf.data(), buf.size());
            return;
        }
#if BRIDGE_ENABLE_LOGS
        if (compar != DynarmicHost::kGuestGameBase + 0x409C7C) {
            char b[128];
            snprintf(b, sizeof(b), "QSORT-SKIP compar=0x%08X n=%u (no host semantics)", compar, n);
            DiagTrace::Note(b);
        }
#endif
    });

    // ARM AEABI Helpers
    RegisterThunk("__aeabi_idiv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int32_t num = static_cast<int32_t>(jit.Regs()[0]);
        int32_t den = static_cast<int32_t>(jit.Regs()[1]);
        jit.Regs()[0] = den ? (num / den) : 0;
    });

    RegisterThunk("__aeabi_uidiv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t num = jit.Regs()[0];
        uint32_t den = jit.Regs()[1];
        jit.Regs()[0] = den ? (num / den) : 0;
    });

    RegisterThunk("__aeabi_idivmod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int32_t num = static_cast<int32_t>(jit.Regs()[0]);
        int32_t den = static_cast<int32_t>(jit.Regs()[1]);
        if (den != 0) {
            jit.Regs()[0] = num / den;
            jit.Regs()[1] = num % den;
        } else {
            jit.Regs()[0] = 0;
            jit.Regs()[1] = 0;
        }
    });

    RegisterThunk("__aeabi_uidivmod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t num = jit.Regs()[0];
        uint32_t den = jit.Regs()[1];
        if (den != 0) {
            jit.Regs()[0] = num / den;
            jit.Regs()[1] = num % den;
        } else {
            jit.Regs()[0] = 0;
            jit.Regs()[1] = 0;
        }
    });

    RegisterThunk("__aeabi_uldivmod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint64_t num = static_cast<uint64_t>(jit.Regs()[0]) | (static_cast<uint64_t>(jit.Regs()[1]) << 32);
        uint64_t den = static_cast<uint64_t>(jit.Regs()[2]) | (static_cast<uint64_t>(jit.Regs()[3]) << 32);
        if (den != 0) {
            uint64_t q = num / den;
            uint64_t r = num % den;
            jit.Regs()[0] = static_cast<uint32_t>(q & 0xFFFFFFFF);
            jit.Regs()[1] = static_cast<uint32_t>(q >> 32);
            jit.Regs()[2] = static_cast<uint32_t>(r & 0xFFFFFFFF);
            jit.Regs()[3] = static_cast<uint32_t>(r >> 32);
        }
    });

    RegisterThunk("__gnu_ldivmod_helper", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int64_t num = static_cast<int64_t>(jit.Regs()[0]) | (static_cast<int64_t>(jit.Regs()[1]) << 32);
        int64_t den = static_cast<int64_t>(jit.Regs()[2]) | (static_cast<int64_t>(jit.Regs()[3]) << 32);
        if (den != 0) {
            int64_t q = num / den;
            int64_t r = num % den;
            jit.Regs()[0] = static_cast<uint32_t>(q & 0xFFFFFFFF);
            jit.Regs()[1] = static_cast<uint32_t>(q >> 32);
            jit.Regs()[2] = static_cast<uint32_t>(r & 0xFFFFFFFF);
            jit.Regs()[3] = static_cast<uint32_t>(r >> 32);
        }
    });

    RegisterThunk("__aeabi_memcpy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* d = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        const void* s = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        if (d && s) memcpy(d, s, n);
    });
    RegisterThunk("__aeabi_memcpy4", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* d = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        const void* s = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        if (d && s) memcpy(d, s, n);
    });
    RegisterThunk("__aeabi_memcpy8", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* d = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        const void* s = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        if (d && s) memcpy(d, s, n);
    });

    RegisterThunk("__aeabi_memmove", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* d = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        const void* s = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        if (d && s) memmove(d, s, n);
    });
    RegisterThunk("__aeabi_memmove4", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* d = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        const void* s = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        if (d && s) memmove(d, s, n);
    });

    RegisterThunk("__aeabi_memclr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* d = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        size_t n = jit.Regs()[1];
        if (d) memset(d, 0, n);
    });
    RegisterThunk("__aeabi_memclr4", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* d = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        size_t n = jit.Regs()[1];
        if (d) memset(d, 0, n);
    });
    RegisterThunk("__aeabi_memclr8", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* d = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        size_t n = jit.Regs()[1];
        if (d) memset(d, 0, n);
    });
    RegisterThunk("__aeabi_memset4", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* d = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        size_t n = jit.Regs()[1];
        int c = static_cast<int>(jit.Regs()[2]);
        if (d) memset(d, c, n);
    });

    RegisterThunk("__aeabi_f2lz", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float f = *reinterpret_cast<float*>(&jit.Regs()[0]);
        int64_t i = static_cast<int64_t>(f);
        jit.Regs()[0] = static_cast<uint32_t>(i & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>(i >> 32);
    });

    RegisterThunk("__aeabi_f2ulz", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float f = *reinterpret_cast<float*>(&jit.Regs()[0]);
        uint64_t u = static_cast<uint64_t>(f);
        jit.Regs()[0] = static_cast<uint32_t>(u & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>(u >> 32);
    });

    RegisterThunk("__aeabi_l2f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int64_t i = static_cast<int64_t>(jit.Regs()[0]) | (static_cast<int64_t>(jit.Regs()[1]) << 32);
        float f = static_cast<float>(i);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&f);
    });

    RegisterThunk("__aeabi_ul2f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint64_t u = static_cast<uint64_t>(jit.Regs()[0]) | (static_cast<uint64_t>(jit.Regs()[1]) << 32);
        float f = static_cast<float>(u);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&f);
    });

    RegisterThunk("__aeabi_l2d", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int64_t i = static_cast<int64_t>(jit.Regs()[0]) | (static_cast<int64_t>(jit.Regs()[1]) << 32);
        double d = static_cast<double>(i);
        uint64_t u = *reinterpret_cast<uint64_t*>(&d);
        jit.Regs()[0] = static_cast<uint32_t>(u & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>(u >> 32);
    });

    // AEABI memory functions
    auto aeabi_memclr_handler = [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dest = jit.Regs()[0];
        uint32_t n = jit.Regs()[1];
        if (dest && n) {
            memset(GuestToHost(host.GetGuestMemoryBase(), dest), 0, n);
        }
    };
    RegisterThunk("__aeabi_memclr", aeabi_memclr_handler);
    RegisterThunk("__aeabi_memclr4", aeabi_memclr_handler);
    RegisterThunk("__aeabi_memclr8", aeabi_memclr_handler);

    auto aeabi_memset_handler = [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dest = jit.Regs()[0];
        uint32_t n = jit.Regs()[1];
        int c = static_cast<int>(jit.Regs()[2]);
        if (dest && n) {
            memset(GuestToHost(host.GetGuestMemoryBase(), dest), c, n);
        }
    };
    RegisterThunk("__aeabi_memset", aeabi_memset_handler);
    RegisterThunk("__aeabi_memset4", aeabi_memset_handler);
    RegisterThunk("__aeabi_memset8", aeabi_memset_handler);

    auto aeabi_memcpy_handler = [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dest = jit.Regs()[0];
        uint32_t src = jit.Regs()[1];
        uint32_t n = jit.Regs()[2];
        if (dest && src && n) {
            memcpy(GuestToHost(host.GetGuestMemoryBase(), dest),
                   GuestToHost(host.GetGuestMemoryBase(), src), n);
        }
    };
    RegisterThunk("__aeabi_memcpy", aeabi_memcpy_handler);
    RegisterThunk("__aeabi_memcpy4", aeabi_memcpy_handler);
    RegisterThunk("__aeabi_memcpy8", aeabi_memcpy_handler);

    auto aeabi_memmove_handler = [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dest = jit.Regs()[0];
        uint32_t src = jit.Regs()[1];
        uint32_t n = jit.Regs()[2];
        if (dest && src && n) {
            memmove(GuestToHost(host.GetGuestMemoryBase(), dest),
                    GuestToHost(host.GetGuestMemoryBase(), src), n);
        }
    };
    RegisterThunk("__aeabi_memmove", aeabi_memmove_handler);
    RegisterThunk("__aeabi_memmove4", aeabi_memmove_handler);
    RegisterThunk("__aeabi_memmove8", aeabi_memmove_handler);

    // Pthreads.
    // R2: real host-backed cond/mutex semantics keyed by guest address. The old
    // pthread_cond_wait stub returned instantly, which degenerated the guest
    // glue's wait loops (onInputQueueCreated/onStart/onResume ack waits) into
    // hot spins that could never observe the worker's broadcast -- four threads
    // at 50-80% CPU and a permanently wedged main thread. Guest pthread objects
    // are opaque to us, so the guest address is just the registry key; state
    // lives in host primitives. Bionic pthread_cond_t is 4 bytes of state, well
    // under the 40-byte slot we reserve, and pthread_cond_t/pthread_mutex_t
    // init thunks below zero the first words so stale reuse of a guest block
    // cannot confuse anything (we never read guest bytes for state).
    static std::mutex g_pthread_registry_mutex;
    struct GuestCond {
        std::mutex m;
        std::condition_variable cv;
        unsigned waiters = 0;
    };
    struct GuestMutexState {
        std::shared_ptr<std::recursive_mutex> m = std::make_shared<std::recursive_mutex>();
        std::atomic<uint32_t> owner_count{0};  // diagnostics: reentrancy depth
    };
    static std::unordered_map<uint32_t, std::shared_ptr<GuestCond>> g_conds;
    static std::unordered_map<uint32_t, std::shared_ptr<GuestMutexState>> g_mutexes;

    auto cond_for = [](uint32_t addr) -> std::shared_ptr<GuestCond> {
        std::lock_guard<std::mutex> lk(g_pthread_registry_mutex);
        auto it = g_conds.find(addr);
        if (it != g_conds.end()) return it->second;
        auto entry = std::make_shared<GuestCond>();
        g_conds.emplace(addr, entry);
        return entry;
    };
    auto mutex_for = [](uint32_t addr) -> std::shared_ptr<GuestMutexState> {
        std::lock_guard<std::mutex> lk(g_pthread_registry_mutex);
        auto it = g_mutexes.find(addr);
        if (it != g_mutexes.end()) return it->second;
        auto entry = std::make_shared<GuestMutexState>();
        g_mutexes.emplace(addr, entry);
        return entry;
    };

    RegisterThunk("pthread_mutex_lock", [mutex_for](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        const uint32_t mtx = jit.Regs()[0];
        jit.Regs()[0] = 0;
        if (!mtx) return;
        // W40: rate-limited caller sample -- finds deadlocks on a mutex whose
        // owner never returns.
        static std::atomic<uint32_t> w40ml{0};
        if ((w40ml.fetch_add(1) & 0x3FFu) == 0) {
            char b[80];
            snprintf(b, sizeof(b), "W40MLOCK mtx=0x%08X lr=0x%08X",
                     mtx, jit.Regs()[14]);
            DiagTrace::Note(b);
        }
        // Hold no registry lock while locking: one waiter blocking here must
        // not stop another thread from creating its own cond/mutex entry.
        auto st = mutex_for(mtx);
        // The former W256 path called unlock() when this thread did not own
        // the recursive mutex. That is undefined behavior and cannot repair
        // an abandoned lock; W142 releases locks held by exiting guest threads.
        st->m->lock();
        st->owner_count.fetch_add(1, std::memory_order_relaxed);
        bool w142_found = false;
        for (auto& h : t_held_guest_mutexes)
            if (h.addr == mtx) { ++h.depth; w142_found = true; break; }
        if (!w142_found)
            t_held_guest_mutexes.push_back({st->m, mtx, 1});
    });
    RegisterThunk("pthread_mutex_unlock", [mutex_for](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        const uint32_t mtx = jit.Regs()[0];
        jit.Regs()[0] = 0;
        if (!mtx) return;
        // W378 (run507): the game thread halts at the ReleaseGraphicsSystem
        // BLX (run506: pc=lr=0x0001179C) -- the last guest action is unlock
        // of the graphics mutex 0x406D95A4. Bracket it to tell a block
        // INSIDE the unlock thunk apart from a death BEFORE it.
        const bool w378 = (mtx == 0x406D95A4u);
        if (w378) DiagTrace::NotePersist("W378 gfx UNLOCK enter");
        mutex_for(mtx)->owner_count.fetch_sub(1, std::memory_order_relaxed);
        for (auto& h : t_held_guest_mutexes)
            if (h.addr == mtx && h.depth > 0) { --h.depth; break; }
        // W216 (run301): the boot froze inside bz_Threading_Release
        // GraphicsSystem's unlock -- std::mutex::unlock throws system_error
        // when the calling thread does not own the mutex, and the throw
        // kills the JIT thread silently. Tolerate it (the guest uses the
        // mutex as a loose graphics-system gate, not a strict owner lock).
        try {
            mutex_for(mtx)->m->unlock();
        } catch (const std::exception&) {
            static std::atomic<uint32_t> w216{0};
            if (w216.fetch_add(1) < 8) {
                char b[80];
                snprintf(b, sizeof(b), "W216 unlock-without-lock tolerated mtx=0x%08X", mtx);
                DiagTrace::NotePersist(b);
                LOGE("%s", b);
            }
        }
        if (w378) DiagTrace::NotePersist("W378 gfx UNLOCK exit");
    });
    RegisterThunk("pthread_cond_wait", [cond_for, mutex_for](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t cond = jit.Regs()[0];
        const uint32_t mutex = jit.Regs()[1];
        // W296 (run399): publish the cond address the thread waits on --
        // the W286 driver reads it to broadcast the LIVE cond and to
        // derive the live app pointer (cond = app+0x44).
        if (cond >= 0x50847E00u && cond <= 0x50848000u) host.MemoryWrite32(0x93000164u, cond);
        static bool logged = false;
        if (!logged) {
            logged = true;
            LOGI("pthread_cond_wait real: cond=0x%08X mutex=0x%08X flag=0x%08X",
                 cond, mutex, mutex ? host.MemoryRead32(mutex + 0x2c) : 0);
        }
        // W40: every entry and every 30 s timeout is recorded with the caller
        // LR -- an eternal waiter on a never-broadcast condvar shows up as a
        // repeating W40CWT line.
        static std::atomic<uint32_t> w40cw{0};
        if ((w40cw.fetch_add(1) & 0x3FFu) == 0) {
            char b[112];
            snprintf(b, sizeof(b), "W40CW cond=0x%08X mtx=0x%08X lr=0x%08X",
                     cond, mutex, jit.Regs()[14]);
            DiagTrace::Note(b);
        }
        jit.Regs()[0] = 0;
        if (!cond) return;
        // Canonical condvar order: take the cond's internal mutex BEFORE
        // releasing the guest mutex. The guest broadcasts under its own mutex
        // (worker: lock -> field=... -> broadcast -> unlock), and the broadcast
        // tank now serializes on this same internal mutex, so a notify can only
        // happen while a waiter is already parked on the cv -- no lost wakeups.
        // POSIX atomically releases the caller's mutex for the duration of the
        // wait; not releasing it here would deadlock the worker's own
        // pthread_mutex_lock and its broadcast would never happen.
        auto entry = cond_for(cond);
        std::unique_lock<std::mutex> lk(entry->m);
        if (mutex) {
            mutex_for(mutex)->owner_count.fetch_sub(1, std::memory_order_relaxed);
            mutex_for(mutex)->m->unlock();
        }
        entry->waiters++;
        // Deadline guard: a waiter whose broadcast never comes must fail loud
        // in the log instead of spinning silently forever (the silent-spin mode
        // is exactly what made this blocker take ten attempts to find).
        const bool woken = entry->cv.wait_for(lk, std::chrono::seconds(30)) == std::cv_status::no_timeout;
        entry->waiters--;
        lk.unlock();
        if (mutex) {
            mutex_for(mutex)->m->lock();
            mutex_for(mutex)->owner_count.fetch_add(1, std::memory_order_relaxed);
        }
        if (!woken) {
            static std::atomic<int> timeouts{0};
            if (timeouts.fetch_add(1) < 5) {
                LOGE("pthread_cond_wait TIMEOUT cond=0x%08X mutex=0x%08X remaining-waiters=%u",
                     cond, mutex, entry->waiters);
            }
            char b[112];
            snprintf(b, sizeof(b), "W40CWT cond=0x%08X mtx=0x%08X lr=0x%08X waiters=%u",
                     cond, mutex, jit.Regs()[14], entry->waiters);
            DiagTrace::NotePersist(b);
        }
    });
    RegisterThunk("pthread_cond_broadcast", [cond_for](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        const uint32_t cond = jit.Regs()[0];
        jit.Regs()[0] = 0;
        if (!cond) return;
        // W40: broadcast trail -- pairs with W40CW/W40CWT to tell a lost
        // wakeup (broadcast before park) from a never-broadcast condvar.
        static std::atomic<uint32_t> w40bc{0};
        if ((w40bc.fetch_add(1) & 0xFFu) == 0) {
            char b[80];
            snprintf(b, sizeof(b), "W40BCST cond=0x%08X lr=0x%08X",
                     cond, jit.Regs()[14]);
            DiagTrace::Note(b);
        }
        auto entry = cond_for(cond);
        std::lock_guard<std::mutex> lk(entry->m);
        entry->cv.notify_all();
    });
    RegisterThunk("pthread_cond_signal", [cond_for](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        const uint32_t cond = jit.Regs()[0];
        jit.Regs()[0] = 0;
        if (!cond) return;
        static std::atomic<uint32_t> w40sg{0};
        if ((w40sg.fetch_add(1) & 0xFFu) == 0) {
            char b[80];
            snprintf(b, sizeof(b), "W40SIG cond=0x%08X lr=0x%08X",
                     cond, jit.Regs()[14]);
            DiagTrace::Note(b);
        }
        auto entry = cond_for(cond);
        std::lock_guard<std::mutex> lk(entry->m);
        entry->cv.notify_one();
    });

    struct GuestOnceState {
        std::mutex mutex;
        std::condition_variable ready;
        bool running = false;
        bool complete = false;
    };
    static std::mutex once_registry_mutex;
    static std::unordered_map<uint32_t, std::shared_ptr<GuestOnceState>> once_registry;
    RegisterThunk("pthread_once", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t control = jit.Regs()[0];
        const uint32_t initializer = jit.Regs()[1];
        if (!control || !initializer ||
            static_cast<uint64_t>(control) + 4u > host.GetGuestMemorySize()) {
            jit.Regs()[0] = EINVAL;
            return;
        }
        std::shared_ptr<GuestOnceState> state;
        {
            std::lock_guard<std::mutex> lock(once_registry_mutex);
            auto& slot = once_registry[control];
            if (!slot) slot = std::make_shared<GuestOnceState>();
            state = slot;
        }
        std::unique_lock<std::mutex> lock(state->mutex);
        if (host.MemoryRead32(control) == 2u) state->complete = true;
        while (state->running) state->ready.wait(lock);
        if (state->complete) {
            jit.Regs()[0] = 0;
            return;
        }
        state->running = true;
        host.MemoryWrite32(control, 1u);  // initializer in progress
        lock.unlock();
        const bool completed = host.RunGuestInitializer(initializer);
        lock.lock();
        host.MemoryWrite32(control, completed ? 2u : 0u);
        state->complete = completed;
        state->running = false;
        lock.unlock();
        state->ready.notify_all();
        static std::atomic<uint32_t> reported{0};
        if (reported.fetch_add(1) < 32)
            LOGI("pthread_once control=%08X initializer=%08X completed=%u",
                 control, initializer, completed ? 1u : 0u);
        jit.Regs()[0] = completed ? 0u : static_cast<uint32_t>(EAGAIN);
    });

    RegisterThunk("pthread_key_create", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t key_ptr = jit.Regs()[0];
        if (key_ptr) host.MemoryWrite32(key_ptr, g_next_tls_key++);
        jit.Regs()[0] = 0;
    });

    RegisterThunk("pthread_setspecific", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t key = jit.Regs()[0];
        uint32_t val = jit.Regs()[1];
        g_tls_map[key] = reinterpret_cast<void*>(static_cast<uintptr_t>(val));
        jit.Regs()[0] = 0;
    });

    RegisterThunk("pthread_getspecific", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t key = jit.Regs()[0];
        auto it = g_tls_map.find(key);
        jit.Regs()[0] = (it != g_tls_map.end()) ? static_cast<uint32_t>(reinterpret_cast<uintptr_t>(it->second)) : 0;
    });

    RegisterThunk("fopen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* mode = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        if (!path) { jit.Regs()[0] = 0; return; }

        // W1 diagnostic: WAD/archive opens are the zero-read suspects.
        if (strstr(path, "WAD") || strstr(path, "wad") || strstr(path, ".obb")) {
            char b[224];
            snprintf(b, sizeof(b), "FOPEN path=%s mode=%s", path, mode ? mode : "");
            DiagTrace::Note(b);
        }

        if (BridgeIsObbPath(path)) {
            if (mode && (mode[0] != 'r' || strchr(mode, '+'))) {
                errno = EROFS;
                jit.Regs()[0] = 0;
                return;
            }
            BridgeObbHandle source;
            if (!BridgeOpenSelectedObb(&source)) {
                LOGE("fopen OBB refused: no validated source for %s", path);
                jit.Regs()[0] = 0;
                return;
            }
            const int fd_for_fileno = dup(source.fd);
            if (fd_for_fileno < 0) {
                close(source.fd);
                jit.Regs()[0] = 0;
                return;
            }
            auto cursor = std::make_shared<FileCursor>();
            FILE* stream = OpenFileBackedStream(source.fd, source.offset, source.length,
                                                cursor, true);
            if (!stream) {
                close(fd_for_fileno);
                jit.Regs()[0] = 0;
                return;
            }
            const int vfd = CreateVirtualFd(fd_for_fileno, source.length, source.offset, cursor);
            const uint32_t handle = g_next_file_handle++;
            g_file_map[handle] = stream;
            g_stream_vfd[handle] = vfd;
            LOGI("fopen OBB source=%s path=%s base=%lld size=%u vfd=%d",
                 BridgeSelectedObbSourceName(), path, static_cast<long long>(source.offset),
                 source.length, vfd);
            jit.Regs()[0] = handle;
            return;
        }

        FILE* f = fopen(path, mode ? mode : "r");
        // W51: open-result trail. An empty path or a failing OBB/stat open
        // upstream is what feeds ThreadingFReadKill's thread suicide.
        {
            static std::atomic<uint32_t> w51fo{0};
            if (w51fo.fetch_add(1) < 80) {
                char b[256];
                if (f) {
                    snprintf(b, sizeof(b), "W51OPEN ok path=%s", path);
                } else {
                    snprintf(b, sizeof(b), "W51OPEN FAIL errno=%d path=%s", errno,
                             path ? path : "(null)");
                }
                DiagTrace::NotePersist(b);
            }
        }
        if (!f) {
            ApkEntry* entry = FindApkEntry(path);
            if (entry && g_apk_indexed_fd >= 0) {
                const int source_fd = dup(g_apk_indexed_fd);
                f = OpenFileBackedStream(source_fd, entry->data_offset, entry->file_size,
                                         std::make_shared<FileCursor>(), false);
                if (f) {
                    LOGI("fopen: APK direct stream opened '%s' -> '%s' (size %lld, offset %lld)",
                         path, entry->name, static_cast<long long>(entry->file_size), static_cast<long long>(entry->data_offset));
                }
            }
        }

        if (f) {
            uint32_t handle = g_next_file_handle++;
            g_file_map[handle] = f;
            jit.Regs()[0] = handle;
        } else {
            jit.Regs()[0] = 0;
        }
    });

    RegisterThunk("fdopen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        const char* mode = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        bool is_virtual = false;
        int stream_fd = -1;
        off_t base = 0;
        off_t length = 0;
        std::shared_ptr<FileCursor> cursor;
        {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto virtual_fd = g_vfd_map.find(fd);
            if (virtual_fd != g_vfd_map.end()) {
                is_virtual = true;
                if (!mode || (mode[0] == 'r' && !strchr(mode, '+'))) {
                    stream_fd = dup(virtual_fd->second.source_fd);
                    base = virtual_fd->second.file_offset;
                    length = virtual_fd->second.file_size;
                    cursor = virtual_fd->second.cursor;
                }
            }
        }
        if (is_virtual) {
            FILE* stream = OpenFileBackedStream(stream_fd, base, length, cursor, true);
            if (!stream) { jit.Regs()[0] = 0; return; }
            const uint32_t handle = g_next_file_handle++;
            g_file_map[handle] = stream;
            g_stream_vfd[handle] = fd;
            jit.Regs()[0] = handle;
            return;
        }
        FILE* f = fdopen(fd, mode);
        if (f) {
            uint32_t handle = g_next_file_handle++;
            g_file_map[handle] = f;
            jit.Regs()[0] = handle;
        } else {
            jit.Regs()[0] = 0;
        }
    });

    RegisterThunk("fclose", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        if (it != g_file_map.end()) {
            auto stream_fd = g_stream_vfd.find(handle);
            if (stream_fd != g_stream_vfd.end()) {
                std::lock_guard<std::mutex> lock(g_vfd_mutex);
                auto virtual_fd = g_vfd_map.find(stream_fd->second);
                if (virtual_fd != g_vfd_map.end()) {
                    close(virtual_fd->second.source_fd);
                    g_vfd_map.erase(virtual_fd);
                }
                g_stream_vfd.erase(stream_fd);
            }
            fclose(it->second);
            g_file_map.erase(it);
            jit.Regs()[0] = 0;
        } else {
            jit.Regs()[0] = -1;
        }
    });

    RegisterThunk("fread", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* ptr = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        size_t size = jit.Regs()[1];
        size_t count = jit.Regs()[2];
        uint32_t handle = jit.Regs()[3];
        auto it = g_file_map.find(handle);
        size_t res = (it != g_file_map.end() && ptr) ? fread(ptr, size, count, it->second) : 0;
        // W321 (run425): every fread call, rate-limited -- names the exact
        // handle/size/ret at the "File Read Error" throw (run421-424).
        {
            static std::atomic<uint32_t> w321fr{0};
            if (w321fr.fetch_add(1) < 96) {
                char b[160];
                snprintf(b, sizeof(b), "W321FREAD res=%zu want=%zu size=%zu handle=0x%08X known=%d",
                         res, count, size, handle, it != g_file_map.end() ? 1 : 0);
                DiagTrace::NotePersist(b);
            }
        }
        // W51: short/failed reads -- the ThreadingFReadKill trigger.
        if (it == g_file_map.end() || res < count) {
            static std::atomic<uint32_t> w51fr{0};
            if (w51fr.fetch_add(1) < 64) {
                char b[160];
                snprintf(b, sizeof(b),
                         "W51FREAD short res=%zu want=%zu (size=%zu) handle=0x%08X errno=%d known=%d",
                         res, count, size, handle,
                         it != g_file_map.end() ? errno : 0,
                         it != g_file_map.end() ? 1 : 0);
                DiagTrace::NotePersist(b);
            }
        }
        jit.Regs()[0] = res;
    });

    RegisterThunk("fwrite", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const void* ptr = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        size_t size = jit.Regs()[1];
        size_t count = jit.Regs()[2];
        uint32_t handle = jit.Regs()[3];
        auto it = g_file_map.find(handle);
        // W1 diagnostic: the guest's own stderr/stdout FILE* (e.g. the
        // terminate-handler message "terminate called after throwing an
        // instance of '...'") is not in g_file_map -- capture it instead of
        // dropping it on the floor.
        if (it == g_file_map.end() && ptr && size && count) {
            static std::atomic<uint32_t> diag_writes{0};
            if (diag_writes.fetch_add(1) < 64) {
                size_t len = size * count;
                if (len > 128) len = 128;
                char b[192];
                memcpy(b, ptr, len);
                b[len] = 0;
                snprintf(b + len, sizeof(b) - len, " (handle=0x%08X)", handle);
                DiagTrace::Note(std::string("GUESTFW ") + b);
                DiagTrace::NotePersist(std::string("GUESTFW ") + b);  // W18
            }
        }
        jit.Regs()[0] = (it != g_file_map.end() && ptr) ? fwrite(ptr, size, count, it->second) : 0;
    });

    RegisterThunk("fseek", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        long offset = static_cast<long>(static_cast<int32_t>(jit.Regs()[1]));
        int whence = static_cast<int>(jit.Regs()[2]);
        auto it = g_file_map.find(handle);
        int res = (it != g_file_map.end()) ? fseek(it->second, offset, whence) : -1;
        // W320 (run424): handle-space fallback. A stream opened through the
        // open() thunk (g_vfd_map, e.g. the APK-direct WAD stream) seeked
        // through stdio missed g_file_map and returned -1 forever -- which
        // tripped bz_fread's "File Read Error" throw and its lethal unwind
        // (run414-423 wall). Serve vfd seeks here.
        if (res < 0) {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto vit = g_vfd_map.find(static_cast<int>(handle));
            if (vit != g_vfd_map.end()) {
                jit.Regs()[0] = SeekVirtualFd(vit->second, offset, whence) < 0
                    ? static_cast<uint32_t>(-1) : 0u;
                return;
            }
        }
        jit.Regs()[0] = res;
    });

    RegisterThunk("fseeko", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        off_t offset = static_cast<off_t>(static_cast<int32_t>(jit.Regs()[1]));
        int whence = static_cast<int>(jit.Regs()[2]);
        auto it = g_file_map.find(handle);
        int res = (it != g_file_map.end()) ? fseeko(it->second, offset, whence) : -1;
        if (res < 0) {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto virtual_fd = g_vfd_map.find(static_cast<int>(handle));
            if (virtual_fd != g_vfd_map.end())
                res = SeekVirtualFd(virtual_fd->second, offset, whence) < 0 ? -1 : 0;
        }
        jit.Regs()[0] = res;
    });

    RegisterThunk("ftell", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        if (it != g_file_map.end()) {
            jit.Regs()[0] = static_cast<uint32_t>(ftell(it->second));
            return;
        }
        // W320: vfd fallback (see fseek).
        {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto vit = g_vfd_map.find(static_cast<int>(handle));
            if (vit != g_vfd_map.end()) {
                std::lock_guard<std::mutex> cursor_lock(vit->second.cursor->mutex);
                jit.Regs()[0] = static_cast<uint32_t>(vit->second.cursor->pos);
                return;
            }
        }
        jit.Regs()[0] = 0;
    });

    RegisterThunk("ftello", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        off_t res = (it != g_file_map.end()) ? ftello(it->second) : -1;
        if (res < 0) {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto virtual_fd = g_vfd_map.find(static_cast<int>(handle));
            if (virtual_fd != g_vfd_map.end()) {
                std::lock_guard<std::mutex> cursor_lock(virtual_fd->second.cursor->mutex);
                res = virtual_fd->second.cursor->pos;
            }
        }
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("fileno", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        auto stream_fd = g_stream_vfd.find(handle);
        if (stream_fd != g_stream_vfd.end()) {
            jit.Regs()[0] = static_cast<uint32_t>(stream_fd->second);
            return;
        }
        auto it = g_file_map.find(handle);
        jit.Regs()[0] = (it != g_file_map.end()) ? fileno(it->second) : -1;
    });

    RegisterThunk("clearerr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        if (it != g_file_map.end()) clearerr(it->second);
    });

    RegisterThunk("ferror", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        jit.Regs()[0] = (it != g_file_map.end()) ? ferror(it->second) : 0;
    });

    RegisterThunk("open", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        int flags = static_cast<int>(jit.Regs()[1]);
        int mode = static_cast<int>(jit.Regs()[2]);

        int fd = -1;
        // The translated process exposes ARMv7/VFP/NEON to guest code. The
        // host's /proc/cpuinfo describes AArch64 instead, which makes FMOD's
        // one-time CPU probe report no usable mixer and reject setOutput.
        if (path && strcmp(path, "/proc/cpuinfo") == 0 &&
            (flags & O_ACCMODE) == O_RDONLY) {
            constexpr char kGuestCpuInfo[] =
                "Processor\t: ARMv7 Processor rev 0 (v7l)\n"
                "Features\t: swp half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt\n"
                "CPU architecture: 7\n";
            int ends[2];
            if (pipe(ends) == 0) {
                const ssize_t sent = write(ends[1], kGuestCpuInfo, sizeof(kGuestCpuInfo) - 1u);
                close(ends[1]);
                if (sent == static_cast<ssize_t>(sizeof(kGuestCpuInfo) - 1u)) {
                    jit.Regs()[0] = static_cast<uint32_t>(ends[0]);
                    return;
                }
                close(ends[0]);
            }
        }
        if (BridgeIsObbPath(path)) {
            if ((flags & (O_CREAT | O_TRUNC | O_WRONLY | O_RDWR | O_APPEND | O_DIRECTORY)) != 0) {
                errno = EROFS;
                jit.Regs()[0] = static_cast<uint32_t>(-1);
                return;
            }
            BridgeObbHandle source;
            if (!BridgeOpenSelectedObb(&source)) {
                LOGE("open OBB refused: no validated source for %s", path);
                jit.Regs()[0] = static_cast<uint32_t>(-1);
                return;
            }
            const int vfd = CreateVirtualFd(source.fd, source.length, source.offset,
                                            std::make_shared<FileCursor>());
            LOGI("open OBB source=%s path=%s base=%lld size=%u vfd=%d",
                 BridgeSelectedObbSourceName(), path, static_cast<long long>(source.offset),
                 source.length, vfd);
            jit.Regs()[0] = static_cast<uint32_t>(vfd);
            return;
        }
        if (path && (flags & O_CREAT) == 0 && (flags & O_WRONLY) == 0 && (flags & O_RDWR) == 0) {
            ApkEntry* entry = FindApkEntry(path);
            if (entry && g_apk_indexed_fd >= 0) {
                int dup_fd = dup(g_apk_indexed_fd);
                if (dup_fd >= 0) {
                    const int vfd = CreateVirtualFd(dup_fd, static_cast<size_t>(entry->file_size),
                                                    entry->data_offset, std::make_shared<FileCursor>());
                    LOGI("open: APK direct stream opened '%s' -> '%s' (vfd %d, size %zu, offset %lld)",
                         path, entry->name, vfd, entry->file_size, static_cast<long long>(entry->data_offset));
                    jit.Regs()[0] = static_cast<uint32_t>(vfd);
                    return;
                }
            }
        }

        fd = open(path ? path : "", flags, mode);
        jit.Regs()[0] = (fd >= 0) ? static_cast<uint32_t>(fd) : static_cast<uint32_t>(-1);
    });

    RegisterThunk("close", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        // W87 (run149): every guest close() of a low host fd number. The
        // glue pipe / looper fds share the host fd namespace with the
        // guest's; one bad close kills ALooper_pollAll with POLL_ERROR.
        if (fd >= 0 && fd < 1024) {
            static std::atomic<uint32_t> w87{0};
            if (w87.fetch_add(1) < 128) {
                char b[96];
                snprintf(b, sizeof(b), "W87CLOSE fd=%d lr=%08X", fd, jit.Regs()[14]);
                DiagTrace::NotePersist(b);
            }
        }
        {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto it = g_vfd_map.find(fd);
            if (it != g_vfd_map.end()) {
                close(it->second.source_fd);
                g_vfd_map.erase(it);
                jit.Regs()[0] = 0;
                return;
            }
        }
        jit.Regs()[0] = (fd >= 0) ? static_cast<uint32_t>(close(fd)) : static_cast<uint32_t>(-1);
    });

    RegisterThunk("read", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        void* buf = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t count = jit.Regs()[2];
        if (!buf) { jit.Regs()[0] = static_cast<uint32_t>(-1); return; }
        // W322 (run427): every read() with its GUEST destination -- the
        // WAD-member descriptor at 0x50B1BF0C was found filled with
        // trap-page words, so the read that fills it must pass here (or
        // through pread) with dst=0x50B1BF0C. Match it.
        {
            static std::atomic<uint32_t> w322{0};
            if (w322.fetch_add(1) < 64) {
                char b[128];
                snprintf(b, sizeof(b), "W322READ fd=%d dst=%08X len=%zu",
                         fd, jit.Regs()[1], count);
                DiagTrace::Note(b);
            }
        }

        {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto it = g_vfd_map.find(fd);
            if (it != g_vfd_map.end()) {
                VirtualFd& vfd = it->second;
                std::lock_guard<std::mutex> cursor_lock(vfd.cursor->mutex);
                if (vfd.cursor->pos >= static_cast<off_t>(vfd.file_size)) {
                    jit.Regs()[0] = 0; // EOF
                    return;
                }
                size_t avail = vfd.file_size - vfd.cursor->pos;
                size_t to_read = (count < avail) ? count : avail;
                ssize_t nread;
                do {
                    nread = pread(vfd.source_fd, buf, to_read, vfd.file_offset + vfd.cursor->pos);
                } while (nread < 0 && errno == EINTR);
                if (nread > 0) {
                    vfd.cursor->pos += nread;
                }
                if (nread == 0 && to_read != 0) errno = EIO;
                jit.Regs()[0] = (nread > 0 || to_read == 0)
                    ? static_cast<uint32_t>(nread) : static_cast<uint32_t>(-1);
                return;
            }
        }

        ssize_t res = (fd >= 0) ? read(fd, buf, count) : -1;
        // W295: identify the native-app-glue command read by its verified
        // guest call site. The former fixed app-address heuristic was tied
        // to an allocator layout from an older build and silently went stale.
        if (jit.Regs()[14] == 0x4017D61Cu) {
            static std::atomic<uint32_t> w295{0};
            const uint32_t n = w295.fetch_add(1);
            if (n < 32) {
                const uint32_t cmd = res == 1 ? *static_cast<const uint8_t*>(buf) : 0xFFFFFFFFu;
                char b[128];
                snprintf(b, sizeof(b),
                         "W295 app-read n=%u fd=%d count=%zu result=%zd cmd=%u lr=%08X",
                         n, fd, count, res, cmd, jit.Regs()[14]);
                DiagTrace::NotePersist(b);
            }
        }
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("write", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        const void* buf = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t count = jit.Regs()[2];
        ssize_t res = (buf && fd >= 0) ? write(fd, buf, count) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("lseek", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        off_t offset = static_cast<off_t>(static_cast<int32_t>(jit.Regs()[1]));
        int whence = static_cast<int>(jit.Regs()[2]);

        {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto it = g_vfd_map.find(fd);
            if (it != g_vfd_map.end()) {
                jit.Regs()[0] = static_cast<uint32_t>(SeekVirtualFd(it->second, offset, whence));
                return;
            }
        }

        off_t res = (fd >= 0) ? lseek(fd, offset, whence) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("lseek64", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        const uint64_t bits = static_cast<uint64_t>(jit.Regs()[2]) |
                              (static_cast<uint64_t>(jit.Regs()[3]) << 32);
        int64_t offset;
        memcpy(&offset, &bits, sizeof(offset));
        int whence = static_cast<int>(host.MemoryRead32(jit.Regs()[13]));

        {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto it = g_vfd_map.find(fd);
            if (it != g_vfd_map.end()) {
                const off_t new_pos = SeekVirtualFd(it->second, offset, whence);
                jit.Regs()[0] = static_cast<uint32_t>(new_pos & 0xFFFFFFFF);
                jit.Regs()[1] = static_cast<uint32_t>(static_cast<uint64_t>(new_pos) >> 32);
                return;
            }
        }

        off64_t res = (fd >= 0) ? lseek64(fd, offset, whence) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>(res >> 32);
    });

    RegisterThunk("access", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        int mode = static_cast<int>(jit.Regs()[1]);
        if (BridgeIsObbPath(path)) {
            BridgeObbHandle source;
            const bool available = BridgeOpenSelectedObb(&source);
            if (available) close(source.fd);
            jit.Regs()[0] = available && (mode & (W_OK | X_OK)) == 0 ? 0u
                          : static_cast<uint32_t>(-1);
            return;
        }
        int res = access(path ? path : "", mode);
        if (res != 0 && FindApkEntry(path)) {
            res = 0;
        }
        jit.Regs()[0] = res;
    });

    RegisterThunk("stat", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        uint32_t buf_gaddr = jit.Regs()[1];
        struct stat st;
        if (BridgeIsObbPath(path)) {
            BridgeObbHandle source;
            if (!BridgeOpenSelectedObb(&source)) {
                jit.Regs()[0] = static_cast<uint32_t>(-1);
                return;
            }
            const int result = fstat(source.fd, &st);
            close(source.fd);
            if (result == 0) {
                st.st_size = source.length;
                st.st_mode = S_IFREG | 0444;
                WriteArm32Stat(host.GetGuestMemoryBase(), buf_gaddr, st);
            }
            jit.Regs()[0] = static_cast<uint32_t>(result);
            return;
        }
        int res = stat(path ? path : "", &st);
        if (res != 0) {
            ApkEntry* entry = FindApkEntry(path);
            if (entry) {
                memset(&st, 0, sizeof(st));
                st.st_size = entry->file_size;
                st.st_mode = S_IFREG | 0444;
                st.st_nlink = 1;
                res = 0;
            }
        }
        if (res == 0) {
            WriteArm32Stat(host.GetGuestMemoryBase(), buf_gaddr, st);
        }
        jit.Regs()[0] = res;
    });

    RegisterThunk("feof", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        jit.Regs()[0] = (it != g_file_map.end()) ? feof(it->second) : 1;
    });

    RegisterThunk("fflush", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        jit.Regs()[0] = (it != g_file_map.end()) ? fflush(it->second) : 0;
    });

    RegisterThunk("setvbuf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });

    // mmap/munmap. Do NOT stub these as "hand out a fresh heap block": a caller that checks
    // the returned address (Boehm does, see lesson 2.15) will abort, and an engine that maps
    // its archive gets 345 MB of zeroes -- which reads as "the pak has no entries", not as an
    // error, and parks the boot on a download screen.
    //
    // The guest arena is one anonymous MAP_PRIVATE reservation, so a file mapping can be laid
    // straight into it with MAP_FIXED and the guest reads it at base + vaddr like any other
    // memory: no copy, no RSS. MAP_PRIVATE, never MAP_SHARED, so a stray guest write cannot
    // reach the file on disk.
    RegisterThunk("mmap", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t len   = jit.Regs()[1];
        const uint32_t flags = jit.Regs()[3];
        const uint32_t sp    = jit.Regs()[13];         // AAPCS: args 5 and 6 are on the stack
        int            fd    = static_cast<int>(host.MemoryRead32(sp));
        off_t          off   = static_cast<off_t>(host.MemoryRead32(sp + 4));

        constexpr uint32_t kMapAnonymous = 0x20;       // Linux MAP_ANONYMOUS on arm
        constexpr uint32_t kMapFailed    = 0xFFFFFFFF;
        const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));

        if (len == 0) { jit.Regs()[0] = kMapFailed; return; }

        if (fd < 0 || (flags & kMapAnonymous)) {
            // Anonymous: fresh mapping space, which the arena zero-fills for us.
            const uint32_t va = host.GuestAllocMapping((len + page - 1) & ~(page - 1), page);
            jit.Regs()[0] = va ? va : kMapFailed;
            return;
        }

        // A virtual FD is a bounded logical file backed by either the chosen
        // whole OBB (embedded/external) or an ordinary stored APK audio entry.
        // Duplicate its source while locked so a concurrent close cannot
        // invalidate the descriptor before mmap consumes it.
        struct ScopedMapFd {
            int fd = -1;
            ~ScopedMapFd() { if (fd >= 0) close(fd); }
        } owned;
        {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto it = g_vfd_map.find(fd);
            if (it != g_vfd_map.end()) {
                if (off < 0 || static_cast<uint64_t>(off) > it->second.file_size ||
                    len > it->second.file_size - static_cast<uint64_t>(off)) {
                    LOGE("mmap rejected: virtual FD range off=%lld len=%u size=%zu",
                         static_cast<long long>(off), len, it->second.file_size);
                    jit.Regs()[0] = kMapFailed;
                    return;
                }
                off += it->second.file_offset;
                owned.fd = dup(it->second.source_fd);
                fd = owned.fd;
            }
        }
        if (fd < 0) { jit.Regs()[0] = kMapFailed; return; }

        // mmap needs a page-aligned file offset; keep the remainder as a bias on the result.
        const off_t  aligned = off & ~static_cast<off_t>(page - 1);
        const size_t bias    = static_cast<size_t>(off - aligned);
        const size_t span    = (len + bias + page - 1) & ~(page - 1);

        struct stat fst{};
        if (fstat(fd, &fst) == 0) {
            std::lock_guard<std::mutex> lock(g_mapping_mutex);
            for (const auto& m : g_guest_file_maps) {
                if (m.dev == fst.st_dev && m.ino == fst.st_ino && m.off == aligned && m.span == span) {
                    jit.Regs()[0] = m.va + static_cast<uint32_t>(bias);
                    return;
                }
            }
        }

        const uint32_t va = host.GuestAllocMapping(span, page);
        if (!va) { LOGE("mmap: no guest arena for %zu bytes", span); jit.Regs()[0] = kMapFailed; return; }
        if (static_cast<uint64_t>(va) + span > host.GetGuestMemorySize()) {
            LOGE("mmap: 0x%08X + %zu would run past the guest arena", va, span);
            jit.Regs()[0] = kMapFailed;
            return;
        }
        void* want = host.GetGuestMemoryBase() + va;
        void* got = ::mmap(want, span, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd, aligned);
        if (got == MAP_FAILED) {
            LOGE("mmap(fd=%d, len=%u, off=%lld) failed: %s", fd, len,
                 static_cast<long long>(off), strerror(errno));
            jit.Regs()[0] = kMapFailed;
            return;
        }
        {
            std::lock_guard<std::mutex> lock(g_mapping_mutex);
            g_guest_file_maps.push_back({fst.st_dev, fst.st_ino, aligned, span, va});
        }
        LOGI("mmap: fd=%d len=%u off=%lld -> guest 0x%08X", fd, len,
             static_cast<long long>(off), va + static_cast<uint32_t>(bias));
        jit.Regs()[0] = va + static_cast<uint32_t>(bias);
    });

    RegisterThunk("munmap", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t addr = jit.Regs()[0];
        const uint32_t len  = jit.Regs()[1];
        const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
        if (!addr || !len) { jit.Regs()[0] = 0; return; }

        const uint32_t base_va = addr & ~static_cast<uint32_t>(page - 1);
        const size_t span = (static_cast<uint64_t>(len) + (addr - base_va) + page - 1) & ~(page - 1);

        // A cached file mapping stays: another filesystem may still be reading through it,
        // and the arena address is never reused anyway.
        {
            std::lock_guard<std::mutex> lock(g_mapping_mutex);
            for (const auto& m : g_guest_file_maps) {
                if (base_va >= m.va && base_va < m.va + m.span) { jit.Regs()[0] = 0; return; }
            }
        }
        // MAP_FIXED writes to *host* address space, and both the address and the length come
        // straight from the guest -- an out-of-range pair would unmap whatever the host keeps
        // after the arena, and that surfaces half a second later as a SIGSEGV in an unrelated
        // free(). Bounds-check before touching anything.
        if (static_cast<uint64_t>(base_va) + span > host.GetGuestMemorySize()) {
            LOGE("munmap(0x%08X, %u) out of arena, ignored", addr, len);
            jit.Regs()[0] = 0;
            return;
        }
        // Put anonymous pages back rather than leaving a hole: the arena has to stay one
        // continuous mapping or the next access through base + vaddr faults.
        ::mmap(host.GetGuestMemoryBase() + base_va, span, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        jit.Regs()[0] = 0;
    });

    RegisterThunk("fstat", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        uint32_t buf_gaddr = jit.Regs()[1];
        struct stat st;
        int res = -1;
        bool virtual_found = false;

        {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto it = g_vfd_map.find(fd);
            if (it != g_vfd_map.end()) {
                virtual_found = true;
                res = fstat(it->second.source_fd, &st);
                if (res == 0) {
                    st.st_size = it->second.file_size;
                    st.st_mode = S_IFREG | 0444;
                }
            }
        }

        if (!virtual_found) {
            res = fstat(fd, &st);
        }

        if (res == 0) {
            WriteArm32Stat(host.GetGuestMemoryBase(), buf_gaddr, st);
        }
        jit.Regs()[0] = res;
    });

    RegisterThunk("remove", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        jit.Regs()[0] = BridgeIsObbPath(path) ? static_cast<uint32_t>(-1)
                      : static_cast<uint32_t>(remove(path ? path : ""));
    });

    RegisterThunk("rename", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* oldp = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* newp = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = BridgeIsObbPath(oldp) || BridgeIsObbPath(newp)
                      ? static_cast<uint32_t>(-1)
                      : static_cast<uint32_t>(rename(oldp ? oldp : "", newp ? newp : ""));
    });

    RegisterThunk("chmod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("umask", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("mkstemp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = -1; });
    RegisterThunk("getpid", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = getpid(); });

    RegisterThunk("time", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = static_cast<uint32_t>(time(nullptr));
    });

    // Same contract as strerror: the caller never frees it. Real localtime
    // overwrites one static buffer per call; this does the same, per thread, so
    // two threads formatting a timestamp cannot scribble on each other.
    RegisterThunk("localtime", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static thread_local uint32_t gtm = 0;
        time_t t = static_cast<time_t>(host.MemoryRead32(jit.Regs()[0]));
        struct tm* tm_res = localtime(&t);
        if (!gtm) gtm = host.GuestAlloc(sizeof(struct tm));
        if (tm_res && gtm) {
            memcpy(GuestToHost(host.GetGuestMemoryBase(), gtm), tm_res, sizeof(struct tm));
            jit.Regs()[0] = gtm;
        } else {
            jit.Regs()[0] = 0;
        }
    });

    RegisterThunk("mktime", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        struct tm* tm_ptr = reinterpret_cast<struct tm*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        jit.Regs()[0] = tm_ptr ? static_cast<uint32_t>(mktime(tm_ptr)) : 0;
    });

    RegisterThunk("raise", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });

    // Runtime guards & hooks
    RegisterThunk("__stack_chk_fail", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGE("Guest stack check failed at PC: 0x%08X", jit.Regs()[15]);
    });

    RegisterThunk("abort", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        // W1 diagnostic: the run7/run8 routes looped abort() 16M+ times (a
        // C++ terminate -> rethrow cycle: __verbose_terminate_handler's
        // _cxa_rethrow re-threw because abort() kept returning).
        static std::atomic<uint32_t> diag_aborts{0};
        const uint32_t count = diag_aborts.fetch_add(1);
        if (count < 8 || count % 1000000 == 0) {
            char b[128];
            snprintf(b, sizeof(b), "ABORT #%u lr=0x%08X", count, jit.Regs()[14]);
            DiagTrace::Note(b);
        }
        if (count == 0) LOGE("Guest called abort()! lr=0x%08X", jit.Regs()[14]);
        // Semantics decision (W3): abort() is noreturn. Returning re-entered
        // the caller's retry/terminate cycle forever. Park the calling guest
        // thread permanently -- the rest of the process stays inspectable.
        for (;;) sleep(3600);
    });

    RegisterThunk("__assert2", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* file = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        int line = static_cast<int>(jit.Regs()[1]);
        const char* func = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2]));
        const char* expr = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3]));
        LOGE("Assertion failed: %s at %s:%d (%s)", expr ? expr : "", file ? file : "", line, func ? func : "");
    });

    RegisterThunk("__cxa_atexit", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__cxa_finalize", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__aeabi_unwind_cpp_pr0", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("__aeabi_unwind_cpp_pr1", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("_Unwind_Resume", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("_Unwind_RaiseException", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("_Unwind_DeleteException", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("_Unwind_GetLanguageSpecificData", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("_Unwind_GetRegionStart", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("_Unwind_VRS_Get", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("_Unwind_VRS_Set", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__gnu_unwind_frame", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });

    // Asset override: see InstallAssetOverrideHook below. R1 is the archive-relative
    // entry name; returning ip=0 makes the veneer return NULL, so the engine's own
    // "not in the archive" path takes over and opens the plain file instead.
    RegisterThunk("asset_override_archive_open", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* name = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[12] = HasAssetOverride(name) ? 0u : g_asset_override_real_fn;
    });
}

// ---------------------------------------------------------------------------
// Loading modified assets from <externalFilesDir>/...
//
// Engines of this era resolve a file through a chain: archive -> optional second
// archive -> plain fopen(rootDir + path). Making the first archive report "not
// found" for any file the user dropped into the override root turns that existing
// fallback into a full mod mechanism, with no archive-format code and no risk to
// the normal path. Point InstallAssetOverrideHook at the guest's archive-open PLT
// slot; everything below is engine-agnostic.
// ---------------------------------------------------------------------------

static std::string g_override_root;   // e.g. /sdcard/Android/data/<pkg>/files/
static bool g_override_enabled = false;

void SetAssetOverrideRoot(const std::string& root) {
    g_override_root = root;
    if (!g_override_root.empty() && g_override_root.back() != '/') g_override_root += '/';
    struct stat st;
    g_override_enabled = !g_override_root.empty() &&
                         stat(g_override_root.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
    LOGI("Asset override root: '%s' (%s)", g_override_root.c_str(), g_override_enabled ? "active" : "inactive");
}

bool HasAssetOverride(const char* entry_name) {
    if (!g_override_enabled || !entry_name) return false;
    // Entry names carry the archive layout, e.g. "assets/data/textures/x.bin" or
    // "<expansion-prefix>/assets/data/textures/x.bin"; the override root mirrors
    // everything below "assets/". Adjust this split if the guest archives differ.
    const char* rel = strstr(entry_name, "assets/");
    if (!rel) return false;
    rel += 7;
    if (!*rel) return false;
    std::string path = g_override_root + rel;
    if (access(path.c_str(), R_OK) != 0) return false;
    LOGI("Asset override: '%s' -> '%s'", entry_name, path.c_str());
    return true;
}

void InstallAssetOverrideHook(DynarmicHost& host, uint32_t plt_slot, const char* real_symbol) {
    if (!g_override_enabled || !plt_slot || !real_symbol) return;

    static bool s_installed = false;
    if (s_installed) return;

    g_asset_override_real_fn = host.GetElfLoader().GetSymbolAddress(real_symbol);
    if (!g_asset_override_real_fn) {
        LOGE("InstallAssetOverrideHook: '%s' not found in the guest", real_symbol);
        return;
    }

    uint32_t hook = host.GetThunkManager().GetOrCreateThunkAddress("asset_override_archive_open");
    uint32_t svc = host.MemoryRead32(hook);
    if ((svc & 0x00010000) != 0xEF000000) {
        LOGE("InstallAssetOverrideHook: unexpected trampoline at 0x%08X", hook);
        return;
    }

    // ARM veneer: run the hook, then either tail-call the real archive-open (ip != 0)
    // or return NULL. BX reaches the whole address space and handles the Thumb bit,
    // so unlike a B-based trampoline there is no +-32 MB limit.
    uint32_t veneer = host.GuestAlloc(32, 4);
    host.MemoryWrite32(veneer + 0,  svc);         // svc  #id
    host.MemoryWrite32(veneer + 4,  0xE35C0000);  // cmp  ip, #0
    host.MemoryWrite32(veneer + 8,  0x112FFF1C);  // bxne ip
    host.MemoryWrite32(veneer + 12, 0xE3A00000);  // mov  r0, #0
    host.MemoryWrite32(veneer + 16, 0xE12FFF1E);  // bx   lr
    host.InvalidateGuestCode(veneer, 32);

    host.MemoryWrite32(plt_slot + 0, 0xE51FF004);  // ldr pc, [pc, #-4]
    host.MemoryWrite32(plt_slot + 4, veneer);
    host.InvalidateGuestCode(plt_slot, 12);
    // The veneer is executable guest code living in the heap, so it must be
    // exempt from runaway-PC containment.
    host.AddExecutableRange(veneer, 32);

    s_installed = true;
    LOGI("Installed asset-override hook on '%s' (plt 0x%08X, veneer 0x%08X)",
         real_symbol, plt_slot, veneer);
}

// W541 (run725): is Render_RenderScene actually reached? One-shot logging
// veneer at its BL site (0x40569624, non-adjacent to any other patch).
struct W541Probe { const char* tag; uint32_t site; uint32_t stub; };
void W541Install(DynarmicHost& host) {
    const W541Probe probes[] = {
        {"w541a", 0x40569624u, 0x8F118C00u},  // BL Render_RenderScene
    };
    for (const W541Probe& pr : probes) {
        char tname[32];
        snprintf(tname, sizeof(tname), "%s_log", pr.tag);
        const char* tag = pr.tag;
        host.GetThunkManager().RegisterThunk(
            tname, [tag](Dynarmic::A32::Jit&, DynarmicHost&) {
                static std::atomic<uint32_t> n541{0};
                const uint32_t n = n541.fetch_add(1);
                if (n < 5 || (n % 2000) == 0) LOGE("[W541] %s HIT n=%u", tag, n);
            });
        const uint32_t tramp = host.GetThunkManager().GetOrCreateThunkAddress(tname);
        const uint32_t orig = host.MemoryRead32(pr.site);
        if ((orig & 0x0F000000u) != 0x0B000000u) {
            LOGE("[W541] %s: site %08X not a BL (%08X)", pr.tag, pr.site, orig);
            continue;
        }
        const int32_t off = static_cast<int32_t>(orig << 8) >> 8;
        const uint32_t target = pr.site + 8u + static_cast<uint32_t>(off << 2);
        const uint32_t code[10] = {
            0xE92D500Fu, 0xE59F300Cu, 0xE12FFF33u, 0xE8BD500Fu,
            0xE59FE008u, 0xE59FF008u, tramp, 0u, pr.site + 4u, target,
        };
        for (size_t i2 = 0; i2 < 10; ++i2)
            host.MemoryWrite32(pr.stub + static_cast<uint32_t>(i2) * 4u, code[i2]);
        host.MemoryWrite32(pr.site, 0xE51FF004u);
        host.MemoryWrite32(pr.site + 4u, pr.stub);
        host.InvalidateGuestCode(pr.site, 8);
        host.InvalidateGuestCode(pr.stub, 40);
        LOGE("[W541] %s veneer site=%08X stub=%08X", pr.tag, pr.site, pr.stub);
    }
}
