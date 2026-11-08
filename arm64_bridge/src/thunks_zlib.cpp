// ABI translation from the Colin McRae Rally / Deus Ex / Warband bridges.
// z_stream is 56 bytes in ARM32 Bionic and 112 bytes on the ARM64 host.
// Host-owned state uses host allocation; guest allocator callbacks are preserved
// in the guest structure, but are not used to allocate host zlib internals.
#include "thunk_manager.h"
#include "dynarmic_host.h"
#include "thunk_types.h"
#include <zlib.h>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace {
using Jit = Dynarmic::A32::Jit;
using Host = DynarmicHost;
struct GuestStream {
    uint32_t next_in, avail_in, total_in, next_out, avail_out, total_out;
    uint32_t msg, state, zalloc, zfree, opaque;
    int32_t data_type;
    uint32_t adler, reserved;
};
static_assert(sizeof(GuestStream) == 56 && offsetof(GuestStream, adler) == 48);
struct Stream {
    std::mutex mutex;
    z_stream value{};
    bool deflating = false;
    bool live = false;
    ~Stream() { if (live) { if (deflating) deflateEnd(&value); else inflateEnd(&value); } }
};
struct Registry {
    std::mutex mutex;
    std::unordered_map<uint32_t, std::shared_ptr<Stream>> streams;
    uint32_t version = 0;
    uint32_t crc_table = 0;
    std::shared_ptr<Stream> Find(uint32_t key) {
        std::lock_guard lock(mutex);
        auto it = streams.find(key);
        return it == streams.end() ? nullptr : it->second;
    }
};
GuestStream* Guest(Host& h, uint32_t address) {
    if (address & 3) return nullptr;
    return static_cast<GuestStream*>(GuestSpan(h.GetGuestMemoryBase(), h.GetGuestMemorySize(), address, sizeof(GuestStream)));
}
bool Pull(Host& h, const GuestStream& g, z_stream& z) {
    if ((g.avail_in && !GuestRangeValid(h.GetGuestMemorySize(), g.next_in, g.avail_in)) ||
        (g.avail_out && !GuestRangeValid(h.GetGuestMemorySize(), g.next_out, g.avail_out))) return false;
    z.next_in = static_cast<Bytef*>(GuestToHost(h.GetGuestMemoryBase(), g.next_in));
    z.next_out = static_cast<Bytef*>(GuestToHost(h.GetGuestMemoryBase(), g.next_out));
    z.avail_in = g.avail_in;
    z.avail_out = g.avail_out;
    return true;
}
void Push(Host& h, GuestStream& g, const Stream& s) {
    const auto& z = s.value;
    g.next_in = HostToGuest(h.GetGuestMemoryBase(), z.next_in);
    g.next_out = HostToGuest(h.GetGuestMemoryBase(), z.next_out);
    g.avail_in = z.avail_in; g.avail_out = z.avail_out;
    g.total_in = static_cast<uint32_t>(z.total_in); g.total_out = static_cast<uint32_t>(z.total_out);
    g.state = s.live ? 0x5a11b001 : 0;
    g.msg = 0;
    g.data_type = z.data_type; g.adler = static_cast<uint32_t>(z.adler);
}
bool VersionValid(Host& h, uint32_t version, uint32_t size) {
    const char* text = GuestCString(h.GetGuestMemoryBase(), h.GetGuestMemorySize(), version);
    return size == sizeof(GuestStream) && text && *text == ZLIB_VERSION[0];
}
}

void ThunkManager::RegisterZlibThunks() {
    auto registry = std::make_shared<Registry>();
    auto initialize = [registry](Jit& j, Host& h, bool deflating, bool extended) {
        Arm32CallArgs args(j, h);
        const uint32_t address = args.Ptr();
        const int level = deflating ? args.I32() : 0;
        const int method = deflating && extended ? args.I32() : Z_DEFLATED;
        const int bits = extended ? args.I32() : MAX_WBITS;
        const int memory = deflating && extended ? args.I32() : 8;
        const int strategy = deflating && extended ? args.I32() : Z_DEFAULT_STRATEGY;
        const uint32_t version = args.Ptr(), size = args.U32();
        GuestStream* g = Guest(h, address);
        if (!g) { j.Regs()[0] = Z_STREAM_ERROR; return; }
        if (!VersionValid(h, version, size)) { j.Regs()[0] = Z_VERSION_ERROR; return; }
        auto stream = std::make_shared<Stream>();
        std::lock_guard state_lock(stream->mutex);
        {
            std::lock_guard lock(registry->mutex);
            if (registry->streams.contains(address)) { j.Regs()[0] = Z_STREAM_ERROR; return; }
            registry->streams.emplace(address, stream);
        }
        stream->deflating = deflating;
        const int result = deflating
            ? deflateInit2(&stream->value, level, method, bits, memory, strategy)
            : inflateInit2(&stream->value, bits);
        stream->live = result == Z_OK;
        if (stream->live) {
            // Init/reset must leave caller-owned input/output windows untouched.
            g->state = 0x5a11b001; g->msg = 0; g->total_in = g->total_out = 0;
            g->data_type = stream->value.data_type; g->adler = stream->value.adler;
        } else {
            std::lock_guard lock(registry->mutex);
            registry->streams.erase(address);
            g->state = 0;
        }
        j.Regs()[0] = result;
    };
    RegisterThunk("inflateInit_", [initialize](Jit& j, Host& h) { initialize(j,h,false,false); });
    RegisterThunk("inflateInit2_", [initialize](Jit& j, Host& h) { initialize(j,h,false,true); });
    RegisterThunk("deflateInit_", [initialize](Jit& j, Host& h) { initialize(j,h,true,false); });
    RegisterThunk("deflateInit2_", [initialize](Jit& j, Host& h) { initialize(j,h,true,true); });

    auto operation = [registry](Jit& j, Host& h, bool deflating, int action) {
        const uint32_t address = j.Regs()[0];
        auto s = registry->Find(address);
        auto* g = Guest(h, address);
        if (!s || !g) { j.Regs()[0] = Z_STREAM_ERROR; return; }
        std::lock_guard lock(s->mutex);
        if (!s->live || s->deflating != deflating || (action == 0 && !Pull(h, *g, s->value))) { j.Regs()[0] = Z_STREAM_ERROR; return; }
        int result;
        if (action == 0) result = deflating ? deflate(&s->value, j.Regs()[1]) : inflate(&s->value, j.Regs()[1]);
        else if (action == 1) result = deflating ? deflateReset(&s->value) : inflateReset(&s->value);
        else {
            result = deflating ? deflateEnd(&s->value) : inflateEnd(&s->value);
            s->live = false;
            std::lock_guard registry_lock(registry->mutex);
            registry->streams.erase(address);
        }
        if (action == 0) Push(h, *g, *s);
        else {
            g->state = s->live ? 0x5a11b001 : 0; g->msg = 0;
            if (action == 1) { g->total_in = g->total_out = 0; g->adler = s->value.adler; }
        }
        j.Regs()[0] = result;
    };
    RegisterThunk("inflate", [operation](Jit& j, Host& h) { operation(j,h,false,0); });
    RegisterThunk("inflateReset", [operation](Jit& j, Host& h) { operation(j,h,false,1); });
    RegisterThunk("inflateEnd", [operation](Jit& j, Host& h) { operation(j,h,false,2); });
    RegisterThunk("deflate", [operation](Jit& j, Host& h) { operation(j,h,true,0); });
    RegisterThunk("deflateReset", [operation](Jit& j, Host& h) { operation(j,h,true,1); });
    RegisterThunk("deflateEnd", [operation](Jit& j, Host& h) { operation(j,h,true,2); });
    RegisterThunk("deflateBound", [registry](Jit& j, Host&) {
        auto s = registry->Find(j.Regs()[0]);
        if (!s) { j.Regs()[0] = 0; return; }
        std::lock_guard lock(s->mutex);
        j.Regs()[0] = s->live && s->deflating ? deflateBound(&s->value, j.Regs()[1]) : 0;
    });
    RegisterThunk("compressBound", [](Jit& j, Host&) { j.Regs()[0] = compressBound(j.Regs()[0]); });
    auto one_shot = [](Jit& j, Host& h, int mode) {
        const uint32_t out = j.Regs()[0], length = j.Regs()[1], input = j.Regs()[2], size = j.Regs()[3];
        if (!GuestRangeValid(h.GetGuestMemorySize(), length, 4)) { j.Regs()[0] = Z_STREAM_ERROR; return; }
        uLongf available = h.MemoryRead32(length);
        auto* destination = static_cast<Bytef*>(GuestSpan(h.GetGuestMemoryBase(),h.GetGuestMemorySize(),out,available));
        auto* source = static_cast<const Bytef*>(GuestSpan(h.GetGuestMemoryBase(),h.GetGuestMemorySize(),input,size));
        if (!destination || !source) { j.Regs()[0] = Z_STREAM_ERROR; return; }
        int result = mode == 0 ? uncompress(destination,&available,source,size)
            : compress2(destination,&available,source,size,mode == 2 ? static_cast<int>(Arm32CallArgs(j,h,4).U32()) : Z_DEFAULT_COMPRESSION);
        h.MemoryWrite32(length, static_cast<uint32_t>(available));
        j.Regs()[0] = result;
    };
    RegisterThunk("uncompress", [one_shot](Jit& j, Host& h) { one_shot(j,h,0); });
    RegisterThunk("compress", [one_shot](Jit& j, Host& h) { one_shot(j,h,1); });
    RegisterThunk("compress2", [one_shot](Jit& j, Host& h) { one_shot(j,h,2); });
    auto checksum = [](Jit& j, Host& h, bool adler) {
        const auto* data = j.Regs()[1] ? static_cast<const Bytef*>(GuestSpan(h.GetGuestMemoryBase(),h.GetGuestMemorySize(),j.Regs()[1],j.Regs()[2])) : nullptr;
        if (j.Regs()[1] && !data) { throw std::out_of_range("Invalid zlib checksum input"); }
        j.Regs()[0] = adler ? adler32(j.Regs()[0],data,j.Regs()[2]) : crc32(j.Regs()[0],data,j.Regs()[2]);
    };
    RegisterThunk("crc32", [checksum](Jit& j, Host& h) { checksum(j,h,false); });
    RegisterThunk("adler32", [checksum](Jit& j, Host& h) { checksum(j,h,true); });
    RegisterThunk("zlibVersion", [registry](Jit& j, Host& h) {
        std::lock_guard lock(registry->mutex);
        if (!registry->version) {
            registry->version = h.GuestAlloc(sizeof(ZLIB_VERSION));
            if (registry->version) memcpy(h.GetGuestMemoryBase()+registry->version,ZLIB_VERSION,sizeof(ZLIB_VERSION));
        }
        j.Regs()[0] = registry->version;
    });
    RegisterThunk("get_crc_table", [registry](Jit& j, Host& h) {
        std::lock_guard lock(registry->mutex);
        if (!registry->crc_table) {
            registry->crc_table = h.GuestAlloc(256*4);
            if (registry->crc_table) for (unsigned i=0;i<256;++i) h.MemoryWrite32(registry->crc_table+i*4,get_crc_table()[i]);
        }
        j.Regs()[0] = registry->crc_table;
    });
}
