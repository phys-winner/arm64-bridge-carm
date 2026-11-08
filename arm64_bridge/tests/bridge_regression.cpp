#include "dynarmic_host.h"
#include "thunk_manager.h"
#include "thunk_types.h"
#include <atomic>
#include <barrier>
#include <bit>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <set>
#include <thread>
#include <vector>
#include <zlib.h>
#include <unistd.h>

namespace {
std::atomic<unsigned> checks{0};
#define CHECK(e) do { ++checks; if (!(e)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#e); fflush(stderr); std::_Exit(1); } } while (0)
uint32_t Call(DynarmicHost& h,const char* name,const std::vector<uint32_t>& args={}) {
    const uint32_t fn=h.GetThunkManager().FindRegisteredSymbol(name); CHECK(fn);
    return h.RunFunction(fn,args);
}
uint32_t Worker(DynarmicHost& h,uint32_t fn,const std::vector<uint32_t>& args={}) {
#if BRIDGE_GAME_MC4
    return h.RunWorkerFunction(fn,args);
#else
    return h.RunFunction(fn,args);
#endif
}
uint32_t Text(DynarmicHost& h,const char* s) {
    uint32_t p=h.GuestAlloc(strlen(s)+1); CHECK(p);memcpy(h.GetGuestMemoryBase()+p,s,strlen(s)+1);return p;
}
void Dispatch(DynarmicHost& h) {
    auto& m=h.GetThunkManager();
    CHECK(!GuestRangeValid(h.GetGuestMemorySize(),1,SIZE_MAX));
    CHECK(!GuestRangeValid(h.GetGuestMemorySize(),UINT32_MAX,8));
    CHECK(m.GetOrCreateThunkAddress("regression_missing_provider")==0);
    const auto symbol_count=m.GetThunkSymbolTable().size();
    CHECK(m.GetOrCreateThunkAddress("regression_missing_provider")==0);
    CHECK(m.GetThunkSymbolTable().size()==symbol_count);
    uint32_t fn=m.RegisterThunk("regression_replace",[](auto& j,auto&){j.Regs()[0]=17;});
    CHECK(h.RunFunction(fn)==17);
    CHECK(m.RegisterThunk("regression_replace",[](auto& j,auto&){j.Regs()[0]=42;})==fn);
    CHECK(h.RunFunction(fn)==42);
    bool rejected=false;
    try { m.RegisterThunk("__stack_chk_guard",[](auto&,auto&){}); } catch(const std::logic_error&) { rejected=true; }
    CHECK(rejected);
    // Replacement during an active callback must not destroy its captures.
    std::barrier ready(2),done(2);
    auto capture=std::make_shared<int>(73);std::weak_ptr<int> weak=capture;
    const uint32_t live=m.RegisterThunk("regression_live",[capture,&ready,&done](auto& j,auto&){ready.arrive_and_wait();done.arrive_and_wait();j.Regs()[0]=*capture;});
    capture.reset();
    std::thread t([&]{CHECK(Worker(h,live)==73);});
    ready.arrive_and_wait();
    CHECK(m.RegisterThunk("regression_live",[](auto& j,auto&){j.Regs()[0]=99;})==live);
    CHECK(!weak.expired());done.arrive_and_wait();t.join();CHECK(h.RunFunction(live)==99);
    // The fifth argument is on an 8-byte-aligned public-interface stack.
    uint32_t abi=m.RegisterThunk("regression_abi",[](auto& j,auto& host){
        CHECK((j.Regs()[13]&7)==0);Arm32CallArgs a(j,host);
        CHECK(a.U32()==1);CHECK(a.U64()==0x1122334455667788ULL);CHECK(a.U32()==5);j.Regs()[0]=61;
    });
    CHECK(h.RunFunction(abi,{1,0,0x55667788,0x11223344,5})==61);
    printf("PASS dispatch replacement, data/function separation, missing symbols, AAPCS32\n");
}
void Cores(DynarmicHost& h) {
    constexpr unsigned n=12;
    // Executable test snippets must live outside the guest heap: the bridge
    // deliberately traps instruction fetches from heap addresses.
    constexpr uint32_t test_code_base=0x8F130000u;
    std::barrier gate(n+1);
    std::array<uint32_t,n> stacks{},results{};
    auto fn=h.GetThunkManager().RegisterThunk("regression_cores",[&](auto& j,auto&){
        auto id=j.Regs()[0];CHECK(id<n);stacks[id]=j.Regs()[13];gate.arrive_and_wait();
        j.Regs()[0]=id+0x1000;
    });
    std::vector<std::thread> threads;
    for(unsigned i=0;i<n;++i)threads.emplace_back([&,i]{results[i]=Worker(h,fn,{i});});
    gate.arrive_and_wait();for(auto& t:threads)t.join();
    CHECK(std::set<uint32_t>(stacks.begin(),stacks.end()).size()==n);
    // Worker stacks are carved from the reserved guest-stack window, not
    // allocated from the guest heap (whose initialization may clear them).
    for(unsigned i=0;i<n;++i) {
        CHECK(results[i]==i+0x1000);
        const uint32_t base=stacks[i]-4*1024*1024;
        CHECK(base>=0x7E000000u && stacks[i]<=0x8E800000u);
        CHECK(h.GuestAllocSize(base)==0);
    }
    // Assemble-free ARM LDREX/STREX increment loop, shared by twelve cores.
    const uint32_t code=test_code_base,counter=h.GuestAlloc(4);
    h.MemoryWrite32(counter,0);
    const uint32_t words[]={0xe1902f9f,0xe2822001,0xe1803f92,0xe3530000,0x1afffffa,0xe2511001,0x1afffff8,0xe12fff1e};
    memcpy(h.GetGuestMemoryBase()+code,words,sizeof(words));h.AddExecutableRange(code,sizeof(words));
    threads.clear();
    for(unsigned i=0;i<n;++i)threads.emplace_back([&]{Worker(h,code,{counter,10000});});
    for(auto& t:threads)t.join();
    CHECK(h.MemoryRead32(counter)==n*10000);
    // Patch from another host thread; the main JIT must be in the live list.
    const uint32_t patched=test_code_base+0x100u;h.AddExecutableRange(patched,8);
    h.MemoryWrite32(patched,0xe3a00001);h.MemoryWrite32(patched+4,0xe12fff1e);
    CHECK(h.RunFunction(patched)==1);
    std::thread patcher([&]{h.MemoryWrite32(patched,0xe3a00002);h.InvalidateGuestCode(patched,4);});patcher.join();
    CHECK(h.RunFunction(patched)==2);
    auto maker=h.GetThunkManager().RegisterThunk("regression_runtime_register",[](auto& j,auto& host){
        host.GetThunkManager().RegisterThunk("regression_created_during_run",[](auto& k,auto&){k.Regs()[0]=82;});j.Regs()[0]=81;
    });
    const uint32_t resume=test_code_base+0x200u;h.AddExecutableRange(resume,24);
    const uint32_t resume_words[]={0xe92d4010,0xe59f4008,0xe12fff34,0xe2800001,0xe8bd8010,maker};
    memcpy(h.GetGuestMemoryBase()+resume,resume_words,sizeof(resume_words));
    CHECK(h.RunFunction(resume)==82);CHECK(Call(h,"regression_created_during_run")==82);
#if BRIDGE_GAME_MC4
    auto nested=h.GetThunkManager().RegisterThunk("regression_nested",[=](auto& j,auto& host){
        j.Regs()[0]=host.RunFunction(patched)+3;
    });
    CHECK(h.RunFunction(nested)==5);
    std::thread caller([&]{CHECK(Worker(h,nested)==5);});caller.join();
#endif
    printf("PASS 12 concurrent cores, isolated stacks, 120000 atomic increments, global invalidation, runtime registration\n");
}
void MathThunks(DynarmicHost& h) {
    std::set<std::string> covered;
    unsigned calls=0;
    const char* current="";
    auto run=[&](const char* name,const std::vector<uint32_t>& args) {
        current=name;covered.insert(name);++calls;
        const uint32_t fn=h.GetThunkManager().FindRegisteredSymbol(name);CHECK(fn);
        bool exited=false;const uint32_t result=h.RunFunction(fn,args,&exited);CHECK(exited);
        return result;
    };
    auto expect=[&](double actual,double expected,double tolerance=2e-13) {
        const bool match=std::isnan(expected) ? std::isnan(actual) :
            expected==0.0 ? actual==0.0 && std::signbit(actual)==std::signbit(expected) :
            std::isinf(expected) ? actual==expected :
            std::isfinite(actual) && std::fabs(actual-expected)<=tolerance*std::max(1.0,std::fabs(expected));
        if(!match)fprintf(stderr,"Math %s: actual=%a expected=%a\n",current,actual,expected);
        CHECK(match);
    };
    auto d=[&](const char* name,double value,const std::vector<uint32_t>& tail=std::vector<uint32_t>{}) {
        const uint64_t bits=std::bit_cast<uint64_t>(value);
        std::vector<uint32_t> args{uint32_t(bits),uint32_t(bits>>32)};
        args.insert(args.end(),tail.begin(),tail.end());run(name,args);
        return ReadDF(h.CurrentJit(),0);
    };
    auto binary=[&](const char* name,double first,double second) {
        const uint64_t bits=std::bit_cast<uint64_t>(second);
        return d(name,first,{uint32_t(bits),uint32_t(bits>>32)});
    };
    auto f=[&](const char* name,float value,const std::vector<uint32_t>& tail=std::vector<uint32_t>{}) {
        std::vector<uint32_t> args{std::bit_cast<uint32_t>(value)};
        args.insert(args.end(),tail.begin(),tail.end());run(name,args);
        return ReadSF(h.CurrentJit(),0);
    };
    // Non-symmetric inputs catch register-pair swaps and float/double confusion.
    const struct { const char* name;double input,expected; } unary[]={
        {"acos",0.5,1.0471975511965977},{"asin",0.5,0.5235987755982989},
        {"atan",1.0,0.7853981633974483},{"ceil",-1.25,-1.0},
        {"cos",0.5,0.8775825618903728},{"cosh",0.5,1.1276259652063807},
        {"exp",1.0,2.718281828459045},{"floor",-1.25,-2.0},
        {"log",2.718281828459045,1.0},{"log10",1000.0,3.0},
        {"rint",2.5,2.0},{"sin",0.5,0.479425538604203},
        {"sinh",0.5,0.5210953054937474},{"sqrt",81.0,9.0},
        {"tan",0.5,0.5463024898437905},{"tanh",0.5,0.46211715726000974}
    };
    const double nan=std::numeric_limits<double>::quiet_NaN();
    const double inf=std::numeric_limits<double>::infinity();
    for(const auto& item:unary) {
        expect(d(item.name,item.input),item.expected);
        expect(d(item.name,nan),nan);
    }
    expect(binary("atan2",3.0,-4.0),2.498091544796509);
    expect(binary("atan2",-0.0,-1.0),-3.141592653589793);
    expect(binary("atan2",nan,1.0),nan);
    expect(binary("fmod",-5.5,2.0),-1.5);expect(binary("fmod",-0.0,2.0),-0.0);
    expect(binary("fmod",1.0,0.0),nan);expect(binary("fmod",inf,2.0),nan);
    expect(binary("pow",2.0,3.0),8.0);expect(binary("pow",-2.0,3.0),-8.0);
    expect(binary("pow",-2.0,0.5),nan);expect(binary("pow",0.0,-1.0),inf);
    expect(binary("pow",nan,1.0),nan);
    for(const char* name:{"sin","tan","atan","sinh","tanh","sqrt","ceil","floor","rint"})
        expect(d(name,-0.0),-0.0);
    for(const char* name:{"acos","asin"})expect(d(name,2.0),nan);
    for(const char* name:{"sqrt","log","log10"})expect(d(name,-1.0),nan);
    for(const char* name:{"log","log10"})expect(d(name,0.0),-inf);
    for(const char* name:{"sin","cos","tan"})expect(d(name,inf),nan);
    expect(d("sqrt",inf),inf);expect(d("exp",inf),inf);expect(d("exp",-inf),0.0);
    expect(d("cosh",-inf),inf);expect(d("tanh",inf),1.0);expect(d("tanh",-inf),-1.0);
    // ARM32 frexp writes four bytes; modf writes eight, with its pointer in r2.
    const uint32_t output=h.GuestAlloc(16);CHECK(output);
    h.MemoryWrite64(output,0);h.MemoryWrite64(output+8,0x123456789abcdef0ULL);
    h.MemoryWrite32(output+4,0xdeadbeef);
    expect(d("frexp",-6.5,{output}),-0.8125);CHECK(h.MemoryRead32(output)==3);
    CHECK(h.MemoryRead32(output+4)==0xdeadbeef);
    expect(d("frexp",-0.0,{output}),-0.0);CHECK(h.MemoryRead32(output)==0);
    expect(d("frexp",inf,{output}),inf);expect(d("frexp",nan,{output}),nan);
    expect(d("ldexp",1.5,{uint32_t(-3)}),0.1875);
    expect(d("ldexp",-0.0,{5}),-0.0);expect(d("ldexp",inf,{1}),inf);
    expect(d("ldexp",nan,{1}),nan);expect(d("ldexp",1.0,{1024}),inf);
    CHECK(std::bit_cast<uint64_t>(d("ldexp",1.0,{uint32_t(-1074)}))==1);
    expect(d("modf",-6.5,{output}),-0.5);
    CHECK(std::bit_cast<double>(h.MemoryRead64(output))==-6.0);
    expect(d("modf",-inf,{output}),-0.0);
    CHECK(std::bit_cast<double>(h.MemoryRead64(output))==-inf);
    expect(d("modf",nan,{output}),nan);CHECK(std::isnan(std::bit_cast<double>(h.MemoryRead64(output))));
    CHECK(h.MemoryRead64(output+8)==0x123456789abcdef0ULL);
    const struct { const char* name;float input,expected; } single[]={
        {"ceilf",-1.25f,-1.0f},{"floorf",-1.25f,-2.0f},
        {"log10f",1000.0f,3.0f},{"sqrtf",81.0f,9.0f}
    };
    for(const auto& item:single) {
        expect(f(item.name,item.input),item.expected,0.0);
        expect(f(item.name,float(nan)),nan);expect(f(item.name,float(inf)),inf);
    }
    for(const char* name:{"ceilf","floorf","sqrtf"})expect(f(name,-0.0f),-0.0);
    expect(f("sqrtf",-1.0f),nan);expect(f("log10f",-1.0f),nan);expect(f("log10f",0.0f),-inf);
    CHECK(int32_t(run("lrintf",{std::bit_cast<uint32_t>(2.5f)}))==2);
    CHECK(int32_t(run("lrintf",{std::bit_cast<uint32_t>(-1.75f)}))==-2);
    CHECK(run("lrintf",{std::bit_cast<uint32_t>(-0.0f)})==0);
    CHECK(covered.size()==27);
    // Also cover the five registered float wrappers absent from guest imports.
    const struct { const char* name;float input,expected;double infinite; } additional[]={
        {"sinf",0.5f,0.47942555f,nan},{"cosf",0.5f,0.87758256f,nan},
        {"atanf",1.0f,0.78539816f,1.5707963267948966},{"acosf",0.5f,1.0471976f,nan}
    };
    for(const auto& item:additional) {
        expect(f(item.name,item.input),item.expected,2e-7);
        expect(f(item.name,float(nan)),nan);expect(f(item.name,float(inf)),item.infinite,2e-7);
    }
    for(const char* name:{"sinf","atanf"})expect(f(name,-0.0f),-0.0);
    expect(f("cosf",-0.0f),1.0);expect(f("acosf",2.0f),nan);
    expect(f("powf",2.0f,{std::bit_cast<uint32_t>(3.0f)}),8.0);
    expect(f("powf",-2.0f,{std::bit_cast<uint32_t>(3.0f)}),-8.0);
    expect(f("powf",-2.0f,{std::bit_cast<uint32_t>(0.5f)}),nan);
    expect(f("powf",-0.0f,{std::bit_cast<uint32_t>(3.0f)}),-0.0);
    expect(f("powf",float(nan),{std::bit_cast<uint32_t>(2.0f)}),nan);
    expect(f("powf",2.0f,{std::bit_cast<uint32_t>(float(inf))}),inf);
    expect(f("powf",0.0f,{std::bit_cast<uint32_t>(-1.0f)}),inf);
    CHECK(covered.size()==32);h.GuestFree(output);
    printf("PASS %zu registered libm thunks (27 imported), %u guest calls, softfp pairs, pointer outputs, signed zero/NaN/Inf/domain\n",covered.size(),calls);
}
void Zlib(DynarmicHost& h) {
    uint32_t source=Text(h,"compress this text, compress this text, compress this text"),packed=h.GuestAlloc(256),out=h.GuestAlloc(256),length=h.GuestAlloc(8);
    const uint32_t size=strlen(reinterpret_cast<char*>(h.GetGuestMemoryBase()+source))+1;
    h.MemoryWrite32(length,256);h.MemoryWrite32(length+4,0xdeadbeef);
    CHECK(Call(h,"compress2",{packed,length,source,size,9})==Z_OK);const uint32_t compressed=h.MemoryRead32(length);
    CHECK(h.MemoryRead32(length+4)==0xdeadbeef);h.MemoryWrite32(length,256);
    CHECK(Call(h,"uncompress",{out,length,packed,compressed})==Z_OK);
    CHECK(h.MemoryRead32(length)==size&&!memcmp(h.GetGuestMemoryBase()+source,h.GetGuestMemoryBase()+out,size));
    uint32_t stream=h.GuestAlloc(64),version=Call(h,"zlibVersion");h.MemoryWrite64(stream+56,0x123456789abcdef0ULL);
    CHECK(static_cast<int32_t>(Call(h,"inflateInit2_",{stream,15,version,112}))==Z_VERSION_ERROR);
    CHECK(Call(h,"inflateInit2_",{stream,15,version,56})==Z_OK);
    h.MemoryWrite32(stream,packed);h.MemoryWrite32(stream+4,compressed);h.MemoryWrite32(stream+12,out);h.MemoryWrite32(stream+16,256);
    CHECK(Call(h,"inflate",{stream,Z_FINISH})==Z_STREAM_END);CHECK(h.MemoryRead32(stream+20)==size);
    CHECK(Call(h,"inflateReset",{stream})==Z_OK&&h.MemoryRead32(stream+20)==0);
    CHECK(Call(h,"inflateEnd",{stream})==Z_OK&&h.MemoryRead32(stream+28)==0);
    CHECK(h.MemoryRead64(stream+56)==0x123456789abcdef0ULL);
    CHECK(Call(h,"deflateInit2_",{stream,6,Z_DEFLATED,15,8,Z_DEFAULT_STRATEGY,version,56})==Z_OK);
    h.MemoryWrite32(stream,source);h.MemoryWrite32(stream+4,size);h.MemoryWrite32(stream+12,packed);h.MemoryWrite32(stream+16,256);
    CHECK(Call(h,"deflate",{stream,Z_FINISH})==Z_STREAM_END);CHECK(Call(h,"deflateEnd",{stream})==Z_OK);
    CHECK(Call(h,"crc32",{0,source,size})==crc32(0,h.GetGuestMemoryBase()+source,size));
    printf("PASS zlib roundtrip, stream32 canaries, stack arguments, reset/end/version\n");
}
#if BRIDGE_GAME_MC4
void Pthreads(DynarmicHost& h) {
    const uint32_t mutex=h.GuestAlloc(4),cond=h.GuestAlloc(4),once=h.GuestAlloc(4),keyp=h.GuestAlloc(4),result=h.GuestAlloc(4),tid=h.GuestAlloc(4);
    CHECK(Call(h,"pthread_mutex_init",{mutex,0})==0);CHECK(Call(h,"pthread_cond_init",{cond,0})==0);
    CHECK(Call(h,"pthread_mutex_lock",{mutex})==0);CHECK(Call(h,"pthread_mutex_trylock",{mutex})==EBUSY);
    CHECK(Call(h,"pthread_mutex_unlock",{mutex})==0);
    std::atomic<unsigned> destructors=0;
    const uint32_t destructor=h.GetThunkManager().RegisterThunk("regression_tls_destructor",[&](auto& j,auto&){CHECK(j.Regs()[0]==23);++destructors;});
    CHECK(Call(h,"pthread_key_create",{keyp,destructor})==0);const uint32_t key=h.MemoryRead32(keyp);
    CHECK(Call(h,"pthread_setspecific",{key,19})==0);
    const auto mainself=Call(h,"pthread_self"),mainerrno=Call(h,"__errno");
    const uint32_t tls=Call(h,"__get_tls");CHECK(mainerrno==tls+8);CHECK(h.MemoryRead32(tls)==tls);
    const uint32_t mrc=h.GuestAlloc(8);h.MemoryWrite32(mrc,0xee1d0f70);h.MemoryWrite32(mrc+4,0xe12fff1e);h.AddExecutableRange(mrc,8);CHECK(h.RunFunction(mrc)==tls);
    std::atomic<bool> ready=false;
    std::atomic<unsigned> inits=0;
    const uint32_t init=h.GetThunkManager().RegisterThunk("regression_once_init",[&](auto&,auto&){++inits;});
    const uint32_t worker=h.GetThunkManager().RegisterThunk("regression_pthread_entry",[&](auto& j,auto& host){
        CHECK(Call(host,"pthread_self")!=mainself);CHECK(Call(host,"__errno")!=mainerrno);
        CHECK(Call(host,"pthread_getspecific",{key})==0);CHECK(Call(host,"pthread_setspecific",{key,23})==0);
        CHECK(Call(host,"pthread_once",{once,init})==0);
        CHECK(Call(host,"pthread_mutex_lock",{mutex})==0);ready.store(true);
        CHECK(Call(host,"pthread_cond_signal",{cond})==0);CHECK(Call(host,"pthread_mutex_unlock",{mutex})==0);
        j.Regs()[0]=0xcafe;
    });
    CHECK(Call(h,"pthread_mutex_lock",{mutex})==0);
    CHECK(Call(h,"pthread_create",{tid,0,worker,0})==0);
    while(!ready.load())CHECK(Call(h,"pthread_cond_wait",{cond,mutex})==0);
    CHECK(Call(h,"pthread_mutex_unlock",{mutex})==0);
    CHECK(Call(h,"pthread_join",{h.MemoryRead32(tid),result})==0);CHECK(h.MemoryRead32(result)==0xcafe);
    CHECK(destructors==1);
    CHECK(Call(h,"pthread_getspecific",{key})==19);CHECK(Call(h,"pthread_once",{once,init})==0);CHECK(inits==1);
    const uint32_t expired=h.GuestAlloc(8);CHECK(Call(h,"pthread_mutex_lock",{mutex})==0);
    CHECK(Call(h,"pthread_cond_timedwait",{cond,mutex,expired})==ETIMEDOUT);
    CHECK(Call(h,"pthread_mutex_unlock",{mutex})==0);CHECK(Call(h,"pthread_mutex_destroy",{mutex})==0);CHECK(Call(h,"pthread_cond_destroy",{cond})==0);
    const uint32_t sem=h.GuestAlloc(4);CHECK(Call(h,"sem_init",{sem,0,0})==0);
    CHECK(Call(h,"sem_trywait",{sem})==UINT32_MAX);CHECK(h.MemoryRead32(mainerrno)==EAGAIN);
    CHECK(Call(h,"sem_post",{sem})==0);CHECK(Call(h,"sem_wait",{sem})==0);CHECK(Call(h,"sem_destroy",{sem})==0);
    const uint32_t attr=h.GuestAlloc(4),recursive=h.GuestAlloc(4);
    CHECK(Call(h,"pthread_mutexattr_init",{attr})==0);CHECK(Call(h,"pthread_mutexattr_settype",{attr,1})==0);
    CHECK(Call(h,"pthread_mutex_init",{recursive,attr})==0);CHECK(Call(h,"pthread_mutex_lock",{recursive})==0);
    CHECK(Call(h,"pthread_mutex_trylock",{recursive})==0);CHECK(Call(h,"pthread_mutex_unlock",{recursive})==0);
    CHECK(Call(h,"pthread_mutex_unlock",{recursive})==0);CHECK(Call(h,"pthread_mutex_destroy",{recursive})==0);
    CHECK(Call(h,"pthread_mutexattr_destroy",{attr})==0);CHECK(Call(h,"pthread_key_delete",{key})==0);
    // A native FILE read calls a guest callback synchronously while the outer
    // fread SVC remains live. The previous defer-to-main path returned zero.
    const uint32_t readfn=h.GetThunkManager().RegisterThunk("regression_funopen_read",[](auto& j,auto& host){
        auto n=std::min(j.Regs()[2],4u);memcpy(host.GetGuestMemoryBase()+j.Regs()[1],"data",n);j.Regs()[0]=n;
    });
    const uint32_t file=Call(h,"funopen",{0,readfn,0,0,0}),buf=h.GuestAlloc(4);CHECK(file);
    CHECK(Call(h,"fread",{buf,1,4,file})==4);CHECK(!memcmp(h.GetGuestMemoryBase()+buf,"data",4));
    CHECK(Call(h,"fclose",{file})==0);
    printf("PASS pthread creation/join, mutex/trylock, cond wait/signal/timeout, once, TLS/CP15, semaphore errno\n");
}
#endif
void TrampolineCapacity(DynarmicHost& h) {
    auto& m=h.GetThunkManager();
    h.MemoryWrite32(0x20000,0xabcddcba);
    bool exhausted=false;
    try {
        for(unsigned i=0;i<8193;++i)
            m.RegisterThunk("regression_capacity_"+std::to_string(i),[](auto&,auto&){});
    } catch(const std::overflow_error&) { exhausted=true; }
    CHECK(exhausted);CHECK(h.MemoryRead32(0x20000)==0xabcddcba);
    printf("PASS trampoline capacity rejects overlap with the next guest page\n");
}
}
int main() {
    setvbuf(stdout,nullptr,_IONBF,0);
    // This is a component test. Existing bring-up diagnostic threads are
    // process-lifetime services; do not pretend this validates host teardown.
    auto* host=new DynarmicHost();CHECK(host->Initialize());
    printf("Device page size: %ld\n",sysconf(_SC_PAGESIZE));
    Dispatch(*host);Cores(*host);MathThunks(*host);Zlib(*host);
#if BRIDGE_GAME_MC4
    Pthreads(*host);
#endif
    TrampolineCapacity(*host);
    printf("PASS %u checks\n",checks.load());fflush(stdout);std::_Exit(0);
}
