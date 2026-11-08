#include "diag_trace.h"

namespace DiagTrace {

void Start(const std::string&) {}
void Thunk(const char*, uint32_t) {}
void GuestLog(const std::string&) {}
void SetPcProvider(std::function<std::vector<uint32_t>()>) {}
void SetHeapCheckProvider(std::function<std::string()>) {}
void SetMapWalkProvider(std::function<std::string()>) {}
void SetSentinelProvider(std::function<std::string()>) {}
void HeapEvent(const std::string&) {}
void Note(const std::string&) {}
void NotePersist(const std::string&) {}
void SetErrorDumpProvider(std::function<std::string()>) {}

}  // namespace DiagTrace
