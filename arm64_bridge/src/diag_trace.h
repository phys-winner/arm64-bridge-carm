#pragma once

// D1 no-progress diagnostics (diagnostic-only, no behavior change).
// Device logcat throttling (LOG_FLOWCTRL OVER PROC QUOTA) hid the guest's own
// markers in the R1-R3 route, so this trace goes to a file in the app's
// external files dir instead: <files>/bridge_diag.txt, rewritten every 10 s.
//
// What it answers (the three hypotheses for the post-EGL worker stall):
//  - hot loop through host thunks  -> delta counters + RLE ring show the loop
//  - pure guest JIT loop           -> deltas go quiet, ring freezes
//  - PDStartup_0 message pump      -> repeated ALooper_pollAll/read in the ring
// Per invariant 6 (diagnostics expire) this file is removable whole after the
// causal classification.

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace DiagTrace {
// Spawns the watchdog writer thread. Safe to call once from activity onCreate.
void Start(const std::string& files_path);
// Hot path: called from ThunkManager::DispatchThunk with the resolved name and
// the guest return address (LR) of the call site.
void Thunk(const char* name, uint32_t guest_lr);
// Feed guest-originated log lines (the game's own markers) into the trace.
void GuestLog(const std::string& line);
// Diagnostic-only PC sampler hook: the writer thread periodically calls this to
// record the guest PC of every registered JIT (thread). Installed by
// jni_bridge.cpp after the host exists; sampling a JIT that is mid-Run on
// another thread may read a torn register, which is acceptable for a histogram.
void SetPcProvider(std::function<std::vector<uint32_t>()> provider);
// C1 diagnostic-only heap canary pass: the writer thread calls this every dump
// cycle and appends the returned report to bridge_diag.txt. Installed by
// jni_bridge.cpp; an empty return means no violation was found.
void SetHeapCheckProvider(std::function<std::string()> provider);
// N1 diagnostic-only: the writer thread calls this every dump cycle and appends
// the returned report (gDynamic_vb_map header + bounded __tree_next walk) to
// bridge_diag.txt. Installed by jni_bridge.cpp.
void SetMapWalkProvider(std::function<std::string()> provider);
// W146 diagnostic-only: the writer thread calls this every dump cycle and
// appends the returned sentinel report (pause flag, LLMem align, pool
// descriptor head + change lines) to bridge_diag.txt. Installed by
// jni_bridge.cpp.
void SetSentinelProvider(std::function<std::string()> provider);
// N2 diagnostic-only: bounded ring of guest-heap events (large guest
// malloc/free with LR, freed-block-write violations), dumped as its own
// section so it cannot flush the 128-line guest log ring.
void HeapEvent(const std::string& line);
// Phase-7 diagnostic-only: bounded notes ring (top-level RunFunction returns,
// qsort call context) that logcat throttling cannot flush; dumped as its own
// section. The last entries identify the dying call chain.
void Note(const std::string& line);
// W15 diagnostic-only: bounded persist ring for death-time events (C++ unwind
// lookups, guest throws). Unlike Note() this survives the post-freeze 10 kHz
// usleep spam that flushes the 2048-entry notes ring in ~0.2 s.
void NotePersist(const std::string& line);
// W3 diagnostic-only: the writer thread calls this every dump cycle; the
// returned string (Lua error dump from the guest scratch block) is appended
// as its own section. Empty return = nothing new.
void SetErrorDumpProvider(std::function<std::string()> provider);
}  // namespace DiagTrace
