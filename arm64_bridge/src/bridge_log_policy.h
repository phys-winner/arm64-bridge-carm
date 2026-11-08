#pragma once

#include <android/log.h>

#if !BRIDGE_ENABLE_LOGS
#define __android_log_print(...) 0
#define __android_log_vprint(...) 0
#define __android_log_write(...) 0
#define __android_log_buf_print(...) 0
#define __android_log_buf_write(...) 0
#endif
