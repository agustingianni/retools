#ifndef __debug_h__
#define __debug_h__

#include <stdio.h>
#include <errno.h>
#include <string.h>

#ifdef NDEBUG
#define LOG_DEBUG(M, ...)
#else
#define LOG_DEBUG(M, ...) fprintf(stdout, "[DBG] %s -> " M "\n", __FUNCTION__, ##__VA_ARGS__)
#endif

#define CLEAN_ERRNO() (errno == 0 ? "None" : (const char *) strerror(errno))
#define LOG_ERR(M, ...) fprintf(stderr, "[ERR] (errno: %s) " M "\n", CLEAN_ERRNO(), ##__VA_ARGS__)
#define LOG_WARN(M, ...) fprintf(stderr, "[WRN] (errno: %s) " M "\n", CLEAN_ERRNO(), ##__VA_ARGS__)
#define LOG_INFO(M, ...) fprintf(stderr, "[NFO] " M "\n", ##__VA_ARGS__)

#endif
