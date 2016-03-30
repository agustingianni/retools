#ifndef __debug_h__
#define __debug_h__

#include <stdio.h>
#include <errno.h>
#include <string.h>

#define FILE (strrchr(__FILE__, '/') ? (const char *) strrchr(__FILE__, '/') + 1 : __FILE__)

#ifdef NDEBUG
#define LOG_DEBUG(M, ...)
#else
#define LOG_DEBUG(M, ...) fprintf(stdout, "[DBG] %s -> " M "\n", __FUNCTION__, ##__VA_ARGS__)
#endif

#define CLEAN_ERRNO() (errno == 0 ? "None" : (const char *) strerror(errno))

#define LOG_ERR(M, ...) fprintf(stderr, "[ERR] (errno: %s) " M "\n", CLEAN_ERRNO(), ##__VA_ARGS__)

#define LOG_WARN(M, ...) fprintf(stderr, "[WRN] (errno: %s) " M "\n", CLEAN_ERRNO(), ##__VA_ARGS__)

#define LOG_INFO(M, ...) fprintf(stderr, "[NFO] " M "\n", ##__VA_ARGS__)

#define CHECK(A, M, ...) if(!(A)) { LOG_ERR(M, ##__VA_ARGS__); errno=0; goto error; }

#define SENTINEL(M, ...)  { LOG_ERR(M, ##__VA_ARGS__); errno=0; goto error; }

#define CHECK_MEM(A) CHECK((A), "Out of memory.")

#define CHECK_DEBUG(A, M, ...) if(!(A)) { DEBUG(M, ##__VA_ARGS__); errno=0; goto error; }

#endif
