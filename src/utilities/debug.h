#ifndef __debug_h__
#define __debug_h__

#include <stdio.h>
#include <errno.h>
#include <string.h>

#define RESET   "\033[0m"
#define BLACK   "\033[30m"      /* Black */
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */
#define YELLOW  "\033[33m"      /* Yellow */
#define BLUE    "\033[34m"      /* Blue */
#define MAGENTA "\033[35m"      /* Magenta */
#define CYAN    "\033[36m"      /* Cyan */
#define WHITE   "\033[37m"      /* White */
#define BOLDBLACK   "\033[1m\033[30m"      /* Bold Black */
#define BOLDRED     "\033[1m\033[31m"      /* Bold Red */
#define BOLDGREEN   "\033[1m\033[32m"      /* Bold Green */
#define BOLDYELLOW  "\033[1m\033[33m"      /* Bold Yellow */
#define BOLDBLUE    "\033[1m\033[34m"      /* Bold Blue */
#define BOLDMAGENTA "\033[1m\033[35m"      /* Bold Magenta */
#define BOLDCYAN    "\033[1m\033[36m"      /* Bold Cyan */
#define BOLDWHITE   "\033[1m\033[37m"      /* Bold White */

#ifdef NDEBUG
#define LOG_DEBUG(M, ...)
#else
#define LOG_DEBUG(M, ...) fprintf(stdout, BOLDBLUE "[DBG] %20s -> " M "\n" RESET, __FUNCTION__, ##__VA_ARGS__)
#endif

#define CLEAN_ERRNO() (errno == 0 ? "None" : (const char *) strerror(errno))
#define LOG_ERR(M, ...) fprintf(stderr, BOLDRED "[ERR] (errno: %s) " M "\n" RESET, CLEAN_ERRNO(), ##__VA_ARGS__)
#define LOG_WARN(M, ...) fprintf(stderr, BOLDYELLOW "[WRN] (errno: %s) " M "\n" RESET, CLEAN_ERRNO(), ##__VA_ARGS__)
#define LOG_INFO(M, ...) fprintf(stderr, BOLDGREEN "[NFO] " M "\n" RESET, ##__VA_ARGS__)

#endif
