#ifndef CONDITIONALS_H_
#define CONDITIONALS_H_

#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif

#if defined(TARGET_OS_OSX) && TARGET_OS_OSX == 1
    #define RETOOLS_TARGET_OS_APPLE 1
    #define RETOOLS_TARGET_OS_MACOS 1
    #define RETOOLS_TARGET_OS_NAME "macOS"
#elif defined(TARGET_OS_IOS) && TARGET_OS_IOS == 1
    #define RETOOLS_TARGET_OS_APPLE 1
    #define RETOOLS_TARGET_OS_IOS 1
    #define RETOOLS_TARGET_OS_NAME "iOS"
#elif defined(__linux__) || defined(linux) || defined(__linux)
    #define RETOOLS_TARGET_OS_LINUX 1
    #define RETOOLS_TARGET_OS_NAME "Linux"
#elif defined(__ANDROID__) || defined(ANDROID)
    #define RETOOLS_TARGET_OS_ANDROID 1
    #define RETOOLS_TARGET_OS_NAME "Android"
#elif defined(WIN32) || defined(_WIN32) || defined(__CYGWIN__) || defined(__MINGW32__)
    #define RETOOLS_TARGET_OS_WINDOWS 1
    #define RETOOLS_TARGET_OS_NAME "Windows"
#else
    #error Unsupported operating system
#endif

#if  defined(_M_IX86) || defined(_X86_) || defined(i386) || defined (__i386__) || defined(__i386)
    #define RETOOLS_TARGET_CPU_X86 1
    #define RETOOLS_TARGET_CPU_NAME "x86"
#elif defined(_M_AMD64) || defined(_M_X64) || defined(__amd64__) || defined(__amd64) || defined(__x86_64__) || defined(__x86_64)
    #define RETOOLS_TARGET_CPU_AMD64 1
    #define RETOOLS_TARGET_CPU_NAME "amd64"
#elif defined(_M_ARM) || defined(_M_ARMT) || defined(__arm__)
    #define RETOOLS_TARGET_CPU_ARM 1
    #define RETOOLS_TARGET_CPU_NAME "arm"
#elif defined(_M_ARM64) || defined(__aarch64__)
    #define RETOOLS_TARGET_CPU_ARM64 1
    #define RETOOLS_TARGET_CPU_NAME "arm64"
#else
    #error Unsupported architecture
#endif

#define RETOOLS_TARGET_DESCRIPTION (RETOOLS_TARGET_OS_NAME ":" RETOOLS_TARGET_CPU_NAME)

#endif /* CONDITIONALS_H_ */
