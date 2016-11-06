#ifndef _MACH_O_RANLIB_H_
#define _MACH_O_RANLIB_H_

#include <cstdint>
#include <sys/types.h>

#define SYMDEF "__.SYMDEF"
#define SYMDEF_SORTED "__.SYMDEF SORTED"

struct ranlib
{
  union
  {
    uint32_t ran_strx;
#ifndef __LP64__
    char* ran_name;
#endif
  } ran_un;
  uint32_t ran_off;
};

#endif
