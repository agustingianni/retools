#ifndef _MACH_O_FAT_H_
#define _MACH_O_FAT_H_

#include <cstdint>

#define FAT_MAGIC 0xcafebabe
#define FAT_CIGAM 0xbebafeca

using cpu_type_t = int;
using cpu_subtype_t = int;

struct fat_header {
  uint32_t magic;
  uint32_t nfat_arch;
};

struct fat_arch {
  cpu_type_t cputype;
  cpu_subtype_t cpusubtype;
  uint32_t offset;
  uint32_t size;
  uint32_t align;
};

#endif /* _MACH_O_FAT_H_ */
