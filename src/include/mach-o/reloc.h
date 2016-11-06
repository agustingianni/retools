#ifndef _MACHO_RELOC_H_
#define _MACHO_RELOC_H_

#include <cstdint>

struct relocation_info
{
  int32_t r_address;
  uint32_t
    r_symbolnum : 24,
    r_pcrel : 1,
    r_length : 2,
    r_extern : 1,
    r_type : 4;
};

#define R_ABS 0
#define R_SCATTERED 0x80000000

struct scattered_relocation_info
{
#ifdef __BIG_ENDIAN__
  uint32_t
    r_scattered : 1,
    r_pcrel : 1,
    r_length : 2,
    r_type : 4,
    r_address : 24;

  int32_t r_value;

#endif

#ifdef __LITTLE_ENDIAN__
  uint32_t
    r_address : 24,
    r_type : 4,
    r_length : 2,
    r_pcrel : 1,
    r_scattered : 1;
  int32_t r_value;

#endif
};

enum reloc_type_generic
{
  GENERIC_RELOC_VANILLA,
  GENERIC_RELOC_PAIR,
  GENERIC_RELOC_SECTDIFF,
  GENERIC_RELOC_PB_LA_PTR,
  GENERIC_RELOC_LOCAL_SECTDIFF,
  GENERIC_RELOC_TLV
};

#endif
