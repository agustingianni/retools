#ifndef _MACHO_LOADER_H_
#define _MACHO_LOADER_H_

#include <cstdint>

using cpu_type_t = int;
using cpu_subtype_t = int;
using vm_prot_t = int;

struct mach_header
{
  uint32_t magic;
  cpu_type_t cputype;
  cpu_subtype_t cpusubtype;
  uint32_t filetype;
  uint32_t ncmds;
  uint32_t sizeofcmds;
  uint32_t flags;
};

#define MH_MAGIC 0xfeedface
#define MH_CIGAM 0xcefaedfe

struct mach_header_64
{
  uint32_t magic;
  cpu_type_t cputype;
  cpu_subtype_t cpusubtype;
  uint32_t filetype;
  uint32_t ncmds;
  uint32_t sizeofcmds;
  uint32_t flags;
  uint32_t reserved;
};

#define MH_MAGIC_64 0xfeedfacf
#define MH_CIGAM_64 0xcffaedfe

#define MH_OBJECT 0x1
#define MH_EXECUTE 0x2
#define MH_FVMLIB 0x3
#define MH_CORE 0x4
#define MH_PRELOAD 0x5
#define MH_DYLIB 0x6
#define MH_DYLINKER 0x7
#define MH_BUNDLE 0x8
#define MH_DYLIB_STUB 0x9
#define MH_DSYM 0xa
#define MH_KEXT_BUNDLE 0xb
#define MH_NOUNDEFS 0x1
#define MH_INCRLINK 0x2
#define MH_DYLDLINK 0x4
#define MH_BINDATLOAD 0x8
#define MH_PREBOUND 0x10
#define MH_SPLIT_SEGS 0x20
#define MH_LAZY_INIT 0x40
#define MH_TWOLEVEL 0x80
#define MH_FORCE_FLAT 0x100
#define MH_NOMULTIDEFS 0x200
#define MH_NOFIXPREBINDING 0x400
#define MH_PREBINDABLE 0x800
#define MH_ALLMODSBOUND 0x1000
#define MH_SUBSECTIONS_VIA_SYMBOLS 0x2000
#define MH_CANONICAL 0x4000
#define MH_WEAK_DEFINES 0x8000
#define MH_BINDS_TO_WEAK 0x10000
#define MH_ALLOW_STACK_EXECUTION 0x20000
#define MH_ROOT_SAFE 0x40000
#define MH_SETUID_SAFE 0x80000
#define MH_NO_REEXPORTED_DYLIBS 0x100000
#define MH_PIE 0x200000
#define MH_DEAD_STRIPPABLE_DYLIB 0x400000
#define MH_HAS_TLV_DESCRIPTORS 0x800000
#define MH_NO_HEAP_EXECUTION 0x1000000
#define MH_APP_EXTENSION_SAFE 0x02000000

struct load_command
{
  uint32_t cmd;
  uint32_t cmdsize;
};

#define LC_REQ_DYLD 0x80000000

#define LC_SEGMENT 0x1
#define LC_SYMTAB 0x2
#define LC_SYMSEG 0x3
#define LC_THREAD 0x4
#define LC_UNIXTHREAD 0x5
#define LC_LOADFVMLIB 0x6
#define LC_IDFVMLIB 0x7
#define LC_IDENT 0x8
#define LC_FVMFILE 0x9
#define LC_PREPAGE 0xa
#define LC_DYSYMTAB 0xb
#define LC_LOAD_DYLIB 0xc
#define LC_ID_DYLIB 0xd
#define LC_LOAD_DYLINKER 0xe
#define LC_ID_DYLINKER 0xf
#define LC_PREBOUND_DYLIB 0x10
#define LC_ROUTINES 0x11
#define LC_SUB_FRAMEWORK 0x12
#define LC_SUB_UMBRELLA 0x13
#define LC_SUB_CLIENT 0x14
#define LC_SUB_LIBRARY 0x15
#define LC_TWOLEVEL_HINTS 0x16
#define LC_PREBIND_CKSUM 0x17
#define LC_LOAD_WEAK_DYLIB (0x18 | LC_REQ_DYLD)
#define LC_SEGMENT_64 0x19
#define LC_ROUTINES_64 0x1a
#define LC_UUID 0x1b
#define LC_RPATH (0x1c | LC_REQ_DYLD)
#define LC_CODE_SIGNATURE 0x1d
#define LC_SEGMENT_SPLIT_INFO 0x1e
#define LC_REEXPORT_DYLIB (0x1f | LC_REQ_DYLD)
#define LC_LAZY_LOAD_DYLIB 0x20
#define LC_ENCRYPTION_INFO 0x21
#define LC_DYLD_INFO 0x22
#define LC_DYLD_INFO_ONLY (0x22 | LC_REQ_DYLD)
#define LC_LOAD_UPWARD_DYLIB (0x23 | LC_REQ_DYLD)
#define LC_VERSION_MIN_MACOSX 0x24
#define LC_VERSION_MIN_IPHONEOS 0x25
#define LC_FUNCTION_STARTS 0x26
#define LC_DYLD_ENVIRONMENT 0x27
#define LC_MAIN (0x28 | LC_REQ_DYLD)
#define LC_DATA_IN_CODE 0x29
#define LC_SOURCE_VERSION 0x2A
#define LC_DYLIB_CODE_SIGN_DRS 0x2B
#define LC_ENCRYPTION_INFO_64 0x2C
#define LC_LINKER_OPTION 0x2D
#define LC_LINKER_OPTIMIZATION_HINT 0x2E
#define LC_VERSION_MIN_TVOS 0x2F
#define LC_VERSION_MIN_WATCHOS 0x30

union lc_str
{
  uint32_t offset;
#ifndef __LP64__
  char* ptr;
#endif
};

struct segment_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  char segname[16];
  uint32_t vmaddr;
  uint32_t vmsize;
  uint32_t fileoff;
  uint32_t filesize;
  vm_prot_t maxprot;
  vm_prot_t initprot;
  uint32_t nsects;
  uint32_t flags;
};

struct segment_command_64
{
  uint32_t cmd;
  uint32_t cmdsize;
  char segname[16];
  uint64_t vmaddr;
  uint64_t vmsize;
  uint64_t fileoff;
  uint64_t filesize;
  vm_prot_t maxprot;
  vm_prot_t initprot;
  uint32_t nsects;
  uint32_t flags;
};

#define SG_HIGHVM 0x1
#define SG_FVMLIB 0x2
#define SG_NORELOC 0x4
#define SG_PROTECTED_VERSION_1 0x8

struct section
{
  char sectname[16];
  char segname[16];
  uint32_t addr;
  uint32_t size;
  uint32_t offset;
  uint32_t align;
  uint32_t reloff;
  uint32_t nreloc;
  uint32_t flags;
  uint32_t reserved1;
  uint32_t reserved2;
};

struct section_64
{
  char sectname[16];
  char segname[16];
  uint64_t addr;
  uint64_t size;
  uint32_t offset;
  uint32_t align;
  uint32_t reloff;
  uint32_t nreloc;
  uint32_t flags;
  uint32_t reserved1;
  uint32_t reserved2;
  uint32_t reserved3;
};

#define SECTION_TYPE 0x000000ff
#define SECTION_ATTRIBUTES 0xffffff00

#define S_REGULAR 0x0
#define S_ZEROFILL 0x1
#define S_CSTRING_LITERALS 0x2
#define S_4BYTE_LITERALS 0x3
#define S_8BYTE_LITERALS 0x4
#define S_LITERAL_POINTERS 0x5
#define S_NON_LAZY_SYMBOL_POINTERS 0x6
#define S_LAZY_SYMBOL_POINTERS 0x7
#define S_SYMBOL_STUBS 0x8
#define S_MOD_INIT_FUNC_POINTERS 0x9
#define S_MOD_TERM_FUNC_POINTERS 0xa
#define S_COALESCED 0xb
#define S_GB_ZEROFILL 0xc
#define S_INTERPOSING 0xd
#define S_16BYTE_LITERALS 0xe
#define S_DTRACE_DOF 0xf
#define S_LAZY_DYLIB_SYMBOL_POINTERS 0x10
#define S_THREAD_LOCAL_REGULAR 0x11
#define S_THREAD_LOCAL_ZEROFILL 0x12
#define S_THREAD_LOCAL_VARIABLES 0x13
#define S_THREAD_LOCAL_VARIABLE_POINTERS 0x14
#define S_THREAD_LOCAL_INIT_FUNCTION_POINTERS 0x15

#define SECTION_ATTRIBUTES_USR 0xff000000
#define S_ATTR_PURE_INSTRUCTIONS 0x80000000
#define S_ATTR_NO_TOC 0x40000000
#define S_ATTR_STRIP_STATIC_SYMS 0x20000000
#define S_ATTR_NO_DEAD_STRIP 0x10000000
#define S_ATTR_LIVE_SUPPORT 0x08000000
#define S_ATTR_SELF_MODIFYING_CODE 0x04000000
#define S_ATTR_DEBUG 0x02000000
#define SECTION_ATTRIBUTES_SYS 0x00ffff00
#define S_ATTR_SOME_INSTRUCTIONS 0x00000400
#define S_ATTR_EXT_RELOC 0x00000200
#define S_ATTR_LOC_RELOC 0x00000100

#define SEG_PAGEZERO "__PAGEZERO"
#define SEG_TEXT "__TEXT"
#define SECT_TEXT "__text"
#define SECT_FVMLIB_INIT0 "__fvmlib_init0"
#define SECT_FVMLIB_INIT1 "__fvmlib_init1"
#define SEG_DATA "__DATA"
#define SECT_DATA "__data"
#define SECT_BSS "__bss"
#define SECT_COMMON "__common"
#define SEG_OBJC "__OBJC"
#define SECT_OBJC_SYMBOLS "__symbol_table"
#define SECT_OBJC_MODULES "__module_info"
#define SECT_OBJC_STRINGS "__selector_strs"
#define SECT_OBJC_REFS "__selector_refs"
#define SEG_ICON "__ICON"
#define SECT_ICON_HEADER "__header"
#define SECT_ICON_TIFF "__tiff"
#define SEG_LINKEDIT "__LINKEDIT"
#define SEG_UNIXSTACK "__UNIXSTACK"
#define SEG_IMPORT "__IMPORT"

struct fvmlib
{
  union lc_str name;
  uint32_t minor_version;
  uint32_t header_addr;
};

struct fvmlib_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  struct fvmlib fvmlib;
};

struct dylib
{
  union lc_str name;
  uint32_t timestamp;
  uint32_t current_version;
  uint32_t compatibility_version;
};

struct dylib_command
{
  uint32_t cmd;

  uint32_t cmdsize;
  struct dylib dylib;
};

struct sub_framework_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  union lc_str umbrella;
};

struct sub_client_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  union lc_str client;
};

struct sub_umbrella_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  union lc_str sub_umbrella;
};

struct sub_library_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  union lc_str sub_library;
};

struct prebound_dylib_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  union lc_str name;
  uint32_t nmodules;
  union lc_str linked_modules;
};

struct dylinker_command
{
  uint32_t cmd;

  uint32_t cmdsize;
  union lc_str name;
};

struct thread_command
{
  uint32_t cmd;
  uint32_t cmdsize;
};

struct routines_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t init_address;
  uint32_t init_module;
  uint32_t reserved1;
  uint32_t reserved2;
  uint32_t reserved3;
  uint32_t reserved4;
  uint32_t reserved5;
  uint32_t reserved6;
};

struct routines_command_64
{
  uint32_t cmd;
  uint32_t cmdsize;
  uint64_t init_address;
  uint64_t init_module;
  uint64_t reserved1;
  uint64_t reserved2;
  uint64_t reserved3;
  uint64_t reserved4;
  uint64_t reserved5;
  uint64_t reserved6;
};

struct symtab_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t symoff;
  uint32_t nsyms;
  uint32_t stroff;
  uint32_t strsize;
};

struct dysymtab_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t ilocalsym;
  uint32_t nlocalsym;

  uint32_t iextdefsym;
  uint32_t nextdefsym;

  uint32_t iundefsym;
  uint32_t nundefsym;

  uint32_t tocoff;
  uint32_t ntoc;

  uint32_t modtaboff;
  uint32_t nmodtab;

  uint32_t extrefsymoff;
  uint32_t nextrefsyms;

  uint32_t indirectsymoff;
  uint32_t nindirectsyms;

  uint32_t extreloff;
  uint32_t nextrel;

  uint32_t locreloff;
  uint32_t nlocrel;
};

#define INDIRECT_SYMBOL_LOCAL 0x80000000
#define INDIRECT_SYMBOL_ABS 0x40000000

struct dylib_table_of_contents
{
  uint32_t symbol_index;

  uint32_t module_index;
};

struct dylib_module
{
  uint32_t module_name;

  uint32_t iextdefsym;
  uint32_t nextdefsym;
  uint32_t irefsym;
  uint32_t nrefsym;
  uint32_t ilocalsym;
  uint32_t nlocalsym;

  uint32_t iextrel;
  uint32_t nextrel;

  uint32_t iinit_iterm;

  uint32_t ninit_nterm;

  uint32_t objc_module_info_addr;
  uint32_t objc_module_info_size;
};

struct dylib_module_64
{
  uint32_t module_name;

  uint32_t iextdefsym;
  uint32_t nextdefsym;
  uint32_t irefsym;
  uint32_t nrefsym;
  uint32_t ilocalsym;
  uint32_t nlocalsym;

  uint32_t iextrel;
  uint32_t nextrel;

  uint32_t iinit_iterm;

  uint32_t ninit_nterm;

  uint32_t objc_module_info_size;
  uint64_t objc_module_info_addr;
};

struct dylib_reference
{
  uint32_t isym : 24, flags : 8;
};

struct twolevel_hints_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t offset;
  uint32_t nhints;
};

struct twolevel_hint
{
  uint32_t isub_image : 8, itoc : 24;
};

struct prebind_cksum_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t cksum;
};

struct uuid_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  uint8_t uuid[16];
};

struct rpath_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  union lc_str path;
};

struct linkedit_data_command
{
  uint32_t cmd;

  uint32_t cmdsize;
  uint32_t dataoff;
  uint32_t datasize;
};

struct encryption_info_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t cryptoff;
  uint32_t cryptsize;
  uint32_t cryptid;
};

struct encryption_info_command_64
{
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t cryptoff;
  uint32_t cryptsize;
  uint32_t cryptid;

  uint32_t pad;
};

struct version_min_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t version;
  uint32_t sdk;
};

struct dyld_info_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t rebase_off;
  uint32_t rebase_size;
  uint32_t bind_off;
  uint32_t bind_size;
  uint32_t weak_bind_off;
  uint32_t weak_bind_size;
  uint32_t lazy_bind_off;
  uint32_t lazy_bind_size;
  uint32_t export_off;
  uint32_t export_size;
};

#define REBASE_TYPE_POINTER 1
#define REBASE_TYPE_TEXT_ABSOLUTE32 2
#define REBASE_TYPE_TEXT_PCREL32 3

#define REBASE_OPCODE_MASK 0xF0
#define REBASE_IMMEDIATE_MASK 0x0F
#define REBASE_OPCODE_DONE 0x00
#define REBASE_OPCODE_SET_TYPE_IMM 0x10
#define REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB 0x20
#define REBASE_OPCODE_ADD_ADDR_ULEB 0x30
#define REBASE_OPCODE_ADD_ADDR_IMM_SCALED 0x40
#define REBASE_OPCODE_DO_REBASE_IMM_TIMES 0x50
#define REBASE_OPCODE_DO_REBASE_ULEB_TIMES 0x60
#define REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB 0x70
#define REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB 0x80

#define BIND_TYPE_POINTER 1
#define BIND_TYPE_TEXT_ABSOLUTE32 2
#define BIND_TYPE_TEXT_PCREL32 3

#define BIND_SPECIAL_DYLIB_SELF 0
#define BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE -1
#define BIND_SPECIAL_DYLIB_FLAT_LOOKUP -2

#define BIND_SYMBOL_FLAGS_WEAK_IMPORT 0x1
#define BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION 0x8

#define BIND_OPCODE_MASK 0xF0
#define BIND_IMMEDIATE_MASK 0x0F
#define BIND_OPCODE_DONE 0x00
#define BIND_OPCODE_SET_DYLIB_ORDINAL_IMM 0x10
#define BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB 0x20
#define BIND_OPCODE_SET_DYLIB_SPECIAL_IMM 0x30
#define BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM 0x40
#define BIND_OPCODE_SET_TYPE_IMM 0x50
#define BIND_OPCODE_SET_ADDEND_SLEB 0x60
#define BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB 0x70
#define BIND_OPCODE_ADD_ADDR_ULEB 0x80
#define BIND_OPCODE_DO_BIND 0x90
#define BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB 0xA0
#define BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED 0xB0
#define BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB 0xC0

#define EXPORT_SYMBOL_FLAGS_KIND_MASK 0x03
#define EXPORT_SYMBOL_FLAGS_KIND_REGULAR 0x00
#define EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL 0x01
#define EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION 0x04
#define EXPORT_SYMBOL_FLAGS_REEXPORT 0x08
#define EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER 0x10

struct linker_option_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t count;
};

struct symseg_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t offset;
  uint32_t size;
};

struct ident_command
{
  uint32_t cmd;
  uint32_t cmdsize;
};

struct fvmfile_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  union lc_str name;
  uint32_t header_addr;
};

struct entry_point_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  uint64_t entryoff;
  uint64_t stacksize;
};

struct source_version_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  uint64_t version;
};

struct data_in_code_entry
{
  uint32_t offset;
  uint16_t length;
  uint16_t kind;
};

#define DICE_KIND_DATA 0x0001
#define DICE_KIND_JUMP_TABLE8 0x0002
#define DICE_KIND_JUMP_TABLE16 0x0003
#define DICE_KIND_JUMP_TABLE32 0x0004
#define DICE_KIND_ABS_JUMP_TABLE32 0x0005

struct tlv_descriptor
{
  void* (*thunk)(struct tlv_descriptor*);
  unsigned long key;
  unsigned long offset;
};

#endif
