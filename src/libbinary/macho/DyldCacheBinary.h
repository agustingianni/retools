/*
 * DyldCacheBinary.h
 *
 *  Created on: Mar 22, 2016
 *      Author: anon
 */

#ifndef SRC_LIBBINARY_MACHO_DYLDCACHEBINARY_H_
#define SRC_LIBBINARY_MACHO_DYLDCACHEBINARY_H_

#include <cstdint>
#include <mach/machine.h>

static const uint16_t bigEndian = 0x1200;
static const uint16_t littleEndian = 0x0012;

struct ArchType {
    cpu_type_t cpu;         // main architecture
    cpu_subtype_t sub;      // subarchitecture
    char magic[16];         // cache file magic string
    char filename[10];      // conventional file name (off cacheFileBase)
    uint16_t order;         // byte order marker
};

#if 0
"dyld_v1 x86_64h" // haswell
"dyld_v1   armv5"
"dyld_v1   armv6"
"dyld_v1   armv7"
"dyld_v1  armv7"
"dyld_v1   arm64"
#endif

const DYLDCache::ArchType DYLDCache::architectures[] = {
    { CPU_TYPE_X86_64, CPU_SUBTYPE_MULTIPLE, "dyld_v1  x86_64", "x86_64", littleEndian },
    { CPU_TYPE_X86, CPU_SUBTYPE_MULTIPLE, "dyld_v1    i386", "i386", littleEndian },
    { CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V6, "dyld_v1   armv6", "armv6", littleEndian },
    { CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7, "dyld_v1   armv7", "armv7", littleEndian },
    { 0 }
};

struct dyld_cache_header {
    char magic[16];              // e.g. "dyld_v0    i386"
    uint32_t mappingOffset;          // file offset to first dyld_cache_mapping_info
    uint32_t mappingCount;           // number of dyld_cache_mapping_info entries
    uint32_t imagesOffset;           // file offset to first dyld_cache_image_info
    uint32_t imagesCount;            // number of dyld_cache_image_info entries
    uint64_t dyldBaseAddress;        // base address of dyld when cache was built
    uint64_t codeSignatureOffset;    // file offset of code signature blob
    uint64_t codeSignatureSize;      // size of code signature blob (zero means to end of file)
    uint64_t slideInfoOffset;        // file offset of kernel slid info
    uint64_t slideInfoSize;          // size of kernel slid info
    uint64_t localSymbolsOffset;     // file offset of where local symbols are stored
    uint64_t localSymbolsSize;       // size of local symbols information
    uint8_t uuid[16];               // unique value for each shared cache file
    uint64_t cacheType;              // 1 for development, 0 for optimized
};

struct dyld_cache_mapping_info {
    uint64_t address;
    uint64_t size;
    uint64_t fileOffset;
    uint32_t maxProt;
    uint32_t initProt;
};

struct dyld_cache_image_info {
    uint64_t address;
    uint64_t modTime;
    uint64_t inode;
    uint32_t pathFileOffset;
    uint32_t pad;
};

struct dyld_cache_slide_info {
    uint32_t version;        // currently 1
    uint32_t toc_offset;
    uint32_t toc_count;
    uint32_t entries_offset;
    uint32_t entries_count;
    uint32_t entries_size;  // currently 128
    // uint16_t toc[toc_count];
    // entrybitmap entries[entries_count];
};

struct dyld_cache_local_symbols_info {
    uint32_t nlistOffset;        // offset into this chunk of nlist entries
    uint32_t nlistCount;         // count of nlist entries
    uint32_t stringsOffset;      // offset into this chunk of string pool
    uint32_t stringsSize;        // byte count of string pool
    uint32_t entriesOffset;      // offset into this chunk of array of dyld_cache_local_symbols_entry
    uint32_t entriesCount;       // number of elements in dyld_cache_local_symbols_entry array
};

struct dyld_cache_local_symbols_entry {
    uint32_t dylibOffset;        // offset in cache file of start of dylib
    uint32_t nlistStartIndex;    // start index of locals for this dylib
    uint32_t nlistCount;         // number of local symbols for this dylib
};

#define MACOSX_DYLD_SHARED_CACHE_DIR    "/var/db/dyld/"
#define IPHONE_DYLD_SHARED_CACHE_DIR    "/System/Library/Caches/com.apple.dyld/"
#define DYLD_SHARED_CACHE_BASE_NAME     "dyld_shared_cache_"
class DyldCacheBinary {
public:
    DyldCacheBinary();
    virtual ~DyldCacheBinary();
};

#endif /* SRC_LIBBINARY_MACHO_DYLDCACHEBINARY_H_ */
