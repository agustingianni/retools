/*
 * MachoBinary.h
 *
 *  Created on: Mar 22, 2015
 *      Author: anon
 */

#ifndef SRC_LIBBINARY_MACHO_MACHOBINARY_H_
#define SRC_LIBBINARY_MACHO_MACHOBINARY_H_

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/stab.h>

#include <mach-o/fat.h>

#include "AbstractBinary.h"

#include <string>

std::string LoadCommandName(unsigned cmd);

// Macros to generate the private accessors to the mach-o header fields.
#define GET_HEADER_VALUE(field) (is32()) ? m_header.header_32.field : m_header.header_64.field
#define DEFINE_HEADER_ACCESSOR(type, field) type field() const { return GET_HEADER_VALUE(field); }

class MachoBinary: public AbstractBinary {
private:
    union {
        mach_header header_32;
        mach_header_64 header_64;
    } m_header;

    // Methods to access the correct version of the fields in the mach-o header.
    DEFINE_HEADER_ACCESSOR(uint32_t, magic)
    DEFINE_HEADER_ACCESSOR(cpu_type_t, cputype)
    DEFINE_HEADER_ACCESSOR(cpu_subtype_t, cpusubtype)
    DEFINE_HEADER_ACCESSOR(uint32_t, filetype)
    DEFINE_HEADER_ACCESSOR(uint32_t, ncmds)
    DEFINE_HEADER_ACCESSOR(uint32_t, sizeofcmds)
    DEFINE_HEADER_ACCESSOR(uint32_t, flags)

    size_t mach_header_size() const {
        return is32() ? sizeof(m_header.header_32) : sizeof(m_header.header_64);
    }

    struct load_command *get_load_command(unsigned i);

    bool parse_load_commands();


    bool parse_data_in_code(struct load_command *lc);
    bool parse_function_starts(struct load_command *lc);

    bool parse_routines_32(struct load_command *lc);
    bool parse_routines_64(struct load_command *lc);

    // Segment and section parsers.
    bool parse_segment_32(struct load_command *lc);
    bool parse_section_32(struct section_32 *lc);
    bool parse_segment_64(struct load_command *lc);
    bool parse_section_64(struct section_64 *lc);

    bool parse_symtab(struct load_command *lc);
    bool parse_generic_symbol(struct nlist_64 *symbol);
    bool parse_stab_symbol(struct nlist_64 *symbol);

    bool parse_dysymtab(struct load_command *lc);
    bool parse_thread(struct load_command *lc);
    bool parse_id_dylib(struct load_command *lc);
    bool parse_dylib(struct load_command *lc);
    bool parse_main(struct load_command *lc);
    bool parse_unixthread(struct load_command *lc);
    bool parse_dyld_info(struct load_command *lc);

    bool parse_encryption_info_32(struct load_command *lc);
    bool parse_encryption_info_64(struct load_command *lc);

    // Required for parsing names and symbols. Loaded at 'parse_symtab'.
    struct nlist_64 *m_symbol_table;
    size_t m_symbol_table_size;

    char *m_string_table;
    size_t m_string_table_size;

public:
    bool init();
};

#endif /* SRC_LIBBINARY_MACHO_MACHOBINARY_H_ */
