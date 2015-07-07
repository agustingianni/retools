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

    template<typename T> bool parse_routines(struct load_command *lc);
    template<typename T> bool parse_encryption_info(struct load_command *lc);

    // Segment and section parsers.
	template<typename Segment_t, typename Section_t> bool parse_segment(struct load_command *lc);
	template<typename Section_t> bool parse_section(Section_t *lc);

    // Section parsers.
    template<typename Section_t> bool parse_cstring_literals_section(Section_t *lc);
    template<typename Section_t> bool parse_4byte_literals(Section_t *lc);
    template<typename Section_t> bool parse_8byte_literals(Section_t *lc);
    template<typename Section_t> bool parse_16byte_literals(Section_t *lc);
    template<typename Section_t> bool parse_literal_pointers(Section_t *lc);
    template<typename Section_t> bool parse_mod_init_func_pointers(Section_t *lc);
    template<typename Section_t> bool parse_mod_term_func_pointers(Section_t *lc);
    template<typename Section_t> bool parse_non_lazy_symbol_pointers(Section_t *lc);
    template<typename Section_t> bool parse_lazy_symbol_pointers(Section_t *lc);
    template<typename Section_t> bool parse_symbol_stubs(Section_t *lc);
    template<typename Section_t> bool parse_interposing(Section_t *lc);
    template<typename Section_t> bool parse_lazy_dylib_symbol_pointers(Section_t *lc);
    template<typename Section_t> bool parse_thread_local_variables(Section_t *lc);
    template<typename Section_t> bool parse_thread_local_variable_pointers(Section_t *lc);
    template<typename Section_t> bool parse_thread_local_init_function_pointers(Section_t *lc);

    bool parse_symtab(struct load_command *lc);
    bool parse_dysymtab(struct load_command *lc);
    bool parse_thread(struct load_command *lc);
    bool parse_id_dylib(struct load_command *lc);
    bool parse_dylib(struct load_command *lc);
    bool parse_main(struct load_command *lc);
    bool parse_unixthread(struct load_command *lc);

    bool parse_dyld_info(struct load_command *lc);
    bool parse_dyld_info_exports(const uint8_t *start, const uint8_t *end);
    bool parse_dyld_info_rebase(const uint8_t *start, const uint8_t *end);
    bool parse_dyld_info_binding(const uint8_t *start, const uint8_t *end);
    bool parse_dyld_info_weak_binding(const uint8_t *start, const uint8_t *end);
    bool parse_dyld_info_lazy_binding(const uint8_t *start, const uint8_t *end);

    template <typename T> void add_segment(T *);
    template <typename T> void add_section(T *);
    std::string segment_name(unsigned index);
    uint64_t segment_address(unsigned index);
    std::string section_name(unsigned index, uint64_t address);
    std::string ordinal_name(int libraryOrdinal);

    // Required for parsing names and symbols. Loaded at 'parse_symtab'.
    struct nlist_64 *m_symbol_table;
    size_t m_symbol_table_size;

    struct dysymtab_command *m_dysymtab_command;

    char *m_string_table;
    size_t m_string_table_size;

    // XXX: This so far represents the address of the first __TEXT segment.
    uint64_t m_base_address;

    // Architecture specific information collected while parsing.
    std::vector<segment_command> m_segments_32;
    std::vector<segment_command_64> m_segments_64;
    std::vector<section> m_sections_32;
    std::vector<section_64> m_sections_64;
    std::vector<std::string> m_imported_libs;

public:
    bool init();
};

#endif /* SRC_LIBBINARY_MACHO_MACHOBINARY_H_ */
