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

#include "AbstractBinary.h"
#include "ThreadState.h"

#include <string>

class MachoBinaryVisitor;

std::string LoadCommandName(unsigned cmd);

// Macros to generate the private accessors to the mach-o header fields.
#define GET_HEADER_VALUE(field) (is32()) ? m_header.header_32->field : m_header.header_64->field
#define DEFINE_HEADER_ACCESSOR(type, field) type field() const { return GET_HEADER_VALUE(field); }

template<typename T> struct Traits;
template<> struct Traits<section> {
	typedef uint32_t pointer_t;
};

template<> struct Traits<section_64> {
	typedef uint64_t pointer_t;
};

class MachoBinary: public AbstractBinary {
private:
    union {
        mach_header *header_32;
        mach_header_64 *header_64;
    } m_header;

	union {
		thread_state_x86_32 x86_32;
		thread_state_x86_64 x86_64;
		thread_state_arm_32 arm_32;
		thread_state_arm_64 arm_64;
	} m_thread_state;

    // Methods to access the correct version of the fields in the mach-o header.
    DEFINE_HEADER_ACCESSOR(uint32_t, magic)
    DEFINE_HEADER_ACCESSOR(cpu_type_t, cputype)
    DEFINE_HEADER_ACCESSOR(cpu_subtype_t, cpusubtype)
    DEFINE_HEADER_ACCESSOR(uint32_t, filetype)
    DEFINE_HEADER_ACCESSOR(uint32_t, ncmds)
    DEFINE_HEADER_ACCESSOR(uint32_t, sizeofcmds)
    DEFINE_HEADER_ACCESSOR(uint32_t, flags)

    size_t mach_header_size() const {
        return is32() ? sizeof(*m_header.header_32) : sizeof(*m_header.header_64);
    }

    struct load_command *get_load_command(unsigned i) const;
    bool parse_load_commands();
    bool parse_load_commands_();

    // Segment parsers.
    template<typename Segment_t, typename Section_t> bool parse_segment(struct load_command *lc);
    template<typename T> bool parse_routines(struct load_command *lc);
    template<typename T> bool parse_encryption_info(struct load_command *lc);
    bool parse_data_in_code(struct load_command *lc);
    bool parse_function_starts(struct load_command *lc);
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

    // Section parsers, 'parse_section' is the main dispatcher..
    template<typename Section_t> bool parse_section(Section_t *lc);
	template<typename Section_t> bool parse_regular_section(Section_t *lc);
	template<typename Section_t> bool parse_data_cfstring(Section_t *lc);
	template<typename Section_t> bool parse_data_const(Section_t *lc);
	template<typename Section_t> bool parse_all_image_info(Section_t *lc);
	template<typename Section_t> bool parse_sfi_class_reg(Section_t *lc);
	template<typename Section_t> bool parse_sysctl_set(Section_t *lc);
	template<typename Section_t> bool parse_objc_catlist(Section_t *lc);
	template<typename Section_t> bool parse_objc_classlist(Section_t *lc);
	template<typename Section_t> bool parse_objc_classrefs(Section_t *lc);
	template<typename Section_t> bool parse_objc_data(Section_t *lc);
	template<typename Section_t> bool parse_objc_imageinfo(Section_t *lc);
	template<typename Section_t> bool parse_objc_ivar(Section_t *lc);
	template<typename Section_t> bool parse_objc_msgrefs(Section_t *lc);
	template<typename Section_t> bool parse_objc_nlcatlist(Section_t *lc);
	template<typename Section_t> bool parse_objc_nlclslist(Section_t *lc);
	template<typename Section_t> bool parse_objc_protolist(Section_t *lc);
	template<typename Section_t> bool parse_objc_protorefs(Section_t *lc);
	template<typename Section_t> bool parse_objc_superrefs(Section_t *lc);
	template<typename Section_t> bool parse_vectors_recover(Section_t *lc);
	template<typename Section_t> bool parse_hib_desc(Section_t *lc);
	template<typename Section_t> bool parse_ustring(Section_t *lc);
    template<typename Section_t> bool parse_data_dyld(Section_t *lc);
    template<typename Section_t> bool parse_data_gcc_except_tab(Section_t *lc);
    template<typename Section_t> bool parse_dwarf_apple_names(Section_t *lc);
    template<typename Section_t> bool parse_dwarf_apple_namespac(Section_t *lc);
    template<typename Section_t> bool parse_dwarf_apple_objc(Section_t *lc);
    template<typename Section_t> bool parse_dwarf_apple_types(Section_t *lc);
    template<typename Section_t> bool parse_dwarf_debug_abbrev(Section_t *lc);
    template<typename Section_t> bool parse_dwarf_debug_aranges(Section_t *lc);
    template<typename Section_t> bool parse_dwarf_debug_frame(Section_t *lc);
    template<typename Section_t> bool parse_dwarf_debug_info(Section_t *lc);
    template<typename Section_t> bool parse_dwarf_debug_inlined(Section_t *lc);
    template<typename Section_t> bool parse_dwarf_debug_line(Section_t *lc);
    template<typename Section_t> bool parse_dwarf_debug_loc(Section_t *lc);
    template<typename Section_t> bool parse_dwarf_debug_macinfo(Section_t *lc);
    template<typename Section_t> bool parse_dwarf_debug_pubnames(Section_t *lc);
    template<typename Section_t> bool parse_dwarf_debug_pubtypes(Section_t *lc);
    template<typename Section_t> bool parse_dwarf_debug_ranges(Section_t *lc);
    template<typename Section_t> bool parse_dwarf_debug_str(Section_t *lc);
    template<typename Section_t> bool parse_ld_compact_unwind(Section_t *lc);
    template<typename Section_t> bool parse_objc_cat_cls_meth(Section_t *lc);
    template<typename Section_t> bool parse_objc_cat_inst_meth(Section_t *lc);
    template<typename Section_t> bool parse_objc_category(Section_t *lc);
    template<typename Section_t> bool parse_objc_class(Section_t *lc);
    template<typename Section_t> bool parse_objc_class_ext(Section_t *lc);
    template<typename Section_t> bool parse_objc_class_vars(Section_t *lc);
    template<typename Section_t> bool parse_objc_cls_meth(Section_t *lc);
    template<typename Section_t> bool parse_objc_cstring_object(Section_t *lc);
    template<typename Section_t> bool parse_objc_image_info(Section_t *lc);
    template<typename Section_t> bool parse_objc_inst_meth(Section_t *lc);
    template<typename Section_t> bool parse_objc_instance_vars(Section_t *lc);
    template<typename Section_t> bool parse_objc_meta_class(Section_t *lc);
    template<typename Section_t> bool parse_objc_module_info(Section_t *lc);
    template<typename Section_t> bool parse_objc_property(Section_t *lc);
    template<typename Section_t> bool parse_objc_protocol(Section_t *lc);
    template<typename Section_t> bool parse_objc_protocol_ext(Section_t *lc);
    template<typename Section_t> bool parse_objc_sel_fixup(Section_t *lc);
    template<typename Section_t> bool parse_objc_string_object(Section_t *lc);
    template<typename Section_t> bool parse_objc_symbols(Section_t *lc);
    template<typename Section_t> bool parse_prelink_info_info(Section_t *lc);
    template<typename Section_t> bool parse_prelink_state_kernel(Section_t *lc);
    template<typename Section_t> bool parse_prelink_state_kexts(Section_t *lc);
    template<typename Section_t> bool parse_prelink_text_text(Section_t *lc);
    template<typename Section_t> bool parse_text_eh_frame(Section_t *lc);
    template<typename Section_t> bool parse_text_gcc_except_tab(Section_t *lc);
    template<typename Section_t> bool parse_text_unwind_info(Section_t *lc);
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
    template<typename Section_t> bool parse_thread_local_init_function_pointers(Section_t *lc);

    template <typename T> void add_segment(T *);
    template <typename T> void add_section(T *);
    std::string segment_name(unsigned index);
    uint64_t segment_address(unsigned index);
    std::string section_name(unsigned index, uint64_t address);
    std::string ordinal_name(int libraryOrdinal);
    template <typename T> T offset_from_rva(T rva);

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

    MachoBinaryVisitor *m_visitor;

public:
	virtual ~MachoBinary() = default;
	MachoBinary(MachoBinaryVisitor *visitor) :
			m_visitor(visitor) {
	}

    bool init() override;
};

#endif /* SRC_LIBBINARY_MACHO_MACHOBINARY_H_ */
