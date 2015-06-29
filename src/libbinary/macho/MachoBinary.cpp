/*
 * MachoBinary.cpp
 *
 *  Created on: Mar 22, 2015
 *      Author: anon
 */

#include "macho/MachoBinary.h"
#include "debug.h"

#include <cassert>
#include <string>

std::string LoadCommandName(unsigned cmd) {
    switch (cmd) {
        case LC_SEGMENT:
            return "LC_SEGMENT";
        case LC_SYMTAB:
            return "LC_SYMTAB";
        case LC_SYMSEG:
            return "LC_SYMSEG";
        case LC_THREAD:
            return "LC_THREAD";
        case LC_UNIXTHREAD:
            return "LC_UNIXTHREAD";
        case LC_LOADFVMLIB:
            return "LC_LOADFVMLIB";
        case LC_IDFVMLIB:
            return "LC_IDFVMLIB";
        case LC_IDENT:
            return "LC_IDENT";
        case LC_FVMFILE:
            return "LC_FVMFILE";
        case LC_PREPAGE:
            return "LC_PREPAGE";
        case LC_DYSYMTAB:
            return "LC_DYSYMTAB";
        case LC_LOAD_DYLIB:
            return "LC_LOAD_DYLIB";
        case LC_ID_DYLIB:
            return "LC_ID_DYLIB";
        case LC_LOAD_DYLINKER:
            return "LC_LOAD_DYLINKER";
        case LC_ID_DYLINKER:
            return "LC_ID_DYLINKER";
        case LC_PREBOUND_DYLIB:
            return "LC_PREBOUND_DYLIB";
        case LC_ROUTINES:
            return "LC_ROUTINES";
        case LC_SUB_FRAMEWORK:
            return "LC_SUB_FRAMEWORK";
        case LC_SUB_UMBRELLA:
            return "LC_SUB_UMBRELLA";
        case LC_SUB_CLIENT:
            return "LC_SUB_CLIENT";
        case LC_SUB_LIBRARY:
            return "LC_SUB_LIBRARY";
        case LC_TWOLEVEL_HINTS:
            return "LC_TWOLEVEL_HINTS";
        case LC_PREBIND_CKSUM:
            return "LC_PREBIND_CKSUM";
        case LC_LOAD_WEAK_DYLIB:
            return "LC_LOAD_WEAK_DYLIB";
        case LC_SEGMENT_64:
            return "LC_SEGMENT_64";
        case LC_ROUTINES_64:
            return "LC_ROUTINES_64";
        case LC_UUID:
            return "LC_UUID";
        case LC_RPATH:
            return "LC_RPATH";
        case LC_CODE_SIGNATURE:
            return "LC_CODE_SIGNATURE";
        case LC_SEGMENT_SPLIT_INFO:
            return "LC_SEGMENT_SPLIT_INFO";
        case LC_REEXPORT_DYLIB:
            return "LC_REEXPORT_DYLIB";
        case LC_LAZY_LOAD_DYLIB:
            return "LC_LAZY_LOAD_DYLIB";
        case LC_ENCRYPTION_INFO:
            return "LC_ENCRYPTION_INFO";
        case LC_DYLD_INFO:
            return "LC_DYLD_INFO";
        case LC_DYLD_INFO_ONLY:
            return "LC_DYLD_INFO_ONLY";
        case LC_LOAD_UPWARD_DYLIB:
            return "LC_LOAD_UPWARD_DYLIB";
        case LC_VERSION_MIN_MACOSX:
            return "LC_VERSION_MIN_MACOSX";
        case LC_VERSION_MIN_IPHONEOS:
            return "LC_VERSION_MIN_IPHONEOS";
        case LC_FUNCTION_STARTS:
            return "LC_FUNCTION_STARTS";
        case LC_DYLD_ENVIRONMENT:
            return "LC_DYLD_ENVIRONMENT";
        case LC_MAIN:
            return "LC_MAIN";
        case LC_DATA_IN_CODE:
            return "LC_DATA_IN_CODE";
        case LC_SOURCE_VERSION:
            return "LC_SOURCE_VERSION";
        case LC_DYLIB_CODE_SIGN_DRS:
            return "LC_DYLIB_CODE_SIGN_DRS";
        case LC_ENCRYPTION_INFO_64:
            return "LC_ENCRYPTION_INFO_64";
        case LC_LINKER_OPTION:
            return "LC_LINKER_OPTION";
        case LC_LINKER_OPTIMIZATION_HINT:
            return "LC_LINKER_OPTIMIZATION_HINT";
        default:
            return "LC_UNKNOWN";
    }
}

bool MachoBinary::init() {
    m_symbol_table = nullptr;
    m_string_table = nullptr;

    struct mach_header *tmp_header = m_data->offset<struct mach_header>(0);
    if (!tmp_header)
        return false;

    // Parse the address space size and the endianness.
    switch (tmp_header->magic) {
        case MH_MAGIC:
            m_endianness = BinaryEndianness::LITTLE;
            m_address_space_size = AddressSpaceSize::BINARY_32;
            break;

        case MH_CIGAM:
            m_endianness = BinaryEndianness::BIG;
            m_address_space_size = AddressSpaceSize::BINARY_32;
            break;

        case MH_MAGIC_64:
            m_endianness = BinaryEndianness::LITTLE;
            m_address_space_size = AddressSpaceSize::BINARY_64;
            break;

        case MH_CIGAM_64:
            m_endianness = BinaryEndianness::BIG;
            m_address_space_size = AddressSpaceSize::BINARY_64;
            break;

        default:
            LOG_ERR("Invalid mach-o magic number 0x%.8x", tmp_header->magic);
            return false;
    }

    // Set the binary format.
    m_binary_format = BinaryFormat::MACHO;

    // Read the header.
    if (is32()) {
        m_header.header_32 = *m_data->offset<struct mach_header>(0);
    } else {
        m_header.header_64 = *m_data->offset<struct mach_header_64>(0);
    }

    // Get the kind of mach-o file.
    switch (filetype()) {
        case MH_OBJECT:
            m_binary_type = BinaryType::Object;
            break;
        case MH_CORE:
            m_binary_type = BinaryType::Core;
            break;
        case MH_EXECUTE:
            m_binary_type = BinaryType::Executable;
            break;
        case MH_DYLIB:
            m_binary_type = BinaryType::Library;
            break;
        default:
            LOG_ERR("Unknown mach-o file type 0x%.8x", filetype());
            return false;
    }

    // Get the CPU type.
    switch (cputype()) {
        case CPU_TYPE_X86:
            m_binary_arch = BinaryArch::X86;
            break;
        case CPU_TYPE_X86_64:
            m_binary_arch = BinaryArch::X86_64;
            break;
        case CPU_TYPE_ARM:
            m_binary_arch = BinaryArch::ARM;
            break;
        case CPU_TYPE_ARM64:
            m_binary_arch = BinaryArch::ARM64;
            break;
        default:
            LOG_ERR("Unknown mach-o CPU type 0x%.8x", cputype());
            return false;
    }

    // Load information from the load commands.
    if (!parse_load_commands()) {
        return false;
    }

    return true;
}

struct load_command *MachoBinary::get_load_command(unsigned idx) {
    // The first load command is past the mach-o header.
    struct load_command *lc = m_data->offset<struct load_command>(mach_header_size());
    if (!lc || idx >= ncmds())
        return nullptr;

    // Skip all the load commands up to the one we want.
    for (unsigned i = 0; i < idx; ++i) {
        // Get the next load command.
        lc = m_data->pointer<struct load_command>(reinterpret_cast<char *>(lc) + lc->cmdsize);
        if (!lc)
            return nullptr;
    }

    return lc;
}

bool MachoBinary::parse_load_commands() {
    // Get the section size align mask.
    unsigned align_mask = is32() ? 3 : 7;

    // For each load command.
    for (unsigned i = 0; i < ncmds(); ++i) {
        // Get the 'i'th load command.
        struct load_command *cur_lc = get_load_command(i);
        if (!cur_lc) {
            LOG_ERR("Could not get command %d", i);
            break;
        }

        // Check the size of the load command.
        if ((cur_lc->cmdsize & align_mask) != 0) {
            LOG_WARN("Load command %u has an unaligned size, skipping", i);
            continue;
        }

        LOG_DEBUG("Parsing command (%s) %d of %d", LoadCommandName(cur_lc->cmd).c_str(), i, ncmds());

        switch (cur_lc->cmd) {
            case LC_DATA_IN_CODE:
                // Table of data start addresses inside code segments.
                if (!parse_data_in_code(cur_lc)) {
                    LOG_WARN("Could not parse the load command, skipping");
                    continue;
                }

                break;
            case LC_FUNCTION_STARTS:
                // Compressed table of function start addresses.
                if (!parse_function_starts(cur_lc)) {
                    LOG_WARN("Could not parse the load command, skipping");
                    continue;
                }

                break;
            case LC_ROUTINES:
                // Describes the location of the shared library initialization function.
                if (!parse_routines_32(cur_lc)) {
                    LOG_WARN("Could not parse the load command, skipping");
                    continue;
                }

                break;
            case LC_ROUTINES_64:
                // Describes the location of the shared library initialization function.
                if (!parse_routines_64(cur_lc)) {
                    LOG_WARN("Could not parse the load command, skipping");
                    continue;
                }

                break;
            case LC_SEGMENT:
                // Defines a segment of this file to be mapped into the address space.
                if (!parse_segment_32(cur_lc)) {
                    LOG_WARN("Could not parse the load command, skipping");
                    continue;
                }

                break;
            case LC_SYMTAB:
                // Specifies the symbol table for this file.
                if (!parse_symtab(cur_lc)) {
                    LOG_WARN("Could not parse the load command, skipping");
                    continue;
                }

                break;
            case LC_SEGMENT_64:
                // Defines a 64-bit segment of this file to be mapped into the address space.
                if (!parse_segment_64(cur_lc)) {
                    LOG_WARN("Could not parse the load command, skipping");
                    continue;
                }

                break;
            case LC_DYSYMTAB:
                // Specifies additional symbol table information used by the dynamic linker.
                if (!parse_dysymtab(cur_lc)) {
                    LOG_WARN("Could not parse the load command, skipping");
                    continue;
                }

                break;
            case LC_THREAD:
                // Defines the initial thread state of the main thread of the process but does not allocate a stack.
                if (!parse_thread(cur_lc)) {
                    LOG_WARN("Could not parse the load command, skipping");
                    continue;
                }

                break;
            case LC_ID_DYLIB:
                // For a shared library, this segments identifies the the name of the library.
                if (!parse_id_dylib(cur_lc)) {
                    LOG_WARN("Could not parse the load command, skipping");
                    continue;
                }

                break;

            case LC_LAZY_LOAD_DYLIB:
            case LC_LOAD_DYLIB:         // Regular dynamic library.
            case LC_LOAD_WEAK_DYLIB:    // Dynamic library that may be missing.
            case LC_LOAD_UPWARD_DYLIB:  // Used for handling mutually dependent libraries.
            case LC_REEXPORT_DYLIB:     // This is worth looking. Used to replace pre-existing library.
                // Defines the name of a dynamic shared library that this file links against.
                if (!parse_dylib(cur_lc)) {
                    LOG_WARN("Could not parse the load command, skipping");
                    continue;
                }

                break;
            case LC_MAIN:
                // Replacement for LC_UNIXTHREAD.
                if (!parse_main(cur_lc)) {
                    LOG_WARN("Could not parse the load command, skipping");
                    continue;
                }

                break;
            case LC_UNIXTHREAD:
                // Defines the initial thread state of the main thread of the process and allocates a stack.
                if (!parse_unixthread(cur_lc)) {
                    LOG_WARN("Could not parse the load command, skipping");
                    continue;
                }

                break;
            case LC_DYLD_INFO:
            case LC_DYLD_INFO_ONLY:
                // Compressed dyld information. This somehow indicates that the mach-o file is compressed.
                if (!parse_dyld_info(cur_lc)) {
                    LOG_WARN("Could not parse the load command, skipping");
                    continue;
                }

                break;
            case LC_ENCRYPTION_INFO:
                if (!parse_encryption_info_32(cur_lc)) {
                    LOG_WARN("Could not parse the load command, skipping");
                    continue;
                }

            	break;
            case LC_ENCRYPTION_INFO_64:
                if (!parse_encryption_info_64(cur_lc)) {
                    LOG_WARN("Could not parse the load command, skipping");
                    continue;
                }

            	break;
            default:
                LOG_INFO("Load command `%s` is not supported", LoadCommandName(cur_lc->cmd).c_str());
                break;
        }
    }

    return true;
}

bool MachoBinary::parse_data_in_code(struct load_command *lc) {
    struct linkedit_data_command *cmd = m_data->pointer<struct linkedit_data_command>(lc);
    if (!cmd)
        return false;

    // The data in code information gives information about data inside a code segment.
    struct data_in_code_entry *data = m_data->offset<struct data_in_code_entry>(cmd->dataoff, cmd->datasize);

    // Get the number of entries.
    unsigned n = cmd->datasize / sizeof(struct data_in_code_entry);

    for (unsigned i = 0; i < n; ++i) {
        switch (data[i].kind) {
            case DICE_KIND_DATA:
                LOG_DEBUG("DICE_KIND_DATA:offset=%u length=%u\n", data[i].offset, data[i].length);
                break;
            case DICE_KIND_JUMP_TABLE8:
                LOG_DEBUG("DICE_KIND_JUMP_TABLE8:offset=%u length=%u\n", data[i].offset, data[i].length);
                break;
            case DICE_KIND_JUMP_TABLE16:
                LOG_DEBUG("DICE_KIND_JUMP_TABLE16:offset=%u length=%u\n", data[i].offset, data[i].length);
                break;
            case DICE_KIND_JUMP_TABLE32:
                LOG_DEBUG("DICE_KIND_JUMP_TABLE32:offset=%u length=%u\n", data[i].offset, data[i].length);
                break;
            case DICE_KIND_ABS_JUMP_TABLE32:
                LOG_DEBUG("DICE_KIND_ABS_JUMP_TABLE32:offset=%u length=%u\n", data[i].offset, data[i].length);
                break;
            default:
                break;
        }
    }

    return true;
}

bool MachoBinary::parse_function_starts(struct load_command *lc) {
    struct linkedit_data_command *cmd = m_data->pointer<struct linkedit_data_command>(lc);
    if (!cmd)
        return false;

    const uint8_t *infoStart = m_data->offset<const uint8_t>(cmd->dataoff, cmd->datasize);
    if (!infoStart)
        return false;

    const uint8_t *infoEnd = &infoStart[cmd->datasize];

    uint64_t address = 0;
    for (const uint8_t* p = infoStart; (*p != 0) && (p < infoEnd);) {
        uint64_t delta = 0;
        uint32_t shift = 0;
        bool more = true;
        do {
            uint8_t byte = *p++;
            delta |= ((byte & 0x7F) << shift);
            shift += 7;

            if (byte < 0x80) {
                address += delta;
                //printFunctionStartLine(address);
                LOG_DEBUG("address = %p", (void * ) address);
                more = false;
            }
        } while (more);
    }

    return true;
}

bool MachoBinary::parse_routines_32(struct load_command *lc) {
    struct routines_command * cmd = m_data->pointer<struct routines_command>(lc);
    LOG_DEBUG("init_address = 0x%.8x init_module = 0x%.8x", cmd->init_address, cmd->init_module);
    return true;
}

bool MachoBinary::parse_routines_64(struct load_command *lc) {
    struct routines_command_64 * cmd = m_data->pointer<struct routines_command_64>(lc);
    LOG_DEBUG("init_address = 0x%.16llx init_module = 0x%.16llx", cmd->init_address, cmd->init_module);
    return true;
}

bool MachoBinary::parse_segment_32(struct load_command *lc) {
    struct segment_command *cmd = m_data->pointer<struct segment_command>(lc);
    printf("name = %-16s | base = 0x%.8x | size = 0x%.8x\n", cmd->segname, cmd->vmaddr, cmd->vmsize);
    return true;
}

bool MachoBinary::parse_section_32(struct section_32 *lc) {
    return true;
}

// Specifies the range of bytes in a 64-bit mach-o file that make up a segment.
// Those bytes are mapped by the loader into the address space of a program.
bool MachoBinary::parse_segment_64(struct load_command *lc) {
    struct segment_command_64 *cmd = m_data->pointer<struct segment_command_64>(lc);

    LOG_DEBUG("name = %-16s | base = 0x%.16llx | size = 0x%.16llx", cmd->segname, cmd->vmaddr, cmd->vmsize);

    // Get a pointer to the first section.
    struct section_64 *cur_section = m_data->pointer<struct section_64>(cmd + 1);

    // Parse each of the segments sections.
    for (unsigned i = 0; i < cmd->nsects; ++i) {
        // Check if the data does not go beyond our loaded memory.
        if (!m_data->valid(cur_section)) {
            LOG_ERR("Error, the current section (%u) goes beyond the mapped file", i);
            break;
        }

        LOG_DEBUG("Parsing section %d of %d", i, cmd->nsects);

        LOG_DEBUG("name%16s:%-16s addr=%p size=0x%.16llx offset=0x%.8x align=0x%.8x reloff=0x%.8x nreloc=0x%.8x flags=0x%.8x",
                cur_section->segname, cur_section->sectname, (void * ) cur_section->addr, cur_section->size, cur_section->offset,
                cur_section->align, cur_section->reloff, cur_section->nreloc, cur_section->flags);

        // Parse the section.
        if (!parse_section_64(cur_section)) {
            LOG_ERR("Error, could not parse section %u of %u, skipping", i, cmd->nsects);
            continue;
        }

        cur_section++;
    }

    return true;
}

bool MachoBinary::parse_section_64(struct section_64 *lc) {
    uint32_t section_type = lc->flags & SECTION_TYPE;
    uint32_t section_usr_attr = lc->flags & SECTION_ATTRIBUTES_USR;
    uint32_t section_sys_attr = lc->flags & SECTION_ATTRIBUTES_SYS;

    switch (section_type) {
        case S_REGULAR:
            // No particular type. This is used for "__TEXT,__text".
            LOG_DEBUG("S_REGULAR");
            break;
        case S_ZEROFILL:
            // This section will be filled with zero bytes whenever it is accessed.
            LOG_DEBUG("S_ZEROFILL");
            break;
        case S_CSTRING_LITERALS:
            // This section contains only constant C strings.
            LOG_DEBUG("S_CSTRING_LITERALS");
            break;
        case S_4BYTE_LITERALS:
            // This section contains only constant values that are 4 bytes long.
            LOG_DEBUG("S_4BYTE_LITERALS");
            break;
        case S_8BYTE_LITERALS:
            // This section contains only constant values that are 8 bytes long.
            LOG_DEBUG("S_8BYTE_LITERALS");
            break;
        case S_LITERAL_POINTERS:
            // This section contains only pointers to constant values.
            LOG_DEBUG("S_LITERAL_POINTERS");
            break;
        case S_NON_LAZY_SYMBOL_POINTERS:
            // This section contains only non-lazy pointers to symbols.
            LOG_DEBUG("S_NON_LAZY_SYMBOL_POINTERS");
            break;
        case S_LAZY_SYMBOL_POINTERS:
            // This section contains only lazy pointers to symbols.
            LOG_DEBUG("S_LAZY_SYMBOL_POINTERS");
            break;
        case S_SYMBOL_STUBS:
            // This section contains symbol stubs.
            LOG_DEBUG("S_SYMBOL_STUBS");
            break;
        case S_MOD_INIT_FUNC_POINTERS:
            // This section contains pointers to module initialization functions.
            LOG_DEBUG("S_MOD_INIT_FUNC_POINTERS");
            break;
        case S_MOD_TERM_FUNC_POINTERS:
            // This section contains pointers to module termination functions.
            LOG_DEBUG("S_MOD_TERM_FUNC_POINTERS");
            break;
        case S_COALESCED:
            // This section contains symbols that are coalesced by the static linker and possibly the dynamic linker.
            LOG_DEBUG("S_COALESCED");
            break;
        case S_GB_ZEROFILL:
            // This is a zero-filled on-demand section.
            LOG_DEBUG("S_GB_ZEROFILL");
            break;
        case S_INTERPOSING:
            LOG_DEBUG("S_INTERPOSING");
            break;
        case S_16BYTE_LITERALS:
            LOG_DEBUG("S_16BYTE_LITERALS");
            break;
        case S_DTRACE_DOF:
            LOG_DEBUG("S_DTRACE_DOF");
            break;
        case S_LAZY_DYLIB_SYMBOL_POINTERS:
            LOG_DEBUG("S_LAZY_DYLIB_SYMBOL_POINTERS");
            break;
        case S_THREAD_LOCAL_REGULAR:
            LOG_DEBUG("S_THREAD_LOCAL_REGULAR");
            break;
        case S_THREAD_LOCAL_ZEROFILL:
            LOG_DEBUG("S_THREAD_LOCAL_ZEROFILL");
            break;
        case S_THREAD_LOCAL_VARIABLES:
            LOG_DEBUG("S_THREAD_LOCAL_VARIABLES");
            break;
        case S_THREAD_LOCAL_VARIABLE_POINTERS:
            LOG_DEBUG("S_THREAD_LOCAL_VARIABLE_POINTERS");
            break;
        case S_THREAD_LOCAL_INIT_FUNCTION_POINTERS:
            LOG_DEBUG("S_THREAD_LOCAL_INIT_FUNCTION_POINTERS");
            break;
        default:
            LOG_WARN("Unknown section type 0x%.8x, ignoring", section_type);
            break;
    }

    switch (section_usr_attr) {
        case S_ATTR_PURE_INSTRUCTIONS:
            // This section contains only executable machine instructions.
            LOG_DEBUG("S_ATTR_PURE_INSTRUCTIONS");
            break;
        case S_ATTR_NO_TOC:
            // This section contains coalesced symbols that must not be placed in the table of contents (SYMDEF member) of a static archive library.
            LOG_DEBUG("S_ATTR_NO_TOC");
            break;
        case S_ATTR_STRIP_STATIC_SYMS:
            // The static symbols in this section can be stripped.
            LOG_DEBUG("S_ATTR_STRIP_STATIC_SYMS");
            break;
        case S_ATTR_NO_DEAD_STRIP:
            // This section must not be dead-stripped.
            LOG_DEBUG("S_ATTR_NO_DEAD_STRIP");
            break;
        case S_ATTR_LIVE_SUPPORT:
            // This section must not be dead-stripped if they reference code that is live, but the reference is undetectable.
            LOG_DEBUG("S_ATTR_LIVE_SUPPORT");
            break;
        case S_ATTR_SELF_MODIFYING_CODE:
            LOG_DEBUG("S_ATTR_SELF_MODIFYING_CODE");
            break;
        case S_ATTR_DEBUG:
            LOG_DEBUG("S_ATTR_DEBUG");
            break;
        case 0:
            break;
        default:
            LOG_WARN("Unknown section user attribute 0x%.8x, ignoring", section_usr_attr);
            break;
    }

    switch (section_sys_attr) {
        case S_ATTR_SOME_INSTRUCTIONS:
            // This section contains executable machine instructions.
            LOG_DEBUG("S_ATTR_SOME_INSTRUCTIONS");
            break;
        case S_ATTR_EXT_RELOC:
            // This section contains external references that must be relocated.
            LOG_DEBUG("S_ATTR_EXT_RELOC");
            break;
        case S_ATTR_LOC_RELOC:
            // This section contains references that must be relocated.
            LOG_DEBUG("S_ATTR_LOC_RELOC");
            break;
        case 0:
            break;
        default:
            LOG_WARN("Unknown section system attribute 0x%.8x, ignoring", section_sys_attr);
            break;
    }

    return true;
}

bool MachoBinary::parse_generic_symbol(struct nlist_64 *symbol) {
    if (symbol->n_type & N_PEXT) {
        // Private external symbol.
        LOG_DEBUG("N_PEXT");
    }

    if (symbol->n_type & N_EXT) {
        // External symbol.
        LOG_DEBUG("N_EXT");
    }

    switch (symbol->n_type & N_TYPE) {
        case N_UNDF:
            LOG_DEBUG("N_UNDF");
            break;
        case N_ABS:
            LOG_DEBUG("N_ABS");
            break;
        case N_SECT:
            LOG_DEBUG("N_SECT");
            break;
        case N_PBUD:
            LOG_DEBUG("N_PBUD");
            break;
        case N_INDR:
            LOG_DEBUG("N_INDR");
            break;
        default:
            LOG_ERR("Unknown symbol type %u, ignoring", symbol->n_type & N_TYPE);
            break;
    }

    // Get the description for symbols of type N_UNDF only.
    switch (symbol->n_desc & REFERENCE_TYPE) {
        case REFERENCE_FLAG_DEFINED:
            LOG_DEBUG("REFERENCE_FLAG_DEFINED");
            break;
        case REFERENCE_FLAG_PRIVATE_DEFINED:
            LOG_DEBUG("REFERENCE_FLAG_PRIVATE_DEFINED");
            break;
        case REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY:
            LOG_DEBUG("REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY");
            break;
        case REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY:
            LOG_DEBUG("REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY");
            break;
        case REFERENCE_FLAG_UNDEFINED_LAZY:
            LOG_DEBUG("REFERENCE_FLAG_UNDEFINED_LAZY");
            break;
        case REFERENCE_FLAG_UNDEFINED_NON_LAZY:
            LOG_DEBUG("REFERENCE_FLAG_UNDEFINED_NON_LAZY");
            break;
        default:
            LOG_ERR("Unknown reference type 0x%.2x, ignoring", symbol->n_desc & REFERENCE_TYPE);
            break;
    }

    LOG_DEBUG("symbol->n_desc = 0x%.2x", symbol->n_desc);
    LOG_DEBUG("symbol->n_desc = 0x%.2x", symbol->n_desc & REFERENCE_TYPE);

    if (symbol->n_desc & REFERENCED_DYNAMICALLY)
        LOG_DEBUG("REFERENCED_DYNAMICALLY");

    if (filetype() == MH_OBJECT && (symbol->n_desc & N_NO_DEAD_STRIP))
        LOG_DEBUG("N_NO_DEAD_STRIP");

    if (filetype() != MH_OBJECT && (symbol->n_desc & N_DESC_DISCARDED))
        LOG_DEBUG("N_DESC_DISCARDED");

    if (symbol->n_desc & N_WEAK_REF)
        LOG_DEBUG("N_WEAK_REF");

    if (symbol->n_desc & N_WEAK_DEF)
        LOG_DEBUG("N_WEAK_DEF");

    if (symbol->n_desc & N_REF_TO_WEAK)
        LOG_DEBUG("N_REF_TO_WEAK");

    if (symbol->n_desc & N_ARM_THUMB_DEF)
        LOG_DEBUG("N_ARM_THUMB_DEF");

    if (symbol->n_desc & N_SYMBOL_RESOLVER)
        LOG_DEBUG("N_SYMBOL_RESOLVER");

    if (symbol->n_desc & N_ALT_ENTRY)
        LOG_DEBUG("N_ALT_ENTRY");

    return true;
}

bool MachoBinary::parse_stab_symbol(struct nlist_64 *symbol) {
    switch (symbol->n_type & N_STAB) {
        /* Labeled as NO_SECT in stab.h */
        case N_GSYM:
        case N_FNAME:
        case N_RSYM:
        case N_SSYM:
        case N_LSYM:
        case N_BINCL:
        case N_PARAMS:
        case N_VERSION:
        case N_OLEVEL:
        case N_PSYM:
        case N_EINCL:
        case N_EXCL:
        case N_BCOMM:
        case N_LENG:
        case N_OPT:
        case N_OSO:
            // sym->is_absolute = 1;
            break;
            /* Labeled as n_sect in stab.h */
        case N_FUN:
        case N_STSYM:
        case N_LCSYM:
        case N_BNSYM:
        case N_SLINE:
        case N_ENSYM:
        case N_SO:
        case N_SOL:
        case N_ENTRY:
        case N_ECOMM:
        case N_ECOML:
            /* These are labeled as NO_SECT in stab.h, but they are actually
             * section-based on OS X.  We must mark them as such so they get
             * relocated.
             */
        case N_RBRAC:
        case N_LBRAC:
            // sym->is_section = 1;
            break;
        default:
            break;
    }
    return true;
}

bool MachoBinary::parse_symtab(struct load_command *lc) {
    struct symtab_command *cmd = m_data->pointer<struct symtab_command>(lc);

    // Save a reference to the symbol table.
    m_symbol_table_size = cmd->nsyms;
    m_symbol_table = m_data->offset<struct nlist_64>(cmd->symoff, cmd->nsyms * sizeof(struct nlist_64));
    if (!m_symbol_table) {
        LOG_ERR("Symbol table is outside the binary mapped file");
        return false;
    }

    // Save a reference to the string table.
    m_string_table_size = cmd->strsize;
    m_string_table = m_data->offset<char>(cmd->stroff, cmd->strsize);
    if (!m_string_table) {
        LOG_ERR("Symbol string table is outside the binary mapped file (offset=%u, size=%u)", cmd->stroff, cmd->strsize);
        return false;
    }

    for (unsigned i = 0; i < cmd->nsyms; ++i) {
        // Get the symbol name.
        unsigned idx = m_symbol_table[i].n_un.n_strx;
        if (idx >= m_string_table_size) {
            LOG_ERR("Symbol index (%u) is outside the string table.", idx);
            continue;
        }

        LOG_DEBUG("symbol->name = %s", idx ? &m_string_table[idx] : "(null)");

        // Get the section index.
        LOG_DEBUG("symbol->n_sect = 0x%.2x", m_symbol_table[i].n_sect);

        // Get the symbol value.
        LOG_DEBUG("symbol->n_value = 0x%.16llx", m_symbol_table[i].n_value);

        if (m_symbol_table[i].n_type & N_STAB) {
            parse_stab_symbol(&m_symbol_table[i]);
        } else {
            parse_generic_symbol(&m_symbol_table[i]);
        }

        LOG_DEBUG("");
    }

    return true;
}

bool MachoBinary::parse_dysymtab(struct load_command *lc) {
    // Symbols used by the dynamic linker.
    // This is an additional segment that requires a prior symtab load command.
    struct dysymtab_command *cmd = m_data->pointer<struct dysymtab_command>(lc);

    // Verify that we have string and symbolic information.
    if (!m_symbol_table || !m_string_table) {
        LOG_ERR("Impossible to parse LC_DYSYMTAB without a LC_SYMTAB entry.");
        return false;
    }

    // List local symbols.
    for (unsigned i = cmd->ilocalsym; i < cmd->nlocalsym; ++i) {
        if (i >= m_symbol_table_size) {
            LOG_ERR("Symbol table entry %u is outside the binary mapped file", i);
            break;
        }

        unsigned idx = m_symbol_table[i].n_un.n_strx;
        LOG_DEBUG("Local symbol:");
        LOG_DEBUG("  symbol->name    = %s", idx ? &m_string_table[idx] : "(null)");
        LOG_DEBUG("  symbol->n_sect  = 0x%.2x", m_symbol_table[i].n_sect);
        LOG_DEBUG("  symbol->n_value = 0x%.16llx\n", m_symbol_table[i].n_value);
    }

    // External defined symbols.
    for (unsigned i = cmd->iextdefsym; i < cmd->nextdefsym; ++i) {
        if (i >= m_symbol_table_size) {
            LOG_ERR("Symbol table entry %u is outside the binary mapped file", i);
            break;
        }

        unsigned idx = m_symbol_table[i].n_un.n_strx;
        LOG_DEBUG("External defined symbol:");
        LOG_DEBUG("  symbol->name    = %s", idx ? &m_string_table[idx] : "(null)");
        LOG_DEBUG("  symbol->n_sect  = 0x%.2x", m_symbol_table[i].n_sect);
        LOG_DEBUG("  symbol->n_value = 0x%.16llx\n", m_symbol_table[i].n_value);
    }

    // External undefined symbols.
    for (unsigned i = cmd->iundefsym; i < cmd->nundefsym; ++i) {
        if (i >= m_symbol_table_size) {
            LOG_ERR("Symbol table entry %u is outside the binary mapped file", i);
            break;
        }

        unsigned idx = m_symbol_table[i].n_un.n_strx;
        LOG_DEBUG("External undefined symbol:");
        LOG_DEBUG("  symbol->name    = %s", idx ? &m_string_table[idx] : "(null)");
        LOG_DEBUG("  symbol->n_sect  = 0x%.2x", m_symbol_table[i].n_sect);
        LOG_DEBUG("  symbol->n_value = 0x%.16llx\n", m_symbol_table[i].n_value);
    }

    uint32_t tocoff; /* file offset to table of contents */
    uint32_t ntoc; /* number of entries in table of contents */

    LOG_DEBUG("tocoff       = 0x%.8x ntoc        = 0x%.8x modtaboff      = 0x%.8x nmodtab       = 0x%.8x", cmd->tocoff, cmd->ntoc,
            cmd->modtaboff, cmd->nmodtab);

    LOG_DEBUG("extrefsymoff = 0x%.8x nextrefsyms = 0x%.8x indirectsymoff = 0x%.8x nindirectsyms = 0x%.8x", cmd->extrefsymoff,
            cmd->nextrefsyms, cmd->indirectsymoff, cmd->nindirectsyms);

    LOG_DEBUG("extreloff    = 0x%.8x nextrel     = 0x%.8x locreloff      = 0x%.8x nlocrel       = 0x%.8x ", cmd->extreloff, cmd->nextrel,
            cmd->locreloff, cmd->nlocrel);

    return true;
}

bool MachoBinary::parse_thread(struct load_command *lc) {
    struct thread_command *cmd = m_data->pointer<struct thread_command>(lc);

    // Skip to the contents.
    uint32_t *contents = m_data->pointer<uint32_t>(cmd + 1);
    assert(contents == reinterpret_cast<uint32_t*>(cmd + 1));

    // After the thread_command we will find two uint32_t's.
    uint32_t flavor = contents[0];
    uint32_t count = contents[1];

    LOG_DEBUG("flavor = 0x%.8x count = 0x%.8x", flavor, count);

    // After these we will have the arch specific thread information.
    return true;
}

bool MachoBinary::parse_id_dylib(struct load_command *lc) {
    struct dylib_command *cmd = m_data->pointer<struct dylib_command>(lc);

    // Get the name of the this library.
    char *name = m_data->pointer<char>(reinterpret_cast<char *>(cmd) + cmd->dylib.name.offset);

    LOG_DEBUG("Current library: name=%-40s tstamp=0x%.8x ver=0x%.8x compat=0x%.8x", name, cmd->dylib.timestamp, cmd->dylib.current_version,
            cmd->dylib.compatibility_version);

    return true;
}

bool MachoBinary::parse_dylib(struct load_command *lc) {
    struct dylib_command *cmd = m_data->pointer<struct dylib_command>(lc);

    // Get the name of the imported library.
    char *name = m_data->pointer<char>(reinterpret_cast<char *>(cmd) + cmd->dylib.name.offset);

    LOG_DEBUG("Imported library: name=%-40s tstamp=0x%.8x ver=0x%.8x compat=0x%.8x", name, cmd->dylib.timestamp, cmd->dylib.current_version,
            cmd->dylib.compatibility_version);

    return true;
}

bool MachoBinary::parse_main(struct load_command *lc) {
    struct entry_point_command *cmd = m_data->pointer<struct entry_point_command>(lc);

    LOG_DEBUG("entryoff=0x%.16llx stacksize=0x%.16llx", cmd->entryoff, cmd->stacksize);

    return true;
}

bool MachoBinary::parse_unixthread(struct load_command *lc) {
    struct thread_command *cmd = m_data->pointer<struct thread_command>(lc);

    // Skip to the contents.
    uint32_t *contents = m_data->pointer<uint32_t>(cmd + 1);
    assert(contents == reinterpret_cast<uint32_t*>(cmd + 1));

    // After the thread_command we will find two uint32_t's.
    uint32_t flavor = contents[0];
    uint32_t count = contents[1];

    LOG_DEBUG("flavor = 0x%.8x count = 0x%.8x", flavor, count);

    // After these we will have the arch specific thread information.
    return true;
}

bool MachoBinary::parse_encryption_info_32(struct load_command *lc) {
	// This commands identify a range of the file that is encrypted.
	struct encryption_info_command *cmd = m_data->pointer<struct encryption_info_command>(lc);
	LOG_DEBUG("cryptoff = 0x%.8x cryptsize = 0x%.8x cryptid = 0x%.8x", cmd->cryptoff, cmd->cryptsize, cmd->cryptid);
	return true;
}

bool MachoBinary::parse_encryption_info_64(struct load_command *lc) {
	// This commands identify a range of the file that is encrypted.
	struct encryption_info_command_64 *cmd = m_data->pointer<struct encryption_info_command_64>(lc);
	LOG_DEBUG("cryptoff = 0x%.8x cryptsize = 0x%.8x cryptid = 0x%.8x", cmd->cryptoff, cmd->cryptsize, cmd->cryptid);
	return true;
}


bool MachoBinary::parse_dyld_info(struct load_command *lc) {
    struct dyld_info_command *cmd = m_data->pointer<struct dyld_info_command>(lc);
    return true;
}
