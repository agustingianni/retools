/*
 * MachoBinary.cpp
 *
 *  Created on: Mar 22, 2015
 *      Author: anon
 */

#include <cassert>
#include <cstring>
#include <iomanip>
#include <queue>
#include <sstream>
#include <string>
#include <vector>
#include <mach-o/dyld_images.h>

#define NDEBUG

#include "debug.h"
#include "macho/Swap.h"
#include "macho/ObjectiveC.h"
#include "macho/MachoBinary.h"
#include "macho/MachoBinaryVisitor.h"
#include "abstract/Segment.h"
#include "abstract/DataInCode.h"

using namespace std;

static void hexdump(const char *desc, void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*) addr;

    // Output description if given.
    if (desc != NULL)
        LOG_DEBUG("%s:\n", desc);

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                LOG_DEBUG("  %s\n", buff);

            // Output the offset.
            LOG_DEBUG("  %04x ", i);
        }

        // Now the hex code for the specific character.
        LOG_DEBUG(" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        LOG_DEBUG("   ");
        i++;
    }

    // And print the final ASCII bit.
    LOG_DEBUG("  %s\n", buff);
}

static int64_t read_sleb128(const uint8_t*& p, const uint8_t* end) {
    int64_t result = 0;
    int bit = 0;
    uint8_t byte;
    do {
        byte = *p++;
        result |= ((byte & 0x7f) << bit);
        bit += 7;
    } while (byte & 0x80);

    if ((byte & 0x40) != 0)
        result |= (-1LL) << bit;
    return result;
}

static uint64_t read_uleb128(const uint8_t *&p, const uint8_t *end) {
    uint64_t result = 0;
    int bit = 0;
    do {

        uint64_t slice = *p & 0x7f;

        result |= (slice << bit);
        bit += 7;
    } while (*p++ & 0x80);

    return result;
}

static uintptr_t read_terminal_size(const uint8_t *&p, const uint8_t *end) {
    uintptr_t terminal_size = *p++;
    if (terminal_size > 127) {
        --p;
        terminal_size = read_uleb128(p, end);
    }

    return terminal_size;
}

string LoadCommandName(unsigned cmd) {
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
            return "LC_UNKNOWN (" + to_string(cmd) + ")";
    }
}

bool MachoBinary::init() {
    m_symbol_table = nullptr;
    m_string_table = nullptr;

    struct mach_header *tmp_header = m_data.offset<mach_header>(0);
    if (!tmp_header) {
        LOG_ERR("Could not get a reference to the mach_header");
        return false;
    }

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

    // Read the header and swap it if needed.
    if (is32()) {
        m_header.header_32 = m_data.offset<mach_header>(0);
        if (!m_header.header_32) {
            LOG_ERR("Failed to read the mach-o header.");
            return false;
        }

        swap_if(needs_swap(), m_header.header_32);
    } else {
        m_header.header_64 = m_data.offset<mach_header_64>(0);
        if (!m_header.header_64) {
            LOG_ERR("Failed to read the mach-o header.");
            return false;
        }

        swap_if(needs_swap(), m_header.header_64);
    }

    // Get the kind of mach-o file.
    switch (filetype()) {
        case MH_OBJECT:
            m_binary_type = BinaryType::Object;
            break;
        case MH_DSYM:
            m_binary_type = BinaryType::Symbols;
            break;
        case MH_CORE:
            m_binary_type = BinaryType::Core;
            break;
        case MH_PRELOAD:
        case MH_EXECUTE:
            m_binary_type = BinaryType::Executable;
            break;
        case MH_DYLIB_STUB:
        case MH_DYLINKER:
        case MH_FVMLIB:
        case MH_DYLIB:
        case MH_BUNDLE:
            m_binary_type = BinaryType::Library;
            break;
        case MH_KEXT_BUNDLE:
            m_binary_type = BinaryType::Driver;
            break;
        default:
            LOG_WARN("Unknown mach-o file type 0x%.8x", filetype());
            m_binary_type = BinaryType::Unknown;
            break;
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
        case CPU_TYPE_POWERPC:
            m_binary_arch = BinaryArch::PowerPC;
            break;
        case CPU_TYPE_POWERPC64:
            m_binary_arch = BinaryArch::PowerPC64;
            break;
        default:
            LOG_WARN("Unknown mach-o CPU type 0x%.8x", cputype());
            m_binary_arch = BinaryArch::Unknown;
            break;
    }

    // Load information from the load commands.
    if (!parse_load_commands()) {
        LOG_ERR("Failed to parse the load commands");
        return false;
    }

    return true;
}

struct load_command *MachoBinary::get_load_command(unsigned idx) const {
    // The first load command is past the mach-o header.
    struct load_command *lc = m_data.offset<load_command>(mach_header_size());
    if (!lc || idx >= ncmds()) {
        LOG_ERR("Filaed to read load command.");
        return nullptr;
    }

    // Skip all the load commands up to the one we want.
    for (unsigned i = 0; i < idx; ++i) {
        // Get the next load command.
        lc = m_data.pointer<load_command>(reinterpret_cast<char *>(lc) + lc->cmdsize);
        if (!lc) {
            LOG_ERR("Failed to read load command.");
            return nullptr;
        }
    }

    return lc;
}

static struct nlist_64 nlist_to_64(const struct nlist &n) {
    struct nlist_64 tmp;
    tmp.n_desc = n.n_desc;
    tmp.n_sect = n.n_sect;
    tmp.n_type = n.n_type;
    tmp.n_un.n_strx = n.n_un.n_strx;
    tmp.n_value = n.n_value;
    return tmp;
}

bool MachoBinary::parse_load_commands() {
    // Get the section size align mask.
    unsigned align_mask = is32() ? 3 : 7;

    // Order is important so we need these load commands to be parsed before the rest.
    for (unsigned i = 0; i < ncmds(); ++i) {
        struct load_command *cur_lc = get_load_command(i);
        if (!cur_lc) {
            LOG_WARN("Could not get command %d, skipping", i);
            continue;
        }

        // Make a copy since we don't want to swap the load command twice.
        struct load_command temp = *cur_lc;

        // Swap load command if necessary.
        swap_if(needs_swap(), &temp);

        // Verify alignment requirements.
        if ((cur_lc->cmdsize & align_mask) != 0) {
            LOG_WARN("Load command %u has an unaligned size, skipping", i);
            continue;
        }

        if (cur_lc->cmd == LC_SYMTAB) {
            auto cmd = m_data.pointer<symtab_command>(cur_lc);
            if (!cmd) {
                LOG_ERR("Error loading symbol table load command.");
                continue;
            }

            // Save a reference to the symbol table.
            m_symbol_table_size = cmd->nsyms;

            // Create space for the symbol table. This should be freed later.
            m_symbol_table = new nlist_64[m_symbol_table_size];

            // This sucks.
            if (is32()) {
                auto temp = m_data.offset<struct nlist>(cmd->symoff, m_symbol_table_size * sizeof(struct nlist));
                if (!temp) {
                    LOG_ERR("Error reading symbol table.");
                    continue;
                }

                for (unsigned i = 0; i < m_symbol_table_size; i++) {
                    m_symbol_table[i] = nlist_to_64(temp[i]);
                }
            } else {
                auto temp = m_data.offset<struct nlist_64>(cmd->symoff, m_symbol_table_size * sizeof(struct nlist_64));
                if (!temp) {
                    LOG_ERR("Error reading symbol table.");
                    continue;
                }

                for (unsigned i = 0; i < m_symbol_table_size; i++) {
                    m_symbol_table[i] = temp[i];
                }
            }

            // Save a reference to the string table.
            m_string_table_size = cmd->strsize;
            m_string_table = m_data.offset<char>(cmd->stroff, m_string_table_size);
            if (!m_string_table) {
                LOG_WARN("Symbol string table is outside the binary mapped file.");
                continue;
            }
        }

        if (cur_lc->cmd == LC_DYSYMTAB) {
            m_dysymtab_command = m_data.pointer<dysymtab_command>(cur_lc);
            if (!m_dysymtab_command) {
                LOG_WARN("Dynamic symbol table is outside the binary mapped file.");
                continue;
            }
        }
    }

    for (unsigned i = 0; i < ncmds(); ++i) {
        struct load_command *cur_lc = get_load_command(i);
        if (!cur_lc) {
            LOG_WARN("Could not get command %d", i);
            continue;
        }

        if ((cur_lc->cmdsize & align_mask) != 0) {
            LOG_WARN("Load command %u has an unaligned size, skipping", i);
            continue;
        }

        bool parsed = false;
        LOG_DEBUG("Parsing command (%s) %d of %d", LoadCommandName(cur_lc->cmd).c_str(), i, ncmds());

        switch (cur_lc->cmd) {
            case LC_DATA_IN_CODE:
                parsed = parse_data_in_code(cur_lc);
                break;

            case LC_FUNCTION_STARTS:
                parsed = parse_function_starts(cur_lc);
                break;

            case LC_ROUTINES:
                parsed = parse_routines<routines_command>(cur_lc);
                break;

            case LC_ROUTINES_64:
                parsed = parse_routines<routines_command_64>(cur_lc);
                break;

            case LC_SEGMENT:
                if (!is32()) {
                    LOG_WARN("Found a 32 bit segment on a 64 bit binary (results may be wrong)");
                }

                parsed = parse_segment<segment_command, section>(cur_lc);
                break;

            case LC_SEGMENT_64:
                if (!is64()) {
                    LOG_WARN("Found a 64 bit segment on a 32 bit binary (results may be wrong)");
                }

                parsed = parse_segment<segment_command_64, section_64>(cur_lc);
                break;

            case LC_SYMTAB:
                parsed = parse_symtab(cur_lc);
                break;

            case LC_DYSYMTAB:
                parsed = parse_dysymtab(cur_lc);

                break;
            case LC_ID_DYLIB:
                parsed = parse_id_dylib(cur_lc);
                break;

            case LC_LOAD_DYLIB:
            case LC_REEXPORT_DYLIB:
            case LC_LAZY_LOAD_DYLIB:
            case LC_LOAD_WEAK_DYLIB:
            case LC_LOAD_UPWARD_DYLIB:
                parsed = parse_dylib(cur_lc);
                break;

            case LC_MAIN:
                parsed = parse_main(cur_lc);
                break;

            case LC_THREAD:
                parsed = parse_thread(cur_lc);
                break;

            case LC_UNIXTHREAD:
                parsed = parse_unixthread(cur_lc);
                break;

            case LC_DYLD_INFO:
            case LC_DYLD_INFO_ONLY:
                parsed = parse_dyld_info(cur_lc);
                break;

            case LC_ENCRYPTION_INFO:
                parsed = parse_encryption_info<encryption_info_command>(cur_lc);
                break;

            case LC_ENCRYPTION_INFO_64:
                parsed = parse_encryption_info<encryption_info_command_64>(cur_lc);
                break;

            case LC_CODE_SIGNATURE:
                parsed = parse_code_signature(cur_lc);
                break;

            case LC_DYLD_ENVIRONMENT:
                parsed = parse_dyld_environment(cur_lc);
                break;

            case LC_LOAD_DYLINKER:
            case LC_ID_DYLINKER:
                parsed = parse_id_dylinker(cur_lc);
                break;

            case LC_SOURCE_VERSION:
                parsed = parse_source_version(cur_lc);
                break;

            case LC_RPATH:
                parsed = parse_rpath(cur_lc);
                break;

            case LC_LINKER_OPTION:
                parsed = parse_linker_option(cur_lc);
                break;

            case LC_SUB_LIBRARY:
                parsed = parse_sub_library(cur_lc);
                break;

            case LC_SUB_CLIENT:
                parsed = parse_sub_client(cur_lc);
                break;

            case LC_SUB_FRAMEWORK:
                parsed = parse_sub_framework(cur_lc);
                break;

            case LC_SUB_UMBRELLA:
                parsed = parse_sub_umbrella(cur_lc);
                break;

            case LC_UUID:
                parsed = parse_uuid(cur_lc);
                break;

            case LC_VERSION_MIN_IPHONEOS:
                m_os = BinaryOperatingSystem::iOS;
                parsed = true;
                break;

            case LC_VERSION_MIN_MACOSX:
                m_os = BinaryOperatingSystem::OSX;
                parsed = true;
                break;

            case LC_VERSION_MIN_TVOS:
                m_os = BinaryOperatingSystem::AppleTV;
                parsed = true;
                break;

            case LC_VERSION_MIN_WATCHOS:
                m_os = BinaryOperatingSystem::AppleWatch;
                parsed = true;
                break;

            case LC_DYLIB_CODE_SIGN_DRS:
                m_signed = true;
                parsed = true;
                break;

            case LC_FVMFILE:
            case LC_IDENT:
            case LC_IDFVMLIB:
            case LC_LINKER_OPTIMIZATION_HINT:
            case LC_LOADFVMLIB:
            case LC_PREBIND_CKSUM:
            case LC_PREBOUND_DYLIB:
            case LC_PREPAGE:
            case LC_SEGMENT_SPLIT_INFO:
            case LC_SYMSEG:
            case LC_TWOLEVEL_HINTS:
            default:
                LOG_INFO("Load command `%s` is not supported", LoadCommandName(cur_lc->cmd).c_str());
                parsed = true;
                break;
        }

        if (!parsed) {
            LOG_INFO("Failed to parse load command `%s`", LoadCommandName(cur_lc->cmd).c_str());
        }
    }

    return true;
}

bool MachoBinary::parse_data_in_code(struct load_command *lc) {
    struct linkedit_data_command *cmd = m_data.pointer<linkedit_data_command>(lc);
    if (!cmd) {
        LOG_ERR("Failed to read load command.");
        return false;
    }

    // The data in code information gives information about data inside a code segment.
    struct data_in_code_entry *data = m_data.offset<data_in_code_entry>(cmd->dataoff, cmd->datasize);
    if (!data) {
        LOG_ERR("Failed to read load command");
        return false;
    }

    // Get the number of entries.
    unsigned count = cmd->datasize / sizeof(*data);
    for (unsigned i = 0; i < count; ++i) {
        Abstract::DataInCodeKind kind;
        switch (data[i].kind) {
            case DICE_KIND_DATA:
                kind = Abstract::DataInCodeKind::DATA;
                break;
            case DICE_KIND_JUMP_TABLE8:
                kind = Abstract::DataInCodeKind::JUMP_TABLE_8;
                break;
            case DICE_KIND_JUMP_TABLE16:
                kind = Abstract::DataInCodeKind::JUMP_TABLE_16;
                break;
            case DICE_KIND_JUMP_TABLE32:
                kind = Abstract::DataInCodeKind::JUMP_TABLE_32;
                break;
            case DICE_KIND_ABS_JUMP_TABLE32:
                kind = Abstract::DataInCodeKind::ABS_JUMP_TABLE_32;
                break;
            default:
                kind = Abstract::DataInCodeKind::Unknown;
                break;
        }

        addDataInCode(data[i].offset, data[i].length, kind, "macho:dice");
    }

    return true;
}

bool MachoBinary::parse_function_starts(struct load_command *lc) {
    struct linkedit_data_command *cmd = m_data.pointer<linkedit_data_command>(lc);
    if (!cmd) {
        LOG_ERR("Failed to read load command.");
        return false;
    }

    const uint8_t *data_start = m_data.offset<const uint8_t>(cmd->dataoff, cmd->datasize);
    if (!data_start) {
        LOG_ERR("Failed to read load command");
        return false;
    }

    const uint8_t *data_end = &data_start[cmd->datasize];

    uint64_t function_offset = 0;
    for (auto p = data_start; (*p != 0) && (p < data_end);) {
        uint64_t delta = 0;
        uint32_t shift = 0;
        bool more = true;
        do {
            uint8_t byte = *p++;
            delta |= ((byte & 0x7F) << shift);
            shift += 7;

            if (byte < 0x80) {
                function_offset += delta;
                more = false;

                addEntryPoint(function_offset);
            }
        } while (more);
    }

    return true;
}

template<typename T> bool MachoBinary::parse_routines(struct load_command *lc) {
    T * cmd = m_data.pointer<T>(lc);
    if (!cmd) {
        LOG_ERR("Failed to read load command.");
        return false;
    }

    LOG_DEBUG("init_address = 0x%.16llx init_module = 0x%.16llx", (uint64_t ) cmd->init_address, (uint64_t ) cmd->init_module);
    addEntryPoint(offset_from_rva(cmd->init_address));
    return true;
}

template<typename Section_t> bool MachoBinary::parse_section(Section_t *lc) {
    uint32_t section_type = lc->flags & SECTION_TYPE;
    uint32_t section_usr_attr = lc->flags & SECTION_ATTRIBUTES_USR;
    uint32_t section_sys_attr = lc->flags & SECTION_ATTRIBUTES_SYS;

    if (!m_data.offset<void>(lc->offset, lc->size)) {
        LOG_ERR("Invalid section, ignoring.");
        LOG_ERR("  name%16s:%-16s addr=0x%.16llx size=0x%.16llx offset=0x%.8x", lc->segname, lc->sectname, (uint64_t ) lc->addr, (uint64_t ) lc->size, lc->offset);
        return false;
    }

    add_section(lc);

    LOG_INFO("name%16s:%-16s addr=0x%.16llx size=0x%.16llx offset=0x%.8x align=0x%.8x reloff=0x%.8x nreloc=0x%.8x flags=0x%.8x", lc->segname, lc->sectname, (uint64_t ) lc->addr, (uint64_t ) lc->size, lc->offset, lc->align, lc->reloff, lc->nreloc, lc->flags);

    // Handle the traditional sections defined by the mach-o specification.
    bool handled = false;
    switch (section_type) {
        case S_REGULAR:
            handled = parse_regular_section(lc);
            break;

        case S_CSTRING_LITERALS:
            handled = parse_cstring_literals_section(lc);
            break;

        case S_4BYTE_LITERALS:
            handled = parse_4byte_literals(lc);
            break;

        case S_8BYTE_LITERALS:
            handled = parse_8byte_literals(lc);
            break;

        case S_16BYTE_LITERALS:
            handled = parse_16byte_literals(lc);
            break;

        case S_LITERAL_POINTERS:
            handled = parse_literal_pointers(lc);
            break;

        case S_MOD_INIT_FUNC_POINTERS:
            handled = parse_mod_init_func_pointers(lc);
            break;

        case S_MOD_TERM_FUNC_POINTERS:
            handled = parse_mod_term_func_pointers(lc);
            break;

        case S_NON_LAZY_SYMBOL_POINTERS:
            handled = parse_non_lazy_symbol_pointers(lc);
            break;

        case S_LAZY_SYMBOL_POINTERS:
            handled = parse_lazy_symbol_pointers(lc);
            break;

        case S_SYMBOL_STUBS:
            handled = parse_symbol_stubs(lc);
            break;

        case S_INTERPOSING:
            handled = parse_interposing(lc);
            break;

        case S_LAZY_DYLIB_SYMBOL_POINTERS:
            handled = parse_lazy_dylib_symbol_pointers(lc);
            break;

        case S_THREAD_LOCAL_INIT_FUNCTION_POINTERS:
            handled = parse_thread_local_init_function_pointers(lc);
            break;

        case S_COALESCED:
        case S_GB_ZEROFILL:
        case S_DTRACE_DOF:
        case S_THREAD_LOCAL_REGULAR:
        case S_THREAD_LOCAL_ZEROFILL:
        case S_THREAD_LOCAL_VARIABLES:
        case S_THREAD_LOCAL_VARIABLE_POINTERS:
        case S_ZEROFILL:
            handled = true;
            break;

        default:
            LOG_WARN("Unknown section type 0x%.8x, ignoring", section_type);
            break;
    }

    return true;
}

template<typename Segment_t, typename Section_t> bool MachoBinary::parse_segment(struct load_command *lc) {
    auto cmd = m_data.pointer<Segment_t>(lc);
    if (!cmd) {
        LOG_ERR("Failed to read segment.");
        return false;
    }

    uint8_t *s_data = m_data.offset<uint8_t>(cmd->fileoff, cmd->filesize);
    if (!s_data) {
        LOG_ERR("Error reading segment data");
        return false;
    }

    add_segment(cmd);

    LOG_DEBUG("name = %-16s | base = 0x%.16llx | size = 0x%.16llx", cmd->segname, (uint64_t ) cmd->vmaddr, (uint64_t ) cmd->vmsize);

    if (string(cmd->segname) == SEG_TEXT) {
        m_base_address = cmd->vmaddr;
        LOG_DEBUG("m_base_address = %p", (void *) m_base_address);
    }

    size_t s_size = cmd->filesize;
    int s_perm = SegmentPermission::toSegmentPermission(cmd->initprot);

    // Add a segment.
    addSegment(s_data, s_size, s_perm, cmd->vmaddr, cmd->vmsize, cmd->fileoff, cmd->filesize);

    // Get a pointer to the first section.
    auto cur_section = m_data.pointer<Section_t>(cmd + 1);
    if (!cur_section) {
        LOG_ERR("Failed to read section.");
        return false;
    }

    for (unsigned i = 0; i < cmd->nsects; ++i) {
        // Check if the data does not go beyond our loaded memory.
        if (!m_data.valid_pointer<Section_t>(&cur_section[i])) {
            LOG_ERR("Error, the current section (%u) goes beyond the mapped file", i);
            break;
        }

        // Parse the section.
        if (!parse_section<Section_t>(&cur_section[i])) {
            LOG_ERR("Error, could not parse section %u of %u, skipping", i, cmd->nsects);
            continue;
        }
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_regular_section(Section_t *lc) {
    bool handled = false;
    string segname = strlen(lc->segname) > 16 ? string(lc->segname, sizeof(lc->segname)) : string(lc->segname);
    string sectname = strlen(lc->sectname) > 16 ? string(lc->sectname, sizeof(lc->sectname)) : string(lc->sectname);

    LOG_DEBUG("Section: %20s %s size=%zu", segname.c_str(), sectname.c_str(), lc->size);

    if (segname == "__DATA" && sectname == "__interpose")
        handled = parse_interposing(lc);

    if (segname == "__DATA" && sectname == "__cfstring")
        handled = parse_data_cfstring(lc);

    if (segname == "__DATA" && sectname == "__got")
        handled = parse_non_lazy_symbol_pointers(lc);

    if (segname == "__DATA" && sectname == "__la_symbol_ptr")
        handled = parse_lazy_symbol_pointers(lc);

    if (segname == "__KLD" && sectname == "__la_symbol_ptr")
        handled = parse_lazy_symbol_pointers(lc);

    if (segname == "__DATA" && sectname == "__nl_symbol_ptr")
        handled = parse_non_lazy_symbol_pointers(lc);

    if (segname == "__KLD" && sectname == "__nl_symbol_ptr")
        handled = parse_non_lazy_symbol_pointers(lc);

    if (segname == "__DATA" && sectname == "__all_image_info")
        handled = parse_all_image_info(lc);

    if (segname == "__DATA" && sectname == "__ld_symbol_ptr")
        handled = parse_lazy_dylib_symbol_pointers(lc);

    if (segname == "__DATA" && sectname == "__sfi_class_reg")
        handled = parse_sfi_class_reg(lc);

    if (segname == "__DATA" && sectname == "__sysctl_set")
        handled = parse_sysctl_set(lc);

    if (segname == "__DATA" && sectname == "__objc_catlist")
        handled = parse_objc_catlist(lc);

    if (segname == "__DATA" && sectname == "__objc_classlist")
        handled = parse_objc_classlist(lc);

    if (segname == "__DATA" && sectname == "__objc_classrefs")
        handled = parse_objc_classrefs(lc);

    if (segname == "__DATA" && sectname == "__objc_const")
        handled = parse_objc_const(lc);

    if (segname == "__DATA" && sectname == "__objc_data")
        handled = parse_objc_data(lc);

    if (segname == "__DATA" && sectname == "__objc_imageinfo")
        handled = parse_objc_imageinfo(lc);

    if (segname == "__DATA" && sectname == "__objc_ivar")
        handled = parse_objc_ivar(lc);

    if (segname == "__DATA" && sectname == "__objc_msgrefs")
        handled = parse_objc_msgrefs(lc);

    if (segname == "__DATA" && sectname == "__objc_nlcatlist")
        handled = parse_objc_nlcatlist(lc);

    if (segname == "__DATA" && sectname == "__objc_nlclslist")
        handled = parse_objc_nlclslist(lc);

    if (segname == "__DATA" && sectname == "__objc_protolist")
        handled = parse_objc_protolist(lc);

    if (segname == "__DATA" && sectname == "__objc_protorefs")
        handled = parse_objc_protorefs(lc);

    if (segname == "__DATA" && sectname == "__objc_selrefs")
        handled = parse_literal_pointers(lc);

    if (segname == "__DATA" && sectname == "__objc_superrefs")
        handled = parse_objc_superrefs(lc);

    if (segname == "__DATA" && sectname == "__objc_init_func")
        handled = parse_objc_init_func(lc); 

    if (segname == "__OBJC" && sectname == "__message_refs")
        handled = parse_objc_message_refs(lc);

    // XXX: No defined format.
    if (segname == "__OBJC" && sectname == "__cat_cls_meth")
        handled = parse_objc_cat_cls_meth(lc);

    // XXX: No defined format.
    if (segname == "__OBJC" && sectname == "__cat_inst_meth")
        handled = parse_objc_cat_inst_meth(lc);

    if (segname == "__OBJC" && sectname == "__category")
        handled = parse_objc_category(lc);

    if (segname == "__OBJC" && sectname == "__class")
        handled = parse_objc_class(lc);

    if (segname == "__OBJC" && sectname == "__class_ext")
        handled = parse_objc_class_ext(lc);

    if (segname == "__OBJC" && sectname == "__class_vars")
        handled = parse_objc_class_vars(lc);

    if (segname == "__OBJC" && sectname == "__cls_meth")
        handled = parse_objc_cls_meth(lc);

    // XXX: No input file available for RE.
    if (segname == "__OBJC" && sectname == "__cstring_object")
        handled = parse_objc_cstring_object(lc);

    if (segname == "__OBJC" && sectname == "__image_info")
        handled = parse_objc_image_info(lc);

    if (segname == "__OBJC" && sectname == "__inst_meth")
        handled = parse_objc_inst_meth(lc);

    if (segname == "__OBJC" && sectname == "__instance_vars")
        handled = parse_objc_instance_vars(lc);

    if (segname == "__OBJC" && sectname == "__meta_class")
        handled = parse_objc_meta_class(lc);

    if (segname == "__OBJC" && sectname == "__module_info")
        handled = parse_objc_module_info(lc);

    if (segname == "__OBJC" && sectname == "__property")
        handled = parse_objc_property(lc);

    if (segname == "__OBJC" && sectname == "__protocol")
        handled = parse_objc_protocol(lc);

    // XXX: No input file available for RE.
    if (segname == "__OBJC" && sectname == "__protocol_ext")
        handled = parse_objc_protocol_ext(lc);

    // XXX: No input file available for RE.
    if (segname == "__OBJC" && sectname == "__sel_fixup")
        handled = parse_objc_sel_fixup(lc);

    // XXX: No input file available for RE.
    if (segname == "__OBJC" && sectname == "__string_object")
        handled = parse_objc_string_object(lc);

    if (segname == "__OBJC" && sectname == "__symbols")
        handled = parse_objc_symbols(lc);

    if (segname == "__VECTORS" && sectname == "__recover")
        handled = parse_vectors_recover(lc);

    if (segname == "__HIB" && sectname == "__desc")
        handled = parse_hib_desc(lc);

    if (segname == "__DWARF" && sectname == "__apple_names")
        handled = parse_dwarf_apple_names(lc);

    if (segname == "__DWARF" && sectname == "__apple_namespac")
        handled = parse_dwarf_apple_namespac(lc);

    if (segname == "__DWARF" && sectname == "__apple_objc")
        handled = parse_dwarf_apple_objc(lc);

    if (segname == "__DWARF" && sectname == "__apple_types")
        handled = parse_dwarf_apple_types(lc);

    if (segname == "__DWARF" && sectname == "__debug_abbrev")
        handled = parse_dwarf_debug_abbrev(lc);

    if (segname == "__DWARF" && sectname == "__debug_aranges")
        handled = parse_dwarf_debug_aranges(lc);

    if (segname == "__DWARF" && sectname == "__debug_frame")
        handled = parse_dwarf_debug_frame(lc);

    if (segname == "__DWARF" && sectname == "__debug_info")
        handled = parse_dwarf_debug_info(lc);

    if (segname == "__DWARF" && sectname == "__debug_inlined")
        handled = parse_dwarf_debug_inlined(lc);

    if (segname == "__DWARF" && sectname == "__debug_line")
        handled = parse_dwarf_debug_line(lc);

    if (segname == "__DWARF" && sectname == "__debug_loc")
        handled = parse_dwarf_debug_loc(lc);

    if (segname == "__DWARF" && sectname == "__debug_macinfo")
        handled = parse_dwarf_debug_macinfo(lc);

    if (segname == "__DWARF" && sectname == "__debug_pubnames")
        handled = parse_dwarf_debug_pubnames(lc);

    if (segname == "__DWARF" && sectname == "__debug_pubtypes")
        handled = parse_dwarf_debug_pubtypes(lc);

    if (segname == "__DWARF" && sectname == "__debug_ranges")
        handled = parse_dwarf_debug_ranges(lc);

    if (segname == "__DWARF" && sectname == "__debug_str")
        handled = parse_dwarf_debug_str(lc);

    if (segname == "__PRELINK_INFO" && sectname == "__info")
        handled = parse_prelink_info_info(lc);

    if (segname == "__PRELINK_STATE" && sectname == "__kernel")
        handled = parse_prelink_state_kernel(lc);

    if (segname == "__PRELINK_STATE" && sectname == "__kexts")
        handled = parse_prelink_state_kexts(lc);

    if (segname == "__PRELINK_TEXT" && sectname == "__text")
        handled = parse_prelink_text_text(lc);

    return handled;
}

template<typename Section_t> bool MachoBinary::parse_data_cfstring(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    struct CFString {
        pointer_t pointer;
        pointer_t data;
        pointer_t cstr; // rva not offset
        pointer_t size;
    };

    unsigned count = lc->size / sizeof(CFString);
    LOG_DEBUG("Number of entries %d", count);

    auto data = m_data.offset<CFString>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read load command contents.");
        return false;
    }

    for (unsigned i = 0; i < count; i++) {
        auto string_data = m_data.offset<char>(offset_from_rva(data[i].cstr), data[i].size);
        if (!string_data) {
            LOG_ERR("Could not read string data.");
            continue;
        }

        string value = string(string_data, data[i].size);
        LOG_DEBUG("CFString -> 0x%.16llx: %s", (uint64_t ) data[i].cstr, value.c_str());

        addString(value, offset_from_rva(data[i].cstr));
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_all_image_info(Section_t *lc) {
    struct dyld_all_image_infos *images = m_data.offset<dyld_all_image_infos>(lc->offset, lc->size);
    if (!images) {
        LOG_ERR("Could not read image info.");
        return false;
    }

    LOG_DEBUG("Version = %.8x", images->version);
    LOG_DEBUG("Array count = %.8x", images->infoArrayCount);
    return true;
}

template<typename Section_t> bool MachoBinary::parse_sfi_class_reg(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    struct sfi_class_registration {
        uint32_t class_id;
        pointer_t class_continuation; // pointer to a function.
        pointer_t class_name;
        pointer_t class_ledger_name;
    };

    auto registrations = m_data.offset<sfi_class_registration>(lc->offset, lc->size);
    if (!registrations) {
        LOG_ERR("Could not read sfi_class_registration.");
        return false;
    }

    unsigned count = lc->size / sizeof(sfi_class_registration);
    for (unsigned i = 0; i < count; i++) {
        auto class_name = m_data.offset<char>(offset_from_rva(registrations[i].class_name));
        if (!class_name) {
            LOG_ERR("Could not read class name.");
            continue;
        }

        auto class_ledger_name = m_data.offset<char>(offset_from_rva(registrations[i].class_name));
        if (!class_ledger_name) {
            LOG_ERR("Could not read class ledger name.");
            continue;
        }

        LOG_DEBUG("class_id = 0x%.8x", registrations[i].class_id);
        LOG_DEBUG("class_continuation = 0x%.16llx", (uint64_t ) registrations[i].class_continuation);
        LOG_DEBUG("class_ledger_name = %s", class_ledger_name);
        LOG_DEBUG("class_name = %s", class_name);
        LOG_DEBUG("");
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_sysctl_set(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;

    struct sysctl_oid {
        pointer_t oid_parent;
        pointer_t oid_link;
        int oid_number;
        int oid_kind;
        pointer_t oid_arg1;
        int oid_arg2;
        pointer_t oid_name;
        pointer_t oid_handler;
        pointer_t oid_fmt;
    };

    auto data = m_data.offset<pointer_t>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    unsigned count = lc->size / sizeof(pointer_t);

    for (unsigned i = 0; i < count; i++) {
        auto oid = m_data.offset<sysctl_oid>(offset_from_rva(data[i]));
        if (!oid) {
            LOG_ERR("Could not read OID.");
            continue;
        }

        auto oid_name = m_data.offset<char>(offset_from_rva(oid->oid_name));
        auto oid_format = m_data.offset<char>(offset_from_rva(oid->oid_fmt));
        if (!oid_name || !oid_format) {
            LOG_ERR("Could not read OID format/name.");
            continue;
        }

        LOG_DEBUG("Dumping OID at 0x%.16llx", (uint64_t ) data[i]);
        LOG_DEBUG("parent  %.16llx", (uint64_t ) oid->oid_parent);
        LOG_DEBUG("link    %.16llx", (uint64_t ) oid->oid_link);
        LOG_DEBUG("number  %.8llx", (uint64_t ) oid->oid_number);
        LOG_DEBUG("kind    %.8llx", (uint64_t ) oid->oid_kind);
        LOG_DEBUG("arg1    %.16llx", (uint64_t ) oid->oid_arg1);
        LOG_DEBUG("arg2    %.8llx", (uint64_t ) oid->oid_arg2);
        LOG_DEBUG("name    %s", oid_name);
        LOG_DEBUG("handler %.16llx", (uint64_t ) oid->oid_handler);
        LOG_DEBUG("format  %s", oid_format);
        LOG_DEBUG("");
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_catlist(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    auto data = m_data.offset<ObjectiveC::v2::category_t<pointer_t> *>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read category_t list.");
        return false;
    }

    auto count = lc->size / sizeof(*data);
    for (auto i = 0; i < count; ++i) {
        LOG_DEBUG("category_t * -> 0x%.16llx", data[i]);
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_classlist(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    auto data = m_data.offset<ObjectiveC::v2::class_t<pointer_t> *>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read class_t list.");
        return false;
    }

    auto count = lc->size / sizeof(*data);
    for (auto i = 0; i < count; ++i) {
        LOG_DEBUG("class_t * -> 0x%.16llx", data[i]);
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_classrefs(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    auto data = m_data.offset<ObjectiveC::v2::class_t<pointer_t> *>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read class_t list.");
        return false;
    }

    auto count = lc->size / sizeof(*data);
    for (auto i = 0; i < count; ++i) {
        LOG_DEBUG("class_t * -> 0x%.16llx", data[i]);
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_const(Section_t *lc) {
    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_data(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    auto data = m_data.offset<ObjectiveC::v2::class_t<pointer_t>>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read class_t.");
        return false;
    }

    auto count = lc->size / sizeof(*data);
    for (auto i = 0; i < count; ++i) {
        LOG_DEBUG("class_t -> isa=0x%.16llx super=0x%.16llx cache=0x%.16llx vtable=0x%.16llx info=0x%.16llx",
            data[i].isa,
            data[i].superclass,
            data[i].cache,
            data[i].vtable,
            data[i].info
        );
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_imageinfo(Section_t *lc) {
    auto data = m_data.offset<ObjectiveC::v2::image_info_t>(lc->offset);
    if (!data) {
        LOG_ERR("Could not read image_info_t.");
        return false;
    }

    LOG_DEBUG("image_info_t:");
    LOG_DEBUG("  version = 0x%.8x", data->version);
    LOG_DEBUG("  flags   = 0x%.8x", data->flags);

    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_ivar(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    auto data = m_data.offset<ObjectiveC::v2::ivar_t<pointer_t> *>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read ivar_t.");
        return false;
    }

    auto count = lc->size / sizeof(*data);
    for (auto i = 0; i < count; ++i) {
        LOG_DEBUG("ivar_t * -> 0x%.16llx", data[i]);
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_msgrefs(Section_t *lc) {
    auto data = m_data.offset<ObjectiveC::v2::message_ref_t<pointer_t>>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read message_ref_t.");
        return false;
    }

    auto count = lc->size / sizeof(*data);
    for (auto i = 0; i < count; ++i) {
        LOG_DEBUG("message_ref_t:");
        LOG_DEBUG("  imp=0x%.16llx", data[i].imp);
        LOG_DEBUG("  sel=0x%.16llx", data[i].sel);
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_nlcatlist(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    auto data = m_data.offset<ObjectiveC::v2::category_t<pointer_t> *>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read category_t.");
        return false;
    }

    auto count = lc->size / sizeof(*data);
    for (auto i = 0; i < count; i++) {
        LOG_DEBUG("category_t -> 0x%.16llx", data[i]);
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_nlclslist(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    auto data = m_data.offset<ObjectiveC::v2::class_t<pointer_t> *>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read class_t.");
        return false;
    }

    auto count = lc->size / sizeof(*data);
    for (auto i = 0; i < count; ++i) {
        LOG_DEBUG("class_t -> 0x%.16llx", data[i]);
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_protolist(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    auto data = m_data.offset<ObjectiveC::v2::prot_t<pointer_t> *>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read prot_t.");
        return false;
    }

    auto count = lc->size / sizeof(*data);
    for (auto i = 0; i < count; ++i) {
        LOG_DEBUG("prot_t -> 0x%.16llx", data[i]);
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_protorefs(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    auto data = m_data.offset<ObjectiveC::v2::prot_t<pointer_t> *>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read prot_t.");
        return false;
    }

    auto count = lc->size / sizeof(*data);
    for (auto i = 0; i < count; ++i) {
        LOG_DEBUG("prot_t -> 0x%.16llx", data[i]);
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_superrefs(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    auto data = m_data.offset<ObjectiveC::v2::class_t<pointer_t> *>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read class_t.");
        return false;
    }

    auto count = lc->size / sizeof(*data);
    for (auto i = 0; i < count; ++i) {
        LOG_DEBUG("class_t -> 0x%.16llx", data[i]);
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_init_func(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    auto data = m_data.offset<pointer_t>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read pointer_t.");
        return false;
    }

    auto count = lc->size / sizeof(*data);
    for (auto i = 0; i < count; ++i) {
        LOG_DEBUG("ObjC initializer -> 0x%.16llx", (uint64_t ) data[i]);
        addEntryPoint(offset_from_rva(data[i]));
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_vectors_recover(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    auto data = m_data.offset<pointer_t>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    auto count = lc->size / sizeof(*data);
    for (auto i = 0; i < count; ++i) {
        LOG_DEBUG("__VECTOR:recover -> 0x%.16llx", (uint64_t ) data[i]);
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_hib_desc(Section_t *lc) {
    // First page is the master_idt64 -> __desc:FFFFFF8000106000                 public _master_idt64
    // Second page is the master_gdt  -> __desc:FFFFFF8000107000                 public _master_gdt
    using pointer_t = typename Traits<Section_t>::pointer_t;
    auto data = m_data.offset<pointer_t>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    auto count = lc->size / sizeof(*data);
    for (auto i = 0; i < count; ++i) {
        LOG_DEBUG("__HIB:__desc -> 0x%.16llx: 0x%.16llx", (uint64_t ) lc->addr + i * sizeof(pointer_t), (uint64_t ) data[i]);
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_dwarf_apple_names(Section_t *lc) {
    auto data = m_data.offset<char>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    hexdump("SHIT", data, (uint64_t) lc->size);
    return true;
}

template<typename Section_t> bool MachoBinary::parse_dwarf_apple_namespac(Section_t *lc) {
    auto data = m_data.offset<char>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    hexdump("SHIT", data, (uint64_t) lc->size);
    return true;
}

template<typename Section_t> bool MachoBinary::parse_dwarf_apple_objc(Section_t *lc) {
    auto data = m_data.offset<char>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    hexdump("SHIT", data, (uint64_t) lc->size);
    return true;
}

template<typename Section_t> bool MachoBinary::parse_dwarf_apple_types(Section_t *lc) {
    auto data = m_data.offset<char>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    hexdump("SHIT", data, (uint64_t) lc->size);
    return true;
}

template<typename Section_t> bool MachoBinary::parse_dwarf_debug_abbrev(Section_t *lc) {
    auto data = m_data.offset<char>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    hexdump("SHIT", data, (uint64_t) lc->size);
    return true;
}

template<typename Section_t> bool MachoBinary::parse_dwarf_debug_aranges(Section_t *lc) {
    auto data = m_data.offset<char>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    hexdump("SHIT", data, (uint64_t) lc->size);
    return true;
}

template<typename Section_t> bool MachoBinary::parse_dwarf_debug_frame(Section_t *lc) {
    auto data = m_data.offset<char>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    hexdump("SHIT", data, (uint64_t) lc->size);
    return true;
}

template<typename Section_t> bool MachoBinary::parse_dwarf_debug_info(Section_t *lc) {
    auto data = m_data.offset<char>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    hexdump("SHIT", data, (uint64_t) lc->size);
    return true;
}

template<typename Section_t> bool MachoBinary::parse_dwarf_debug_inlined(Section_t *lc) {
    auto data = m_data.offset<char>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    hexdump("SHIT", data, (uint64_t) lc->size);
    return true;
}

template<typename Section_t> bool MachoBinary::parse_dwarf_debug_line(Section_t *lc) {
    auto data = m_data.offset<char>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    hexdump("SHIT", data, (uint64_t) lc->size);
    return true;
}

template<typename Section_t> bool MachoBinary::parse_dwarf_debug_loc(Section_t *lc) {
    auto data = m_data.offset<char>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    hexdump("SHIT", data, (uint64_t) lc->size);
    return true;
}

template<typename Section_t> bool MachoBinary::parse_dwarf_debug_macinfo(Section_t *lc) {
    auto data = m_data.offset<char>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    hexdump("SHIT", data, (uint64_t) lc->size);
    return true;
}

template<typename Section_t> bool MachoBinary::parse_dwarf_debug_pubnames(Section_t *lc) {
    auto data = m_data.offset<char>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    hexdump("SHIT", data, (uint64_t) lc->size);
    return true;
}

template<typename Section_t> bool MachoBinary::parse_dwarf_debug_pubtypes(Section_t *lc) {
    auto data = m_data.offset<char>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    hexdump("SHIT", data, (uint64_t) lc->size);
    return true;
}

template<typename Section_t> bool MachoBinary::parse_dwarf_debug_ranges(Section_t *lc) {
    auto data = m_data.offset<char>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    hexdump("SHIT", data, (uint64_t) lc->size);
    return true;
}

template<typename Section_t> bool MachoBinary::parse_dwarf_debug_str(Section_t *lc) {
    auto data = m_data.offset<char>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    hexdump("SHIT", data, (uint64_t) lc->size);
    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_message_refs(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    auto data = m_data.offset<ObjectiveC::v1::message_ref_t<pointer_t>>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read message_ref_t.");
        return false;
    }

    auto count = lc->size / sizeof(*data);
    for (auto i = 0; i < count; ++i) {
        LOG_DEBUG("message_ref_t -> sel=0x%.16llx", data[i].sel);
    }

    return true;    
}

template<typename Section_t> bool MachoBinary::parse_objc_cat_cls_meth(Section_t *lc) {
    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_cat_inst_meth(Section_t *lc) {
    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_category(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    auto data = m_data.offset<ObjectiveC::v1::category_struct_t<pointer_t>>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read __objc_category_struct.");
        return false;
    }

    auto count = lc->size / sizeof(*data);
    for (auto i = 0; i < count; ++i) {
        LOG_DEBUG("__objc_category_struct");
        LOG_DEBUG("  category_name=0x%.16llx", data[i].category_name);
        LOG_DEBUG("  class_name=0x%.16llx", data[i].class_name);
        LOG_DEBUG("  instance_methods=0x%.16llx", data[i].instance_methods);
        LOG_DEBUG("  class_methods=0x%.16llx", data[i].class_methods);
        LOG_DEBUG("  protocols=0x%.16llx", data[i].protocols);
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_class(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    auto data = m_data.offset<ObjectiveC::v1::class_struct_ext_t<pointer_t>>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read __objc_class_struct_ext.");
        return false;
    }

    auto count = lc->size / sizeof(*data);
    for (auto i = 0; i < count; ++i) {
        LOG_DEBUG("__objc_class_struct_ext");
        LOG_DEBUG("  isa=0x%.16llx", data[i].isa);
        LOG_DEBUG("  super_class=0x%.16llx", data[i].super_class);
        LOG_DEBUG("  name=0x%.16llx", data[i].name);
        LOG_DEBUG("  version=0x%.16llx", data[i].version);
        LOG_DEBUG("  info=0x%.16llx", data[i].info);
        LOG_DEBUG("  instance_size=0x%.16llx", data[i].instance_size);
        LOG_DEBUG("  ivars=0x%.16llx", data[i].ivars);
        LOG_DEBUG("  methods=0x%.16llx", data[i].methods);
        LOG_DEBUG("  cache=0x%.16llx", data[i].cache);
        LOG_DEBUG("  protocols=0x%.16llx", data[i].protocols);
        LOG_DEBUG("  ivar_layout=0x%.16llx", data[i].ivar_layout);
        LOG_DEBUG("  ext=0x%.16llx", data[i].ext);
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_class_ext(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    auto data = m_data.offset<ObjectiveC::v1::class_ext_t<pointer_t>>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read __objc_class_ext.");
        return false;
    }

    auto count = lc->size / sizeof(*data);
    for (auto i = 0; i < count; ++i) {
        LOG_DEBUG("__objc_class_ext");
        LOG_DEBUG("  size=0x%.16llx", data[i].size);
        LOG_DEBUG("  weak_ivar_layout=0x%.16llx", data[i].weak_ivar_layout);
        LOG_DEBUG("  property_lists=0x%.16llx", data[i].property_lists);
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_class_vars(Section_t *lc) {
    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_cls_meth(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    auto cur_off = lc->offset;
    while (cur_off < (lc->offset + lc->size)) {
        auto data = m_data.offset<ObjectiveC::v1::method_list_t<pointer_t>>(cur_off, lc->size);
        if (!data) {
            LOG_ERR("Could not read __objc_method_list.");
            return false;
        }

        LOG_DEBUG("__objc_method_list:");
        LOG_DEBUG("  unk=0x%.8x count=0x%.8x", data->unk, data->count);

        for (auto i = 0 ; i < data->count; i++) {
            LOG_DEBUG("  __objc_method:");
            LOG_DEBUG("    method_name=0x%.16llx", data->elements[i].method_name);
            LOG_DEBUG("    method_types=0x%.16llx", data->elements[i].method_types);
            LOG_DEBUG("    method_imp=0x%.16llx", data->elements[i].method_imp);
        }

        cur_off += sizeof(*data) + data->count * sizeof(data->elements[0]);
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_cstring_object(Section_t *lc) {
    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_image_info(Section_t *lc) {
    auto data = m_data.offset<ObjectiveC::v1::image_info_t>(lc->offset);
    if (!data) {
        LOG_ERR("Could not read image_info_t.");
        return false;
    }

    LOG_DEBUG("image_info_t");
    LOG_DEBUG("  version = 0x%.8x", data->version);
    LOG_DEBUG("  flags = 0x%.8x", data->flags);

    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_inst_meth(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    auto cur_off = lc->offset;
    while (cur_off < (lc->offset + lc->size)) {
        LOG_DEBUG("cur_off=0x%.8x", cur_off);

        auto data = m_data.offset<ObjectiveC::v1::method_list_t<pointer_t>>(cur_off, lc->size);
        if (!data) {
            LOG_ERR("Could not read __objc_method_list.");
            return false;
        }

        LOG_DEBUG("__objc_method_list:");
        LOG_DEBUG("  unk=0x%.8x count=0x%.8x", data->unk, data->count);

        for (auto i = 0 ; i < data->count; i++) {
            LOG_DEBUG("  __objc_method:");
            LOG_DEBUG("    method_name=0x%.16llx", data->elements[i].method_name);
            LOG_DEBUG("    method_types=0x%.16llx", data->elements[i].method_types);
            LOG_DEBUG("    method_imp=0x%.16llx", data->elements[i].method_imp);
        }

        cur_off += sizeof(*data) + data->count * sizeof(data->elements[0]);
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_instance_vars(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    auto cur_off = lc->offset;
    while (cur_off < (lc->offset + lc->size)) {
        LOG_DEBUG("cur_off=0x%.8x", cur_off);

        auto data = m_data.offset<ObjectiveC::v1::instance_vars_struct_list_t<pointer_t>>(cur_off, lc->size);
        if (!data) {
            LOG_ERR("Could not read __objc_instance_vars_struct_list.");
            return false;
        }

        LOG_DEBUG("__objc_instance_vars_struct_list:");
        LOG_DEBUG("  count=0x%.8x", data->count);

        for (auto i = 0 ; i < data->count; i++) {
            LOG_DEBUG("  __objc_instance_vars_struct:");
            LOG_DEBUG("    name=0x%.16llx", data->elements[i].name);
            LOG_DEBUG("    type=0x%.16llx", data->elements[i].type);
        }

        cur_off += sizeof(*data) + data->count * sizeof(data->elements[0]);
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_meta_class(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    auto data = m_data.offset<ObjectiveC::v1::class_struct_ext_t<pointer_t>>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    auto count = lc->size / sizeof(*data);
    for (auto i = 0; i < count; i++) {
        LOG_DEBUG("__objc_class_struct_ext:");
        LOG_DEBUG("  isa=0x%.16llx", data[i].isa);
        LOG_DEBUG("  super_class=0x%.16llx", data[i].super_class);
        LOG_DEBUG("  name=0x%.16llx", data[i].name);
        LOG_DEBUG("  version=%d", data[i].version);
        LOG_DEBUG("  info=%d", data[i].info);
        LOG_DEBUG("  instance_size=%d", data[i].instance_size);
        LOG_DEBUG("  ivars=0x%.16llx", data[i].ivars);
        LOG_DEBUG("  methods=0x%.16llx", data[i].methods);
        LOG_DEBUG("  cache=%d", data[i].cache);
        LOG_DEBUG("  protocols=0x%.16llx", data[i].protocols);
        LOG_DEBUG("  ivar_layout=0x%.16llx", data[i].ivar_layout);
        LOG_DEBUG("  ext=0x%.16llx", data[i].ext);
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_module_info(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    auto data = m_data.offset<ObjectiveC::v1::module_info_struct_t<pointer_t>>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    auto count = lc->size / sizeof(*data);
    for (auto i = 0; i < count; i++) {
        LOG_DEBUG("__objc_module_info_struct:");
        LOG_DEBUG("  version=0x%.16llx", data[i].version);
        LOG_DEBUG("  size=0x%.16llx", data[i].size);
        LOG_DEBUG("  name=0x%.16llx", data[i].name);
        LOG_DEBUG("  symbols=0x%.16llx", data[i].symbols);
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_property(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    auto cur_off = lc->offset;
    while (cur_off < (lc->offset + lc->size)) {
        LOG_DEBUG("cur_off=0x%.8x", cur_off);

        auto data = m_data.offset<ObjectiveC::v1::property_list_t<pointer_t>>(cur_off, lc->size);
        if (!data) {
            LOG_ERR("Could not read __objc_property_list.");
            return false;
        }

        LOG_DEBUG("__objc_property_list:");
        LOG_DEBUG("  size=0x%.8x count=0x%.8x", data->size, data->count);
        assert(data->size == sizeof(data->elements[0]));

        for (auto i = 0 ; i < data->count; i++) {
            LOG_DEBUG("  __objc_property:");
            LOG_DEBUG("    name=0x%.16llx", data->elements[i].name);
            LOG_DEBUG("    attributes=0x%.16llx", data->elements[i].attributes);
        }

        cur_off += sizeof(*data) + data->count * sizeof(data->elements[0]);
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_protocol(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    auto data = m_data.offset<ObjectiveC::v1::protocol_struct_t<pointer_t>>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    auto count = lc->size / sizeof(*data);
    for (auto i = 0; i < count; i++) {
        LOG_DEBUG("__objc_protocol_struct:");
        LOG_DEBUG("  isa=0x%.16llx", data[i].isa);
        LOG_DEBUG("  protocol_name=0x%.16llx", data[i].protocol_name);
        LOG_DEBUG("  protocol_list=0x%.16llx", data[i].protocol_list);
        LOG_DEBUG("  instance_methods=0x%.16llx", data[i].instance_methods);
        LOG_DEBUG("  class_methods=0x%.16llx", data[i].class_methods);
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_protocol_ext(Section_t *lc) {
    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_sel_fixup(Section_t *lc) {
    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_string_object(Section_t *lc) {
    return true;
}

template<typename Section_t> bool MachoBinary::parse_objc_symbols(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    auto cur_off = lc->offset;
    while (cur_off < (lc->offset + lc->size)) {
        LOG_DEBUG("cur_off=0x%.8x", cur_off);

        auto data = m_data.offset<ObjectiveC::v1::symtab_struct_t<pointer_t>>(cur_off, lc->size);
        if (!data) {
            LOG_ERR("Could not read __objc_symtab_struct.");
            return false;
        }

        LOG_DEBUG("__objc_symtab_struct:");
        LOG_DEBUG("  sel_ref_cnt=0x%.16llx", data->sel_ref_cnt);
        LOG_DEBUG("  refs=0x%.16llx", data->refs);
        LOG_DEBUG("  cls_def_count=0x%.16llx", data->cls_def_count);
        LOG_DEBUG("  cat_def_count=0x%.16llx", data->cat_def_count);

        for (auto i = 0 ; i < data->cls_def_count; i++) {
            LOG_DEBUG("    name=0x%.16llx", data->defs[i]);
        }

        cur_off += sizeof(*data) + data->cls_def_count * sizeof(data->defs[0]);
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_prelink_info_info(Section_t *lc) {
    auto data = m_data.offset<char>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    hexdump("SHIT", data, (uint64_t) lc->size);
    return true;
}

template<typename Section_t> bool MachoBinary::parse_prelink_state_kernel(Section_t *lc) {
    auto data = m_data.offset<char>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    hexdump("SHIT", data, (uint64_t) lc->size);
    return true;
}

template<typename Section_t> bool MachoBinary::parse_prelink_state_kexts(Section_t *lc) {
    auto data = m_data.offset<char>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    hexdump("SHIT", data, (uint64_t) lc->size);
    return true;
}

template<typename Section_t> bool MachoBinary::parse_prelink_text_text(Section_t *lc) {
    // Though targetted at the OS X platform, information gleaned from these projects are
    // relevant to iOS as well. Specifically, we can see that the __PRELINK_TEXT segment
    // is simply a concatenation of all the kext Mach-O objects. There is no delimiter
    // specified for these objects, but we can identify the start of a new object from
    // the Mach-O object header magic
    auto data = m_data.offset<char>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    hexdump("SHIT", data, (uint64_t) lc->size);
    return true;
}

template<typename Section_t> bool MachoBinary::parse_cstring_literals_section(Section_t *lc) {
    auto start = m_data.offset<const char>(lc->offset, lc->size);
    if (!start) {
        return false;
    }

    const char *end = start + lc->size;
    const char *cur_byte = start;
    const char *cur_string = cur_byte;
    auto cur_off = lc->offset;

    while (cur_byte < end) {
        if (!*cur_byte) {
            LOG_DEBUG("String: %s @ %.8x", cur_string, cur_off);

            addString(string(cur_string), cur_off);
            addComment(cur_off, "CString");

            cur_string = ++cur_byte;
            cur_off++;
            continue;
        }

        cur_off++;
        cur_byte++;
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_4byte_literals(Section_t *lc) {
    if (auto start = m_data.offset<uint32_t>(lc->offset, lc->size)) {
        for (unsigned i = 0; i < lc->size / sizeof(uint32_t); ++i) {
            LOG_DEBUG("Four byte literal: off=0x%.8x 0x%.8x", lc->offset + (i * 4), start[i]);
            addComment(lc->offset + (i * 4), "uint32_t literal");
        }
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_8byte_literals(Section_t *lc) {
    if (auto start = m_data.offset<uint64_t>(lc->offset, lc->size)) {
        for (unsigned i = 0; i < lc->size / sizeof(uint64_t); ++i) {
            LOG_DEBUG("Eight byte literal: 0x%.16llx", start[i]);
            addComment(lc->offset + (i * 8), "uint64_t literal");
        }
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_16byte_literals(Section_t *lc) {
    if (auto start = m_data.offset<uint32_t>(lc->offset, lc->size)) {
        for (unsigned i = 0; i < lc->size / sizeof(uint32_t); i += 4) {
            LOG_DEBUG("Sixteen byte literal: 0x%.8x 0x%.8x 0x%.8x 0x%.8x", start[i], start[i + 1], start[i + 2], start[i + 3]);
            addComment(lc->offset + (i * 16), "uint128_t literal");
        }
    }

    return true;
}

// Table of pointers to strings.
template<typename Section_t> bool MachoBinary::parse_literal_pointers(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    if (auto start = m_data.offset<pointer_t>(lc->offset, lc->size)) {
        for (unsigned i = 0; i < lc->size / sizeof(pointer_t); ++i) {
            auto name = m_data.offset<char>(offset_from_rva(start[i]));
            if (!name) {
                LOG_ERR("Could not read POINTER name.");
                continue;
            }

            LOG_DEBUG("POINTER: 0x%.16llx -> 0x%.16llx (%s)", (uint64_t ) lc->addr + i * sizeof(pointer_t), (uint64_t ) start[i], name);
        }
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_mod_init_func_pointers(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    for (pointer_t initializer = lc->addr; initializer < lc->addr + lc->size; initializer += sizeof(pointer_t)) {
        auto val = m_data.offset<pointer_t>(initializer);
        if (!val) {
            LOG_ERR("Could not read initializer val.");
            continue;
        }

        LOG_DEBUG("  Initializer at: %p -> %p", (void * ) (initializer + m_base_address), (void *) *val);

        addEntryPoint(*val);
        addComment(*val, "Initializer");
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_mod_term_func_pointers(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    for (pointer_t terminator = lc->addr; terminator < lc->addr + lc->size; terminator += sizeof(pointer_t)) {
        auto val = m_data.offset<pointer_t>(terminator);
        if (!val) {
            LOG_ERR("Could not read terminator val.");
            continue;
        }

        LOG_DEBUG("  Terminator at: %p -> %p", (void * ) (terminator + m_base_address), (void *) *val);

        addEntryPoint(*val);
        addComment(*val, "Terminator");
    }

    return true;
}

// This is the place where there will be a pointer to a symbol.
// US  -> 0000000100002000 0x0000000f NONLAZY dyld_stub_binder
// IDA -> 0000000100002000 dyld_stub_binder_ptr dq offset dyld_stub_binder
template<typename Section_t> bool MachoBinary::parse_non_lazy_symbol_pointers(Section_t *lc) {
    if (!m_dysymtab_command) {
        LOG_WARN("Dynamic symbol table is outside the binary mapped file.");
        return false;
    }

    using pointer_t = typename Traits<Section_t>::pointer_t;

    uint32_t indirect_offset = lc->reserved1;
    uint32_t *indirect_symbol_table = m_data.offset<uint32_t>(
        m_dysymtab_command->indirectsymoff, m_dysymtab_command->nindirectsyms * sizeof(uint32_t));

    if (!indirect_symbol_table) {
        LOG_ERR("Failed to retrieve the indirect symbol table.");
        return false;
    }

    uint32_t count = lc->size / sizeof(pointer_t);

    for (unsigned i = 0; i < count; ++i) {
        if ((indirect_offset + i) >= m_dysymtab_command->nindirectsyms) {
            LOG_ERR("Invalid indirect symbol entry.");
            return false;
        }

        unsigned symbol_index = indirect_symbol_table[indirect_offset + i];
        pointer_t addr = lc->addr + i * sizeof(pointer_t);
        string symbol_name;

        switch (symbol_index) {
            case INDIRECT_SYMBOL_ABS:
                symbol_name = "INDIRECT_SYMBOL_ABS";
                break;
            case INDIRECT_SYMBOL_LOCAL:
                symbol_name = "INDIRECT_SYMBOL_LOCAL";
                break;
            case INDIRECT_SYMBOL_ABS | INDIRECT_SYMBOL_LOCAL:
                symbol_name = "INDIRECT_SYMBOL_ABS | INDIRECT_SYMBOL_LOCAL";
                break;
            default:
                symbol_name = "invalid";
                if (symbol_index < m_symbol_table_size) {
                    auto idx = m_symbol_table[symbol_index].n_un.n_strx;
                    if (idx < m_string_table_size) {
                        symbol_name = &m_string_table[idx];
                    }
                }

                break;
        }

        auto value = m_data.offset<pointer_t>(offset_from_rva(addr));
        LOG_DEBUG("%p %p 0x%.8x NONLAZY %s\n", (void *) addr, (void *) *value, symbol_index, symbol_name.c_str());
        addComment(offset_from_rva(addr), "NONLAZY -> " + symbol_name);
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_lazy_symbol_pointers(Section_t *lc) {
    if (!m_dysymtab_command) {
        LOG_WARN("Dynamic symbol table is outside the binary mapped file.");
        return false;
    }

    using pointer_t = typename Traits<Section_t>::pointer_t;
    uint32_t indirect_offset = lc->reserved1;
    uint32_t *indirect_symbol_table =
        m_data.offset<uint32_t>(m_dysymtab_command->indirectsymoff, m_dysymtab_command->nindirectsyms
            * sizeof(uint32_t));

    if (!indirect_symbol_table) {
        LOG_ERR("Failed to retrieve the indirect symbol table.");
        return false;
    }

    LOG_DEBUG("lazy symbol pointers:");

    auto data = m_data.offset<pointer_t>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    auto count = lc->size / sizeof(pointer_t);
    for (unsigned i = 0; i < count; i++) {
        if ((indirect_offset + i) >= m_dysymtab_command->nindirectsyms) {
            LOG_ERR("Invalid indirect symbol entry.");
            return false;
        }

        unsigned symbol_index = indirect_symbol_table[indirect_offset + i];
        pointer_t addr = lc->addr + i * sizeof(pointer_t);
        string symbol_name = "invalid";
        if (symbol_index < m_symbol_table_size) {
            auto idx = m_symbol_table[symbol_index].n_un.n_strx;
            if (idx < m_string_table_size) {
                symbol_name = &m_string_table[idx];
            }
        }

        LOG_DEBUG("0x%.16llx 0x%.16llx LAZY %s\n", (uint64_t) addr, (uint64_t) data[i], symbol_name.c_str());

        addEntryPoint(offset_from_rva(data[i]));
        addComment(offset_from_rva(addr), "LAZY_SYMBOL -> " + symbol_name);
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_symbol_stubs(Section_t *lc) {
    // A symbol_stubs section contains symbol stubs, which are sequences of machine instructions
    // (all the same size) used for lazily binding undefined function calls at runtime.
    unsigned indirect_table_offset = lc->reserved1;
    unsigned element_size = lc->reserved2;
    if (!element_size) {
        LOG_ERR("Malformed symbol stubs table.");
        return false;
    }

    unsigned element_count = lc->size / element_size;

    for (unsigned i = 0; i < element_count; i++) {
        LOG_DEBUG("Stub at 0x%.16llx", (uint64_t ) lc->addr + i * element_size);
        addEntryPoint(offset_from_rva(lc->addr + i * element_size));
        addComment(offset_from_rva(lc->addr + i * element_size), "SYMBOL_STUB");
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_interposing(Section_t *lc) {
    // TODO:
    // The 'to' address will always be zero as it needs to be
    // resolved manually by us.
    using pointer_t = typename Traits<Section_t>::pointer_t;
    struct interposer {
        pointer_t from, to;
    };

    auto data = m_data.offset<interposer>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    auto count = lc->size / sizeof(interposer);
    for (unsigned i = 0; i < count; i++) {
        LOG_DEBUG("Interposer from 0x%.16llx to 0x%.16llx", (uint64_t ) data[i].from, (uint64_t ) data[i].to);
        addEntryPoint(offset_from_rva(data[i].from));
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_lazy_dylib_symbol_pointers(Section_t *lc) {
    if (!m_dysymtab_command) {
        LOG_WARN("Dynamic symbol table is outside the binary mapped file.");
        return false;
    }

    using pointer_t = typename Traits<Section_t>::pointer_t;
    uint32_t indirect_offset = lc->reserved1;
    uint32_t *indirect_symbol_table =
        m_data.offset<uint32_t>(m_dysymtab_command->indirectsymoff, m_dysymtab_command->nindirectsyms
            * sizeof(uint32_t));

    if (!indirect_symbol_table) {
        LOG_ERR("Failed to retrieve the indirect symbol table.");
        return false;
    }

    auto data = m_data.offset<pointer_t>(lc->offset, lc->size);
    if (!data) {
        LOG_ERR("Could not read data.");
        return false;
    }

    auto count = lc->size / sizeof(pointer_t);
    for (unsigned i = 0; i < count; i++) {
        if ((indirect_offset + i) >= m_dysymtab_command->nindirectsyms) {
            LOG_ERR("Invalid indirect symbol entry.");
            return false;
        }

        unsigned symbol_index = indirect_symbol_table[indirect_offset + i];
        pointer_t addr = lc->addr + i * sizeof(pointer_t);
        string symbol_name = "invalid";
        if (symbol_index < m_symbol_table_size) {
            auto idx = m_symbol_table[symbol_index].n_un.n_strx;
            if (idx < m_string_table_size) {
                symbol_name = &m_string_table[idx];
            }
        }

        LOG_DEBUG("0x%.16llx 0x%.16llx parse_lazy_dylib_symbol_pointers %s\n", (uint64_t) addr, (uint64_t) data[i], symbol_name.c_str());
    }

    return true;
}

template<typename Section_t> bool MachoBinary::parse_thread_local_init_function_pointers(Section_t *lc) {
    using pointer_t = typename Traits<Section_t>::pointer_t;
    const size_t count = lc->size / sizeof(pointer_t);
    for (unsigned i = 0; i < count; i++) {
        LOG_DEBUG("PEPE at: 0x%.16llx", (uint64_t ) lc->addr + i * sizeof(pointer_t));
        addEntryPoint(offset_from_rva(lc->addr + i * sizeof(pointer_t)));
    }

    return true;
}

bool MachoBinary::parse_symtab(struct load_command *lc) {
    struct symtab_command *cmd = m_data.pointer<symtab_command>(lc);
    if (!cmd) {
        LOG_ERR("Failed to read symtab load command.");
        return false;
    }    

    if (!m_symbol_table) {
        LOG_ERR("Invalid symbol table.");
        return false;
    }

    if (!m_string_table) {
        LOG_ERR("Invalid string table.");
        return false;
    }

    for (unsigned i = 0; i < cmd->nsyms; ++i) {
        if (i >= m_symbol_table_size) {
            LOG_ERR("Symbol table index (%u) is outside the symbol table.", i);
            continue;
        }

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

        // Get the symbol description.
        string desc = "";
        if (m_symbol_table[i].n_desc & N_WEAK_REF)
            desc += "N_WEAK_REF";

        if (m_symbol_table[i].n_desc & N_WEAK_DEF)
            desc += "N_WEAK_DEF";

        if (m_symbol_table[i].n_desc & N_ARM_THUMB_DEF)
            desc += "N_ARM_THUMB_DEF";

        if (m_symbol_table[i].n_desc & N_SYMBOL_RESOLVER)
            desc += "N_SYMBOL_RESOLVER";

        LOG_DEBUG("symbol->n_desc = %s (%.2x)", desc.c_str(), m_symbol_table[i].n_desc);

        addSymbol(string(&m_string_table[idx]), m_symbol_table[i].n_value);
    }

    return true;
}

bool MachoBinary::parse_dysymtab(struct load_command *lc) {
    // Symbols used by the dynamic linker.
    // This is an additional segment that requires a prior symtab load command.
    struct dysymtab_command *cmd = m_data.pointer<dysymtab_command>(lc);
    if (!cmd) {
        LOG_ERR("Failed to read dysymtab load command.");
        return false;
    }

    if (!m_dysymtab_command) {
        LOG_ERR("Invalid dynamic symbol table");
        return false;
    }

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
        if (idx >= m_string_table_size) {
            LOG_ERR("String table entry %u is outside the binary mapped file", idx);
            break;
        }

        LOG_DEBUG("Local symbol:");
        LOG_DEBUG("  symbol->name    = %s", idx ? &m_string_table[idx] : "(null)");
        LOG_DEBUG("  symbol->n_sect  = 0x%.2x", m_symbol_table[i].n_sect);
        LOG_DEBUG("  symbol->n_value = 0x%.16llx\n", m_symbol_table[i].n_value);

        addSymbol(string(&m_string_table[idx]), m_symbol_table[i].n_value);
    }

    // External defined symbols.
    for (unsigned i = cmd->iextdefsym; i < cmd->nextdefsym; ++i) {
        if (i >= m_symbol_table_size) {
            LOG_ERR("Symbol table entry %u is outside the binary mapped file", i);
            break;
        }

        unsigned idx = m_symbol_table[i].n_un.n_strx;
        if (idx >= m_string_table_size) {
            LOG_ERR("String table entry %u is outside the binary mapped file", idx);
            break;
        }

        LOG_DEBUG("External defined symbol:");
        LOG_DEBUG("  symbol->name    = %s", idx ? &m_string_table[idx] : "(null)");
        LOG_DEBUG("  symbol->n_sect  = 0x%.2x", m_symbol_table[i].n_sect);
        LOG_DEBUG("  symbol->n_value = 0x%.16llx\n", m_symbol_table[i].n_value);

        addSymbol(string(&m_string_table[idx]), m_symbol_table[i].n_value);
    }

    // External undefined symbols.
    for (unsigned i = cmd->iundefsym; i < cmd->nundefsym; ++i) {
        if (i >= m_symbol_table_size) {
            LOG_ERR("Symbol table entry %u is outside the binary mapped file", i);
            break;
        }

        unsigned idx = m_symbol_table[i].n_un.n_strx;
        if (idx >= m_string_table_size) {
            LOG_ERR("String table entry %u is outside the binary mapped file", idx);
            break;
        }

        LOG_DEBUG("External undefined symbol:");
        LOG_DEBUG("  symbol->name    = %s", idx ? &m_string_table[idx] : "(null)");
        LOG_DEBUG("  symbol->n_sect  = 0x%.2x", m_symbol_table[i].n_sect);
        LOG_DEBUG("  symbol->n_value = 0x%.16llx\n", m_symbol_table[i].n_value);

        addSymbol(string(&m_string_table[idx]), m_symbol_table[i].n_value);
    }

    LOG_DEBUG("tocoff       = 0x%.8x ntoc        = 0x%.8x modtaboff      = 0x%.8x nmodtab       = 0x%.8x", cmd->tocoff, cmd->ntoc, cmd->modtaboff, cmd->nmodtab);

    LOG_DEBUG("extrefsymoff = 0x%.8x nextrefsyms = 0x%.8x indirectsymoff = 0x%.8x nindirectsyms = 0x%.8x", cmd->extrefsymoff, cmd->nextrefsyms, cmd->indirectsymoff, cmd->nindirectsyms);

    LOG_DEBUG("extreloff    = 0x%.8x nextrel     = 0x%.8x locreloff      = 0x%.8x nlocrel       = 0x%.8x ", cmd->extreloff, cmd->nextrel, cmd->locreloff, cmd->nlocrel);

    return true;
}

static void debug_thread_state_arm_32(thread_state_arm_32 &ts) {
    stringstream ss;
    for (unsigned i = 0; i < sizeof(ts.r); i++) {
        ss << "r" << i << " = " << (void *) ts.r[i] << " ";
    }

    ss << "sp = " << (void *) ts.sp;
    ss << "lr = " << (void *) ts.lr;
    ss << "pc = " << (void *) ts.pc;
    ss << "cpsr = " << (void *) ts.cpsr;
    ss << "far = " << (void *) ts.far;
    ss << "esr = " << (void *) ts.esr;
    ss << "exception = " << (void *) ts.exception;

    LOG_DEBUG("Dump: %s", ss.str().c_str());
}

static void debug_thread_state_arm_64(thread_state_arm_64 &ts) {
    stringstream ss;
    for (unsigned i = 0; i < sizeof(ts.x); i++) {
        ss << "r" << i << " = " << (void *) ts.x[i] << " ";
    }

    ss << "fp = " << (void *) ts.fp;
    ss << "lr = " << (void *) ts.lr;
    ss << "sp = " << (void *) ts.sp;
    ss << "pc = " << (void *) ts.pc;
    ss << "cpsr = " << (void *) ts.cpsr;
    ss << "reserved = " << (void *) ts.reserved;
    ss << "far = " << (void *) ts.far;
    ss << "esr = " << (void *) ts.esr;
    ss << "exception = " << (void *) ts.exception;

    LOG_DEBUG("Dump: %s", ss.str().c_str());
}

static void debug_thread_state_x86_32(thread_state_x86_32 &ts) {
    stringstream ss;
    ss << "eax = " << (void *) ts.eax;
    ss << "ebx = " << (void *) ts.ebx;
    ss << "ecx = " << (void *) ts.ecx;
    ss << "edx = " << (void *) ts.edx;
    ss << "edi = " << (void *) ts.edi;
    ss << "esi = " << (void *) ts.esi;
    ss << "ebp = " << (void *) ts.ebp;
    ss << "esp = " << (void *) ts.esp;
    ss << "ss = " << (void *) ts.ss;
    ss << "eflags = " << (void *) ts.eflags;
    ss << "eip = " << (void *) ts.eip;
    ss << "cs = " << (void *) ts.cs;
    ss << "ds = " << (void *) ts.ds;
    ss << "es = " << (void *) ts.es;
    ss << "fs = " << (void *) ts.fs;
    ss << "gs = " << (void *) ts.gs;
    LOG_DEBUG("Dump: %s", ss.str().c_str());
}

static void debug_thread_state_x86_64(thread_state_x86_64 &ts) {
    stringstream ss;
    ss << "rax = " << (void *) ts.rax;
    ss << "rbx = " << (void *) ts.rbx;
    ss << "rcx = " << (void *) ts.rcx;
    ss << "rdx = " << (void *) ts.rdx;
    ss << "rdi = " << (void *) ts.rdi;
    ss << "rsi = " << (void *) ts.rsi;
    ss << "rbp = " << (void *) ts.rbp;
    ss << "rsp = " << (void *) ts.rsp;
    ss << "r8 = " << (void *) ts.r8;
    ss << "r9 = " << (void *) ts.r9;
    ss << "r10 = " << (void *) ts.r10;
    ss << "r11 = " << (void *) ts.r11;
    ss << "r12 = " << (void *) ts.r12;
    ss << "r13 = " << (void *) ts.r13;
    ss << "r14 = " << (void *) ts.r14;
    ss << "r15 = " << (void *) ts.r15;
    ss << "rip = " << (void *) ts.rip;
    ss << "rflags = " << (void *) ts.rflags;
    ss << "cs = " << (void *) ts.cs;
    ss << "fs = " << (void *) ts.fs;
    ss << "gs = " << (void *) ts.gs;
    LOG_DEBUG("Dump: %s", ss.str().c_str());
}

bool MachoBinary::parse_thread(struct load_command *lc) {
    struct thread_command *cmd = m_data.pointer<thread_command>(lc);
    if (!cmd) {
        LOG_ERR("Error loading segment from load command");
        return false;
    }

    // Skip to the contents.
    uint32_t *contents = m_data.pointer<uint32_t>(cmd + 1, sizeof(uint32_t) * 2);
    if (!contents) {
        LOG_ERR("Error loading segment from load command");
        return false;
    }

    // After the thread_command we will find two uint32_t's.
    uint32_t flavor = contents[0];
    uint32_t count = contents[1];

    LOG_DEBUG("flavor = 0x%.8x count = 0x%.8x", flavor, count);
    if (!count) {
        LOG_INFO("Count is zero which means there is no thread state.");
        return true;
    }

    switch (cputype()) {
        case CPU_TYPE_ARM:
        {
            LOG_DEBUG("sizeof(m_thread_state.arm_32) = %lu", sizeof(m_thread_state.arm_32));
            auto ctx = m_data.pointer<thread_state_arm_32>(&contents[2]);
            if (!ctx) {
                LOG_ERR("Error reading ARM32 thread state.");
                break;
            }

            m_thread_state.arm_32 = *ctx;
            debug_thread_state_arm_32(m_thread_state.arm_32);
            break;
        }
        case CPU_TYPE_ARM64:
        {
            LOG_DEBUG("sizeof(m_thread_state.arm_64) = %lu", sizeof(m_thread_state.arm_64));
            auto ctx = m_data.pointer<thread_state_arm_64>(&contents[2]);
            if (!ctx) {
                LOG_ERR("Error reading ARM64 thread state.");
                break;
            }

            m_thread_state.arm_64 = *ctx;
            debug_thread_state_arm_64(m_thread_state.arm_64);
            break;
        }
        case CPU_TYPE_X86:
        {
            LOG_DEBUG("sizeof(m_thread_state.x86_32) = %lu", sizeof(m_thread_state.x86_32));
            auto ctx = m_data.pointer<thread_state_x86_32>(&contents[2]);
            if (!ctx) {
                LOG_ERR("Error reading x86_32 thread state.");
                break;
            }

            m_thread_state.x86_32 = *ctx;
            debug_thread_state_x86_32(m_thread_state.x86_32);
            break;
        }
        case CPU_TYPE_X86_64:
        {
            LOG_DEBUG("sizeof(m_thread_state.x86_64) = %lu", sizeof(m_thread_state.x86_64));
            auto ctx = m_data.pointer<thread_state_x86_64>(&contents[2]);
            if (!ctx) {
                LOG_ERR("Error reading x86_64 thread state.");
                break;
            }

            m_thread_state.x86_64 = *ctx;
            debug_thread_state_x86_64(m_thread_state.x86_64);
            break;
        }
        default:
        {
            break;
        }
    }

    return true;
}

bool MachoBinary::parse_id_dylib(struct load_command *lc) {
    struct dylib_command *cmd = m_data.pointer<dylib_command>(lc);
    if (!cmd) {
        LOG_ERR("Error loading segment from load command");
        return false;
    }

    // Get the name of the this library.
    char *name = m_data.pointer<char>(reinterpret_cast<char *>(cmd) + cmd->dylib.name.offset);
    if (!name) {
        LOG_ERR("Error reading library name.");
        return false;
    }

    LOG_DEBUG("Current library: name=%-40s tstamp=0x%.8x ver=0x%.8x compat=0x%.8x", name, cmd->dylib.timestamp, cmd->dylib.current_version, cmd->dylib.compatibility_version);

    addLibrary(string(name));

    return true;
}

bool MachoBinary::parse_dylib(struct load_command *lc) {
    struct dylib_command *cmd = m_data.pointer<dylib_command>(lc);
    if (!cmd) {
        LOG_ERR("Error loading segment from load command");
        return false;
    }

    // Get the name of the imported library.
    auto tmp = m_data.pointer<char>(reinterpret_cast<char *>(cmd) + cmd->dylib.name.offset);
    if (!tmp) {
        LOG_ERR("Error reading dylib name.");
        return false;
    }

    string name = string(tmp);
    LOG_DEBUG("Imported library: name=%-40s tstamp=0x%.8x ver=0x%.8x compat=0x%.8x", name.c_str(), cmd->dylib.timestamp, cmd->dylib.current_version, cmd->dylib.compatibility_version);

    string base_filename = name;
    if (auto idx = name.find_last_of("/\\")) {
        base_filename = name.substr(idx + 1);
    }

    m_imported_libs.push_back(base_filename);

    addLibrary(name);

    return true;
}

bool MachoBinary::parse_main(struct load_command *lc) {
    struct entry_point_command *cmd = m_data.pointer<entry_point_command>(lc);
    if (!cmd) {
        LOG_ERR("Error loading segment from load command");
        return false;
    }

    LOG_DEBUG("entryoff=0x%.16llx stacksize=0x%.16llx", cmd->entryoff, cmd->stacksize);

    addEntryPoint(cmd->entryoff);

    return true;
}

bool MachoBinary::parse_unixthread(struct load_command *lc) {
    struct thread_command *cmd = m_data.pointer<thread_command>(lc);
    if (!cmd) {
        LOG_ERR("Error loading segment from load command");
        return false;
    }

    // Skip to the contents.
    uint32_t *contents = m_data.pointer<uint32_t>(cmd + 1);
    if (!contents) {
        LOG_ERR("Error getting load command contents.");
        return false;
    }

    // After the thread_command we will find two uint32_t's.
    uint32_t flavor = contents[0];
    uint32_t count = contents[1];

    LOG_DEBUG("flavor = 0x%.8x count = 0x%.8x", flavor, count);

    // After these we will have the arch specific thread information.
    return true;
}

template<typename T> bool MachoBinary::parse_encryption_info(struct load_command *lc) {
    m_encrypted = true;

    // This commands identify a range of the file that is encrypted.
    T *cmd = m_data.pointer<T>(lc);
    if (!cmd) {
        LOG_ERR("Error loading segment from load command");
        return false;
    }

    LOG_DEBUG("cryptoff = 0x%.8x cryptsize = 0x%.8x cryptid = 0x%.8x", cmd->cryptoff, cmd->cryptsize, cmd->cryptid);
    return true;
}

template<> void MachoBinary::add_segment<segment_command>(segment_command *cmd) {
    m_segments_32.push_back(*cmd);
}

template<> void MachoBinary::add_segment<segment_command_64>(segment_command_64 *cmd) {
    m_segments_64.push_back(*cmd);
}

template<> void MachoBinary::add_section<section>(section *cmd) {
    m_sections_32.push_back(*cmd);
}

template<> void MachoBinary::add_section<section_64>(section_64 *cmd) {
    m_sections_64.push_back(*cmd);
}

string MachoBinary::segment_name(unsigned index) {
    if (is64()) {
        return (index < m_segments_64.size()) ? m_segments_64[index].segname : "invalid";
    }

    return (index < m_segments_32.size()) ? m_segments_32[index].segname : "invalid";
}

string MachoBinary::section_name(unsigned index, uint64_t address) {
    if (is64()) {
        for (auto section : m_sections_64) {
            if (address >= section.addr && address < (section.addr + section.size)) {
                return section.sectname;
            }
        }
    } else {
        for (auto section : m_sections_32) {
            if (address >= section.addr && address < (section.addr + section.size)) {
                return section.sectname;
            }
        }
    }

    return "invalid";
}

uint64_t MachoBinary::segment_address(unsigned index) {
    if (is64()) {
        return (index < m_segments_64.size()) ? m_segments_64[index].vmaddr : 0;
    }

    return (index < m_segments_32.size()) ? m_segments_32[index].vmaddr : 0;
}

bool MachoBinary::parse_dyld_info_exports(const uint8_t *export_start, const uint8_t *export_end) {
    struct Node;
    struct Edge {
        Node *next;
        string label;
    };

    struct Node {
        vector<Edge *> m_children;
        unsigned m_terminal_size;
        const uint8_t *m_data;
        uintptr_t m_offset;
    };

    // Start from offset zero.
    Node *init = new Node();
    init->m_offset = 0;

    // Setup the initial node.
    queue<Node *> working_set;
    working_set.push(init);

    const uint8_t* cur_byte = export_start;

    // Process all the nodes.
    while (!working_set.empty() && cur_byte < export_end) {
        // Get a Node from the queue.
        Node *cur_node = working_set.front();
        working_set.pop();

        // Get a pointer to the data.
        cur_byte = export_start + cur_node->m_offset;
        if (cur_byte >= export_end) {
            return false;
        }

        cur_node->m_data = cur_byte;

        // Read the terminal size.
        cur_node->m_terminal_size = read_terminal_size(cur_byte, export_end);
        if (cur_byte >= export_end) {
            return false;
        }

        // Skip the symbol properties to get to the children.
        cur_byte += cur_node->m_terminal_size;
        if (cur_byte >= export_end) {
            return false;
        }

        uint8_t child_count = *cur_byte;
        cur_byte++;
        if (cur_byte >= export_end) {
            return false;
        }


        for (unsigned i = 0; i < child_count; i++) {
            // Current child label.
            const char *edge_label = (const char *) cur_byte;

            // Skip the node label.
            cur_byte += strlen(edge_label) + 1;
            if (cur_byte >= export_end) {
                return false;
            }

            // Get the offset of the node.
            uintptr_t node_offset = read_uleb128(cur_byte, export_end);
            if (cur_byte >= export_end) {
                return false;
            }

            Node *new_node = new Node();
            new_node->m_offset = node_offset;

            Edge *new_edge = new Edge();
            new_edge->next = new_node;
            new_edge->label = edge_label;

            cur_node->m_children.push_back(new_edge);
            working_set.push(new_node);
        }
    }

    function<void(Node *, vector<string> &vec)> dfs_printer = [&dfs_printer](Node *node, vector<string> &vec) {
        if (node->m_terminal_size) {
            string joined;
            for(const auto &el : vec) {
                joined += el;
            }

            LOG_DEBUG("label = %s", joined.c_str());
        }

        for(Edge *edge : node->m_children) {
            vec.push_back(edge->label);
            dfs_printer(edge->next, vec);
            vec.pop_back();
        }
    };

    vector<string> vec;
    dfs_printer(init, vec);

#define EXPORT_SYMBOL_FLAGS_KIND_MASK               0x03
#define EXPORT_SYMBOL_FLAGS_KIND_REGULAR            0x00
#define EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL       0x01
#define EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION         0x04
#define EXPORT_SYMBOL_FLAGS_REEXPORT                0x08
#define EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER       0x10

    return true;
}

static string rebaseTypeName(uint8_t type) {
    switch (type) {
        case REBASE_TYPE_POINTER:
            return "pointer";
        case REBASE_TYPE_TEXT_ABSOLUTE32:
            return "text abs32";
        case REBASE_TYPE_TEXT_PCREL32:
            return "text rel32";
    }

    return "!!unknown!!";
}

static string bindTypeName(uint8_t type) {
    switch (type) {
        case BIND_TYPE_POINTER:
            return "pointer";
        case BIND_TYPE_TEXT_ABSOLUTE32:
            return "text abs32";
        case BIND_TYPE_TEXT_PCREL32:
            return "text rel32";
    }
    return "!!unknown!!";
}

bool MachoBinary::parse_dyld_info_rebase(const uint8_t *start, const uint8_t *end) {
    auto p = start;
    auto done = false;

    uint8_t type = 0;
    uint8_t seg_index = 0;
    uint64_t seg_offset = 0;
    int64_t addend = 0;
    uint32_t count;
    uint32_t skip;
    uint64_t seg_addr = 0;
    string seg_name = "??", sec_name = "???";
    string type_name = "??";
    uintptr_t address = 0;

    LOG_DEBUG("rebase information (from compressed dyld info):\n");
    LOG_DEBUG("segment section          address             type\n");

    while (!done && p < end) {
        uint8_t imm = *p & REBASE_IMMEDIATE_MASK;
        uint8_t opcode = *p & REBASE_OPCODE_MASK;
        p++;

        switch (opcode) {
            case REBASE_OPCODE_DONE:
                done = true;
                break;

            case REBASE_OPCODE_SET_TYPE_IMM:
                type = imm;
                type_name = rebaseTypeName(type);
                break;

            case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                seg_index = imm;
                seg_offset = read_uleb128(p, end);
                seg_addr = segment_address(seg_index);
                seg_name = segment_name(seg_index);
                break;

            case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
                seg_offset += imm * pointer_size();
                break;

            case REBASE_OPCODE_ADD_ADDR_ULEB:
                seg_offset += read_uleb128(p, end);
                break;

            case REBASE_OPCODE_DO_REBASE_IMM_TIMES:
                for (int i = 0; i < imm; ++i) {
                    sec_name = section_name(seg_index, seg_addr + seg_offset);
                    LOG_DEBUG("%-7s %-16s 0x%08llX  %s REBASE_OPCODE_DO_REBASE_IMM_TIMES\n", seg_name.c_str(), sec_name.c_str(), seg_addr
                        + seg_offset, type_name.c_str());
                    seg_offset += pointer_size();
                }
                break;

            case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
                sec_name = section_name(seg_index, seg_addr + seg_offset);
                LOG_DEBUG("%-7s %-16s 0x%08llX  %s REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB\n", seg_name.c_str(), sec_name.c_str(), seg_addr
                    + seg_offset, type_name.c_str());
                seg_offset += read_uleb128(p, end) + pointer_size();
                break;

            case REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
                count = read_uleb128(p, end);
                for (uint32_t i = 0; i < count; ++i) {
                    sec_name = section_name(seg_index, seg_addr + seg_offset);
                    LOG_DEBUG("%-7s %-16s 0x%08llX  %s REBASE_OPCODE_DO_REBASE_ULEB_TIMES\n", seg_name.c_str(), sec_name.c_str(), seg_addr
                        + seg_offset, type_name.c_str());
                    seg_offset += pointer_size();
                }
                break;

            case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
                count = read_uleb128(p, end);
                skip = read_uleb128(p, end);
                for (uint32_t i = 0; i < count; ++i) {
                    sec_name = section_name(seg_index, seg_addr + seg_offset);
                    LOG_DEBUG("%-7s %-16s 0x%08llX  %s REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB\n", seg_name.c_str(), sec_name.c_str(), seg_addr
                        + seg_offset, type_name.c_str());
                    seg_offset += skip + pointer_size();
                }
                break;

            default:
                LOG_ERR("Invalid rebase opcode! (%.2x)", opcode);
                break;
        }
    }

    return true;
}

string MachoBinary::ordinal_name(int libraryOrdinal) {
    switch (libraryOrdinal) {
        case BIND_SPECIAL_DYLIB_SELF:
            return "this-image";
        case BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE:
            return "main-executable";
        case BIND_SPECIAL_DYLIB_FLAT_LOOKUP:
            return "flat-namespace";
    }

    if (libraryOrdinal < BIND_SPECIAL_DYLIB_FLAT_LOOKUP || libraryOrdinal > m_imported_libs.size())
        return "invalid";

    return m_imported_libs[libraryOrdinal - 1];
}

uint64_t MachoBinary::offset_from_rva(uint64_t rva) {
    if (is32()) {
        for (auto seg : m_segments_32) {
            if (rva >= seg.vmaddr && rva < seg.vmaddr + seg.vmsize) {
                return (rva - seg.vmaddr) + seg.fileoff;
            }
        }
    }

    for (auto seg : m_segments_64) {
        if (rva >= seg.vmaddr && rva < seg.vmaddr + seg.vmsize) {
            return (rva - seg.vmaddr) + seg.fileoff;
        }
    }

    return 0;
}

uint64_t MachoBinary::rva_from_offset(uint64_t offset) {
    if (is32()) {
        for (auto seg : m_segments_32) {
            if (offset >= seg.fileoff && offset < seg.fileoff + seg.filesize) {
                return (offset - seg.fileoff) + seg.vmaddr;
            }
        }

        return 0;
    }

    for (auto seg : m_segments_64) {
        if (offset >= seg.fileoff && offset < seg.fileoff + seg.filesize) {
            return (offset - seg.fileoff) + seg.vmaddr;
        }
    }

    return 0;
}

bool MachoBinary::parse_dyld_info_binding(const uint8_t *start, const uint8_t *end) {
    LOG_DEBUG("bind information:\n");
    LOG_DEBUG("segment section          address        type    addend dylib            symbol\n");
    const uint8_t* p = start;

    uint8_t type = 0;
    uint8_t segIndex = 0;
    uint64_t segOffset = 0;
    string symbolName = "";
    string fromDylib = "??";
    int libraryOrdinal = 0;
    int64_t addend = 0;
    uint32_t count;
    uint32_t skip;
    uint64_t segStartAddr = 0;
    string segName = "??";
    string typeName = "??";
    string weak_import = "";
    bool done = false;

    while (!done && (p < end)) {
        uint8_t immediate = *p & BIND_IMMEDIATE_MASK;
        uint8_t opcode = *p & BIND_OPCODE_MASK;
        ++p;

        switch (opcode) {
            case BIND_OPCODE_DONE:
                done = true;
                break;

            case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                libraryOrdinal = immediate;
                fromDylib = ordinal_name(libraryOrdinal);
                break;

            case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                libraryOrdinal = read_uleb128(p, end);
                fromDylib = ordinal_name(libraryOrdinal);
                break;

            case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                // the special ordinals are negative numbers
                if (immediate == 0)
                    libraryOrdinal = 0;
                else {
                    int8_t signExtended = BIND_OPCODE_MASK | immediate;
                    libraryOrdinal = signExtended;
                }
                fromDylib = ordinal_name(libraryOrdinal);
                break;
            case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                symbolName = (char*) p;
                while (*p != '\0')
                    ++p;
                ++p;
                if ((immediate & BIND_SYMBOL_FLAGS_WEAK_IMPORT) != 0)
                    weak_import = " (weak import)";
                else
                    weak_import = "";
                break;
            case BIND_OPCODE_SET_TYPE_IMM:
                type = immediate;
                typeName = bindTypeName(type);
                break;
            case BIND_OPCODE_SET_ADDEND_SLEB:
                addend = read_sleb128(p, end);
                break;
            case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                segIndex = immediate;
                segStartAddr = segment_address(segIndex);
                segName = segment_name(segIndex);
                segOffset = read_uleb128(p, end);
                break;
            case BIND_OPCODE_ADD_ADDR_ULEB:
                segOffset += read_uleb128(p, end);
                break;
            case BIND_OPCODE_DO_BIND:
                LOG_DEBUG("%-7s %-16s 0x%08llX %10s  %5lld %-16s %s%s\n", segName.c_str(), section_name(segIndex, segStartAddr
                    + segOffset).c_str(), segStartAddr + segOffset, typeName.c_str(), addend, fromDylib.c_str(), symbolName.c_str(), weak_import.c_str());

                segOffset += pointer_size();
                break;
            case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
                LOG_DEBUG("%-7s %-16s 0x%08llX %10s  %5lld %-16s %s%s\n", segName.c_str(), section_name(segIndex, segStartAddr
                    + segOffset).c_str(), segStartAddr + segOffset, typeName.c_str(), addend, fromDylib.c_str(), symbolName.c_str(), weak_import.c_str());

                segOffset += read_uleb128(p, end) + pointer_size();
                break;
            case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
                LOG_DEBUG("%-7s %-16s 0x%08llX %10s  %5lld %-16s %s%s\n", segName.c_str(), section_name(segIndex, segStartAddr
                    + segOffset).c_str(), segStartAddr + segOffset, typeName.c_str(), addend, fromDylib.c_str(), symbolName.c_str(), weak_import.c_str());

                segOffset += immediate * pointer_size() + pointer_size();
                break;
            case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
                count = read_uleb128(p, end);
                skip = read_uleb128(p, end);
                for (uint32_t i = 0; i < count; ++i) {
                    LOG_DEBUG("%-7s %-16s 0x%08llX %10s  %5lld %-16s %s%s\n", segName.c_str(), section_name(segIndex, segStartAddr
                        + segOffset).c_str(), segStartAddr + segOffset, typeName.c_str(), addend, fromDylib.c_str(), symbolName.c_str(), weak_import.c_str());

                    segOffset += skip + pointer_size();
                }
                break;
            default:
                LOG_ERR("bad bind opcode %d", *p);
        }
    }

    return true;
}

bool MachoBinary::parse_dyld_info_weak_binding(const uint8_t *start, const uint8_t *end) {
    LOG_DEBUG("weak binding information:\n");
    LOG_DEBUG("segment section          address       type     addend symbol\n");
    const uint8_t* p = start;

    uint8_t type = 0;
    uint8_t segIndex = 0;
    uint64_t segOffset = 0;
    string symbolName = "";

    int64_t addend = 0;
    uint32_t count;
    uint32_t skip;
    uint64_t segStartAddr = 0;
    string segName = "??";
    string typeName = "??";
    bool done = false;
    while (!done && (p < end)) {
        uint8_t immediate = *p & BIND_IMMEDIATE_MASK;
        uint8_t opcode = *p & BIND_OPCODE_MASK;
        ++p;
        switch (opcode) {
            case BIND_OPCODE_DONE:
                done = true;
                break;
            case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                symbolName = (char*) p;
                while (*p != '\0')
                    ++p;
                ++p;
                if ((immediate & BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION) != 0)
                    LOG_DEBUG("                                       strong          %s\n", symbolName.c_str());
                break;
            case BIND_OPCODE_SET_TYPE_IMM:
                type = immediate;
                typeName = bindTypeName(type);
                break;
            case BIND_OPCODE_SET_ADDEND_SLEB:
                addend = read_sleb128(p, end);
                break;
            case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                segIndex = immediate;
                segStartAddr = segment_address(segIndex);
                segName = segment_name(segIndex);
                segOffset = read_uleb128(p, end);
                break;
            case BIND_OPCODE_ADD_ADDR_ULEB:
                segOffset += read_uleb128(p, end);
                break;
            case BIND_OPCODE_DO_BIND:
                LOG_DEBUG("%-7s %-16s 0x%08llX %10s   %5lld %s\n", segName.c_str(), section_name(segIndex, segStartAddr
                    + segOffset).c_str(), segStartAddr + segOffset, typeName.c_str(), addend, symbolName.c_str());

                segOffset += pointer_size();
                break;
            case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
                LOG_DEBUG("%-7s %-16s 0x%08llX %10s   %5lld %s\n", segName.c_str(), section_name(segIndex, segStartAddr
                    + segOffset).c_str(), segStartAddr + segOffset, typeName.c_str(), addend, symbolName.c_str());

                segOffset += read_uleb128(p, end) + pointer_size();
                break;
            case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
                LOG_DEBUG("%-7s %-16s 0x%08llX %10s   %5lld %s\n", segName.c_str(), section_name(segIndex, segStartAddr
                    + segOffset).c_str(), segStartAddr + segOffset, typeName.c_str(), addend, symbolName.c_str());

                segOffset += immediate * pointer_size() + pointer_size();
                break;
            case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
                count = read_uleb128(p, end);
                skip = read_uleb128(p, end);
                for (uint32_t i = 0; i < count; ++i) {
                    LOG_DEBUG("%-7s %-16s 0x%08llX %10s   %5lld %s\n", segName.c_str(), section_name(segIndex, segStartAddr
                        + segOffset).c_str(), segStartAddr + segOffset, typeName.c_str(), addend, symbolName.c_str());

                    segOffset += skip + pointer_size();
                }
                break;
            default:
                LOG_ERR("unknown weak bind opcode %d", *p);
        }
    }

    return true;
}

bool MachoBinary::parse_dyld_info_lazy_binding(const uint8_t *start, const uint8_t *end) {
    LOG_DEBUG("lazy binding information (from lazy_bind part of dyld info):\n");
    LOG_DEBUG("segment section          address    index  dylib            symbol\n");

    uint8_t type = BIND_TYPE_POINTER;
    uint8_t segIndex = 0;
    uint64_t segOffset = 0;
    string symbolName = "";

    string fromDylib = "??";
    int libraryOrdinal = 0;
    int64_t addend = 0;
    uint32_t lazy_offset = 0;
    uint64_t segStartAddr = 0;
    string segName = "??";
    string typeName = "??";
    string weak_import = "";
    for (const uint8_t* p = start; p < end;) {
        uint8_t immediate = *p & BIND_IMMEDIATE_MASK;
        uint8_t opcode = *p & BIND_OPCODE_MASK;
        ++p;
        switch (opcode) {
            case BIND_OPCODE_DONE:
                lazy_offset = p - start;
                break;
            case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                libraryOrdinal = immediate;
                fromDylib = ordinal_name(libraryOrdinal);
                break;
            case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                libraryOrdinal = read_uleb128(p, end);
                fromDylib = ordinal_name(libraryOrdinal);
                break;
            case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                // the special ordinals are negative numbers
                if (immediate == 0)
                    libraryOrdinal = 0;
                else {
                    int8_t signExtended = BIND_OPCODE_MASK | immediate;
                    libraryOrdinal = signExtended;
                }
                fromDylib = ordinal_name(libraryOrdinal);
                break;
            case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                symbolName = (char*) p;
                while (*p != '\0')
                    ++p;
                ++p;
                if ((immediate & BIND_SYMBOL_FLAGS_WEAK_IMPORT) != 0)
                    weak_import = " (weak import)";
                else
                    weak_import = "";
                break;
            case BIND_OPCODE_SET_TYPE_IMM:
                type = immediate;
                typeName = bindTypeName(type);
                break;
            case BIND_OPCODE_SET_ADDEND_SLEB:
                addend = read_sleb128(p, end);
                break;
            case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                segIndex = immediate;
                segStartAddr = segment_address(segIndex);
                segName = segment_name(segIndex);
                segOffset = read_uleb128(p, end);
                break;
            case BIND_OPCODE_ADD_ADDR_ULEB:
                segOffset += read_uleb128(p, end);
                break;
            case BIND_OPCODE_DO_BIND:
                LOG_DEBUG("%-7s %-16s 0x%08llX 0x%04X %-16s %s%s\n", segName.c_str(), section_name(segIndex, segStartAddr
                    + segOffset).c_str(), segStartAddr + segOffset, lazy_offset, fromDylib.c_str(), symbolName.c_str(), weak_import.c_str());

                segOffset += pointer_size();
                break;
            default:
                LOG_ERR("bad lazy bind opcode %d", *p);
        }
    }

    return true;
}

bool MachoBinary::parse_code_signature(struct load_command *lc) {
    m_signed = true;
    return true;
}

bool MachoBinary::parse_dyld_environment(struct load_command *lc) {
    struct dylinker_command *cmd = m_data.pointer<dylinker_command>(lc);
    if (!cmd) {
        LOG_ERR("Error loading segment from load command");
        return false;
    }

    auto tmp = m_data.pointer<char>(reinterpret_cast<char *>(cmd) + cmd->name.offset);
    if (!tmp) {
        LOG_ERR("Error reading environment variable.");
        return false;
    }

    string env(tmp);
    m_environment.push_back(env);
    LOG_DEBUG("New environment string: %s", env.c_str());
    return true;
}

bool MachoBinary::parse_id_dylinker(struct load_command *lc) {
    struct dylinker_command *cmd = m_data.pointer<dylinker_command>(lc);
    if (!cmd) {
        LOG_ERR("Error loading segment from load command");
        return false;
    }

    auto tmp = m_data.pointer<char>(reinterpret_cast<char *>(cmd) + cmd->name.offset);
    if (!tmp) {
        LOG_ERR("Error reading linker name.");
        return false;
    }

    string linker(tmp);
    m_linker = linker;
    LOG_DEBUG("Linker: %s", linker.c_str());
    return true;
}

bool MachoBinary::parse_rpath(struct load_command *lc) {
    struct rpath_command *cmd = m_data.pointer<rpath_command>(lc);
    if (!cmd) {
        LOG_ERR("Error loading segment from load command");
        return false;
    }

    auto tmp = m_data.pointer<char>(reinterpret_cast<char *>(cmd) + cmd->path.offset);
    if (!tmp) {
        LOG_ERR("Error reading rpath.");
        return false;
    }

    string rpath(tmp);
    m_dynamic_linker_paths.push_back(rpath);
    LOG_DEBUG("RPATH: %s", rpath.c_str());
    return true;
}

bool MachoBinary::parse_linker_option(struct load_command *lc) {
    struct linker_option_command *cmd = m_data.pointer<linker_option_command>(lc);
    if (!cmd) {
        LOG_ERR("Error loading segment from load command");
        return false;
    }

    const char *strings = m_data.pointer<const char>(cmd + 1, cmd->cmdsize);
    if (!strings) {
        LOG_ERR("Error reading strings.");
        return false;
    }

    for (unsigned i = 0; i < cmd->count; i++) {
        auto string_size = strnlen(strings, cmd->cmdsize);
        if (!string_size || string_size == cmd->cmdsize) {
            LOG_ERR("Invalid string.");
            break;
        }

        LOG_INFO("Linker command: %u %p %s", string_size, strings, strings);

        strings += string_size + 1;
        m_linker_commands.push_back(string(strings));
    }

    return true;
}

bool MachoBinary::parse_sub_library(struct load_command *lc) {
    struct sub_library_command *cmd = m_data.pointer<sub_library_command>(lc);
    if (!cmd) {
        LOG_ERR("Error loading segment from load command");
        return false;
    }

    auto tmp = m_data.pointer<char>(reinterpret_cast<char *>(cmd) + cmd->sub_library.offset);
    if (!tmp) {
        LOG_ERR("Error reading sub library name.");
        return false;
    }

    string sub_library(tmp);
    LOG_DEBUG("sub_library: %s", sub_library.c_str());
    return true;
}

bool MachoBinary::parse_sub_client(struct load_command *lc) {
    struct sub_client_command *cmd = m_data.pointer<sub_client_command>(lc);
    if (!cmd) {
        LOG_ERR("Error loading segment from load command");
        return false;
    }

    auto tmp = m_data.pointer<char>(reinterpret_cast<char *>(cmd) + cmd->client.offset);
    if (!tmp) {
        LOG_ERR("Error reading sub client name.");
        return false;
    }

    string sub_client(tmp);
    LOG_DEBUG("sub_client: %s", sub_client.c_str());
    return true;
}

bool MachoBinary::parse_sub_framework(struct load_command *lc) {
    struct sub_framework_command *cmd = m_data.pointer<sub_framework_command>(lc);
    if (!cmd) {
        LOG_ERR("Error loading segment from load command");
        return false;
    }

    auto tmp = m_data.pointer<char>(reinterpret_cast<char *>(cmd) + cmd->umbrella.offset);
    if (!tmp) {
        LOG_ERR("Error reading sub framework name.");
        return false;
    }

    string sub_framework(tmp);
    LOG_DEBUG("sub_framework: %s", sub_framework.c_str());
    return true;
}

bool MachoBinary::parse_sub_umbrella(struct load_command *lc) {
    struct sub_umbrella_command *cmd = m_data.pointer<sub_umbrella_command>(lc);
    if (!cmd) {
        LOG_ERR("Error loading segment from load command");
        return false;
    }

    auto tmp = m_data.pointer<char>(reinterpret_cast<char *>(cmd) + cmd->sub_umbrella.offset);
    if (!tmp) {
        LOG_ERR("Error reading sub umbrella name.");
        return false;
    }

    string sub_umbrella(tmp);
    LOG_DEBUG("sub_umbrella: %s", sub_umbrella.c_str());
    return true;
}

bool MachoBinary::parse_uuid(struct load_command *lc) {
    struct uuid_command *cmd = m_data.pointer<uuid_command>(lc);
    if (!cmd) {
        LOG_ERR("Error loading segment from load command");
        return false;
    }    

    char buffer[16];
    stringstream ss;
    for(unsigned i = 0; i < sizeof(cmd->uuid); i++) {
        sprintf(buffer, "%.2x", cmd->uuid[i]);
        ss << buffer;
    }

    m_unique_id = ss.str();

    LOG_DEBUG("uuid_command: %s", ss.str().c_str());
    return true;
}

bool MachoBinary::parse_source_version(struct load_command *lc) {
    struct source_version_command *cmd = m_data.pointer<source_version_command>(lc);
    if (!cmd) {
        LOG_ERR("Error loading segment from load command");
        return false;
    }

    stringstream ss;
    ss << (cmd->version >> 40) << '.'
        << ((cmd->version >> 30) & 0x3ff) << '.'
        << ((cmd->version >> 20) & 0x3ff) << '.'
        << ((cmd->version >> 10) & 0x3ff) << '.'
        << (cmd->version & 0x3ff);

    m_version = ss.str();
    LOG_DEBUG("Version: %s", m_version.c_str());
    return true;
}

bool MachoBinary::parse_dyld_info(struct load_command *lc) {
    struct dyld_info_command *cmd = m_data.pointer<dyld_info_command>(lc);
    if (!cmd) {
        LOG_ERR("Error loading segment from load command");
        return false;
    }


    LOG_DEBUG("Rebase information: rebase_off = 0x%.8x rebase_size = 0x%.8x", cmd->rebase_off, cmd->rebase_size);
    LOG_DEBUG("Binding information: bind_off = 0x%.8x bind_size = 0x%.8x", cmd->bind_off, cmd->bind_size);
    LOG_DEBUG("Weak binding information: weak_bind_off = 0x%.8x weak_bind_size = 0x%.8x", cmd->weak_bind_off, cmd->weak_bind_size);
    LOG_DEBUG("Lazy binding information: lazy_bind_off = 0x%.8x lazy_bind_size = 0x%.8x", cmd->lazy_bind_off, cmd->lazy_bind_size);
    LOG_DEBUG("Export information: export_off = 0x%.8x export_size = 0x%.8x", cmd->export_off, cmd->export_size);

    // Parse rebase information.
    if (auto start = m_data.offset<const uint8_t>(cmd->rebase_off, cmd->rebase_size)) {
        auto end = start + cmd->rebase_size;
        parse_dyld_info_rebase(start, end);
    }

    // Parse binding information.
    if (auto start = m_data.offset<const uint8_t>(cmd->bind_off, cmd->bind_size)) {
        auto end = start + cmd->bind_size;
        parse_dyld_info_binding(start, end);
    }

    // Parse weak binding information.
    if (auto start = m_data.offset<const uint8_t>(cmd->weak_bind_off, cmd->weak_bind_size)) {
        auto end = start + cmd->weak_bind_size;
        parse_dyld_info_weak_binding(start, end);
    }

    // Parse lazy binding information.
    if (auto start = m_data.offset<const uint8_t>(cmd->lazy_bind_off, cmd->lazy_bind_size)) {
        auto end = start + cmd->lazy_bind_size;
        parse_dyld_info_lazy_binding(start, end);
    }

    // Parse the exports information.
    if (auto start = m_data.offset<const uint8_t>(cmd->export_off, cmd->export_size)) {
        auto end = start + cmd->export_size;
        parse_dyld_info_exports(start, end);
    }

    return true;
}
