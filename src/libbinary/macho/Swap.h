/*
 * Swap.h
 *
 *  Created on: Jul 16, 2015
 *      Author: anon
 */

#ifndef SRC_LIBBINARY_MACHO_SWAP_H_
#define SRC_LIBBINARY_MACHO_SWAP_H_

#include "AbstractBinary.h"

#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>
#include <mach-o/ranlib.h>

void swap(uint64_t *data);
void swap(uint32_t *data);
void swap(uint16_t *data);
void swap(struct fat_header *data);
void swap(struct fat_arch *data, uint32_t nfat_arch);
void swap(struct mach_header *data);
void swap(struct mach_header_64 *data);
void swap(struct load_command *data);
void swap(struct segment_command *data);
void swap(struct segment_command_64 *data);
void swap(struct section *data, uint32_t nsects);
void swap(struct section_64 *data, uint32_t nsects);
void swap(struct symtab_command *data);
void swap(struct dysymtab_command *data);
void swap(struct symseg_command *data);
void swap(struct fvmlib_command *data);
void swap(struct dylib_command *data);
void swap(struct sub_framework_command *data);
void swap(struct sub_umbrella_command *data);
void swap(struct sub_library_command *data);
void swap(struct sub_client_command *data);
void swap(struct prebound_dylib_command *data);
void swap(struct dylinker_command *data);
void swap(struct fvmfile_command *data);
void swap(struct thread_command *data);
void swap(struct ident_command *data);
void swap(struct routines_command *data);
void swap(struct routines_command_64 *data);
void swap(struct twolevel_hints_command *data);
void swap(struct prebind_cksum_command *data);
void swap(struct uuid_command *data);
void swap(struct linkedit_data_command *data);
void swap(struct version_min_command *data);
void swap(struct rpath_command *data);
void swap(struct encryption_info_command *data);
void swap(struct encryption_info_command_64 *data);
void swap(struct linker_option_command *data);
void swap(struct dyld_info_command *data);
void swap(struct entry_point_command *data);
void swap(struct source_version_command *data);
void swap(struct twolevel_hint *data, uint32_t nhints);
void swap(struct nlist *data, uint32_t nsymbols);
void swap(struct nlist_64 *data, uint32_t nsymbols);
void swap(struct ranlib *data, uint32_t nranlibs);
void swap(struct relocation_info *data, uint32_t nrelocs);
void swap(struct dylib_reference *data, uint32_t nrefs);
void swap(struct dylib_module *data, uint32_t nmods);
void swap(struct dylib_module_64 *data, uint32_t nmods);
void swap(struct dylib_table_of_contents *data, uint32_t ntocs);

template<typename... Args> void swap_if(bool needs_swap, Args... args) {
	if (needs_swap)
		swap(args...);
}

#endif /* SRC_LIBBINARY_MACHO_SWAP_H_ */
