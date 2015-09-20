/*
 * Swap.cpp
 *
 *  Created on: Jul 16, 2015
 *      Author: anon
 */

#include <cassert>
#include "Swap.h"

void swap(uint16_t *data) {
	uint16_t hi = *data << 8;
	uint16_t lo = *data >> 8;
	*data = hi | lo;
}

void swap(uint32_t *data) {
	uint32_t Byte0 = *data & 0x000000FF;
	uint32_t Byte1 = *data & 0x0000FF00;
	uint32_t Byte2 = *data & 0x00FF0000;
	uint32_t Byte3 = *data & 0xFF000000;
	*data = (Byte0 << 24) | (Byte1 << 8) | (Byte2 >> 8) | (Byte3 >> 24);
}

void swap(uint64_t *data) {
	uint32_t *as_32 = (uint32_t *) data;
	swap(&as_32[0]);
	swap(&as_32[1]);
	*data = ((uint64_t) as_32[0] << 32) | as_32[1];
}

void swap(struct twolevel_hint *data, uint32_t nhints) {
	assert(false && "twolevel_hint is not implemented");
}

void swap(struct relocation_info *data, uint32_t nrelocs) {
	assert(false && "relocation_info is not implemented");
}

void swap(struct dylib_reference *data, uint32_t nrefs) {
	assert(false && "relocation_info is not implemented");
}

void swap(struct fat_header *data) {
	swap(&data->magic);
	swap(&data->nfat_arch);
}

void swap(struct fat_arch *data, uint32_t nfat_arch) {
	for (unsigned i = 0; i < nfat_arch; ++i) {
		swap(&data[i].align);
		swap((uint32_t *) &data[i].cpusubtype);
		swap((uint32_t *) &data[i].cputype);
		swap(&data[i].offset);
		swap(&data[i].size);
	}
}

void swap(struct mach_header *data) {
	swap((uint32_t *) &data->cpusubtype);
	swap((uint32_t *) &data->cputype);
	swap(&data->filetype);
	swap(&data->flags);
	swap(&data->magic);
	swap(&data->ncmds);
	swap(&data->sizeofcmds);
}

void swap(struct mach_header_64 *data) {
	swap((uint32_t *) &data->cpusubtype);
	swap((uint32_t *) &data->cputype);
	swap(&data->filetype);
	swap(&data->flags);
	swap(&data->magic);
	swap(&data->ncmds);
	swap(&data->reserved);
	swap(&data->sizeofcmds);
}

void swap(struct load_command *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
}

void swap(struct segment_command *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
	swap(&data->fileoff);
	swap(&data->filesize);
	swap(&data->flags);
	swap((uint32_t *) &data->initprot);
	swap((uint32_t *) &data->maxprot);
	swap(&data->nsects);
	swap(&data->vmaddr);
	swap(&data->vmsize);
}

void swap(struct segment_command_64 *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
	swap(&data->fileoff);
	swap(&data->filesize);
	swap(&data->flags);
	swap((uint32_t *) &data->initprot);
	swap((uint32_t *) &data->maxprot);
	swap(&data->nsects);
	swap(&data->vmaddr);
	swap(&data->vmsize);
}

void swap(struct section *data, uint32_t nsects) {
	for (unsigned i = 0; i < nsects; ++i) {
		swap(&data->addr);
		swap(&data->size);
		swap(&data->offset);
		swap(&data->align);
		swap(&data->reloff);
		swap(&data->nreloc);
		swap(&data->flags);
		swap(&data->reserved1);
		swap(&data->reserved2);
	}
}

void swap(struct section_64 *data, uint32_t nsects) {
	for (unsigned i = 0; i < nsects; ++i) {
		swap(&data->addr);
		swap(&data->size);
		swap(&data->offset);
		swap(&data->align);
		swap(&data->reloff);
		swap(&data->nreloc);
		swap(&data->flags);
		swap(&data->reserved1);
		swap(&data->reserved2);
		swap(&data->reserved3);
	}
}

void swap(struct symtab_command *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
	swap(&data->symoff);
	swap(&data->nsyms);
	swap(&data->stroff);
	swap(&data->strsize);
}

void swap(struct dysymtab_command *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
	swap(&data->ilocalsym);
	swap(&data->nlocalsym);
	swap(&data->iextdefsym);
	swap(&data->nextdefsym);
	swap(&data->iundefsym);
	swap(&data->nundefsym);
	swap(&data->tocoff);
	swap(&data->ntoc);
	swap(&data->modtaboff);
	swap(&data->nmodtab);
	swap(&data->extrefsymoff);
	swap(&data->nextrefsyms);
	swap(&data->indirectsymoff);
	swap(&data->nindirectsyms);
	swap(&data->extreloff);
	swap(&data->nextrel);
	swap(&data->locreloff);
	swap(&data->nlocrel);
}

void swap(struct symseg_command *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
	swap(&data->offset);
	swap(&data->size);
}

void swap(struct fvmlib_command *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
	swap(&data->fvmlib.header_addr);
	swap(&data->fvmlib.minor_version);
	swap(&data->fvmlib.name.offset);
}

void swap(struct dylib_command *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
	swap(&data->dylib.compatibility_version);
	swap(&data->dylib.current_version);
	swap(&data->dylib.name.offset);
	swap(&data->dylib.timestamp);
}

void swap(struct sub_framework_command *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
	swap(&data->umbrella.offset);
}

void swap(struct sub_umbrella_command *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
	swap(&data->sub_umbrella.offset);
}

void swap(struct sub_library_command *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
	swap(&data->sub_library.offset);
}

void swap(struct sub_client_command *data) {
	swap(&data->client.offset);
	swap(&data->cmd);
	swap(&data->cmdsize);
}

void swap(struct prebound_dylib_command *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
	swap(&data->linked_modules.offset);
	swap(&data->name.offset);
	swap(&data->nmodules);
}

void swap(struct dylinker_command *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
	swap(&data->name.offset);
}

void swap(struct fvmfile_command *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
	swap(&data->header_addr);
	swap(&data->name.offset);
}

void swap(struct thread_command *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
}

void swap(struct ident_command *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
}

void swap(struct routines_command *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
	swap(&data->init_address);
	swap(&data->init_module);
	swap(&data->reserved1);
	swap(&data->reserved2);
	swap(&data->reserved3);
	swap(&data->reserved4);
	swap(&data->reserved5);
	swap(&data->reserved6);
}

void swap(struct routines_command_64 *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
	swap(&data->init_address);
	swap(&data->init_module);
	swap(&data->reserved1);
	swap(&data->reserved2);
	swap(&data->reserved3);
	swap(&data->reserved4);
	swap(&data->reserved5);
	swap(&data->reserved6);
}

void swap(struct twolevel_hints_command *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
	swap(&data->offset);
	swap(&data->nhints);
}

void swap(struct prebind_cksum_command *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
	swap(&data->cksum);
}

void swap(struct uuid_command *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
}

void swap(struct linkedit_data_command *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
	swap(&data->dataoff);
	swap(&data->datasize);
}

void swap(struct version_min_command *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
	swap(&data->sdk);
	swap(&data->version);
}

void swap(struct rpath_command *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
	swap(&data->path.offset);
}

void swap(struct encryption_info_command *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
	swap(&data->cryptid);
	swap(&data->cryptoff);
	swap(&data->cryptsize);
}

void swap(struct encryption_info_command_64 *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
	swap(&data->cryptid);
	swap(&data->cryptoff);
	swap(&data->cryptsize);
	swap(&data->pad);
}

void swap(struct linker_option_command *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
	swap(&data->count);
}

void swap(struct dyld_info_command *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
	swap(&data->bind_off);
	swap(&data->bind_size);
	swap(&data->export_off);
	swap(&data->export_size);
	swap(&data->lazy_bind_off);
	swap(&data->lazy_bind_size);
	swap(&data->rebase_off);
	swap(&data->rebase_size);
	swap(&data->weak_bind_off);
	swap(&data->weak_bind_size);
}

void swap(struct entry_point_command *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
	swap(&data->entryoff);
	swap(&data->stacksize);
}

void swap(struct source_version_command *data) {
	swap(&data->cmd);
	swap(&data->cmdsize);
	swap(&data->version);
}

void swap(struct nlist *data, uint32_t nsymbols) {
	for (unsigned i = 0; i < nsymbols; ++i) {
		swap((uint16_t *) &data[i].n_desc);
		swap(&data[i].n_value);
		swap(&data[i].n_un.n_strx);
	}
}

void swap(struct nlist_64 *data, uint32_t nsymbols) {
	for (unsigned i = 0; i < nsymbols; ++i) {
		swap(&data[i].n_desc);
		swap(&data[i].n_value);
		swap(&data[i].n_un.n_strx);
	}
}

void swap(struct ranlib *data, uint32_t nranlibs) {
	for (unsigned i = 0; i < nranlibs; ++i) {
		swap(&data[i].ran_off);
		swap(&data[i].ran_un.ran_strx);
	}
}

void swap(struct dylib_module *data, uint32_t nmods) {
	for (unsigned i = 0; i < nmods; ++i) {
		swap(&data[i].iextdefsym);
		swap(&data[i].iextrel);
		swap(&data[i].iinit_iterm);
		swap(&data[i].ilocalsym);
		swap(&data[i].irefsym);
		swap(&data[i].module_name);
		swap(&data[i].nextdefsym);
		swap(&data[i].nextrel);
		swap(&data[i].ninit_nterm);
		swap(&data[i].nlocalsym);
		swap(&data[i].nrefsym);
		swap(&data[i].objc_module_info_addr);
		swap(&data[i].objc_module_info_size);
	}
}

void swap(struct dylib_module_64 *data, uint32_t nmods) {
	for (unsigned i = 0; i < nmods; ++i) {
		swap(&data[i].iextdefsym);
		swap(&data[i].iextrel);
		swap(&data[i].iinit_iterm);
		swap(&data[i].ilocalsym);
		swap(&data[i].irefsym);
		swap(&data[i].module_name);
		swap(&data[i].nextdefsym);
		swap(&data[i].nextrel);
		swap(&data[i].ninit_nterm);
		swap(&data[i].nlocalsym);
		swap(&data[i].nrefsym);
		swap(&data[i].objc_module_info_addr);
		swap(&data[i].objc_module_info_size);
	}
}

void swap(struct dylib_table_of_contents *data, uint32_t ntocs) {
	for (unsigned i = 0; i < ntocs; ++i) {
		swap(&data[i].module_index);
		swap(&data[i].symbol_index);
	}
}
