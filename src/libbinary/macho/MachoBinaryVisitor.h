/*
 * MachoBinaryVisitor.h
 *
 *  Created on: Jul 22, 2015
 *      Author: anon
 */

#ifndef SRC_LIBBINARY_MACHO_MACHOBINARYVISITOR_H_
#define SRC_LIBBINARY_MACHO_MACHOBINARYVISITOR_H_

#include <mach-o/loader.h>

#include "debug.h"

class MachoBinaryVisitor {
public:
    virtual ~MachoBinaryVisitor() = default;

    virtual bool handle_mach_header(const struct mach_header &header) {
    	LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
    	return true;
    }

    virtual bool handle_mach_header(const struct mach_header_64 &header) {
    	LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
    	return true;
    }

    virtual bool handle_section(const struct section &section) {
    	LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
    	return true;
    }

    virtual bool handle_section(const struct section_64 &section_64) {
    	LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
    	return true;
    }

    virtual bool handle_code_signature(const struct linkedit_data_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_data_in_code(const struct linkedit_data_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_dyld_environment(const struct dylinker_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_dyld_info(const struct dyld_info_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_dyld_info_only(const struct dyld_info_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_dylib_code_sign_drs(const struct linkedit_data_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_dysymtab(const struct dysymtab_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_encryption_info(const struct encryption_info_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_encryption_info(const struct encryption_info_command_64 &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_function_starts(const struct linkedit_data_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_fvmfile(const struct fvmfile_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_id_dylib(const struct dylib_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_id_dylinker(const struct dylinker_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_ident(const struct ident_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_idfvmlib(const struct fvmlib_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_lazy_load_dylib(const struct load_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_linker_option(const struct linker_option_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_linker_optimization_hint(const struct linkedit_data_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_load_dylib(const struct dylib_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_load_dylinker(const struct dylinker_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_load_upward_dylib(const struct load_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_load_weak_dylib(const struct dylib_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_loadfvmlib(const struct fvmlib_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_main(const struct entry_point_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_prebind_cksum(const struct prebind_cksum_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_prebound_dylib(const struct prebound_dylib_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_prepage(const struct load_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_reexport_dylib(const struct dylib_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_routines(const struct routines_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_routines(const struct routines_command_64 &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_rpath(const struct rpath_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_segment(const struct segment_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_segment(const struct segment_command_64 &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_segment_split_info(const struct linkedit_data_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_source_version(const struct source_version_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_sub_client(const struct sub_client_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_sub_framework(const struct sub_framework_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_sub_library(const struct sub_library_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_sub_umbrella(const struct sub_umbrella_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_symseg(const struct symseg_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_symtab(const struct symtab_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_thread(const struct thread_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_twolevel_hints(const struct twolevel_hints_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_unixthread(const struct thread_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_uuid(const struct uuid_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_version_min_iphoneos(const struct version_min_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }

    virtual bool handle_version_min_macosx(const struct version_min_command &command) {
        LOG_DEBUG("Visitor -> %s", __PRETTY_FUNCTION__);
        return true;
    }
};

#endif /* SRC_LIBBINARY_MACHO_MACHOBINARYVISITOR_H_ */
