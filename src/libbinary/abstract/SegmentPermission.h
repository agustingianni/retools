/*
 * SegmentPermission.h
 *
 *  Created on: Mar 20, 2016
 *      Author: anon
 */

#ifndef SRC_LIBBINARY_ABSTRACT_SEGMENTPERMISSION_H_
#define SRC_LIBBINARY_ABSTRACT_SEGMENTPERMISSION_H_

#define	VM_PROT_NONE 0x00
#define VM_PROT_READ 0x01
#define VM_PROT_WRITE 0x02
#define VM_PROT_EXECUTE 0x04

using vm_prot_t = int;

namespace SegmentPermission {
	constexpr int READ = 1;
	constexpr int WRITE = 2;
	constexpr int EXECUTE = 4;
	constexpr int NONE = 0;

	static std::string toString(int perm) {
	    std::string out;
	    out += perm & SegmentPermission::READ ? "r" : "-";
	    out += perm & SegmentPermission::WRITE ? "w" : "-";
	    out += perm & SegmentPermission::EXECUTE ? "x" : "-";
	    return out;
	}

	static int toSegmentPermission(vm_prot_t prot) {
		int segment_permission = SegmentPermission::NONE;

		if (prot & VM_PROT_READ)
			segment_permission |= SegmentPermission::READ;

		if (prot & VM_PROT_WRITE)
			segment_permission |= SegmentPermission::WRITE;

		if (prot & VM_PROT_EXECUTE)
			segment_permission |= SegmentPermission::EXECUTE;

		return segment_permission;
	}
}

#endif /* SRC_LIBBINARY_ABSTRACT_SEGMENTPERMISSION_H_ */
