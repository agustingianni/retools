//
// Created by anon on 3/19/16.
//

#ifndef RETOOLS_BINARYSEGMENT_H
#define RETOOLS_BINARYSEGMENT_H

#include <cstdint>
#include <string>

#include "SegmentPermission.h"

namespace Abstract {

class Segment {
private:
    uint8_t *m_data = nullptr;
    size_t m_size = 0;
    int m_permission = 0;
    uint64_t m_address = 0;
    uint64_t m_vm_size = 0;
    uint64_t m_offset = 0;
    uint64_t m_fs_size = 0;

public:
    Segment(uint8_t *m_data, size_t m_size, int m_permission, uint64_t address, uint64_t vm_size, uint64_t offset, uint64_t fs_size) :
        m_data(m_data), m_size(m_size), m_permission(m_permission), m_address(address), m_vm_size(vm_size), m_offset(offset), m_fs_size(fs_size) {
    }

    uint8_t *getData() const {
        return m_data;
    }

    size_t getSize() const {
        return m_size;
    }

    int getPermission() const {
        return m_permission;
    }

    bool isExecutable() const {
        return getPermission() & SegmentPermission::EXECUTE;
    }

    bool isReadable() const {
        return getPermission() & SegmentPermission::READ;
    }

    bool isWritable() const {
        return getPermission() & SegmentPermission::WRITE;
    }

    uint64_t getAddress() const {
        return m_address;
    }

    uint64_t getInFileSize() const {
        return m_fs_size;
    }

    uint64_t getOffset() const {
        return m_offset;
    }

    uint64_t getInMemorySize() const {
        return m_vm_size;
    }

    std::string toString() {
        return std::string("BinarySegment: m_data=" + std::to_string((uintptr_t) m_data) + " m_size="
            + std::to_string(m_size));
    }
};

}

#endif //RETOOLS_BINARYSEGMENT_H
