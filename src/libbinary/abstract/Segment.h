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
    uint8_t *m_data;
    size_t m_size;
    int m_permission;

public:
    Segment(uint8_t *m_data, size_t m_size, int m_permission) :
            m_data(m_data), m_size(m_size), m_permission(m_permission) {
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

    std::string toString() {
        return std::string(
                "BinarySegment: m_data=" + std::to_string((uintptr_t) m_data) + " m_size=" + std::to_string(m_size));
    }
};

}

#endif //RETOOLS_BINARYSEGMENT_H
