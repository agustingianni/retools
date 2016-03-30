/*
 * EntryPoint.h
 *
 *  Created on: Mar 20, 2016
 *      Author: anon
 */

#ifndef SRC_LIBBINARY_ABSTRACT_ENTRYPOINT_H_
#define SRC_LIBBINARY_ABSTRACT_ENTRYPOINT_H_

namespace Abstract {

#include <cstdint>
#include <string>

class EntryPoint {

private:
    uint64_t m_offset;

public:
    EntryPoint(uint64_t offset) :
        m_offset { offset } {

    }

    uint64_t getValue() const {
        return m_offset;
    }

    std::string toString() const {
        return std::string();
    }
};

}

#endif /* SRC_LIBBINARY_ABSTRACT_ENTRYPOINT_H_ */
