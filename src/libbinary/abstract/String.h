/*
 * String.h
 *
 *  Created on: Mar 20, 2016
 *      Author: anon
 */

#ifndef SRC_LIBBINARY_ABSTRACT_STRING_H_
#define SRC_LIBBINARY_ABSTRACT_STRING_H_

#include <string>
#include <cstdint>

namespace Abstract {

class String {
private:
    std::string m_string;
    size_t m_offset;

public:
    String(std::string value, size_t offset) :
        m_string { value }, m_offset { offset } {

    }

    size_t getOffset() const {
        return m_offset;
    }

    const std::string &getString() const {
        return m_string;
    }
};

}

#endif /* SRC_LIBBINARY_ABSTRACT_STRING_H_ */
