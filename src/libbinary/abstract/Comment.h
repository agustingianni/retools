/*
 * Comment.h
 *
 *  Created on: Mar 24, 2016
 *      Author: anon
 */

#ifndef SRC_LIBBINARY_ABSTRACT_COMMENT_H_
#define SRC_LIBBINARY_ABSTRACT_COMMENT_H_

#include <string>
#include <cstdint>

namespace Abstract {

class Comment {
private:
    std::string m_value;
    uint64_t m_offset;

public:
    Comment(uint64_t offset, std::string value) :
        m_offset { offset }, m_value { value } {

    }

    uint64_t getOffset() const {
        return m_offset;
    }

    const std::string& getValue() const {
        return m_value;
    }
};

}

#endif /* SRC_LIBBINARY_ABSTRACT_COMMENT_H_ */
