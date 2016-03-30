/*
 * DataInCode.h
 *
 *  Created on: Mar 22, 2016
 *      Author: anon
 */

#ifndef SRC_LIBBINARY_ABSTRACT_DATAINCODE_H_
#define SRC_LIBBINARY_ABSTRACT_DATAINCODE_H_

namespace Abstract {

#include <cstdint>
#include <string>

enum class DataInCodeKind {
    DATA, JUMP_TABLE_8, JUMP_TABLE_16, JUMP_TABLE_32, ABS_JUMP_TABLE_32, Unknown
};

class DataInCode {

private:
    uint64_t m_offset;
    uint64_t m_length;
    DataInCodeKind m_kind;
    std::string m_description;

public:
    DataInCode(uint64_t offset, uint64_t lenght, DataInCodeKind kind, std::string description) :
        m_offset { offset }, m_length { lenght }, m_kind { kind }, m_description { description } {
    }

    const std::string& getDescription() const {
        return m_description;
    }

    DataInCodeKind getKind() const {
        return m_kind;
    }

    uint64_t getLength() const {
        return m_length;
    }

    uint64_t getOffset() const {
        return m_offset;
    }
};

}

#endif /* SRC_LIBBINARY_ABSTRACT_DATAINCODE_H_ */
