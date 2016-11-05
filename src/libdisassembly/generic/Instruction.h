/*
 * Instruction.h
 *
 *  Created on: Mar 18, 2016
 *      Author: anon
 */

#ifndef SRC_LIBDISASSEMBLY_GENERIC_INSTRUCTION_H_
#define SRC_LIBDISASSEMBLY_GENERIC_INSTRUCTION_H_

#include "Address.h"
#include "Operand.h"

#include <vector>

class Instruction {
private:
    Address m_address;
    std::vector<Operand> m_operands;
    std::vector<uint8_t> m_data;
    std::string m_mnemonic;

public:
    size_t getLength() const {
        return m_data.size();
    }

    const Address &getAddress() const {
        return m_address;
    }

    const std::vector<Operand> &getOperands() const {
        return m_operands;
    }

    const std::vector<uint8_t> &getData() const {
        return m_data;
    }

    const std::string &getMnemonic() const {
        return m_mnemonic;
    }
};

#endif /* SRC_LIBDISASSEMBLY_GENERIC_INSTRUCTION_H_ */
