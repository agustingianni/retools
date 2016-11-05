/*
 * BasicBlock.h
 *
 *  Created on: Mar 18, 2016
 *      Author: anon
 */

#ifndef SRC_LIBDISASSEMBLY_GENERIC_BASICBLOCK_H_
#define SRC_LIBDISASSEMBLY_GENERIC_BASICBLOCK_H_

#include <vector>

#include "Instruction.h"
#include "Function.h"
#include "Address.h"

class BasicBlock {
private:
    Function m_function;
    std::vector<Instruction> m_instructions;
    std::vector<BasicBlock> m_children;
    std::vector<BasicBlock> m_parents;

public:
    BasicBlock(std::vector<Instruction> &instructions, Function function) :
            m_instructions{instructions}, m_function{function} {

    }

    static void link(BasicBlock &parent, BasicBlock &child) {
        parent.m_children.push_back(child);
        child.m_parents.push_back(parent);
    }

    const Address &getAddress() const {
        return m_instructions[0].getAddress();
    }

    const Function &getFunction() const {
        return m_function;
    }

    const std::vector<Instruction> &getInstructions() const {
        return m_instructions;
    }

    const std::vector<BasicBlock> &getChildren() const {
        return m_children;
    }

    const std::vector<BasicBlock> &getParents() const {
        return m_parents;
    }
};

#endif /* SRC_LIBDISASSEMBLY_GENERIC_BASICBLOCK_H_ */
