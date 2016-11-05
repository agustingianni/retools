/*
 * Function.h
 *
 *  Created on: Mar 18, 2016
 *      Author: anon
 */

#ifndef SRC_LIBDISASSEMBLY_GENERIC_FUNCTION_H_
#define SRC_LIBDISASSEMBLY_GENERIC_FUNCTION_H_

#include "Address.h"
#include "Module.h"
#include "FlowGraph.h"

enum FunctionType {
    NORMAL, LIBRARY, IMPORT, THUNK, INVALID, UNKNOWN
};

class Function {
private:
    Address m_address;
    Module m_module;
    FlowGraph m_graph;

private:
    std::string m_description;
    std::string m_name;
    FunctionType m_type;

public:
    const Address &getAddress() const {
        return m_address;
    }

    const Module &getModule() const {
        return m_module;
    }

    const std::string &getDescription() const {
        return m_description;
    }

    const std::string &getName() const {
        return m_name;
    }

    unsigned getInDegree() const {
        return 0;
    }

    unsigned getOutDegree() const {
        return 0;
    }

    FunctionType getType() const {
        return m_type;
    }

    unsigned getEdgeCount() const {
        return 0;
    }

    unsigned getBasicBlockCount() const {
        return 0;
    }
};

#endif /* SRC_LIBDISASSEMBLY_GENERIC_FUNCTION_H_ */
