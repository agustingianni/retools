/*
 * Module.h
 *
 *  Created on: Mar 18, 2016
 *      Author: anon
 */

#ifndef SRC_LIBDISASSEMBLY_GENERIC_MODULE_H_
#define SRC_LIBDISASSEMBLY_GENERIC_MODULE_H_

#include <string>
#include <set>

class Function;

class Module {
private:
    std::string m_name;
    std::set<Function> m_functions;

public:
    const std::string &getName() const {
        return m_name;
    }

    const std::set<Function> &getFunctions() const {
        return m_functions;
    }
};

#endif /* SRC_LIBDISASSEMBLY_GENERIC_MODULE_H_ */
