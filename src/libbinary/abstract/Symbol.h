/*
 * Symbol.h
 *
 *  Created on: Mar 20, 2016
 *      Author: anon
 */

#ifndef SRC_LIBBINARY_ABSTRACT_SYMBOL_H_
#define SRC_LIBBINARY_ABSTRACT_SYMBOL_H_

namespace Abstract {

#include <string>
#include <cstdint>

class Symbol {
private:
    std::string m_name;
    uint64_t m_address;

public:
    Symbol(std::string name, uint64_t address) :
        m_name { name }, m_address { address } {
    }

    std::string getName() const {
        return m_name;
    }

    uint64_t getAddress() const {
        return m_address;
    }
};

}

#endif /* SRC_LIBBINARY_ABSTRACT_SYMBOL_H_ */
