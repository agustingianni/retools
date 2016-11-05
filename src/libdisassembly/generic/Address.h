/*
 * Address.h
 *
 *  Created on: Mar 17, 2016
 *      Author: anon
 */

#ifndef SRC_LIBDISASSEMBLY_GENERIC_ADDRESS_H_
#define SRC_LIBDISASSEMBLY_GENERIC_ADDRESS_H_

#include <string>
#include <cstdint>
#include <cstring>

class Address {
private:
    uint64_t m_value;

public:
    Address(uint64_t value) :
            m_value{value} {

    }

    uint64_t getValue() const {
        return m_value;
    }

    const Address &operator+() const {
        return Address(+m_value);
    }

    const Address &operator-() const {
        return Address(-m_value);
    }

    const Address &operator~() const {
        return Address(~m_value);
    }

    // Prefix.
    const Address &operator++() {
        m_value++;
        return Address(m_value);
    }

    // Postfix.
    const Address &operator++(int) {
        auto old = Address(m_value);
        m_value++;
        return old;
    }

    // Prefix.
    const Address &operator--() {
        m_value--;
        return Address(m_value);
    }

    // Postfix.
    const Address &operator--(int) {
        auto old = Address(m_value);
        m_value--;
        return old;
    }

    const Address &operator+(const Address &rhs) const {
        return Address(m_value + rhs.m_value);
    }

    const Address &operator-(const Address &rhs) const {
        return Address(m_value - rhs.m_value);
    }

    const Address &operator*(const Address &rhs) const {
        return Address(m_value * rhs.m_value);
    }

    const Address &operator/(const Address &rhs) const {
        return Address(m_value / rhs.m_value);
    }

    const Address &operator%(const Address &rhs) const {
        return Address(m_value % rhs.m_value);
    }

    const Address &operator^(const Address &rhs) const {
        return Address(m_value ^ rhs.m_value);
    }

    const Address &operator&(const Address &rhs) const {
        return Address(m_value & rhs.m_value);
    }

    const Address &operator|(const Address &rhs) const {
        return Address(m_value | rhs.m_value);
    }

    const Address &operator<<(const Address &rhs) const {
        return Address(m_value << rhs.m_value);
    }

    const Address &operator>>(const Address &rhs) const {
        return Address(m_value >> rhs.m_value);
    }

    Address &operator=(const Address &rhs) {
        m_value = rhs.m_value;
        return *this;
    }

    Address &operator+=(const Address &rhs) {
        m_value += rhs.m_value;
        return *this;
    }

    Address &operator-=(const Address &rhs) {
        m_value -= rhs.m_value;
        return *this;
    }

    Address &operator/=(const Address &rhs) {
        m_value /= rhs.m_value;
        return *this;
    }

    Address &operator%=(const Address &rhs) {
        m_value %= rhs.m_value;
        return *this;
    }

    Address &operator^=(const Address &rhs) {
        m_value ^= rhs.m_value;
        return *this;
    }

    Address &operator&=(const Address &rhs) {
        m_value &= rhs.m_value;
        return *this;
    }

    Address &operator|=(const Address &rhs) {
        m_value |= rhs.m_value;
        return *this;
    }

    Address &operator>>=(const Address &rhs) {
        m_value >>= rhs.m_value;
        return *this;
    }

    Address &operator<<=(const Address &rhs) {
        m_value <<= rhs.m_value;
        return *this;
    }

    int operator==(const Address rhs) const {
        return m_value == rhs.m_value;
    }

    int operator!=(const Address rhs) const {
        return m_value != rhs.m_value;
    }

    int operator<=(const Address rhs) const {
        return m_value <= rhs.m_value;
    }

    int operator>=(const Address rhs) const {
        return m_value >= rhs.m_value;
    }

    int operator<(const Address rhs) const {
        return m_value < rhs.m_value;
    }

    int operator>(const Address rhs) const {
        return m_value > rhs.m_value;
    }

    int operator&&(const Address rhs) const {
        return m_value && rhs.m_value;
    }

    int operator||(const Address rhs) const {
        return m_value || rhs.m_value;
    }

    const std::string &toString() const {
        char buffer[32];
        snprintf(buffer, sizeof(buffer), "0x%.16llx", m_value);
        return std::string(buffer);
    }

};

#endif /* SRC_LIBDISASSEMBLY_GENERIC_ADDRESS_H_ */
