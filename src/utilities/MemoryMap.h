/*
 * MemoryMap.h
 *
 *  Created on: May 22, 2015
 *      Author: anon
 */

#ifndef SRC_UTILITIES_MEMORYMAP_H_
#define SRC_UTILITIES_MEMORYMAP_H_

#include <cstdint>

class MemoryMap {
private:
    uint8_t *m_memory = nullptr;
    uint8_t *m_end = nullptr;

public:
    MemoryMap() = default;

    MemoryMap(uint8_t *memory, size_t size) :
        m_memory(memory), m_end(memory + size) {
    }

    template <typename T>
    T *element(void *mem, size_t index) const {
        auto offset = index * sizeof(T);
        return pointer<T>(static_cast<uint8_t *>(mem) + offset, sizeof(T));
    }

    // Get a sane pointer to a given type and a memory pointer.
    template<typename T> T *pointer(void *mem, size_t size = sizeof(T)) const {
        return valid(static_cast<uint8_t *>(mem) + size) ? reinterpret_cast<T *>(mem) : nullptr;
    }

    // Get a sane pointer to a given type and an offset.
    template<typename T> T *offset(uint64_t offset, uint64_t size = sizeof(T)) const {
        // Check if 'offset + size' overflows.
        if (offset > std::numeric_limits<uint64_t>::max() - size)
            return nullptr;

        // Calculate the end byte.
        uint64_t end = offset + size;

        // Check for 32 bits.
        if (end > std::numeric_limits<uintptr_t>::max())
            return nullptr;

        // Check if 'm_memory + end' overflows.
        if (reinterpret_cast<uintptr_t>(m_memory) > std::numeric_limits<uintptr_t>::max() - static_cast<uintptr_t>(end))
            return nullptr;

        // Check if the last byte is in range.
        if (!valid(m_memory + end))
            return nullptr;

        return reinterpret_cast<T *>(m_memory + offset);
    }

    // Validate a pointer.
    bool valid(void *ptr) const {
        return ptr >= m_memory && ptr <= m_end;
    }

    // Validate a pointer.
    template<typename T> bool valid_pointer(T *ptr) const {
        return reinterpret_cast<uint8_t *>((ptr + 1)) <= m_end;
    }
};

#endif /* SRC_UTILITIES_MEMORYMAP_H_ */
