/*
 * MemoryMap.h
 *
 *  Created on: May 22, 2015
 *      Author: anon
 */

#ifndef SRC_UTILITIES_MEMORYMAP_H_
#define SRC_UTILITIES_MEMORYMAP_H_

class MemoryMap {
private:
    unsigned char *m_memory;
    unsigned char *m_end;

public:
    MemoryMap(unsigned char *memory, size_t size) :
            m_memory(memory), m_end(memory + size) {
    }

    // Get a sane pointer to a given type and a memory pointer.
    template<typename T> T *pointer(void *mem, size_t size = sizeof(T)) {
        return valid(static_cast<unsigned char *>(mem) + size) ? reinterpret_cast<T *>(mem) : nullptr;
    }

    // Get a sane pointer to a given type and an offset.
    template<typename T> T *offset(unsigned offset, size_t size = sizeof(T)) {
        return valid(m_memory + offset + size) ? reinterpret_cast<T *>(m_memory + offset) : nullptr;
    }

    // Validate a pointer.
    bool valid(void *ptr) {
        return ptr <= m_end;
    }
};

#endif /* SRC_UTILITIES_MEMORYMAP_H_ */
