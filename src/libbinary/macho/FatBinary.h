/*
 * FatBinary.h
 *
 *  Created on: Jul 16, 2015
 *      Author: anon
 */

#ifndef SRC_LIBBINARY_MACHO_FATBINARY_H_
#define SRC_LIBBINARY_MACHO_FATBINARY_H_

#include <vector>
#include <mach-o/fat.h>
#include <cstdint>

#include "AbstractBinary.h"

class FatBinary: public AbstractBinary {
public:
    virtual ~FatBinary() {
    }

    bool init() override;

    static bool check(uint8_t *memory, size_t size) {
        if (!memory || size < sizeof(struct fat_header)) {
            return false;
        }

        auto tmp_header = reinterpret_cast<fat_header *>(memory);

        if (tmp_header->magic == FAT_MAGIC)
            return true;

        if (tmp_header->magic == FAT_CIGAM)
            return true;

        return false;
    }

private:
    fat_header m_header;
    std::vector<fat_arch> m_archs;
};

#endif /* SRC_LIBBINARY_MACHO_FATBINARY_H_ */
