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

#include "AbstractBinary.h"

class FatBinary: public AbstractBinary {
public:
	virtual ~FatBinary() {
	}

	bool init() override;

private:
	fat_header m_header;
	std::vector<fat_arch> m_archs;
};

#endif /* SRC_LIBBINARY_MACHO_FATBINARY_H_ */
