/*
 * AbstractBinary.h
 *
 *  Created on: Mar 22, 2015
 *      Author: anon
 */

#ifndef SRC_LIBBINARY_ABSTRACTBINARY_H_
#define SRC_LIBBINARY_ABSTRACTBINARY_H_

#include <string>
#include <vector>

#include "MemoryMap.h"

struct BinarySegment {
	uintptr_t m_start_addr;
	uintptr_t m_end_addr;
	unsigned m_permissions;
	size_t m_size;
	char *m_contents;
	std::string m_name;
};

enum class AddressSpaceSize {
	BINARY_16, BINARY_32, BINARY_64, MULTIPLE
};

enum class BinaryEndianness {
	BIG, LITTLE
};

enum class BinaryType {
	Object, Core, Executable, Library, Collection, Unknown
};

enum class BinaryArch {
	X86, X86_64, ARM, ARM64, MULTIPLE
};

enum class BinaryFormat {
	MACHO, ELF, PE, FAT
};

class AbstractBinary {
public:
	virtual ~AbstractBinary() {
	}

	// Create a new binary by reading the file pointer by 'path'.
	bool load(const std::string &path);

	// Create a new binary by reading the file located at 'memory'.
	bool load(unsigned char *memory, size_t size);

	// Free any used resources.
	bool unload();

	// Override this for each implemented binary.
	virtual bool init() = 0;

	BinaryFormat getBinaryFormat() const {
		return m_binary_format;
	}

	BinaryArch getBinaryArch() const {
		return m_binary_arch;
	}

	BinaryType getBinaryType() const {
		return m_binary_type;
	}

	AddressSpaceSize getAddressSpaceSize() const {
		return m_address_space_size;
	}

	BinaryEndianness getBinaryEndianness() const {
		return m_endianness;
	}

	bool isLittleEndian() const {
		return m_endianness == BinaryEndianness::LITTLE;
	}

	bool isBigEndian() const {
		return !isLittleEndian();
	}

	bool is16() const {
		return m_address_space_size == AddressSpaceSize::BINARY_16;
	}

	bool is32() const {
		return m_address_space_size == AddressSpaceSize::BINARY_32;
	}

	bool is64() const {
		return m_address_space_size == AddressSpaceSize::BINARY_64;
	}

protected:

	unsigned pointer_size() const {
		switch (m_address_space_size) {
		case AddressSpaceSize::BINARY_64:
			return sizeof(uint64_t);

		case AddressSpaceSize::BINARY_32:
			return sizeof(uint32_t);

		case AddressSpaceSize::BINARY_16:
			return sizeof(uint16_t);

		default:
			return 0;
		}
	}

	MemoryMap *m_data;
	unsigned char *m_memory;
	std::string m_path;
	bool m_unmap;
	size_t m_size;

	BinaryType m_binary_type;
	AddressSpaceSize m_address_space_size;
	BinaryEndianness m_endianness;
	BinaryArch m_binary_arch;
	BinaryFormat m_binary_format;
};

#endif /* SRC_LIBBINARY_ABSTRACTBINARY_H_ */
