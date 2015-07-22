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
#include "Utilities.h"

enum class AddressSpaceSize {
	BINARY_16, BINARY_32, BINARY_64, MULTIPLE, Unknown
};

enum class BinaryEndianness {
	BIG, LITTLE, Unknown
};

enum class BinaryType {
	Object, Core, Executable, Library, Collection, Unknown
};

enum class BinaryArch {
	X86, X86_64, ARM, ARM64, MULTIPLE, Unknown
};

enum class BinaryFormat {
	MACHO, ELF, PE, FAT, Unknown
};

class AbstractBinary {
public:
	AbstractBinary() :
		m_size(0),
		m_data(nullptr),
		m_memory(nullptr),
		m_unmap(false),
		m_address_space_size(AddressSpaceSize::Unknown),
		m_endianness(BinaryEndianness::Unknown),
		m_host_endianness(IsHostBigEndian() ? BinaryEndianness::BIG : BinaryEndianness::LITTLE),
		m_binary_arch(BinaryArch::Unknown),
		m_binary_format(BinaryFormat::Unknown),
		m_binary_type(BinaryType::Unknown) {
	}

	virtual ~AbstractBinary() = default;

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

	bool needs_swap() const {
		return m_host_endianness != m_endianness;
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

	const std::vector<AbstractBinary *> &binaries() const {
		return m_binaries;
	}

	size_t binary_count() const {
		return m_binaries.size();
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

	// Some binaries contain a collection of binaries inside (e.g. fat mach-o).
	std::vector<AbstractBinary *> m_binaries;

	// Access to binaries memory is performed using a memory map.
	// Access to the binary memory is performed using a memory map.
	MemoryMap *m_data;
	std::string m_path;

	// If 'm_unmap' is true then we need to clean the resources used.
	bool m_unmap;
	unsigned char *m_memory;
	size_t m_size;

	BinaryType m_binary_type;
	AddressSpaceSize m_address_space_size;
	BinaryEndianness m_endianness;
	BinaryEndianness m_host_endianness;
	BinaryArch m_binary_arch;
	BinaryFormat m_binary_format;
};

#endif /* SRC_LIBBINARY_ABSTRACTBINARY_H_ */
