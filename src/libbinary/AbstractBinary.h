/*
 * AbstractBinary.h
 *
 *  Created on: Mar 22, 2015
 *      Author: anon
 */

#ifndef SRC_LIBBINARY_ABSTRACTBINARY_H_
#define SRC_LIBBINARY_ABSTRACTBINARY_H_

#include <abstract/Segment.h>
#include <string>
#include <vector>

#include "MemoryMap.h"
#include "Utilities.h"

#include "abstract/EntryPoint.h"
#include "abstract/Export.h"
#include "abstract/Import.h"
#include "abstract/Library.h"
#include "abstract/Relocation.h"
#include "abstract/String.h"
#include "abstract/Symbol.h"

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
		m_data(nullptr),
		m_unmap(false),
		m_memory(nullptr),
		m_size(0),
		m_binary_type(BinaryType::Unknown),
		m_address_space_size(AddressSpaceSize::Unknown),
		m_endianness(BinaryEndianness::Unknown),
		m_host_endianness(IsHostBigEndian() ? BinaryEndianness::BIG : BinaryEndianness::LITTLE),
		m_binary_arch(BinaryArch::Unknown),
		m_binary_format(BinaryFormat::Unknown) {
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

    void addSegment(const Abstract::Segment &segment) {
        m_segments.push_back(segment);
    }

    void addSegment(uint8_t *data, size_t size, int permission) {
        addSegment(Abstract::Segment(data, size, permission));
    }

    void addEntryPoint(const Abstract::EntryPoint &entry_point) {
        m_entry_points.push_back(entry_point);
    }

    void addEntryPoint(uint64_t entry_point) {
        addEntryPoint(Abstract::EntryPoint(entry_point));
    }

    void addSymbol(const Abstract::Symbol &symbol) {
        m_symbols.push_back(symbol);
    }

    void addSymbol(std::string name, uint64_t address) {
        addSymbol(Abstract::Symbol(name, address));
    }

    void addLibrary(std::string library) {
        addLibrary(Abstract::Library(library));
    }

    void addLibrary(const Abstract::Library &library) {
        m_libraries.push_back(library);
    }

    // Return the list of segments.
    const std::vector<Abstract::Segment> &getSegments() const {
        return m_segments;
    }

    const std::vector<Abstract::EntryPoint> &getEntryPoints() const {
        return m_entry_points;
    }

    const std::vector<Abstract::Symbol> &getSymbols() const {
        return m_symbols;
    }

    const std::vector<Abstract::Library> &getLibraries() const {
        return m_libraries;
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

    // Collected information.
    std::vector<Abstract::EntryPoint> m_entry_points;
    std::vector<Abstract::Export> m_exports;
    std::vector<Abstract::Import> m_imports;
    std::vector<Abstract::Library> m_libraries;
    std::vector<Abstract::Relocation> m_relocations;
    std::vector<Abstract::Segment> m_segments;
    std::vector<Abstract::String> m_strings;
    std::vector<Abstract::Symbol> m_symbols;

    // Some binaries contain a collection of binaries inside (e.g. fat mach-o).
    std::vector<AbstractBinary *> m_binaries;

    // Access to binaries memory is performed using a memory map.
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
