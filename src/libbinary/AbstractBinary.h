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

#include "abstract/Segment.h"
#include "abstract/EntryPoint.h"
#include "abstract/Export.h"
#include "abstract/Import.h"
#include "abstract/Library.h"
#include "abstract/Relocation.h"
#include "abstract/String.h"
#include "abstract/Symbol.h"
#include "abstract/DataInCode.h"
#include "abstract/Comment.h"

#include "Utilities.h"
#include "MemoryMap.h"

enum class AddressSpaceSize {
    BINARY_16, BINARY_32, BINARY_64, MULTIPLE, Unknown
};

enum class BinaryEndianness {
    BIG, LITTLE, Unknown
};

enum class BinaryType {
    Object, Core, Executable, Library, Driver, Collection, Symbols, Unknown
};

enum class BinaryArch {
    X86, X86_64, ARM, ARM64, MULTIPLE, PowerPC, PowerPC64, Unknown
};

enum class BinaryFormat {
    MACHO, ELF, PE, FAT, Unknown
};

enum class BinaryOperatingSystem {
    iOS, OSX, AppleTV, AppleWatch, Windows, Linux, Unknown
};

class AbstractBinary {
public:
    // Returns the correct 'concrete' binary as an 'abstract' one.
    static AbstractBinary *create(std::string path);

    // Override this for each implemented binary.
    virtual bool init() = 0;
    virtual ~AbstractBinary() = default;

    // Create a new binary by reading the file pointer by 'path'.
    bool load(const std::string &path);

    // Create a new binary by reading the file located at 'memory'.
    bool load(unsigned char *memory, size_t size);

    // Free any used resources.
    bool unload();

    BinaryOperatingSystem getOS() const;
    BinaryFormat getBinaryFormat() const;
    BinaryArch getBinaryArch() const;
    BinaryType getBinaryType() const;
    AddressSpaceSize getAddressSpaceSize() const;
    BinaryEndianness getBinaryEndianness() const;

    bool isEncrypted() const;
    bool isSigned() const;

    bool isLittleEndian() const;
    bool isBigEndian() const;
    bool needs_swap() const;

    bool is16() const;
    bool is32() const;
    bool is64() const;

    const std::vector<AbstractBinary *> &binaries() const;
    size_t binary_count() const;

    void addEntryPoint(const Abstract::EntryPoint &entry_point);
    void addEntryPoint(uint64_t entry_point);
    void addLibrary(const Abstract::Library &library);
    void addLibrary(std::string library);
    void addSegment(const Abstract::Segment &segment);
    void addSegment(uint8_t *data, size_t size, int permission, uint64_t addr, uint64_t vm_size, uint64_t off, uint64_t fs_size);
    void addString(const Abstract::String &value);
    void addString(std::string value, uint64_t offset);
    void addComment(const Abstract::Comment &comment);
    void addComment(uint64_t offset, std::string comment);
    void addSymbol(const Abstract::Symbol &symbol);
    void addSymbol(std::string name, uint64_t address);
    void addDataInCode(const Abstract::DataInCode &dice);
    void addDataInCode(uint64_t offset, uint64_t length, Abstract::DataInCodeKind kind, std::string description);

    const std::vector<Abstract::EntryPoint> &getEntryPoints() const;
    const std::vector<Abstract::Export> &getExports() const;
    const std::vector<Abstract::Import> &getImports() const;
    const std::vector<Abstract::Library> &getLibraries() const;
    const std::vector<Abstract::Relocation> &getRelocations() const;
    const std::vector<Abstract::Segment> &getSegments() const;
    const std::vector<Abstract::String> &getStrings() const;
    const std::vector<Abstract::Symbol> &getSymbols() const;
    const std::vector<Abstract::DataInCode> &getDataInCode() const;

    const std::vector<std::string> &getEnvironmentVariables() const;
    const std::vector<std::string> &getLibraryPaths() const;
    const std::vector<std::string> &getLinkerCommands() const;

    const std::string &getLinker() const;
    const std::string &getVersion() const;
    const std::string &getUniqueId() const;

protected:
    unsigned pointer_size() const;

    // Collected information.
    std::vector<Abstract::EntryPoint> m_entry_points;
    std::vector<Abstract::Export> m_exports;
    std::vector<Abstract::Import> m_imports;
    std::vector<Abstract::Library> m_libraries;
    std::vector<Abstract::Relocation> m_relocations;
    std::vector<Abstract::Segment> m_segments;
    std::vector<Abstract::String> m_strings;
    std::vector<Abstract::Symbol> m_symbols;
    std::vector<Abstract::DataInCode> m_data_in_code;
    std::vector<Abstract::Comment> m_comments;

    // Some binaries contain a collection of binaries inside (e.g. fat mach-o).
    std::vector<AbstractBinary *> m_binaries;

    // Environment variables to set when loading the binary.
    std::vector<std::string> m_environment;

    // Additional dynamic linker paths used to search for libraries.
    std::vector<std::string> m_dynamic_linker_paths;
    std::vector<std::string> m_linker_commands;

    // Access to binaries memory is performed using a memory map.
    MemoryMap m_data;
    std::string m_path;

    // If 'm_unmap' is true then we need to clean the resources used.
    bool m_unmap = false;
    unsigned char *m_memory = nullptr;
    size_t m_size = 0;

    AddressSpaceSize m_address_space_size = AddressSpaceSize::Unknown;
    BinaryArch m_binary_arch = BinaryArch::Unknown;
    BinaryEndianness m_endianness = BinaryEndianness::Unknown;
    BinaryEndianness m_host_endianness = IsHostBigEndian() ? BinaryEndianness::BIG : BinaryEndianness::LITTLE;
    BinaryFormat m_binary_format = BinaryFormat::Unknown;
    BinaryOperatingSystem m_os = BinaryOperatingSystem::Unknown;
    BinaryType m_binary_type = BinaryType::Unknown;
    bool m_encrypted = false;
    bool m_signed = false;
    std::string m_linker;
    std::string m_version;
    std::string m_rpath;
    std::string m_unique_id;
};

#endif /* SRC_LIBBINARY_ABSTRACTBINARY_H_ */
