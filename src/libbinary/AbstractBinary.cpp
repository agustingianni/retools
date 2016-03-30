/*
 * AbstractBinary.cpp
 *
 *  Created on: Mar 22, 2015
 *      Author: anon
 */

#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "AbstractBinary.h"
#include "macho/FatBinary.h"
#include "macho/MachoBinary.h"
#include "debug.h"

unsigned AbstractBinary::pointer_size() const {
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

BinaryOperatingSystem AbstractBinary::getOS() const {
    return m_os;
}

BinaryFormat AbstractBinary::getBinaryFormat() const {
    return m_binary_format;
}

BinaryArch AbstractBinary::getBinaryArch() const {
    return m_binary_arch;
}

BinaryType AbstractBinary::getBinaryType() const {
    return m_binary_type;
}

AddressSpaceSize AbstractBinary::getAddressSpaceSize() const {
    return m_address_space_size;
}

BinaryEndianness AbstractBinary::getBinaryEndianness() const {
    return m_endianness;
}

bool AbstractBinary::isEncrypted() const {
    return m_encrypted;
}

bool AbstractBinary::isSigned() const {
    return m_signed;
}

bool AbstractBinary::isLittleEndian() const {
    return m_endianness == BinaryEndianness::LITTLE;
}

bool AbstractBinary::isBigEndian() const {
    return !isLittleEndian();
}

bool AbstractBinary::needs_swap() const {
    return m_host_endianness != m_endianness;
}

bool AbstractBinary::is16() const {
    return m_address_space_size == AddressSpaceSize::BINARY_16;
}

bool AbstractBinary::is32() const {
    return m_address_space_size == AddressSpaceSize::BINARY_32;
}

bool AbstractBinary::is64() const {
    return m_address_space_size == AddressSpaceSize::BINARY_64;
}

const std::vector<AbstractBinary *> &AbstractBinary::binaries() const {
    return m_binaries;
}

size_t AbstractBinary::binary_count() const {
    return m_binaries.size();
}

void AbstractBinary::addSegment(const Abstract::Segment &segment) {
    m_segments.push_back(segment);
}

void AbstractBinary::addSegment(uint8_t *data, size_t size, int permission, uint64_t addr, uint64_t vm_size, uint64_t off, uint64_t fs_size) {
    addSegment(Abstract::Segment(data, size, permission, addr, vm_size, off, fs_size));
}

void AbstractBinary::addEntryPoint(const Abstract::EntryPoint &entry_point) {
    m_entry_points.push_back(entry_point);
}

void AbstractBinary::addEntryPoint(uint64_t entry_point) {
    addEntryPoint(Abstract::EntryPoint(entry_point));
}

void AbstractBinary::addComment(const Abstract::Comment &comment) {
    m_comments.push_back(comment);
}

void AbstractBinary::addComment(uint64_t offset, std::string comment) {
    addComment(Abstract::Comment(offset, comment));
}

void AbstractBinary::addSymbol(const Abstract::Symbol &symbol) {
    m_symbols.push_back(symbol);
}

void AbstractBinary::addSymbol(std::string name, uint64_t address) {
    addSymbol(Abstract::Symbol(name, address));
}

void AbstractBinary::addDataInCode(const Abstract::DataInCode &dice) {
    m_data_in_code.push_back(dice);
}

void AbstractBinary::addDataInCode(uint64_t offset, uint64_t length, Abstract::DataInCodeKind kind, std::string description) {
    addDataInCode(offset, length, kind, description);
}

void AbstractBinary::addLibrary(std::string library) {
    addLibrary(Abstract::Library(library));
}

void AbstractBinary::addLibrary(const Abstract::Library &library) {
    m_libraries.push_back(library);
}

void AbstractBinary::addString(const Abstract::String &value) {
    m_strings.push_back(value);
}

void AbstractBinary::addString(std::string value, uint64_t offset) {
    addString(Abstract::String(value, offset));
}

const std::vector<Abstract::Segment> &AbstractBinary::getSegments() const {
    return m_segments;
}

const std::vector<Abstract::EntryPoint> &AbstractBinary::getEntryPoints() const {
    return m_entry_points;
}

const std::vector<Abstract::Symbol> &AbstractBinary::getSymbols() const {
    return m_symbols;
}

const std::vector<Abstract::DataInCode> &AbstractBinary::getDataInCode() const {
    return m_data_in_code;
}

const std::vector<Abstract::Library> &AbstractBinary::getLibraries() const {
    return m_libraries;
}

const std::vector<Abstract::Export> &AbstractBinary::getExports() const {
    return m_exports;
}

const std::vector<Abstract::Import> &AbstractBinary::getImports() const {
    return m_imports;
}

const std::vector<Abstract::Relocation> &AbstractBinary::getRelocations() const {
    return m_relocations;
}

const std::vector<Abstract::String> &AbstractBinary::getStrings() const {
    return m_strings;
}

const std::vector<std::string> &AbstractBinary::getEnvironmentVariables() const {
    return m_environment;
}

const std::vector<std::string> &AbstractBinary::getLibraryPaths() const {
    return m_dynamic_linker_paths;
}

const std::vector<std::string> &AbstractBinary::getLinkerCommands() const {
    return m_linker_commands;
}

const std::string &AbstractBinary::getLinker() const {
    return m_linker;
}

const std::string &AbstractBinary::getVersion() const {
    return m_version;
}

const std::string &AbstractBinary::getUniqueId() const {
    return m_unique_id;
}

AbstractBinary *AbstractBinary::create(std::string path) {
    if (!path.size()) {
        LOG_ERR("Invalid path");
        return nullptr;
    }

    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        LOG_ERR("Could not open file '%s'", path.c_str());
        return nullptr;
    }

    constexpr size_t size = 4096;
    uint8_t memory[size] = { 0 };

    if (read(fd, memory, size) <= 0) {
        LOG_ERR("Failed reading file contents.");
        close(fd);
        return nullptr;
    }

    close(fd);

    if (FatBinary::check(memory, size)) {
        LOG_DEBUG("Found a fat mach-o binary");
        return new FatBinary;
    }

    if (MachoBinary::check(memory, size)) {
        LOG_DEBUG("Found a mach-o binary");
        return new MachoBinary;
    }

    return nullptr;
}

// Create a new binary by reading the file pointer by 'path'.
bool AbstractBinary::load(const std::string &path) {
    if (!path.size()) {
        LOG_ERR("Invalid path");
        return false;
    }

    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        LOG_ERR("Could not open file '%s'", path.c_str());
        return false;
    }

    struct stat file_stats;
    if (fstat(fd, &file_stats) < 0) {
        LOG_ERR("Could not open fstat '%s'", path.c_str());
        close(fd);
        return false;
    }

    m_path = path;
    m_size = file_stats.st_size;
    m_memory = static_cast<unsigned char *>(mmap(nullptr, m_size, PROT_READ | PROT_WRITE, MAP_FILE | MAP_PRIVATE, fd, 0));
    if (m_memory == MAP_FAILED) {
        LOG_ERR("Could not open mmap '%s'", path.c_str());
        close(fd);
        return false;
    }

    m_data = MemoryMap(m_memory, m_size);
    m_unmap = true;

    close(fd);

    return true;
}

// Create a new binary by reading the file located at 'memory'.
bool AbstractBinary::load(unsigned char *memory, size_t size) {
    if (!memory || !size) {
        return false;
    }

    m_size = size;
    m_unmap = false;
    m_path = "(loaded from memory)";
    m_memory = memory;

    m_data = MemoryMap(m_memory, m_size);

    return true;
}

// Free any used resources.
bool AbstractBinary::unload() {
    if (m_unmap && m_memory) {
        if (munmap(m_memory, m_size) < 0) {
            return false;
        }
    }

    return true;
}
