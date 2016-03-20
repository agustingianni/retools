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
#include "debug.h"

// Create a new binary by reading the file pointer by 'path'.
bool AbstractBinary::load(const std::string &path) {
    if (!path.size()) {
        LOG_ERR("Invalid path");
        return false;
    }

    m_path = path;

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

    m_size = file_stats.st_size;
    m_memory = static_cast<unsigned char *>(mmap(nullptr, m_size, PROT_READ | PROT_WRITE, MAP_FILE | MAP_PRIVATE, fd, 0));
    if (m_memory == MAP_FAILED) {
        LOG_ERR("Could not open mmap '%s'", path.c_str());
        close(fd);
        return false;
    }

    m_data = new MemoryMap(m_memory, m_size);
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

    m_data = new MemoryMap(m_memory, m_size);

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
