/*
 * FatBinary.cpp
 *
 *  Created on: Jul 16, 2015
 *      Author: anon
 */

#include "Swap.h"
#include "FatBinary.h"
#include "MachoBinary.h"
#include "debug.h"

bool FatBinary::init() {
	// Readh the fat header.
	auto header = m_data->offset<fat_header>(0);
	if (!header) {
		LOG_ERR("Could not get a reference to the fat header");
		return false;
	}

	m_header = *header;

	// Set generic types for the details of the binary.
	m_binary_type = BinaryType::Collection;
	m_address_space_size = AddressSpaceSize::MULTIPLE;
	m_binary_arch = BinaryArch::MULTIPLE;
	m_binary_format = BinaryFormat::FAT;

	switch (m_header.magic) {
	case FAT_MAGIC:
		m_endianness = BinaryEndianness::LITTLE;
		LOG_DEBUG("Little endian");
		break;

	case FAT_CIGAM:
		m_endianness = BinaryEndianness::BIG;
		LOG_DEBUG("Big endian");
		break;

	default:
		LOG_ERR("Invalid fat magic number 0x%.8x", m_header.magic);
		return false;
	}

	swap_if(needs_swap(), &m_header);
	LOG_DEBUG("magic 0x%.8x nfat_arch = 0x%.8x", m_header.magic, m_header.nfat_arch);

	// Read the fat archs array.
	auto archs = m_data->pointer<fat_arch>(header + 1, sizeof(fat_arch) * m_header.nfat_arch);
	if (!archs) {
		LOG_ERR("Could not get a reference to the fat_arch array.");
		return false;
	}

	m_archs.assign(archs, archs + m_header.nfat_arch);

	// Change endianness of the fat_arch's if necessary.
	swap_if(needs_swap(), &m_archs[0], m_header.nfat_arch);

	for (unsigned i = 0; i < m_header.nfat_arch; i++) {
		LOG_DEBUG("Loading file %u of %u", i, m_header.nfat_arch);
		LOG_DEBUG("cputype = %.8x cpusubtype = %.8x offset = %.8x size = %.8x align = %.8x",
				m_archs[i].cputype, m_archs[i].cpusubtype, m_archs[i].offset, m_archs[i].size, m_archs[i].align);

		auto binary_mem = m_data->offset<unsigned char>(m_archs[i].offset, m_archs[i].size);
		if (!binary_mem) {
			LOG_ERR("Could not get a reference to the %uth mach-o binary", i);
			continue;
		}

		MachoBinary *macho_binary = new MachoBinary(nullptr);
		if (!macho_binary->load(binary_mem, m_archs[i].size)) {
			LOG_ERR("Could not load the %uth mach-o binary", i);
			continue;
		}

		if (!macho_binary->init()) {
			LOG_ERR("Could not initialize mach-o binary %u", i);
			continue;
		}

		LOG_DEBUG("Loaded binary number %u", i);
		m_binaries.push_back(macho_binary);
	}

	return true;
}
