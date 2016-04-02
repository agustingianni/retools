/*
 * ARMDisassembler.cpp
 *
 *  Created on: Aug 25, 2014
 *      Author: anon
 */

#include "arm/ARMDisassembler.h"
#include "arm/ARMUtilities.h"
#include "arm/ARMArch.h"
#include "arm/gen/ARMDecodingTable.h"
#include "Utilities.h"

#include <functional>
#include <iostream>

using namespace std;
using namespace Disassembler;

namespace Disassembler {
    ARMDisassembler::ARMDisassembler(ARMVariants variant) :
        m_variant(variant) {
        m_decoder = new ARMDecoder(m_variant);
    }

    std::shared_ptr<ARMInstruction> ARMDisassembler::disassemble(uint32_t op_code, ARMMode mode) {
        return m_decoder->decode(op_code, mode);
    }
} /* namespace Disassembler */
