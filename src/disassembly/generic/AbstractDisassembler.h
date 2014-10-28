/*
 * AbstractDisassembler.h
 *
 *  Created on: Aug 25, 2014
 *      Author: anon
 */

#ifndef ABSTRACTDISASSEMBLER_H_
#define ABSTRACTDISASSEMBLER_H_

#include <vector>
#include <deque>

#include "disassembly/generic/Instruction.h"

namespace Disassembler {

	class AbstractDisassembler {
		public:
			AbstractDisassembler();
			virtual ~AbstractDisassembler();

			virtual std::deque<Instruction> disassemble(std::vector<uint8_t> buffer) = 0;
	};

} /* namespace Disassembler */

#endif /* ABSTRACTDISASSEMBLER_H_ */
