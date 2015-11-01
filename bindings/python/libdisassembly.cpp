/*
 * libdisassembly.cpp
 *
 *  Created on: Sep 20, 2015
 *      Author: anon
 */

#include <memory>
#include <boost/python.hpp>
#include <iostream>

#include "arm/ARMDisassembler.h"
#include "arm/ARMArch.h"

using namespace Disassembler;
using namespace boost::python;
using namespace std;

BOOST_PYTHON_MODULE(disassembler) {
	enum_<ARMMode>("ARMMode")
		.value("ARMMode_ARM", ARMMode_ARM)
		.value("ARMMode_Thumb", ARMMode_Thumb)
		.value("ARMMode_Jazelle", ARMMode_Jazelle)
		.value("ARMMode_ThumbEE", ARMMode_ThumbEE)
		.value("ARMMode_Invalid", ARMMode_Invalid)
		.value("InstrSet_ARM", ARMMode_ARM)
		.value("InstrSet_Thumb", ARMMode_Thumb)
		.value("InstrSet_Jazelle", ARMMode_Jazelle)
		.value("InstrSet_ThumbEE", ARMMode_ThumbEE);

	enum_<ARMVariants>("ARMVariants")
		.value("ARMv4", ARMv4)
		.value("ARMv4T", ARMv4T)
		.value("ARMv4All", ARMv4All)
		.value("ARMv5T", ARMv5T)
		.value("ARMv5TE", ARMv5TE)
		.value("ARMv5TEJ", ARMv5TEJ)
		.value("ARMv5TEAll", ARMv5TEAll)
		.value("ARMv5TAll", ARMv5TAll)
		.value("ARMv6", ARMv6)
		.value("ARMv6K", ARMv6K)
		.value("ARMv6T2", ARMv6T2)
		.value("ARMv6All", ARMv6All)
		.value("ARMv7", ARMv7)
		.value("ARMv7S", ARMv7S)
		.value("ARMv7VE", ARMv7VE)
		.value("ARMv7R", ARMv7R)
		.value("ARMv7All", ARMv7All)
		.value("ARMv8", ARMv8)
		.value("ARMSecurityExtension", ARMSecurityExtension)
		.value("ARMvAll", ARMvAll);

	class_<ARMInstruction>("ARMInstruction")
		.def("__str__", &ARMInstruction::toString);

	class_<ARMDisassembler>("ARMDisassembler", init<ARMVariants>())
		.def("disassemble", &ARMDisassembler::disassemble);

	// This implements the translation from std::shared_ptr<ARMInstruction> to python.
	register_ptr_to_python<shared_ptr<ARMInstruction>>();
}
