/*
 * libemulation.cpp
 *
 *  Created on: Jan 15, 2017
 *      Author: anon
 */

#include <boost/python.hpp>

#include <arm/ARMArch.h>
#include <arm/ARMContext.h>
#include <arm/ARMEmulator.h>
#include <memory/Memory.h>

using namespace Memory;
using namespace Emulator;
using namespace boost::python;
using namespace std;

BOOST_PYTHON_MODULE(emulator) {
    class_<AbstractMemory, boost::noncopyable>("AbstractMemory", no_init)
        .def("protect", &AbstractMemory::protect)
        .def("unmap", &AbstractMemory::unmap)
        .def("map", &AbstractMemory::map)
        .def("read", &AbstractMemory::read)
        .def("write", &AbstractMemory::write);

    class_<ConcreteMemory, bases<AbstractMemory>>("ConcreteMemory");

    class_<ZeroMemoryMap, bases<AbstractMemory>>("ZeroMemoryMap");

	class_<ARMContext>("ARMContext")
        .def(init<AbstractMemory *>())
		.def("getCurrentInstructionAddress", &ARMContext::getCurrentInstructionAddress)
        .def("getCoreRegisters", &ARMContext::getCoreRegisters)
        .def("getDoubleRegisters", &ARMContext::getDoubleRegisters)
        .def("setCoreRegisters", &ARMContext::setCoreRegisters)
        .def("setDoubleRegisters", &ARMContext::setDoubleRegisters)
        .def("readMemory", &ARMContext::readMemory)
        .def("writeMemory", &ARMContext::writeMemory);

	class_<ARMEmulator>("ARMEmulator", init<ARMContext *, AbstractMemory *, ARMMode, ARMVariants>())
		.def("start", &ARMEmulator::start)
        .def("getContext", &ARMEmulator::getContext, return_internal_reference<>())
        .def("setMode", &ARMEmulator::setMode);
}
