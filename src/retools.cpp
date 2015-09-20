#include <iostream>

#include "macho/MachoBinary.h"
#include "macho/FatBinary.h"
#include "AbstractBinary.h"
#include "macho/MachoBinaryVisitor.h"

using namespace std;

// Que quiero hacer?
// Principalmente quiero que la libreria sea flexible para que pueda ser utilizada para varias cosas.
// En particular, para hacer una tool de inspeccion de mach-o y tambien como un parser de mach-o para
// el disassembler. Los dos escenarios son propicios para implementar algo tipo observer, donde cada
// load command tiene su handler. El problema llega cuando queremos informacion de las sections. Que
// es lo que hacemos? Las sections estan dentro de un segment o segment_64. Para llamar a los handlers
// de las sections deberiamos tener una forma de inspeccionar los segment's.
class MachoBinaryPrinterVisitor: public MachoBinaryVisitor {
public:
    virtual ~MachoBinaryPrinterVisitor() = default;

    virtual bool handle_mach_header(const struct mach_header &header) override {
    	LOG_DEBUG("CACA -> %s", __PRETTY_FUNCTION__);
    	return true;
    }

    virtual bool handle_mach_header(const struct mach_header_64 &header) override {
    	LOG_DEBUG("CACA -> %s", __PRETTY_FUNCTION__);
    	return true;
    }
};

int main(int argc, char **argv) {
	MachoBinary binary { new MachoBinaryPrinterVisitor() };
	if (!binary.load(argv[1])) {
		cerr << "Could not open mach-o binary" << endl;
		return -1;
	}

	if (!binary.init()) {
		cerr << "Could not initialize mach-o binary" << endl;
		binary.unload();
		return -1;
	}

	cout << "Welcome to reTools!" << endl;
	return 0;

	if (argc < 2) {
		cerr << "I need a binary to analyze" << endl;
		return -1;
	}

	FatBinary fat_binary { };
	if (!fat_binary.load(argv[1])) {
		cerr << "Could not open mach-o binary" << endl;
		return -1;
	}

	if (!fat_binary.init()) {
		cerr << "Could not initialize mach-o binary" << endl;
		fat_binary.unload();
		return -1;
	}

	// For each of the underlying binaries.
	for (AbstractBinary *sub_binary : fat_binary.binaries()) {
	}

	return 0;
}
