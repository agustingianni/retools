#include <iostream>

#include "macho/MachoBinary.h"

using namespace std;

int main(int argc, char **argv) {
	if (argc < 2) {
		cerr << "I need a binary to analyze" << endl;
		return -1;
	}

	MachoBinary binary { };

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
}
