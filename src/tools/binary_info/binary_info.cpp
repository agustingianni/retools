/*
 * dis.cpp
 *
 *  Created on: Sep 20, 2015
 *      Author: anon
 */

#include <memory>
#include <string>
#include <cstdint>
#include <iostream>

#include "AbstractBinary.h"

using namespace std;

int main(int argc, char **argv) {
    if (argc < 2) {
        cerr << "Usage: ./" << argv[0] << " [file_path]" << endl;
        return -1;
    }

    string filename { string(argv[1]) };

    // Get an instance for the correct binary type.
    AbstractBinary *binary = AbstractBinary::create(filename);
    if (!binary) {
        cerr << "Could not open binary" << endl;
        return -1;
    }

    // Load the contents of the file.
    if (!binary->load(filename)) {
        cerr << "Could not load mach-o binary" << endl;
        return -1;
    }

    // Load the binary.
    if (!binary->init()) {
        cerr << "Could not initialize mach-o binary" << endl;
        binary->unload();
        return -1;
    }

    cout << "Initialized binary" << endl;

    return 0;
}
