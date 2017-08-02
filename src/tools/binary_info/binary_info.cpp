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
#include "abstract/Segment.h"

using namespace std;

int main(int argc, char** argv)
{
    if (argc < 2) {
        cerr << "Usage: ./" << argv[0] << " [file_path]" << endl;
        return -1;
    }

    string filename{ string(argv[1]) };

    // Get an instance for the correct binary type.
    AbstractBinary* binary = AbstractBinary::create(filename);
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

    for (AbstractBinary* cur : binary->binaries()) {
        cout << endl;
        cout << "Current binary:" << endl;

        cout << "  Linker: " << cur->getLinker() << endl;
        cout << "  Version: " << cur->getVersion() << endl;
        cout << "  UID: " << cur->getUniqueId() << endl;

        if (!cur->getEnvironmentVariables().empty()) {
            cout << "  Environment variables:" << endl;
            for (auto var : cur->getEnvironmentVariables()) {
                cout << "    variable:" << var << endl;
            }
        }

        if (!cur->getLibraryPaths().empty()) {
            cout << "  Library paths:" << endl;
            for (auto path : cur->getLibraryPaths()) {
                cout << "    path: " << path << endl;
            }
        }

        if (!cur->getLinkerCommands().empty()) {
            cout << "  Linker command:" << endl;
            for (auto command : cur->getLinkerCommands()) {
                cout << "    command: " << command << endl;
            }
        }

        if (!cur->getEntryPoints().empty()) {
            cout << "  Entry points:" << endl;
            for (auto ep : cur->getEntryPoints()) {
                cout << "    entry: " << reinterpret_cast<void*>(ep.getValue()) << endl;
            }
        }

        if (!cur->getLibraries().empty()) {
            cout << "  Libraries:" << endl;
            for (auto lib : cur->getLibraries()) {
                cout << "    lib: " << lib.getPath() << endl;
            }
        }

        if (!cur->getStrings().empty()) {
            cout << "  Strings:" << endl;
            for (auto val : cur->getStrings()) {
                // Replace new lines with its escaped representation.
                auto clean_str = val.getString();
                clean_str.erase(std::remove(clean_str.begin(), clean_str.end(), '\n'), clean_str.end());
                cout << "    val: " << clean_str << endl;
            }
        }

        if (!cur->getSymbols().empty()) {
            cout << "  Symbols:" << endl;
            for (auto sym : cur->getSymbols()) {
                cout << "    sym: " << sym.getName() << " @ " << reinterpret_cast<void*>(sym.getAddress()) << endl;
            }
        }

        if (!cur->getDataInCode().empty()) {
            cout << "  Data in code definitions:" << endl;
            for (auto data : cur->getDataInCode()) {
                cout << "    data: " << data.getDescription() << endl;
            }
        }

        for (const Abstract::Segment& segment : cur->getSegments()) {
            cout << "  Segment:" << endl;
            cout << "    address : " << (void*)segment.getAddress() << endl;
            cout << "    size    : " << (void*)segment.getInMemorySize() << endl;
            cout << "    perm    : " << SegmentPermission::toString(segment.getPermission()) << endl;
        }
    }

    return 0;
}
