/*
 * harness.cpp
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

#ifdef __AFL_LOOP
int main(int argc, char **argv) {
    string filename { string(argv[1]) };

    while(__AFL_LOOP(100000)) {
        unique_ptr<AbstractBinary> binary(AbstractBinary::create(filename));
        if (!binary || !binary->load(filename)) {
            continue;
        }

        if (!binary->init()) {
            binary->unload();
            continue;
        }
    }

    return 0;
}
#else
int main(int argc, char **argv) {
    string filename { string(argv[1]) };

    unique_ptr<AbstractBinary> binary(AbstractBinary::create(filename));
    if (!binary || !binary->load(filename)) {
        return -1;
    }

    if (!binary->init()) {
        binary->unload();
        return -1;
    }

    return 0;
}
#endif
