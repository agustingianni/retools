#include <iostream>
#include <unicorn/unicorn.h>

#include "Utilities.h"

struct instruction_effects {
};

struct instruction_effects unicorn_emulate(uint32_t opcode, unsigned mode) {
}

struct instruction_effects retools_emulate(uint32_t opcode, unsigned mode) {
}

void test_arm(unsigned n, unsigned start, unsigned finish, FILE *file) {
}

void test_thumb(unsigned n, unsigned start, unsigned finish, FILE *file) {
}

int main(int argc, char **argv) {
    std::cout << "HOLA\n";
    return 0;
}