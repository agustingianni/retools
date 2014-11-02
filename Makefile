CXX = clang++
CFLAGS = -std=c++11 -Wall -O3 -Wno-unused-function

OBJS = retools
GENERATOR_SCRIPTS = src/disassembly/arm/scripts

all:
	$(CXX) $(CFLAGS) src/retools.cpp src/disassembly/arm/ARMDisassembler.cpp src/disassembly/generic/AbstractDisassembler.cpp -o retools -I src
	
clean:
	rm -f $(OBJS)

# Generate the decoding tables and the instruction decoders.
tables:
	python $(GENERATOR_SCRIPTS)/generator.py