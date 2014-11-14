"""
Script that uses the android toolchain to compile a small
file that contains the opcode that we want to disassemble
and then it calls objdump to disassemble it.

This is actually the easiest way to use libopcode. Fuck you
binutils.
"""
import tempfile
import subprocess
import os
import struct
import re
import sys

ANDROID_TOOLCHAIN_PATH = "/Users/anon/android-toolchain/bin/"
COMPILER = os.path.join(ANDROID_TOOLCHAIN_PATH, "arm-linux-androideabi-gcc")
DISASSEMBLER = os.path.join(ANDROID_TOOLCHAIN_PATH, "arm-linux-androideabi-objdump")

def to_inline_asm(opcode):
    bytes = ", ".join(map(lambda x: "0x%.2x" % ord(x), list(struct.pack("<L", opcode))))
    bytes = ".byte %s" % bytes
    return '__asm__ ("%s");' % bytes

def compile(file_name, compiler_flags=""):
    name, extension = os.path.splitext(file_name)
    name = "%s.o" % name

    subprocess.call("%s %s -o %s -c" % (COMPILER, file_name, name), shell=True)

    return name

def disassemble(op_code):
    file_name = "/tmp/test.c"
    with open(file_name, "w") as f:
        f.write(to_inline_asm(op_code))

    out_name = compile("/tmp/test.c")

    ret = subprocess.check_output([DISASSEMBLER, "-d", out_name])

    for line in ret.split("\n"):
        if "0:" in line:
            ret = " ".join(line.strip().split()[2:]).split(";")[0].strip()
            return ret

    os.unlink(file_name)
    os.unlink(out_name)

def normalize(input_str):
    pattern = "#[1-9a-f][0-9a-f]*"
    out = input_str
    for match in re.findall(pattern, input_str):
        try:
            out = out.replace(match, "#0x%x" % int(match[1:]))
        
        except ValueError:
            out = out.replace(match, "#0x%x" % int(match[1:], 16))
                
    return out

try:
    op_code = int(sys.argv[1]) if not "0x" in sys.argv[1] else int(sys.argv[1], 16)
    print normalize(disassemble(op_code))

except KeyboardInterrupt:
    print "interrupted"
