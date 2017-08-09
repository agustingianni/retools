import os
import sys
import json
import subprocess
from pprint import pprint

PATH_BUILD_DIR = os.path.abspath("../../../build/")
PATH_INSTRUCTION_FUZZ_BIN = os.path.join(PATH_BUILD_DIR, "tests/instruction_fuzz")
PATH_TESTS_JSON = os.path.join(PATH_BUILD_DIR, "tests.json")

def test_instruction_fuzz(number, start, finish, mode, out_file):
    """
    @number: Number of cases generated for each instruction.
    @start: Start number in the decoding table.
    @finish: End number in the decoding table. If it is equal to the
             start number then we test from (start, table_end).
             If the end is bigger than table_end, we truncate it.
    @mode: Can be 0 for ARM  or 1 for THUMB.
    """
    subprocess.call([PATH_INSTRUCTION_FUZZ_BIN, str(number), str(start), str(finish), str(mode), out_file])

def __compare__(retools, capstone, darm):
    # Normalize the case and strip leading and trailing whitespaces.
    retools = retools.lower().strip()
    capstone = capstone.lower().strip()
    darm = darm.lower().strip()

    # Remove a bad comma at the end, this will be fixed later.
    if retools[-1] == ",":
        retools = retools[:-1]

    # Remove ', lsl #0'
    retools = retools.replace(", lsl #0", "")

    # Normalize the register names.
    replace = [("r9", "sb"), ("r10", "sl"), ("r11", "fp"), ("r12", "ip"), ("r13", "sp"), ("r14", "ls"), ("r15", "pc")]
    for a, b in replace:
        retools = retools.replace(a, b)
        capstone = capstone.replace(a, b)
        darm = darm.replace(a, b)

    # Replace decimal numbers with hex numbers.
    import re
    pattern = re.compile(ur'#([1-9][0-9]*)')

    for match in pattern.findall(retools):
        a = "#%s" % match
        b = "#0x%x" % int(match)
        retools = retools.replace(a, b, 1)

    for match in pattern.findall(capstone):
        a = "#%s" % match
        b = "#0x%x" % int(match)
        capstone = capstone.replace(a, b, 1)

    for match in pattern.findall(darm):
        a = "#%s" % int(match)
        b = "#0x%x" % int(match)
        darm = darm.replace(a, b, 1)

    # Replace all the negative hex values for positive hex values.
    pattern = re.compile(ur'#(-0x[1-9a-f][0-9a-f]*)')
    for match in pattern.findall(retools):
        a = "#%s" % match
        b = "#0x%x" % (int(match, 16) & 0xffffffff)
        retools = retools.replace(a, b)

    for match in pattern.findall(capstone):
        a = "#%s" % match
        b = "#0x%x" % (int(match, 16) & 0xffffffff)
        capstone = capstone.replace(a, b)

    for match in pattern.findall(darm):
        a = "#%s" % match
        b = "#0x%x" % (int(match, 16) & 0xffffffff)
        darm = darm.replace(a, b)

    # Replace all the negative dec values for positive hex values.
    pattern = re.compile(ur'#(-[1-9][0-9]*)')
    for match in pattern.findall(retools):
        a = "#%s" % match
        b = "#0x%x" % (int(match) & 0xffffffff)
        retools = retools.replace(a, b)

    for match in pattern.findall(capstone):
        a = "#%s" % match
        b = "#0x%x" % (int(match) & 0xffffffff)
        capstone = capstone.replace(a, b)

    for match in pattern.findall(darm):
        a = "#%s" % match
        b = "#0x%x" % (int(match) & 0xffffffff)
        darm = darm.replace(a, b)

    # Replace single zeros.
    retools = re.sub(ur'#0x0\b', "#0", retools)
    capstone = re.sub(ur'#0x0\b', "#0", capstone)

    # From '#-0x0' -> '#-0'
    retools = re.sub(ur'#-0x0', "#-0", retools)
    capstone = re.sub(ur'#-0x0', "#-0", capstone)

    # From 'ldrsbt r5, [r0, #0]' -> 'ldrsbt r5, [r0]'
    retools = re.sub(ur', #0]', "]", retools)
    capstone = re.sub(ur', #0]', "]", capstone)

    # From 'strb r8, [r3, #-0]' -> 'strb r8, [r3]'
    retools = re.sub(ur', #-0]', "]", retools)
    capstone = re.sub(ur', #-0]', "]", capstone)

    # ldmia -> ldm
    retools = re.sub(ur'ldmia', "ldm", retools)
    capstone = re.sub(ur'ldmia', "ldm", capstone)

    # stmia -> stm
    retools = re.sub(ur'stmia', "stm", retools)
    capstone = re.sub(ur'stmia', "stm", capstone)

    # vldm -> fldmx
    retools = re.sub(ur'vldm', "fldmx", retools)
    capstone = re.sub(ur'vldm', "fldmx", capstone)

    # vstm -> fstmx
    retools = re.sub(ur'vstm', "fstmx", retools)
    capstone = re.sub(ur'vstm', "fstmx", capstone)

    # mvnscs -> mvnshs
    darm = re.sub(ur'mvnscs', "mvnshs", darm)
    darm = re.sub(ur'movscs', "movshs", darm)
    darm = re.sub(ur'lsrscs', "lsrshs", darm)
    darm = re.sub(ur'rorscs', "rorshs", darm)
    darm = re.sub(ur'asrscs', "asrshs", darm)
    darm = re.sub(ur'pushcs', "pushhs", darm)

    # Normalize the wide operator.
    try:
        opname_r, rest_r = retools[:retools.index(" ")], retools[retools.index(" "):]
        opname_c, rest_c = capstone[:capstone.index(" ")], capstone[capstone.index(" "):]

        if opname_r.endswith(".w"):
            opname_r = opname_r[:-2]

        elif opname_r.endswith("w"):
            opname_r = opname_r[:-1]

        if opname_c.endswith(".w"):
            opname_c = opname_c[:-2]

        elif opname_c.endswith("w"):
            opname_c = opname_c[:-1]

        retools = opname_r + rest_r
        capstone = opname_c + rest_c

    except ValueError:
        pass

    return retools, capstone, darm

def is_invalid_or_unpredictable(instruction):
    return ("unpredictableinstruction" in instruction or "undefinedinstruction" in instruction)

def process_instruction_fuzz_tests(in_file, start, end):
    json_data = open(in_file)
    data = json.load(json_data)
    i = start - 1

    # These are tests that we have manually verified that are correct.
    arm_ignored_tests = []
    arm_ignored_tests.append("CDP, CDP2")                  # Reason: capstone fails to disassemble this.
    arm_ignored_tests.append("ERET")                       # Reason: capstone does not disassemble this.
    arm_ignored_tests.append("HVC")                        # Reason: capstone does not disassemble this.
    arm_ignored_tests.append("LDR (immediate, ARM)")       # Reason: capstone fails to disassemble this.
    arm_ignored_tests.append("LDRB (immediate, ARM)")      # Reason: capstone fails to disassemble this.
    arm_ignored_tests.append("LDRD (immediate)")           # Reason: capstone fails to disassemble this.
    arm_ignored_tests.append("LDRH (immediate, ARM)")      # Reason: capstone fails to disassemble this.
    arm_ignored_tests.append("LDRSB (immediate)")          # Reason: capstone fails to disassemble this.
    arm_ignored_tests.append("LDRSH (immediate)")          # Reason: capstone fails to disassemble this.
    arm_ignored_tests.append("MCR, MCR2")                  # Reason: capstone fails to disassemble this.
    arm_ignored_tests.append("MRS (Banked register)")      # Reason: capstone does not disassemble this.

    thumb_ignored_tests = []
    thumb_ignored_tests.append("B")                        # Reason: capstone fails to disassemble this.
    thumb_ignored_tests.append("CDP, CDP2")                # Reason: capstone fails to disassemble this.
    thumb_ignored_tests.append("CPS (Thumb)")              # Reason: capstone fails to disassemble this.
    thumb_ignored_tests.append("ERET")                     # Reason: capstone does not disassemble this.
    thumb_ignored_tests.append("HVC")                      # Reason: capstone does not disassemble this.
    thumb_ignored_tests.append("IT")                       # Reason: capstone fails to disassemble this.
    thumb_ignored_tests.append("LDRH (immediate, Thumb)")  # Reason: capstone fails to disassemble this.
    thumb_ignored_tests.append("LDRH (literal)")           # Reason: capstone fails to disassemble this.
    thumb_ignored_tests.append("MRS (Banked register)")    # Reason: capstone does not disassemble this.
    thumb_ignored_tests.append("POP (Thumb)")              # Reason: capstone represents pop as a ldr.
    thumb_ignored_tests.append("PUSH")                     # Reason: capstone represents push as a str.
    thumb_ignored_tests.append("SMC (previously SMI)")     # Reason: capstone does not disassemble this.
    thumb_ignored_tests.append("SMC")                      # Reason: capstone does not disassemble this.
    thumb_ignored_tests.append("SSAT")                     # Reason: capstone fails to disassemble this.
    thumb_ignored_tests.append("STC, STC2")                # Reason: capstone fails to disassemble this.

    ignored_tests = arm_ignored_tests
    if data["mode"] == "THUMB":
        ignored_tests = thumb_ignored_tests

    print "Checking test in %s mode" % data["mode"]

    for test in data["tests"]:
        i += 1

        name = test["name"]
        encoding = test["encoding"]
        mask = test["mask"]
        value = test["value"]
        size = test["size"]

        results = test["results"]

        if name in ignored_tests:
            continue

        n_errors = 0
        n_ok = 0
        n_skip = 0

        printed_header = False

        for result in results:
            retools = result["reto"]
            darm = result["darm"]
            capstone = result["caps"]
            opcode = result["opcode"]

            retools, capstone, darm = __compare__(retools, capstone, darm)
            ret = retools == capstone or retools == darm

            # VMRS et all are not disassembled by capstone.
            if "custom_reg" in retools or "vpop" in retools or "vpush" in retools:
                n_ok += 1
                continue

            # If retools says that this is unpredictable, it certainly is.
            if is_invalid_or_unpredictable(retools):
                n_ok += 1
                continue

                # Capstone agrees.
                if capstone == "invalid":
                    n_ok += 1
                    continue

                if not printed_header:
                    printed_header = True
                    print "Entry %d for '%s' with encoding %s 0x%.8x, 0x%.8x" % (i, name, encoding, mask, value)

                n_skip += 1
                print "  opcode: 0x%.8x %40s" % (opcode, retools)
                print "  opcode: 0x%.8x %40s" % (opcode, capstone)
                print
                continue

            if retools == "unknown":
                # Capstone agrees.
                if capstone == "invalid":
                    n_ok += 1
                    continue

                if not printed_header:
                    printed_header = True
                    print "Entry %d for '%s' with encoding %s 0x%.8x, 0x%.8x" % (i, name, encoding, mask, value)

                n_skip += 1
                if n_skip < 10:
                    print "  opcode: 0x%.8x %40s" % (opcode, retools)
                    print "  opcode: 0x%.8x %40s" % (opcode, capstone)
                    print

                continue

            if not ret:
                n_errors += 1
                if not printed_header:
                    printed_header = True
                    print "Entry %d for '%s' with encoding %s 0x%.8x, 0x%.8x" % (i, name, encoding, mask, value)

                if n_errors < 20:
                    print "  opcode: 0x%.8x %40s %s" % (opcode, retools, result["decoder"])
                    print "  opcode: 0x%.8x %40s" % (opcode, capstone)
                    print
            else:
                n_ok += 1

        if n_errors != 0 or n_skip != 0:
            if not printed_header:
                printed_header = True
                print "Entry %d for '%s' with encoding %s 0x%.8x, 0x%.8x" % (i, name, encoding, mask, value)

            print "  n_ok=%d n_error=%d n_skip=%d" % (n_ok, n_errors, n_skip)
            print

    json_data.close()

n = int(sys.argv[1])
start = int(sys.argv[2])
end = int(sys.argv[3])
mode = 0

print "Testing instructions from %d to %d, %d times" % (start, end, n)
test_instruction_fuzz(n, start, end, mode, PATH_TESTS_JSON)
process_instruction_fuzz_tests(PATH_TESTS_JSON, start, end)
