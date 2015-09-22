import os
import sys
import json
import subprocess
from pprint import pprint

PATH_BUILD_DIR = os.path.abspath("../build/")
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
    retools = retools.replace("adr", "add")

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
    darm = re.sub(ur'#0x0\b', "#0", darm)

    # From 'ldrsbt r5, [r0, #0]' -> ldrsbt r5, [r0]
    retools = re.sub(ur', #0]', "]", retools)
    capstone = re.sub(ur', #0]', "]", capstone)

    # #-0x0 -> #-0
    retools = re.sub(ur'#-0x0', "#-0", retools)
    capstone = re.sub(ur'#-0x0', "#-0", capstone)

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

def process_instruction_fuzz_tests(in_file, start, end):
    json_data = open(in_file)
    data = json.load(json_data)
    i = start - 1

    print "Checking test in %s mode" % data["mode"]

    for test in data["tests"]:
        i += 1

        name = test["name"]
        encoding = test["encoding"]
        mask = test["mask"]
        value = test["value"]
        size = test["size"]

        results = test["results"]

        print "Testing entry %4d for '%-30s' with encoding %s 0x%.8x, 0x%.8x" % (i, name, encoding, mask, value)

        n_errors = 0
        n_ok = 0
        n_skip = 0

        if name in ["BFC", "BFI", "CDP, CDP2", "POP (ARM)", "PUSH", "STC, STC2",
            "LDC, LDC2 (immediate)", "LDC, LDC2 (literal)", "ADD (SP plus immediate)",
            "ADR", "POP (Thumb)"]:
            print "  n_ok=%d n_error=%d n_skip=%d (skipped)" % (n_ok, n_errors, n_skip)
            print
            continue

        printed_header = False

        for result in results:
            retools = result["reto"]
            darm = result["darm"]
            capstone = result["caps"]
            opcode = result["opcode"]

            retools, capstone, darm = __compare__(retools, capstone, darm)
            ret = retools == capstone or retools == darm

            # If retools says that this is unpredictable, it certainly is.
            if retools in ["unpredictableinstruction", "undefinedinstruction", "unknown"]:
                n_skip += 1
                continue

            if not ret:
                n_errors += 1
                if not printed_header:
                    printed_header = True
                    print "Entry %d for '%s' with encoding %s 0x%.8x, 0x%.8x" % (i, name, encoding, mask, value)

                if n_errors < 10:
                    print "  opcode: 0x%.8x %40s %s" % (opcode, retools, result["decoder"])
                    print "  opcode: 0x%.8x %40s" % (opcode, capstone)
                    print
            else:
                n_ok += 1

        print "  n_ok=%d n_error=%d n_skip=%d" % (n_ok, n_errors, n_skip)
        print

    json_data.close()

n = int(sys.argv[1])
start = int(sys.argv[2])
end = int(sys.argv[3])
mode = 1

test_instruction_fuzz(n, start, end, mode, PATH_TESTS_JSON)
process_instruction_fuzz_tests(PATH_TESTS_JSON, start, end)
