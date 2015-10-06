name = "ARMv7_Specification.txt"

def validate_decoding_length():
    i = 0
    skip = True
    for line in open(name):
        i += 1
        if line == "\n":
            skip = True
            continue

        if skip:
            skip = False
            continue

        s = 0
        for a in line[:-1].split()[1:]:
            if "#" in a:
                b, c = a.split("#")
                s += int(c)

            else:
                s += len(a)

        if not s in [16, 32]:
            print i
            print line[:-1], "->", s

def convert():
    entry_template = """{
    "name" : "%s",
    "encoding" : "%s",
    "version" : "",
    "format" : "",
    "pattern" : "%s",
    "decoder" : \"\"\"\"\"\"
}"""
    ins_name = None
    i = 0
    skip = True
    print "instructions = ["
    for line in open(name):
        i += 1
        if line == "\n":
            skip = True
            continue

        if skip:
            ins_name = line.strip()
            skip = False
            continue

        print entry_template % (ins_name, line[:2], line[3:].strip()), ",",

        if i == 10:
            break

    print "]"

def validate_binary_numbers():
    """
    Look for invalid binary numbers. The spec should use '00010101010' for
    binaries, but it sometimes skips the '' and uses just the binary number
    which is confusing.
    """
    import re
    regex = re.compile("[01][01]+")
    from ARMv7DecodingSpec import instructions
    for ins in instructions:
        for line in ins["decoder"].split("\n"):
            for res in regex.findall(line):
                idx = line.find(res)

                if line[idx - 1] != "'" and line[idx - 1] != '"':
                    print "//", ins["name"]
                    print "//", "=" * 80
                    print line, "// should have ", res
                    print "//", "=" * 80

def validate_thumb_and_conditional():
    from ARMv7DecodingSpec import instructions
    for ins in instructions:
        if "T" in ins["encoding"] and "<c>" in ins["format"] and not ("cond#4" in ins["pattern"]):
            print ins["name"]
            print ins["encoding"]
            print ins["format"]
            print "-" * 80
