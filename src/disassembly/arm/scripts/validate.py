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
convert()