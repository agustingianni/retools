def get_size(input):
    s = 0
    for e in input.split():
        if not "#" in e:
            s += len(e)

        else:
            s += int(e.split("#")[1])

    return "eSize32" if s == 32 else "eSize16"

def get_value(input):
    r = "0b"
    for e in input.split():
        if not "#" in e:
            r += e

        else:
            r += "0" * int(e.split("#")[1])

    return int(r, 2)

def get_mask(input):
    r = ""
    for e in input.split():
        if not "#" in e:
            r += "1" * len(e)
        else:
            r += "0" * int(e.split("#")[1])

    # If we are a 16 bit instruction we need to pad it with 0xffff
    if len(r) == 16:
        r = "1111111111111111" + r

    r = "0b" + r

    return int(r, 2)
