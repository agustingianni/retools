import os
import re
import sys
import logging
import argparse

DEBUG = False

def instruction_decoder_name(ins_name):
    ins_name = re.sub('[\s\(\)\-\,\/\#]', '_', ins_name)
    ins_name = ins_name.replace("__", "_")
    ins_name = ins_name.rstrip("_")
    return "interpret_" + ins_name.lower()

test_code = \
"""if ConditionPassed() then
    EncodingSpecificOperations();
    (result, carry, overflow) = AddWithCarry(R[n], imm32, APSR.C);
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
    endif

    if setflags then
        APSR.N = result<31>;
        APSR.Z = IsZeroBit(result);
        APSR.C = carry;
        APSR.V = overflow;
    endif
endif"""

def create_interpreter(interpreter_name_h, interpreter_name_cpp):
    """
    Create ARMInterpreter.h and ARMInterpreter.cpp.
    """
    import ARMv7Parser
    from ARVv7OperationSpec import instructions

    with open(interpreter_name_h, "w") as fd:
        header = ""
        header += '#include "arm/ARMContext.h"\n\n' 
        header += "class ARMInterpreter {\n"
        header += "    ARMInterpreter() {};\n\n"
        
        fd.write(header)
        for instruction in instructions:
            ins_name = instruction["name"]
            fd.write("    bool %s(ARMContext &ctxt);\n" % instruction_decoder_name(ins_name))
        
        fd.write("};\n")
    
    with open(interpreter_name_cpp, "w") as fd:
        header = ""
        header += '#include "gen/ARMInterpreter.h"\n'
        header += '#include "arm/ARMContext.h"\n\n' 
        
        fd.write(header)
        i = 0
        for instruction in instructions:
            if i < 0:
                i += 1
                continue

            ins_name = instruction["name"]
            logging.info("Doing instruction '%s'" % ins_name)

            fd.write("bool ARMInterpreter::%s(ARMContext &ctxt) {\n" % instruction_decoder_name(ins_name))
            
            ins_operation = instruction["operation"]
            # ins_operation = test_code

            # Remove empty lines, because I suck at parsing.
            ins_operation = os.linesep.join([s for s in ins_operation.splitlines() if not re.match(r'^\s*$', s)])
            
            try:
                ret = ARMv7Parser.program.parseString(ins_operation, parseAll=True)
            except Exception, e:
                print e
                print "-" * 80
                print ins_name
                print "-" * 80

                print "Error: col=%d loc=%d parserElement=%s" % (e.col, e.loc, e.parserElement)
                print "    markInputline -> " + repr(e.markInputline())
                print

                class bcolors:
                    HEADER = '\033[95m'
                    OKBLUE = '\033[94m'
                    OKGREEN = '\033[92m'
                    WARNING = '\033[93m'
                    FAIL = '\033[91m'
                    ENDC = '\033[0m'
                    BOLD = '\033[1m'
                    UNDERLINE = '\033[4m'

                j = 1
                for line in ins_operation.splitlines():
                    if j == e.lineno:
                        print bcolors.OKGREEN + ("%2d: %s" % (j, line[:e.col-1])) + bcolors.FAIL + ("%s" % (line[e.col-1:])) + bcolors.ENDC
                    
                    else:    
                        print "%2d: %s" % (j, line)

                    j += 1

                print "-" * 80
                print e
                print "# ", i, " of ", len(instructions)
                return False

            i += 1
            
            fd.write("    return true;\n")
            fd.write("};\n")
            fd.write("\n")
            
            # return True
            
    return True

def main():
    #parser = ARMv7Parser.InstructionFormatParser()
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description='Generator.')
    parser.add_argument("--gendir", default="../gen", help="Directory where the generated files will be placed.")
    parser.add_argument("--geninterpreter", action='store_true', help="Generate ARMInterpreter[.h|.cpp]")
    parser.add_argument("--debug", action='store_true', help="Enable debugging information, just for developers.")

    args = parser.parse_args()

    DEBUG = args.debug
    gen_decoder = args.geninterpreter

    if not gen_decoder:
        logging.warn("Nothing to generate, please choose one option")
        parser.print_help()
        return

    # Filenames and path's.
    gen_dir = os.path.abspath(args.gendir)
    interpreter_name_h = os.path.join(gen_dir, "ARMInterpreter.h")
    interpreter_name_cpp = os.path.join(gen_dir, "ARMInterpreter.cpp")

    if not os.path.exists(gen_dir):
        logging.info("Directory '%s' does not exist, creating it ..." % gen_dir)
        os.makedirs(gen_dir)

    logging.info("Placing all the generated files in '%s'." % gen_dir)

    # We've chosen to regenerate the ARM interpreter.
    if gen_decoder:
        if os.path.exists(interpreter_name_h):
            os.remove(interpreter_name_h)

        if os.path.exists(interpreter_name_cpp):
            os.remove(interpreter_name_cpp)

        logging.info("Creating decoders at '%s'." % interpreter_name_h)
        logging.info("Creating decoders at '%s'." % interpreter_name_cpp)
        
        if not create_interpreter(interpreter_name_h, interpreter_name_cpp):
            logging.error("Could not create the interpreter.")
            return False

    logging.info("Finished creating autogenerated stubs.")

    return True

if __name__ == '__main__':
    main()
