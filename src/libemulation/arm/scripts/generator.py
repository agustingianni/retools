import os
import re
import json
import logging
import argparse

import ARMv7Parser
import ARVv7OperationSpec

DEBUG = False

def instruction_decoder_name(ins_name):
    ins_name = re.sub('[\s\(\)\-\,\/\#]', '_', ins_name)
    ins_name = ins_name.replace("__", "_")
    ins_name = ins_name.rstrip("_")
    return "interpret_" + ins_name.lower()

def create_interpreter(interpreter_name_h, interpreter_name_cpp, symbols_file):
    """
    Create ARMInterpreter.h and ARMInterpreter.cpp.
    """    
    # Load symbols file.
    with open(symbols_file, "r") as fd:
        symbols = json.load(fd)

    with open(interpreter_name_h, "w") as fd:
        header = ""
        header += '#include "arm/ARMContext.h"\n\n' 
        header += "class ARMInterpreter {\n"
        header += "    ARMInterpreter() {};\n\n"
        
        fd.write(header)
        for instruction in ARVv7OperationSpec.instructions:
            ins_name = instruction["name"]
            fd.write("    bool %s(ARMContext &ctx, const ARMInstruction &ins);\n" % instruction_decoder_name(ins_name))
        
        fd.write("};\n")
    
    with open(interpreter_name_cpp, "w") as fd:
        header = ""
        header += '#include "gen/ARMInterpreter.h"\n'
        header += '#include "arm/ARMContext.h"\n\n' 
        
        fd.write(header)
        i = 0
        for instruction in ARVv7OperationSpec.instructions:
            ins_name = instruction["name"]
            logging.info("Doing instruction '%s'" % ins_name)

            fd.write("bool ARMInterpreter::%s(ARMContext &ctx, const ARMInstruction &ins) {\n" % instruction_decoder_name(ins_name))
            
            ins_operation = instruction["operation"]

            # Remove empty lines, because I suck at parsing.
            ins_operation = os.linesep.join([s for s in ins_operation.splitlines() if not re.match(r'^\s*$', s)])
            
            try:
                program_ast = ARMv7Parser.program.parseString(ins_operation, parseAll=True)
                            
            except Exception, e:
                logging.error("-" * 80)
                logging.error(ins_name)
                logging.error("-" * 80)
                logging.error("Error: col=%d loc=%d parserElement=%s" % (e.col, e.loc, e.parserElement))

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
                        logging.error(bcolors.OKGREEN + ("%2d: %s" % (j, line[:e.col-1])) + bcolors.FAIL + ("%s" % (line[e.col-1:])) + bcolors.ENDC)
                    
                    else:    
                        logging.error("%2d: %s" % (j, line))

                    j += 1

                logging.error("-" * 80)
                logging.error(e)
                logging.error("# ", i, " of ", len(instructions), " to go ", len(ARVv7OperationSpec.instructions) - i)
                return False

            # Set the types for implicit things in the pseudocode.
            known_types = []

            # Set the types for known expressions.
            known_types.append({"name" : "ARMExpandImm",                     "type" : ("int", 32)})
            known_types.append({"name" : "ARMExpandImm_C",                   "type" : ("list", 2)})
            known_types.append({"name" : "AddWithCarry",                     "type" : ("list", 3)})
            known_types.append({"name" : "AdvSIMDExpandImm",                 "type" : ("int", 64)})
            known_types.append({"name" : "Align",                            "type" : ("int", 32)})
            known_types.append({"name" : "BigEndian",                        "type" : ("int", 1)})
            known_types.append({"name" : "BitCount",                         "type" : ("int", 32)})
            known_types.append({"name" : "ConditionPassed",                  "type" : ("int", 1)})
            known_types.append({"name" : "Coproc_Accepted",                  "type" : ("int", 1)})
            known_types.append({"name" : "Coproc_DoneLoading",               "type" : ("int", 1)})
            known_types.append({"name" : "Coproc_DoneStoring",               "type" : ("int", 1)})
            known_types.append({"name" : "Coproc_GetOneWord",                "type" : ("int", 1)})
            known_types.append({"name" : "Coproc_GetTwoWords",               "type" : ("list", 2)})
            known_types.append({"name" : "Coproc_GetTwoWords",               "type" : ("list", 2)})
            known_types.append({"name" : "Coproc_GetWordToStore",            "type" : ("int", 32)})
            known_types.append({"name" : "CurrentCond",                      "type" : ("int", 4)})
            known_types.append({"name" : "CurrentModeIsHyp",                 "type" : ("int", 1)})
            known_types.append({"name" : "CurrentModeIsNotUser",             "type" : ("int", 1)})
            known_types.append({"name" : "CurrentModeIsUserOrSystem",        "type" : ("int", 1)})
            known_types.append({"name" : "DecodeImmShift",                   "type" : ("list", 2)})
            known_types.append({"name" : "ELR_hyp",                          "type" : ("int", 32)})
            known_types.append({"name" : "FPCompare",                        "type" : ("list", 4)})
            known_types.append({"name" : "FPCompareEQ",                      "type" : ("int",  1)})
            known_types.append({"name" : "FPCompareGE",                      "type" : ("int", 1)})
            known_types.append({"name" : "FPCompareGT",                      "type" : ("int", 1)})
            known_types.append({"name" : "FPDoubleToSingle",                 "type" : ("int", 32)})
            known_types.append({"name" : "FPHalfToSingle",                   "type" : ("int", 32)})
            known_types.append({"name" : "FPRSqrtEstimate",                  "type" : ("int", 32)})
            known_types.append({"name" : "FPRSqrtStep",                      "type" : ("int", 32)})
            known_types.append({"name" : "FPRecipEstimate",                  "type" : ("int", 32)})
            known_types.append({"name" : "FPRecipStep",                      "type" : ("int", 32)})
            known_types.append({"name" : "FPSingleToDouble",                 "type" : ("int", 64)})
            known_types.append({"name" : "FPSingleToHalf",                   "type" : ("int", 16)})
            known_types.append({"name" : "HasVirtExt",                       "type" : ("int", 1)})
            known_types.append({"name" : "HaveLPAE",                         "type" : ("int", 1)})
            known_types.append({"name" : "HaveMPExt",                        "type" : ("int", 1)})
            known_types.append({"name" : "HaveVirtExt",                      "type" : ("int", 1)})
            known_types.append({"name" : "InITBlock",                        "type" : ("int", 1)})
            known_types.append({"name" : "IntegerZeroDivideTrappingEnabled", "type" : ("int", 1)})
            known_types.append({"name" : "IsAlignmentFault",                 "type" : ("int", 1)})
            known_types.append({"name" : "IsExternalAbort",                  "type" : ("int", 1)})
            known_types.append({"name" : "IsExternalAbort",                  "type" : ("int", 1)})
            known_types.append({"name" : "IsSecure",                         "type" : ("int", 1)})
            known_types.append({"name" : "IsZero",                           "type" : ("int",  1)})
            known_types.append({"name" : "IsZeroBit",                        "type" : ("int",  1)})
            known_types.append({"name" : "JazelleAcceptsExecution",          "type" : ("int", 1)})
            known_types.append({"name" : "LR",                               "type" : ("int", 32)})
            known_types.append({"name" : "LSInstructionSyndrome",            "type" : ("int", 9)})
            known_types.append({"name" : "LastInITBlock",                    "type" : ("int", 1)})
            known_types.append({"name" : "PC",                               "type" : ("int", 32)})
            known_types.append({"name" : "PCStoreValue",                     "type" : ("int", 32)})
            known_types.append({"name" : "RemapRegsHaveResetValues",         "type" : ("int", 1)})
            known_types.append({"name" : "SP",                               "type" : ("int", 32)})
            known_types.append({"name" : "SatQ",                             "type" : ("list", 2)})
            known_types.append({"name" : "Shift",                            "type" : ("int", 32)})
            known_types.append({"name" : "Shift_C",                          "type" : ("list", 2)})
            known_types.append({"name" : "SignedSatQ",                       "type" : ("list", 2)})
            known_types.append({"name" : "StandardFPSCRValue",               "type" : ("int", 32)})
            known_types.append({"name" : "ThisInstr",                        "type" : ("int", 32)})
            known_types.append({"name" : "ThumbExpandImm",                   "type" : ("int", 32)})
            known_types.append({"name" : "ThumbExpandImm_C",                 "type" : ("list", 2)})
            known_types.append({"name" : "UnalignedSupport",                 "type" : ("int", 1)})
            known_types.append({"name" : "UnsignedRSqrtEstimate",            "type" : ("int", 32)})
            known_types.append({"name" : "UnsignedRecipEstimate",            "type" : ("int", 32)})
            known_types.append({"name" : "UnsignedSatQ",                     "type" : ("list", 2)})

            # I'm not sure if enums are 32 bits but probably yes.
            known_types.append({"name" : "MBReqDomain_FullSystem", "type" : ("int", 32)})
            known_types.append({"name" : "MBReqDomain_InnerShareable", "type" : ("int", 32)})
            known_types.append({"name" : "MBReqDomain_Nonshareable", "type" : ("int", 32)})
            known_types.append({"name" : "MBReqDomain_OuterShareable", "type" : ("int", 32)})
            known_types.append({"name" : "MBReqTypes_All", "type" : ("int", 32)})
            known_types.append({"name" : "MBReqTypes_Writes", "type" : ("int", 32)})

            for symbol in symbols:
                known_types.append({"name" : symbol, "type" : ("int", 32)})

            # Translate the AST into code.
            translator = ARMv7Parser.CPPTranslatorVisitor(known_types=known_types)

            body = ""
            for ast_node in program_ast:
                ast_node = ast_node[0]
                code = translator.accept(ast_node)
                body += ARMv7Parser.indent(code)
                
                if type(ast_node) == ARMv7Parser.ProcedureCall:
                    body = body[:-1] + ";\n"

            # Write the translated body of the decoding procedure.
            fd.write(body)            
            fd.write("    return true;\n")
            fd.write("};\n")
            fd.write("\n")

            i += 1
            
    return True

def main():
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
    symbols_file = os.path.join(os.path.abspath("../../../libdisassembly/arm/gen/"), "symbols.sym")
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

        if not create_interpreter(interpreter_name_h, interpreter_name_cpp, symbols_file):
            logging.error("Could not create the interpreter.")
            return False

    logging.info("Finished creating autogenerated stubs.")

    return True

if __name__ == '__main__':
    main()
