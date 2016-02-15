import os
import re
import json
import logging
import argparse

from parser import ARMv7Parser
from specification import ARMv7OperationSpec, ARMv7Types
from ast.passes import IdentifierRenamer
from ast.translators import CPPTranslatorVisitor, indent, NeedsSemiColon

DEBUG = False

def instruction_interpreter_name(ins_name):
    ins_name = re.sub('[\s\(\)\-\,\/\#]', '_', ins_name)
    ins_name = ins_name.replace("__", "_")
    ins_name = ins_name.rstrip("_")
    return "interpret_" + ins_name.lower()

def create_interpreter(interpreter_name_h, interpreter_name_cpp, symbols_file):
    """
    Create ARMInterpreter.h and ARMInterpreter.cpp.
    """
    # Inherit the basic types.
    known_types = list(ARMv7Types.known_types)

    # Load symbols file.
    with open(symbols_file, "r") as fd:
        symbols = json.load(fd)
        for symbol in symbols:
            known_types.append({"name" : "ins." + symbol, "type" : ("int", 32)})

    with open(interpreter_name_h, "w") as fd:
        header = ""
        header += '#include "arm/ARMContext.h"\n'
        header += '#include "arm/ARMDisassembler.h"\n\n'
        header += 'using namespace Disassembler;\n\n' 
        header += "class ARMInterpreter {\n"
        header += "    ARMInterpreter() {};\n\n"
        header += "    bool ConditionPassed() { return true; }\n"
        header += "    void EncodingSpecificOperations() {}\n"    
        header += "\n"
        header += "    apsr_t APSR;\n"
        header += "    fpscr_t FPSCR;\n"
        
        fd.write(header)
        for instruction in ARMv7OperationSpec.instructions:
            ins_name = instruction["name"]
            fd.write("    bool %s(ARMContext &ctx, const ARMInstruction &ins);\n" % instruction_interpreter_name(ins_name))
        
        fd.write("};\n")
    
    with open(interpreter_name_cpp, "w") as fd:
        header = ""
        header += '#include "arm/gen/ARMInterpreter.h"\n'
        header += '#include "arm/ARMContext.h"\n'
        header += '#include "arm/ARMUtilities.h"\n'
        header += '#include "Utilities.h"\n\n'
        header += '#include <tuple>\n\n' 
        
        fd.write(header)
        for i, instruction in enumerate(ARMv7OperationSpec.instructions):
            ins_name = instruction["name"]
            logging.info("Doing instruction '%s' (%d)" % (ins_name, i))

            fd.write("bool ARMInterpreter::%s(ARMContext &ctx, const ARMInstruction &ins) {\n" % instruction_interpreter_name(ins_name))
            
            ins_operation = instruction["operation"]

            # Remove empty lines, because I suck at parsing.
            ins_operation = os.linesep.join([s for s in ins_operation.splitlines() if not re.match(r'^\s*$', s)])

            # Get the AST for the decoder pseudocode and translate it to C++.            
            program_ast = ARMv7Parser.parse_program(ins_operation)

            # Convert all the local variables to instance variables.
            IdentifierRenamer(symbols, "ins.").transform(program_ast)

            translator = CPPTranslatorVisitor(known_types=known_types)

            body = ""

            # For each of the statements, do a translation.
            for ast_statement in program_ast:
                code = translator.accept(ast_statement)
                if NeedsSemiColon(ast_statement):
                    code += ";"

                body += indent(code)

            fd.write("\n")
                
            # Write the translated body of the decoding procedure.
            fd.write(body)            
            fd.write("    return true;\n")
            fd.write("}\n")
            fd.write("\n")
            
    return True

def main():
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description='Generator.')
    parser.add_argument("--gendir", default="../gen/", help="Directory where the generated files will be placed.")
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
    symbols_file = os.path.join(gen_dir, "symbols.sym")
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

        logging.info("Creating interpreter at '%s'." % interpreter_name_h)
        logging.info("Creating interpreter at '%s'." % interpreter_name_cpp)

        if not create_interpreter(interpreter_name_h, interpreter_name_cpp, symbols_file):
            logging.error("Could not create the interpreter.")
            return False

    logging.info("Finished creating autogenerated stubs.")

    return True

if __name__ == '__main__':
    main()
