import inspect

from ast.visitor import Visitor
from ast.nodes import *

debug = False
type_check = False

op_name = {
    "+": "add",
    "-": "sub",
    "/": "div",
    "*": "mul",
   "<<": "lshift",
   ">>": "rshift",
   "DIV": "idiv",
   "MOD": "imod",
   "^": "xor",
   "||": "or",
   "&&": "and",
   "==": "eq",
   "!=": "ne",
   ">": "gt",
   "<": "lt",
   ">=": "gte",
   "<=": "lte",
   "IN": "in",
   "=": "assign",
   "EOR": "xor",
   ":": "concatenation",
   "AND": "and",
   "OR": "or"
}

name_op = {v: k for k, v in op_name.items()}

UnaryExpressionNameToOperator = {
    "negate" : "!",
    "minus" : "-",
    "invert" : "~",
    "plus" : "+"
}

BinaryExpressionNameToOperator = {
    "add" : "+",
    "and" : "&&",
    "eq" : "==",
    "gt" : ">",
    "gte" : ">=",
    "imod" : "%",
    "mod" : "%",
    "idiv" : "/",
    "div" : "/",
    "lshift" : "<<",
    "rshift" : ">>",
    "lt" : "<",
    "mul" : "*",
    "ne" : "!=",
    "or" : "||",
    "sub" : "-",
    "xor" : "^",
    "lte" : "<="
}

def NeedsSemiColon(node):
    return not (type(node) in [RepeatUntil, While, For, If, Case])

def indent(lines):
    t = ""
    for l in lines.split("\n"):
        t += "    %s\n" % l

    return t

def lineno():
    return inspect.currentframe().f_back.f_lineno

def IsUnknownType(type_):
    return type_ == ("unknown", None)

def IsBooleanOperator(opname):
    return opname in ["and", "or", "eq", "ne", "gt", "lt", "gte", "lte", "in"]

def cases(mask):
    p = []

    def rec(mask, acum):
        if not len(mask):
            p.append(int(acum, 2))
            return

        if mask[0] == "x":
            rec(mask[1:], acum + "0")
            rec(mask[1:], acum + "1")

        else:
            rec(mask[1:], acum + mask[0])

    rec(mask, "")

    return p

class CPPTranslatorVisitor(Visitor):
    """
    Implementation of a source to source translator that
    will spit compilable C++ code.
    """
    def needs_cast(self, identifier):
        return str(identifier) in self.needs_cast_

    def cast(self, identifier):
        return "*reinterpret_cast<unsigned *>(&%s)" % str(identifier)

    def __init__(self, input_vars=None, known_types=None):
        """
        @input_vars: Variables that the decoder reads from the opcode itself. These
        variables are not defined inside the decoding pseudocode but they are used.

        @known_types: Some hardcoded variable types used to "help" the type system
        to infer the type of some variables.
        """
        self.symbol_table = set()   # Table of symbols.
        self.define_me = set()      # Variables that need to be defined.
        self.node_types = {}        # Map from Node to type.

        # Identifiers that need a cast to another type.
        self.needs_cast_ = ["APSR", "CPSR", "SPSR", "SPSR_abt", "SPSR_fiq", \
            "SPSR_hyp", "SPSR_irq", "SPSR_mon", "SPSR_svc", "SPSR_und", "FPSCR"]

        if input_vars:
            for input_var in input_vars:
                self.symbol_table.add(input_var[0])
                self.set_type(Identifier(input_var[0]), ("int", input_var[1]))

        if known_types:
            for type_ in known_types:
                self.symbol_table.add(type_["name"])
                self.set_type(Identifier(type_["name"]), type_["type"])

    def set_type(self, node, type_, override=False):
        """
        Set the type of a node. Use a dictionary indexed by the string representation
        of the current node.
        """
        key = str(node.name) if type(node) is ProcedureCall else str(node)
        if not self.node_types.has_key(key):
            self.node_types[key] = type_

    def get_type(self, node):
        """
        Get the type of 'node'. 
        """
        key = str(node.name) if type(node) is ProcedureCall else str(node)
        if self.node_types.has_key(key):
            return self.node_types[key]

        return ("unknown", None)

    def accept_RegularRegisterRead(self, parent, node):
        self.set_type(node, ("int", 32))
        register_no_expression = self.accept(node, node.expr1)
        return "ctx.readRegularRegister(%s)" % (register_no_expression)

    def accept_RmodeRead(self, parent, node):
        self.set_type(node, ("int", 32))
        expr1 = self.accept(node, node.expr1)
        expr2 = self.accept(node, node.expr2)
        return "ctx.readRmode(%s, %s)" % (expr1, expr2)

    def accept_SingleRegisterRead(self, parent, node):
        self.set_type(node, ("int", 32))
        register_no_expression = self.accept(node, node.expr1)
        return "ctx.readSingleRegister(%s)" % (register_no_expression)

    def accept_DoubleRegisterRead(self, parent, node):
        self.set_type(node, ("int", 64))
        register_no_expression = self.accept(node, node.expr1)
        return "ctx.readDoubleRegister(%s)" % (register_no_expression)

    def accept_QuadRegisterRead(self, parent, node):
        self.set_type(node, ("int", 128))
        register_no_expression = self.accept(node, node.expr1)
        return "ctx.readQuadRegister(%s)" % (register_no_expression)

    def accept_MemoryRead(self, parent, node):
        expr1 = self.accept(node, node.expr1)
        expr2 = self.accept(node, node.expr2)

        # Set the type of the memory access.
        type_width = int(expr2) * 8 if expr2.isdigit() else expr2
        self.set_type(node, ("int", type_width))

        return "ctx.readMemory(%s, %s)" % (expr1, expr2)

    def accept_RegularRegisterWrite(self, parent, node):
        register_no_expression = self.accept(node, node.left_expr.expr1)
        register_value_expression = self.accept(node, node.right_expr)
        return "ctx.writeRegularRegister(%s, %s)" % (register_no_expression, register_value_expression)

    def accept_RmodeWrite(self, parent, node):
        expr1 = self.accept(node, node.left_expr.expr1)
        expr2 = self.accept(node, node.left_expr.expr2)
        value = self.accept(node, node.right_expr)
        return "ctx.writeRmode(%s, %s, %s)" % (expr1, expr2, value)

    def accept_SingleRegisterWrite(self, parent, node):
        register_no_expression = self.accept(node, node.left_expr.expr1)
        register_value_expression = self.accept(node, node.right_expr)
        return "ctx.writeSingleRegister(%s, %s)" % (register_no_expression, register_value_expression)

    def accept_DoubleRegisterWrite(self, parent, node):
        register_no_expression = self.accept(node, node.left_expr.expr1)
        register_value_expression = self.accept(node, node.right_expr)
        return "ctx.writeDoubleRegister(%s, %s)" % (register_no_expression, register_value_expression)

    def accept_QuadRegisterWrite(self, parent, node):
        register_no_expression = self.accept(node, node.left_expr.expr1)
        register_value_expression = self.accept(node, node.right_expr)
        return "ctx.writeQuadRegister(%s, %s)" % (register_no_expression, register_value_expression)

    def accept_MemoryWrite(self, parent, node):
        address = self.accept(node, node.left_expr.expr1)
        size = self.accept(node, node.left_expr.expr2)
        value = self.accept(node, node.right_expr)
        return "ctx.writeMemory(%s, %s, %s)" % (address, size, value)

    def accept_ElementRead(self, parent, node):
        vector = self.accept(node, node.expr1)
        element = self.accept(node, node.expr2)
        size = self.accept(node, node.expr3)

        # Set the type of the memory access.
        type_width = int(size) * 8 if size.isdigit() else size
        self.set_type(node, ("int", type_width))

        return "ctx.readElement(%s, %s, %s)" % (vector, element, size)

    def accept_ElementWrite(self, parent, node):
        vector = self.accept(node, node.left_expr.expr1)
        element = self.accept(node, node.left_expr.expr2)
        size = self.accept(node, node.left_expr.expr3)
        value = self.accept(node, node.right_expr)
        return "ctx.writeElement(%s, %s, %s, %s)" % (vector, element, size, value)

    def accept_ArrayAccess(self, parent, node):
        node_name = str(node.name)

        if node_name in ["R"]: 
            return self.accept_RegularRegisterRead(parent, node)

        elif node_name in ["Rmode"]:
            return self.accept_RmodeRead(parent, node)

        elif node_name in ["S"]:
            return self.accept_SingleRegisterRead(parent, node)

        elif node_name in ["D", "Din"]:
            return self.accept_DoubleRegisterRead(parent, node)

        elif node_name in ["Q", "Qin"]:
            return self.accept_QuadRegisterRead(parent, node)

        elif node_name in ["Elem"]:
            return self.accept_ElementRead(parent, node)

        elif node_name in ["Mem", "MemA", "MemU", "MemA_unpriv", "MemU_unpriv", "MemA_with_priv", "MemU_with_priv"]:
            return self.accept_MemoryRead(parent, node)

        raise RuntimeError("Unknown ArrayAccess name: %s" % str(node.name))

    def accept_BooleanValue(self, parent, node):
        self.set_type(node, ("int", 1))
        return str(node)

    def accept_Identifier(self, parent, node):
        return str(node)

    def accept_NumberValue(self, parent, node):
        self.set_type(node, ("int", len(node)))
        return str(node)

    def accept_UnaryExpression(self, parent, node):
        expr_str = self.accept(node, node.expr)
        expr_type = self.get_type(node.expr)
        
        # Make the node inherit the type of the expression.
        self.set_type(node, expr_type)

        return "%s%s" % (UnaryExpressionNameToOperator[node.type], expr_str)

    def accept_InExpression(self, parent, node):
        left_expr = self.accept(node, node.left_expr)

        # We set the type to boolean.
        self.set_type(node, ("int", 1))

        # Handle:
        #   c in {0, 1} -> ((c == 0) || (c == 1))
        #   c in "1x"   -> (c == 10b || c == 11b)
        if type(node.right_expr) is MaskedBinary:
            def can_optimize(cases_):
                prev = cases_[0]
                for i in xrange(1, len(cases_)):
                    if cases_[i] != prev + 1:
                        return False

                    prev += 1

                return True

            cases_ = cases(node.right_expr.value)

            if can_optimize(cases_):
                return "(%s >= %d && %s <= %d)" % (left_expr, cases_[0], left_expr, cases_[-1])

            t = []
            for case in cases_:
                t.append("%s == %d" % (left_expr, case))

            return "(%s)" % (" || ".join(t))

        elif type(node.right_expr) in [List, Enumeration]:
            t = []
            for cond in node.right_expr.values:
                t.append("%s == %s" % (left_expr, self.accept(node, cond)))

            return "(%s)" % (" || ".join(t))

        raise RuntimeError("Invalid 'IN' expression.")

    def accept_ConcatenationExpression(self, parent, node):
        # imm = a:b -> imm = Concatenate(a, b, len(b))
        left_expr = self.accept(node, node.left_expr)
        right_expr = self.accept(node, node.right_expr)

        # Get the types.
        left_expr_type = self.get_type(node.left_expr)
        right_expr_type = self.get_type(node.right_expr)

        assert not (IsUnknownType(left_expr_type) or IsUnknownType(right_expr_type))

        # A 'NumberValue' parsed from a string '0b00' has 'bit_size' of 2 instead of 32 as with the default numbers.
        if type(node.right_expr) is NumberValue and right_expr_type[1] != node.right_expr.bit_size:
            right_expr_type = (right_expr_type[0], node.right_expr.bit_size)

        # Create a new type.
        result_expr_type = ("int", left_expr_type[1] + right_expr_type[1])
        self.set_type(node, result_expr_type)

        return "Concatenate(%s, %s, %d)" % (left_expr, right_expr, right_expr_type[1])

    def accept_AssignmentStatement(self, parent, node):
        # Handle: (a, b) = (1, 2)
        if type(node.left_expr) is List and type(node.right_expr) is List:
            # Accept the unused nodes so we can have type checking.
            self.accept(node, node.left_expr)
            self.accept(node, node.right_expr)

            # Check that the lists are of the same type.
            assert self.get_type(node.left_expr) == self.get_type(node.right_expr)

            t = ""
            last = len(node.left_expr.values) - 1
            # For each of the left variables.
            for i, var in enumerate(node.left_expr.values):
                if not str(var) in self.symbol_table:
                    # Declare it and initialize it.
                    self.symbol_table.add(str(var))
                    self.define_me.add(str(var))

                # Make the assignment.
                t += "%s %s %s" % (var, name_op[node.type], node.right_expr.values[i])
                if i != last:
                    t += ", "

                # Set the types of the assignee and the assigned.
                self.set_type(var, ("int", 32))
                self.set_type(node.right_expr.values[i], ("int", 32))

            return t

        # Handle: (a, b) = SomeFunction(arguments)
        elif type(node.left_expr) is List and type(node.right_expr) is ProcedureCall:
            # Accept the unused nodes so we can have type checking.
            left_expr = self.accept(node, node.left_expr) 
            right_expr = self.accept(node, node.right_expr)

            # Check that the lists are of the same type.
            t1 = self.get_type(node.left_expr)
            t2 = self.get_type(node.right_expr)
            t3 = self.get_type(node.right_expr.name)

            assert t1 == t2 or t1 == t3
            
            # Small hack.
            if self.accept(node, node.right_expr.name) in ["SignedSatQ", "UnsignedSatQ"]:
                # Get the saturation size.
                sat_size = self.accept(node, node.right_expr.arguments[1])
                if sat_size.isdigit():
                    sat_size = int(sat_size)

                arg0 = self.accept(node.left_expr, node.left_expr.values[0])
                arg1 = self.accept(node.left_expr, node.left_expr.values[1])

                # Set the type either to an integer or an integer expression.
                self.set_type(arg0, ("int", sat_size))
                self.set_type(arg1, ("int", 1))

                # Accept all the function arguments.
                tmp = []
                for val in node.left_expr.values:
                    name = self.accept(node.left_expr, val)
                    tmp.append(name)

                    if not name in self.symbol_table:
                        # Declare it and initialize it.
                        self.symbol_table.add(name)
                        self.define_me.add(name)

                return "std::tie(%s) = %s" % (", ".join(tmp), right_expr)

            names = []

            # For each of the left variables.
            for i, var in enumerate(node.left_expr.values):
                # Set a special name for the ignored values.
                name = ("ignored_%d" % i) if type(var) is Ignore else str(var)

                if not name in self.symbol_table:
                    # Declare it and initialize it.
                    self.symbol_table.add(name)
                    self.define_me.add(name)
                
                names.append(name)

                self.set_type(var, ("int", 32))

            return "std::tie(%s) = %s" % (", ".join(names), right_expr)

        # Handle: SomeArray[expression] = expression
        elif type(node.left_expr) is ArrayAccess:
            # Get the name of the array.
            node_name = str(node.left_expr.name)
            
            # It is a register.
            if node_name in ["R"]:
                return self.accept_RegularRegisterWrite(parent, node)

            elif node_name in ["Rmode"]:
                return self.accept_RmodeWrite(parent, node)

            elif node_name in ["S"]:
                return self.accept_SingleRegisterWrite(parent, node)

            elif node_name in ["D", "Din"]:
                return self.accept_DoubleRegisterWrite(parent, node)

            elif node_name in ["Q", "Qin"]:
                return self.accept_QuadRegisterWrite(parent, node)

            elif node_name in ["Elem"]:
                # TODO: This is just for testing.
                return self.accept_ElementWrite(parent, node)

            elif node_name in ["Mem", "MemA", "MemU", "MemA_unpriv", "MemU_unpriv", "MemA_with_priv", "MemU_with_priv"]:
                return self.accept_MemoryWrite(parent, node)

            else:
                raise RuntimeError("Unknown node: %s" % str(node))
        
        # Handle: expression<hi:lo> = expression
        elif type(node.left_expr) is BitExtraction:            
            raise RuntimeError("Assignment to a bit extraction, please rephrase.")

        left_expr = self.accept(node, node.left_expr)
        right_expr = self.accept(node, node.right_expr)

        # Get the types.
        left_expr_type = self.get_type(node.left_expr)
        right_expr_type = self.get_type(node.right_expr)
        
        # Set the type of the 'lhs' to the type of the 'rhs'.
        if IsUnknownType(left_expr_type):
            left_expr_type = right_expr_type
            self.set_type(node.left_expr, right_expr_type)

        if type_check and left_expr_type != right_expr_type:
            print "DEBUG: Assignment statement:"
            print "DEBUG: node                 = %s" % str(node)
            print "DEBUG: node.left_expr       = %s" % str(left_expr)
            print "DEBUG: node.right_expr      = %s" % str(right_expr)
            print "DEBUG: node.left_expr.type  = %s" % str(left_expr_type)
            print "DEBUG: node.right_expr.type = %s" % str(right_expr_type)
            print
        
        # Add the left symbol to the symbol table.
        if not left_expr in self.symbol_table:
            self.symbol_table.add(left_expr)
            self.define_me.add(left_expr)

        # Declare it and initialize it.
        return "%s %s %s" % (left_expr, name_op[node.type], right_expr)

    def accept_BinaryExpression(self, parent, node):
        if node.type == "in":
            return self.accept_InExpression(parent, node)

        elif node.type == "concatenation":
            return self.accept_ConcatenationExpression(parent, node)

        elif node.type == "assign":
            return self.accept_AssignmentStatement(parent, node)

        left_expr = self.accept(node, node.left_expr)
        right_expr = self.accept(node, node.right_expr)
        op_name = BinaryExpressionNameToOperator[node.type]

        # Boolean operations do not need type checking.
        if IsBooleanOperator(node.type):
            self.set_type(node, ("int", 1))
            return "(%s %s %s)" % (left_expr, op_name, right_expr)

        left_expr_type = self.get_type(node.left_expr)
        right_expr_type = self.get_type(node.right_expr)

        if type_check and left_expr_type[0] != right_expr_type[0]:
            raise RuntimeError("Types do not match: t1='%s' t2='%s'" % (left_expr_type, right_expr_type))
                
        # Inherit the "biggest" type.
        self.set_type(node, max(left_expr_type, right_expr_type))
        return "(%s %s %s)" % (left_expr, op_name, right_expr)

    def accept_ProcedureCall(self, parent, node):
        # Accept all the arguments.
        arguments = [self.accept(node, arg) for arg in node.arguments]

        # Inherit the type of the function via its arguments.
        if str(node.name) in ["ZeroExtend", "FPZero", "SignedSat", "UnsignedSat", "Sat"]:
            # If the argument is an integer then it is the size of the expression.
            if arguments[1].isdigit():
                self.set_type(node, ("int", int(arguments[1])))

            return "%s(%s)" % (node.name, ", ".join(arguments))

        elif str(node.name) in ["ROR", "LSL", "FPNeg", "FPMul", "RoundTowardsZero"]:
            # Inherit the type of the first argument.
            arg_type = self.get_type(node.arguments[0])
            if not IsUnknownType(arg_type):
                self.set_type(node, arg_type)

            return "%s(%s)" % (node.name, ", ".join(arguments))

        elif str(node.name) in ["Zeros", "Ones"]:
            # If the argument is an integer then it is the size of the generated integer.
            if arguments[0].isdigit():
                self.set_type(node, ("int", int(arguments[0])))

            return "%s(%s)" % (node.name, ", ".join(arguments))
            
        elif str(node.name) in ["Int"]:
            # Integers are always 32 bits.
            self.set_type(node, ("int", 32))
            
            if arguments[1] == "unsigned":
                return "UInt(%s)" % (arguments[0])

            elif arguments[1] == "signed":
                arg_type = self.get_type(node.arguments[0])
                if IsUnknownType(arg_type):
                    print "DEBUG(%4d):" % (lineno())
                    print 'DEBUG: arg_type == ("unknown", None)'
                    print "DEBUG: node      = %s" % str(arguments[0])
                    print "DEBUG: node.name = %s" % str(node.name)

                    if type_check:
                        raise RuntimeError("Sign extension (SInt) failed due to arg_type == ('unknown', None)")
    
                arg_bit_len = arg_type[1]
                return "SInt(%s, %s)" % (arguments[0], arg_bit_len)

            else:
                arg_type = self.get_type(node.arguments[0])
                if IsUnknownType(arg_type):
                    assert  type(node.arguments[0]) == ArrayAccess
                    arg_type = ("int", self.accept(node, node.arguments[0].expr3))

                arg_bit_len = arg_type[1]
                return "((%s) ? %s : %s)" % (arguments[1], "UInt(%s)" % arguments[0], "SInt(%s, %s)" % (arguments[0], arg_bit_len))

        elif str(node.name) in ["SInt"]:
            # Get the argument type.
            arg_type = self.get_type(node.arguments[0])
            if IsUnknownType(arg_type):
                assert type(node.arguments[0]) == ArrayAccess
                arg_type = ("int", self.accept(node, node.arguments[0].expr3))

            # Integers are always 32 bits.
            self.set_type(node, ("int", 32))

            # Get the bit lenght.
            arg_bit_len = arg_type[1]
            return "SInt(%s, %s)" % (arguments[0], arg_bit_len)

        elif str(node.name) in ["NOT"]:
            # Inherit the type of the argument.
            assert len(node.arguments) == 1
            arg_type = self.get_type(node.arguments[0])
            if IsUnknownType(arg_type) and type_check:
                raise RuntimeError("Type of NOT expression is unknown.")

            self.set_type(node, arg_type)
            return "NOT(%s, %s)" % (", ".join(arguments), arg_type[1])

        elif str(node.name) == "Consistent":
            self.set_type(node, ("int", 1))
            # We replace Consistent(Rm) with (Rm == Rm_).
            return "(%s == %s_)" % (node.arguments[0], node.arguments[0])

        elif str(node.name) == "SignExtend":
            # Sign extend in c++ needs the bitsize of the bit string.
            arg_type = self.get_type(node.arguments[0])
            if IsUnknownType(arg_type):
                print "DEBUG(%4d):" % (lineno())
                print 'DEBUG: arg_type == ("unknown", None)'
                print "DEBUG: node      = %s" % str(self.accept(node, node.arguments[0]))
                print "DEBUG: node.name = %s" % (str(node.name))

            arg_bit_len = arg_type[1]

            # The resulting size is the second argument.
            if arguments[1].isdigit():
                self.set_type(node, ("int", int(arguments[1])))

            return "SignExtend(%s, %s)" % (arguments[0], arg_bit_len)

        elif str(node.name) in ["ALUWritePC"]:
            return "ctx.%s(%s)" % (node.name, ", ".join(arguments))

        return "%s(%s)" % (node.name, ", ".join(arguments))

    def accept_RepeatUntil(self, parent, node):
        t = "do {\n"

        for st in node.statements:
            t += "    %s" % self.accept(node, st)
            if NeedsSemiColon(st):
                t += ";"

            t += "\n"

        t += "} while (%s);\n" % self.accept(node, node.condition)

        return t

    def accept_While(self, parent, node):
        t = "while (%s) {\n" % self.accept(node, node.condition)
        for st in node.statements:
            t += "    %s" % self.accept(node, st)
            if NeedsSemiColon(st):
                t += ";"

            t += "\n"

        t += "}\n"

        return t

    def accept_For(self, parent, node):
        assert node.from_.type == "assign"
        var_name = self.accept(node, node.from_.left_expr)
        var_value = self.accept(node, node.from_.right_expr)
        to_ = self.accept(node, node.to)

        t = "for (unsigned %s = %s; %s < %s; ++%s) {\n" % (var_name, var_value, var_name, to_, var_name)
        
        last = len(node.statements) - 1
        for_statements = ""
        for i, st in enumerate(node.statements):
            for_statements += self.accept(node, st)
            if NeedsSemiColon(st):
                for_statements += ";"
            
            if i != last:
                for_statements += "\n"

        t += indent(for_statements)
        t += "}\n"

        return t

    def accept_If(self, parent, node):
        def hint(condition, statements):
            # Set the reason why Undefined or Unpredictable instructions are "skipped".
            for statement in statements:
                if type(statement) in [Undefined, Unpredictable]:
                    statements[0].reason = condition

            if any(type(s) in [Undefined, Unpredictable, See] for s in statements):
                return "unlikely(%s)" % condition

            return condition

        # Hint unlikely expressions.
        t = "if (%s) {\n" % hint(self.accept(node, node.condition), node.if_statements)
        
        # For each of the statements of the true branch.
        true_block = ""
        last = len(node.if_statements)
        for i, st in enumerate(node.if_statements):
            true_block += self.accept(node, st)
            
            if NeedsSemiColon(st):
                true_block += ";"

            if i != last - 1:
                true_block += "\n"

        t += indent(true_block)
        t += "}"

        if len(node.else_statements):
            last = len(node.else_statements)
            false_block = ""
            t += " else {\n"
            for i, st in enumerate(node.else_statements):
                false_block += self.accept(node, st)

                if NeedsSemiColon(st):
                    false_block += ";"

                if i != last - 1:
                    false_block += "\n"

            t += indent(false_block)
            t += "}"
        
        return t

    def accept_BitExtraction(self, parent, node):
        # The identifier may be an expression, evaluate it.
        node_name = self.accept(node, node.identifier)

        # The type is a one bit integer.
        if len(node.range) == 1:
            self.set_type(node, ("int", 1))
            return "get_bit(%s, %s)" % (node_name, self.accept(node, node.range[0]))

        # Accept the limits.
        hi_lim = self.accept(node, node.range[0])
        lo_lim = self.accept(node, node.range[1])
        
        # If both types are numbers we can get typing information.
        if type(node.range[0]) is NumberValue and type(node.range[1]) is NumberValue:
            bit_size = int(hi_lim) - int(lo_lim) + 1
            self.set_type(node, ("int", bit_size))
            return "get_bits(%s, %s, %s)" % (node_name, hi_lim, lo_lim)

        # Assume the bit extraction expression is a 32 bit expression.
        self.set_type(node, ("int", 32))
        return "get_bits(%s, %s, %s)" % (node_name, hi_lim, lo_lim)

    def accept_IfExpression(self, parent, node):
        condition = self.accept(node, node.condition)
        trueValue = self.accept(node, node.trueValue)
        falseValue = self.accept(node, node.falseValue)

        trueValue_type = self.get_type(node.trueValue)
        falseValue_type = self.get_type(node.falseValue)

        # We can't do shit.
        if type_check and IsUnknownType(trueValue_type) and IsUnknownType(falseValue_type):
            print "DEBUG(%4d):" % (lineno())
            print "DEBUG: Types differ in expression = %s" % (node)
            print "DEBUG: trueValue.type             = %s" % str(trueValue_type)
            print "DEBUG: falseValue.type            = %s" % str(falseValue_type)
            print "DEBUG: node.trueValue             = %r" % self.accept(node, node.trueValue)
            print "DEBUG: node.falseValue            = %r" % self.accept(node, node.falseValue)
            raise RuntimeError("Cannot infer type for IfExpression")

        elif IsUnknownType(trueValue_type):
            self.set_type(node, falseValue_type)            

        elif IsUnknownType(falseValue_type):
            self.set_type(node, trueValue_type)

        elif falseValue_type[1] > trueValue_type[1]:
            self.set_type(node, falseValue_type)
        
        else:
            self.set_type(node, trueValue_type)

        return "((%s) ? %s : %s)" % (condition, trueValue, falseValue)

    def accept_CaseElement(self, parent, node):
        # The special case is when we have a masked binary that we will interpret as a range.
        if type(node.value) is MaskedBinary:
            t = "// Values of %s\n" % node.value.value
            for val in cases(node.value.value):
                t += "case %s:\n" % val

        elif node.value == None:
            t = "default:\n"

        else:
            t = "case %s:\n" % self.accept(node, node.value)

        for st in node.statements:
            t += "    %s" % self.accept(node, st)
            if NeedsSemiColon(st):
                t += ";"

            t += "\n"

        t += "    break;\n"

        return t

    def accept_Case(self, parent, node):
        t = "switch (%s) {\n" % self.accept(node, node.expr)
        for case in node.cases:
            t += indent(self.accept(node, case))

        t += "}\n"

        return t

    def accept_Undefined(self, parent, node):
        self.set_type(node, ("unknown", None))
        return """return shared_ptr<ARMInstruction>(new UndefinedInstruction("Reason: %s"))""" % node.reason

    def accept_Unpredictable(self, parent, node):
        self.set_type(node, ("unknown", None))
        return """return shared_ptr<ARMInstruction>(new UnpredictableInstruction("Reason: %s"))""" % node.reason

    def accept_See(self, parent, node):
        self.set_type(node, ("unknown", None))
        return "return shared_ptr<ARMInstruction>(new SeeInstruction(\"%s\"))" % str(node.msg)

    def accept_ImplementationDefined(self, parent, node):
        self.set_type(node, ("unknown", None))
        return "return shared_ptr<ARMInstruction>(new ImplementationDefinedInstruction())"

    def accept_SubArchitectureDefined(self, parent, node):
        self.set_type(node, ("unknown", None))
        return "return shared_ptr<ARMInstruction>(new SubArchitectureDefinedInstruction())"

    def accept_Return(self, parent, node):
        t = "return %s;" % self.accept(node, node.value)
        ret_type = self.get_type(node.value)
        self.set_type(node, ret_type)
        return t

    def accept_List(self, parent, node):
        # We accept every element of the list.
        for element in node.values:
            self.accept(node, element)

        # Create the type list with the right number of elements. This is for type checking mostly.
        self.set_type(node, ("list", len(node.values)))

        # Lists are not representable in c++.
        return None

class InterpreterCPPTranslator(CPPTranslatorVisitor):
    """
    Especialize the translator to generate code for the interpreter.
    """
    def accept_Undefined(self, parent, node):
        self.set_type(node, ("unknown", None))
        return "return false"

    def accept_Unpredictable(self, parent, node):
        self.set_type(node, ("unknown", None))
        return "return false"

    def accept_See(self, parent, node):
        self.set_type(node, ("unknown", None))
        return "return false"

    def accept_ImplementationDefined(self, parent, node):
        self.set_type(node, ("unknown", None))
        return "return false"

    def accept_SubArchitectureDefined(self, parent, node):
        self.set_type(node, ("unknown", None))
        return "return false"
