"""
Python parser for the ARM Architecture Reference Manual (ARMv7-A and ARMv7-R edition)
pseudocode.
"""
import string
import re

from pyparsing import *
from string import letters
from collections import namedtuple

debug = False
type_check = False

from ARMv7DecodingSpec import instructions
from utils import get_mask, get_value, get_size

def verbose(name, e):
    print "name=%s type=%s, str=%s, repr=%r" % (name, type(e).__name__, str(e), repr(e))

# Avoid treating newlines as whitespaces.
ParserElement.setDefaultWhitespaceChars(" \t")

# Enable optimizations.
ParserElement.enablePackrat()

# Define basic tokens.
LPAR, RPAR, LBRACK, RBRACK, LBRACE, RBRACE, SEMI, COMMA, COLON, EQUALS, LANGLE, RANGLE = map(Suppress, "()[]{};,:=<>")
QUOTE = Suppress("'") ^ Suppress('"')

# New line.
EOL = Suppress(LineEnd())

# Define basic keywords.
IF = Keyword("if")
ENDIF = Keyword("endif")
THEN = Keyword("then")
ELSE = Keyword("else")
ELSIF = Keyword("elsif")
WHILE = Keyword("while")
DO = Keyword("do")
REPEAT = Keyword("repeat")
UNTIL = Keyword("until")
FOR = Keyword("for")
ENDFOR = Keyword("endfor")
TO = Keyword("to")
CASE = Keyword("case")
ENDCASE = Keyword("endcase")
OF = Keyword("of")
WHEN = Keyword("when")
OTHERWISE = Keyword("otherwise")
RETURN = Keyword("return")
BIT = Keyword("bit")
BITSTRING = Keyword("bitstring")
INTEGER = Keyword("integer")
BOOLEAN = Keyword("boolean")
REAL = Keyword("real")
ENUMERATION = Keyword("enumeration")
LIST = Keyword("list")
ARRAY = Keyword("array")

# Commonly used constants.
TRUE = Keyword("TRUE")
FALSE = Keyword("FALSE")
UNKNOWN = Keyword("UNKNOWN")
UNDEFINED = Keyword("UNDEFINED")
UNPREDICTABLE = Keyword("UNPREDICTABLE")
SEE = Keyword("SEE")
IMPLEMENTATION_DEFINED = Keyword("IMPLEMENTATION_DEFINED")
SUBARCHITECTURE_DEFINED = Keyword("SUBARCHITECTURE_DEFINED")


def cases(mask):
    """
    cases("0x") -> ["00", "01"]
    cases("xx") -> ["00", "01", "10", "11"]
    cases("00") -> ["00"]
    cases("1" ) -> ["1"]
    """
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

class BaseNode(object):
    def accept(self, visitor):
        return visitor.accept(self)


class BooleanValue(BaseNode):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return str("true" if self.value else "false")


class Identifier(BaseNode):
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return str(self.name)


class NumberValue(BaseNode):
    def __init__(self, value, bit_size=32):
        self.value = value
        self.bit_size = bit_size

    def __len__(self):
        """
        Return the bitsize of the number. Important for things like
        the concatenation operator.
        """
        return self.bit_size

    def __str__(self):
        return str(self.value)


class List(BaseNode):
    def __init__(self, values):
        self.values = values

    def __len__(self):
        return len(self.values)

    def __str__(self):
        return "(%s)" % ", ".join(map(str, self.values))


class Enumeration(BaseNode):
    def __init__(self, values):
        self.values = values

    def __len__(self):
        return len(self.values)

    def __str__(self):
        return "{%s}" % ", ".join(map(str, self.values))


class UnaryExpression(BaseNode):
    def __init__(self, type_, expr):
        self.type = type_
        self.expr = expr

    def __str__(self):
        return "%s%s" % (str(self.type), str(self.expr))


class BinaryExpression(BaseNode):
    def __init__(self, type_, left_expr, right_expr):
        self.type = type_
        self.left_expr = left_expr
        self.right_expr = right_expr

    def __str__(self):
        return "%s %s %s" % (str(self.type), str(self.left_expr), str(self.right_expr))


class ProcedureCall(BaseNode):
    def __init__(self, name_, arguments):
        self.name = name_
        self.arguments = arguments

    def __str__(self):
        return "%s(%s)" % (str(self.name), ", ".join(map(str, self.arguments)))


class RepeatUntil(BaseNode):
    def __init__(self, statements, condition):
        self.statements = statements
        self.condition = condition

    def __str__(self):
        return "RepeatUntil: %s %s" % (str(self.statements), str(self.condition))


class While(BaseNode):
    def __init__(self, condition, statements):
        self.condition = condition
        self.statements = statements

    def __str__(self):
        return "While: %s %s" % (str(self.condition), str(self.statements))


class For(BaseNode):
    def __init__(self, from_, to, statements):
        self.from_ = from_
        self.to = to
        self.statements = statements

    def __str__(self):
        return "For: %s %s %s" % (str(self.from_), str(self.to), str(self.statements))


class If(BaseNode):
    def __init__(self, condition, if_statements, else_statements):
        self.condition = condition
        self.if_statements = if_statements
        self.else_statements = else_statements

    def __str__(self):
        return "If: %s %s %s" % (str(self.condition), map(str, self.if_statements), map(str, self.else_statements))


class BitExtraction(BaseNode):
    def __init__(self, identifier_, range_):
        self.identifier = identifier_
        self.range = range_

    def __str__(self):
        return "BitExtraction: %s %s" % (str(self.identifier), str(self.range))

class ArrayAccess(BaseNode):
    def __init__(self, name, expr1, expr2, expr3):
        self.name = name
        self.expr1 = expr1
        self.expr2 = expr2
        self.expr3 = expr3

    def __str__(self):
        args = [str(self.expr1)]
        if self.expr2:
            args.append(str(self.expr2))

        if self.expr3:
            args.append(str(self.expr3))

        return "ArrayAccess: %s[%s]" % (str(self.name), " ".join(args))


class MaskedBinary(BaseNode):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return "MaskedBinary: %s" % (str(self.value))


class Ignore(BaseNode):
    def __str__(self):
        return "Ignore"


class IfExpression(BaseNode):
    def __init__(self, condition, trueValue, falseValue):
        self.condition = condition
        self.trueValue = trueValue
        self.falseValue = falseValue

    def __str__(self):
        return "IfExpression: %s %s %s" % (str(self.condition), str(self.trueValue), str(self.falseValue))


class CaseElement(BaseNode):
    def __init__(self, value, statements):
        self.value = value
        self.statements = statements

    def __str__(self):
        return "CaseElement: %s %s" % (str(self.value), str(self.statements))


class Case(BaseNode):
    def __init__(self, expr, cases):
        self.expr = expr
        self.cases = cases

    def __str__(self):
        return "Case: %s %s" % (str(self.expr), str(self.cases))


class Undefined(BaseNode):
    def __init__(self):
        self.reason = ""

    def __str__(self):
        return "Undefined"


class Unpredictable(BaseNode):
    def __init__(self):
        self.reason = ""

    def __str__(self):
        return "Unpredictable"


class See(BaseNode):
    def __init__(self, msg):
        self.msg = msg.strip('"')

    def __str__(self):
        return "See: %s" % (str(self.msg))


class ImplementationDefined(BaseNode):
    def __str__(self):
        return "ImplementationDefined"


class SubArchitectureDefined(BaseNode):
    def __str__(self):
        return "SubArchitectureDefined"


class Return(BaseNode):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return "Return: %s" % (str(self.value))


class Visitor(object):
    """
    Abstract base class that collects generic properties of
    the visitor pattern.
    """

    def accept(self, node):
        """
        Main dispatcher of the visitor. It will route the 'accept' call
        to the particular accept method associated with the type.
        """
        if type(node) is BooleanValue:
            r = self.accept_BooleanValue(node)

        elif type(node) is Identifier:
            r = self.accept_Identifier(node)

        elif type(node) is NumberValue:
            r = self.accept_NumberValue(node)

        elif type(node) is List:
            r = self.accept_List(node)

        elif type(node) is Enumeration:
            r = self.accept_Enumeration(node)

        elif type(node) is UnaryExpression:
            r = self.accept_UnaryExpression(node)

        elif type(node) is BinaryExpression:
            r = self.accept_BinaryExpression(node)

        elif type(node) is ProcedureCall:
            r = self.accept_ProcedureCall(node)

        elif type(node) is RepeatUntil:
            r = self.accept_RepeatUntil(node)

        elif type(node) is While:
            r = self.accept_While(node)

        elif type(node) is For:
            r = self.accept_For(node)

        elif type(node) is If:
            r = self.accept_If(node)

        elif type(node) is BitExtraction:
            r = self.accept_BitExtraction(node)

        elif type(node) is ArrayAccess:
            r = self.accept_ArrayAccess(node)

        elif type(node) is MaskedBinary:
            r = self.accept_MaskedBinary(node)

        elif type(node) is Ignore:
            r = self.accept_Ignore(node)

        elif type(node) is IfExpression:
            r = self.accept_IfExpression(node)

        elif type(node) is CaseElement:
            r = self.accept_CaseElement(node)

        elif type(node) is Case:
            r = self.accept_Case(node)

        elif type(node) is Undefined:
            r = self.accept_Undefined(node)

        elif type(node) is Unpredictable:
            r = self.accept_Unpredictable(node)

        elif type(node) is See:
            r = self.accept_See(node)

        elif type(node) is ImplementationDefined:
            r = self.accept_ImplementationDefined(node)

        elif type(node) is SubArchitectureDefined:
            r = self.accept_SubArchitectureDefined(node)

        elif type(node) is Return:
            r = self.accept_Return(node)

        else:
            raise RuntimeError("Invalid type: '%r' (%s)" % (type(node), str(node)))

        return r


# from pydot import Dot, Node, Edge

def create_node(node):
    import uuid
    return Node(str(uuid.uuid4()), label=str(node))


class GrapVisitor(Visitor):
    def __init__(self):
        self.graph = Dot(graph_type='digraph')

    def save(self, filename="graph.png"):
        self.graph.write_png(filename)

    def accept_BooleanValue(self, node):
        n = create_node(str(node))
        self.graph.add_node(n)
        return n

    def accept_Identifier(self, node):
        n = create_node(str(node))
        self.graph.add_node(n)
        return n

    def accept_NumberValue(self, node):
        n = create_node(str(node))
        self.graph.add_node(n)
        return n

    def accept_List(self, node):
        n = create_node(str(node))
        self.graph.add_node(n)
        return n

    def accept_Enumeration(self, node):
        n = create_node(str(node))
        self.graph.add_node(n)
        return n

    def accept_UnaryExpression(self, node):
        n1 = create_node(str(node.type))
        n2 = self.accept(node.expr)
        e = Edge(n1, n2)

        self.graph.add_node(n1)
        self.graph.add_edge(e)

        return n1

    def accept_BinaryExpression(self, node):
        n1 = create_node(str(node.type))
        n2 = self.accept(node.left_expr)
        n3 = self.accept(node.right_expr)

        e1 = Edge(n1, n2)
        e2 = Edge(n1, n3)

        self.graph.add_node(n1)
        self.graph.add_edge(e1)
        self.graph.add_edge(e2)

        return n1

    def accept_ProcedureCall(self, node):
        n1 = create_node("call")
        n2 = create_node(str(node.name))
        n3 = create_node("arguments")

        self.graph.add_node(n1)
        self.graph.add_node(n2)
        self.graph.add_node(n3)

        self.graph.add_edge(Edge(n1, n2))
        self.graph.add_edge(Edge(n1, n3))

        for arg in node.arguments:
            arg_node = self.accept(arg)
            self.graph.add_edge(Edge(n3, arg_node))

        return n1

    def accept_RepeatUntil(self, node):
        n1 = create_node("RepeatUntil")
        n2 = create_node(self.accept(node.condition))
        n3 = create_node("statements")

        self.graph.add_edge(Edge(n1, n2))
        self.graph.add_edge(Edge(n1, n3))

        self.graph.add_node(n1)
        self.graph.add_node(n2)
        self.graph.add_node(n3)

        for st in node.statements:
            st_node = self.accept(st)
            self.graph.add_edge(Edge(n3, st_node))

        return n1

    def accept_While(self, node):
        n1 = create_node("While")
        n2 = create_node(self.accept(node.condition))
        n3 = create_node("statements")

        self.graph.add_node(n1)
        self.graph.add_node(n2)
        self.graph.add_node(n3)

        self.graph.add_edge(Edge(n1, n2))
        self.graph.add_edge(Edge(n1, n3))

        for st in node.statements:
            st_node = self.accept(st)
            self.graph.add_edge(Edge(n3, st_node))

        return n1

    def accept_For(self, node):
        n1 = create_node("For")
        n2 = create_node("from")
        n3 = create_node("to")
        n4 = create_node("statements")
        n5 = self.accept(node.from_)
        n6 = self.accept(node.to)

        self.graph.add_node(n1)
        self.graph.add_node(n2)
        self.graph.add_node(n3)
        self.graph.add_node(n4)

        self.graph.add_edge(Edge(n1, n2))
        self.graph.add_edge(Edge(n1, n3))
        self.graph.add_edge(Edge(n1, n4))
        self.graph.add_edge(Edge(n2, n5))
        self.graph.add_edge(Edge(n3, n6))

        for st in node.statements:
            st_node = self.accept(st)
            self.graph.add_edge(Edge(n4, st_node))

        return n1

    def accept_If(self, node):
        n1 = create_node("If")
        n2 = create_node("condition")
        n3 = create_node("if_statements")
        n4 = create_node("else_statements")
        n5 = self.accept(node.condition)

        self.graph.add_node(n1)
        self.graph.add_node(n2)
        self.graph.add_node(n3)
        self.graph.add_node(n4)
        self.graph.add_node(n5)

        self.graph.add_edge(Edge(n1, n2))
        self.graph.add_edge(Edge(n1, n3))
        self.graph.add_edge(Edge(n1, n4))
        self.graph.add_edge(Edge(n2, n5))

        for st in node.if_statements:
            st_node = self.accept(st)
            self.graph.add_edge(Edge(n3, st_node))

        for st in node.else_statements:
            st_node = self.accept(st)
            self.graph.add_edge(Edge(n4, st_node))

        return n1

    def accept_BitExtraction(self, node):
        n1 = create_node("BitExtraction")
        n2 = create_node(str(node.identifier))

        self.graph.add_node(n1)
        self.graph.add_node(n2)

        self.graph.add_edge(Edge(n1, n2))

        for r in node.range:
            n = self.accept(r)
            self.graph.add_edge(Edge(n1, n))

        return 1

    def accept_MaskedBinary(self, node):
        n1 = create_node("MaskedBinary")
        n2 = create_node(str(node.value))

        self.graph.add_node(n1)
        self.graph.add_node(n2)

        self.graph.add_edge(Edge(n1, n2))

        return n1

    def accept_Ignore(self, node):
        n = create_node(str(node))
        self.graph.add_node(n)
        return n

    def accept_IfExpression(self, node):
        n1 = create_node("IfExpression")
        n2 = create_node("condition")
        n3 = self.accept(node.condition)
        n4 = create_node("ifTrue")
        n5 = create_node("ifFalse")

        self.graph.add_node(n1)
        self.graph.add_node(n2)
        self.graph.add_node(n3)
        self.graph.add_node(n4)
        self.graph.add_node(n5)

        self.graph.add_edge(Edge(n1, n2))
        self.graph.add_edge(Edge(n2, n3))
        self.graph.add_edge(Edge(n1, n4))
        self.graph.add_edge(Edge(n1, n5))

        node_true = self.accept(node.trueValue)
        node_false = self.accept(node.falseValue)

        self.graph.add_edge(Edge(n4, node_true))
        self.graph.add_edge(Edge(n5, node_false))

        return n1

    def accept_CaseElement(self, node):
        n1 = create_node("CaseElement")
        n2 = self.accept(node.value)
        n3 = create_node("statements")

        self.graph.add_node(n1)
        self.graph.add_node(n3)
        self.graph.add_edge(Edge(n1, n2))
        self.graph.add_edge(Edge(n1, n3))

        for st in node.statements:
            st_node = self.accept(st)
            self.graph.add_edge(Edge(n3, st_node))

        return n1

    def accept_Case(self, node):
        n1 = create_node("Case")
        n2 = self.accept(node.expr)
        n3 = create_node("cases")

        self.graph.add_node(n1)
        self.graph.add_node(n3)
        self.graph.add_edge(Edge(n1, n2))
        self.graph.add_edge(Edge(n1, n3))

        for st in node.cases:
            st_node = self.accept(st)
            self.graph.add_edge(Edge(n3, st_node))

        return n1

    def accept_Undefined(self, node):
        n = create_node(str(node))
        self.graph.add_node(n)
        return n

    def accept_Unpredictable(self, node):
        n = create_node(str(node))
        self.graph.add_node(n)
        return n

    def accept_See(self, node):
        n = create_node(str(node))
        self.graph.add_node(n)
        return n

    def accept_ImplementationDefined(self, node):
        n = create_node(str(node))
        self.graph.add_node(n)
        return n

    def accept_SubArchitectureDefined(self, node):
        n = create_node(str(node))
        self.graph.add_node(n)
        return n

    def accept_Return(self, node):
        n = create_node(str(node))
        self.graph.add_node(n)
        return n

def indent(lines):
    t = ""
    for l in lines.split("\n"):
        t += "    %s\n" % l

    return t

class CPPTranslatorVisitor(Visitor):
    """
    Implementation of a source to source translator that
    will spit compilable C++ code.
    """
    def __init__(self, input_vars=None, known_types=None):
        self.var_bit_length = {}
        self.symbol_table = set()
        self.define_me = set()
        self.seen_see = set()
        self.node_types = {}

        if input_vars:
            # Add the opcode variables and their types to the system.
            for input_var in input_vars:
                # Map from variable name to bit lenght.
                self.var_bit_length[input_var[0]] = input_var[1]
                
                # Create a new symbol.
                self.symbol_table.add(input_var[0])

                # Set the type.
                self.set_type(Identifier(input_var[0]), ("int", input_var[1]))

        if known_types:
            for type_ in known_types:
                self.var_bit_length[type_["name"]] = type_["type"][0]
                self.symbol_table.add(type_["name"])
                self.set_type(Identifier(type_["name"]), type_["type"])

    def set_type(self, node, type_, override=False):
        """
        Set the type of a node. Use a dictionary indexed by the string representation
        of the current node.
        """
        if not self.node_types.has_key(str(node)):
            self.node_types[str(node)] = type_

    def get_type(self, node):
        """
        Get the type of 'node'. 
        """
        if self.node_types.has_key(str(node)):
            return self.node_types[str(node)]

        if type(node) is ProcedureCall and self.node_types.has_key(str(node.name)):          
            return self.node_types[str(node.name)]

        if str(node) in self.symbol_table:
           return ("int", self.var_bit_length[str(node)])

        return ("unknown", None)

    def accept_RegularRegisterRead(self, node):
        self.set_type(node, ("int", 32))
        register_no_expression = self.accept(node.expr1)
        return "ctx.readRegularRegister(%s)" % (register_no_expression)

    def accept_RmodeRead(self, node):
        self.set_type(node, ("int", 32))
        expr1 = self.accept(node.expr1)
        expr2 = self.accept(node.expr2)
        return "ctx.readRmode(%s, %s)" % (expr1, expr2)

    def accept_SingleRegisterRead(self, node):
        self.set_type(node, ("int", 32))
        register_no_expression = self.accept(node.expr1)
        return "ctx.readSingleRegister(%s)" % (register_no_expression)

    def accept_DoubleRegisterRead(self, node):
        self.set_type(node, ("int", 64))
        register_no_expression = self.accept(node.expr1)
        return "ctx.readDoubleRegister(%s)" % (register_no_expression)

    def accept_QuadRegisterRead(self, node):
        self.set_type(node, ("int", 128))
        register_no_expression = self.accept(node.expr1)
        return "ctx.readQuadRegister(%s)" % (register_no_expression)

    def accept_MemoryRead(self, node):
        expr1 = self.accept(node.expr1)
        expr2 = self.accept(node.expr2)

        # Set the type of the memory access.
        if expr2.isdigit():
            self.set_type(node, ("int", int(expr2)))

        return "ctx.readMemory(%s, %s)" % (expr1, expr2)

    def accept_RegularRegisterWrite(self, node):
        # Receives a BinaryExpression with an ArrayAccess and an expression.
        register_no_expression = self.accept(node.left_expr.expr1)
        register_value_expression = self.accept(node.right_expr)
        return "ctx.writeRegularRegister(%s, %s)" % (register_no_expression, register_value_expression)

    def accept_RmodeWrite(self, node):
        # Receives a BinaryExpression with an ArrayAccess and an expression.
        expr1 = self.accept(node.left_expr.expr1)
        expr2 = self.accept(node.left_expr.expr2)
        value = self.accept(node.right_expr)
        return "ctx.writeRmode(%s, %s, %s)" % (expr1, expr2, value)

    def accept_SingleRegisterWrite(self, node):
        register_no_expression = self.accept(node.left_expr.expr1)
        register_value_expression = self.accept(node.right_expr)
        return "ctx.writeSingleRegister(%s, %s)" % (register_no_expression, register_value_expression)

    def accept_DoubleRegisterWrite(self, node):
        register_no_expression = self.accept(node.left_expr.expr1)
        register_value_expression = self.accept(node.right_expr)
        return "ctx.writeDoubleRegister(%s, %s)" % (register_no_expression, register_value_expression)

    def accept_QuadRegisterWrite(self, node):
        register_no_expression = self.accept(node.left_expr.expr1)
        register_value_expression = self.accept(node.right_expr)
        return "ctx.writeQuadRegister(%s, %s)" % (register_no_expression, register_value_expression)

    def accept_ElementWrite(self, node):
        return "ctx.TODO_writeElement()"

    def accept_MemoryWrite(self, node):
        # Receives a BinaryExpression with an ArrayAccess and an expression.
        args = [self.accept(node.left_expr.expr1), self.accept(node.right_expr)]
        if node.left_expr.expr2:
            args.append(self.accept(node.left_expr.expr2))

        if node.left_expr.expr3:
            args.append(self.accept(node.left_expr.expr3))

        return "ctx.writeMemory(%s)" % (", ".join(args))

    def accept_ElementRead(self, node):
        """
        The pseudocode function Elem[] accesses the element of a specified index and size in a vector:
        
        bits(size) Elem[bits(N) vector, integer e, integer size]
            return vector<(e+1)*size-1:e*size>;
        """
        # TODO: Implement.
        return "TODO_accept_ElementRead()"

    def accept_ArrayAccess(self, node):
        """
        bits(32) Rmode[integer n, bits(5) mode]
        Rmode[integer n, bits(5) mode] = bits(32) value
        bits(32) R[integer n]
        R[integer n] = bits(32) value        
        """
        node_name = str(node.name)

        # TODO: Rmode has two arguments
        if node_name in ["R"]: 
            return self.accept_RegularRegisterRead(node)

        elif node_name in ["Rmode"]:
            return self.accept_RmodeRead(node)

        elif node_name in ["S"]:
            return self.accept_SingleRegisterRead(node)

        elif node_name in ["D", "Din"]:
            return self.accept_DoubleRegisterRead(node)

        elif node_name in ["Q", "Qin"]:
            return self.accept_QuadRegisterRead(node)

        elif node_name in ["Elem"]:
            # TODO: This is just for testing.
            return self.accept_ElementRead(node)

        elif node_name in ["Mem", "MemA", "MemU", "MemA_unpriv", "MemU_unpriv", "MemA_with_priv", "MemU_with_priv"]:
            return self.accept_MemoryRead(node)

        print "DEBUG:"
        print "DEBUG: node = %s" % str(node)
        print "DEBUG: node.name = %s" % str(node.name)
        print "DEBUG: node.expr1", str(node.expr1)
        print "DEBUG: node.expr2", str(node.expr2)
        print "DEBUG: node.expr3", str(node.expr3)

        raise RuntimeError("Unknown ArrayAccess name: %s" % str(node.name))

    def accept_BooleanValue(self, node):
        self.set_type(node, ("int", 1))
        return str(node)

    def accept_Identifier(self, node):
        return str(node)

    def accept_NumberValue(self, node):
        self.set_type(node, ("int", len(node)))
        return str(node)

    def accept_UnaryExpression(self, node):
        t = {
            "negate" : "!",
            "minus" : "-",
            "invert" : "~",
            "plus" : "+",
        }

        expr_str = self.accept(node.expr)
        t = "%s%s" % (t[str(node.type)], expr_str)

        # Obtain the type of the expression.
        expr_type = self.get_type(node.expr)

        if expr_type == ("unknown", None):
            print "DEBUG:"
            print "DEBUG: Unary expresion type unknown."
            print "DEBUG: node      = %s" % str(node)
            print "DEBUG: node.expr = %s" % str(expr_str)

            if type_check:
                raise RuntimeError("Unary expresion type unknown.")

        # Make the node inherit the type of the expression.
        self.set_type(node, expr_type)

        return t

    def accept_BinaryExpression(self, node):
        t = {
            "idiv" : "/",
            "imod" : "%",
            "xor"  : "^",
            "and"  : "&&",
            "or"   : "||"
        }

        if node.type == "in":
            left_expr = self.accept(node.left_expr)

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

                else:
                    t = []
                    for case in cases_:
                        t.append("%s == %d" % (left_expr, case))

                    return "(%s)" % (" || ".join(t))

            elif type(node.right_expr) in [List, Enumeration]:
                t = []
                for cond in node.right_expr.values:
                    t.append("%s == %s" % (left_expr, self.accept(cond)))

                return "(%s)" % (" || ".join(t))

        elif node.type == "concatenation":
            # imm = a:b -> imm = Concatenate(a, b, len(b))
            left_expr = self.accept(node.left_expr)
            right_expr = self.accept(node.right_expr)

            # Get the types.
            left_expr_type = self.get_type(node.left_expr)
            right_expr_type = self.get_type(node.right_expr)

            if left_expr_type == ("unknown", None) or right_expr_type == ("unknown", None):
                print "DEBUG:"
                print "DEBUG: Concatenated expressions type is unknown."
                print "DEBUG: node            = %s" % str(node)
                print "DEBUG: node.left_expr  = %s" % str(left_expr)
                print "DEBUG: node.right_expr = %s" % str(right_expr)

                if type_check:
                    raise RuntimeError("Unary expresion type unknown.")

            # Since all constants have the same string representation, we need to
            # cheat a bit and use the bit_size instead of the inferred type.
            if type(node.right_expr) is NumberValue and right_expr_type[1] != node.right_expr.bit_size:
                right_expr_type = (right_expr_type[0], node.right_expr.bit_size)

            # Create a new type.
            result_expr_type = ("int", left_expr_type[1] + right_expr_type[1])
            self.set_type(node, result_expr_type)

            return "Concatenate(%s, %s, %d)" % (left_expr, right_expr, right_expr_type[1])

        elif node.type == "assign":
            # Handle: (a, b) = (1, 2)
            if type(node.left_expr) is List and type(node.right_expr) is List:
                # It is safe to assume the types to be (uint32_t, uint32_t)
                # (shift_t, shift_n) = (SRType_LSL, 0);
                # (shift_t, shift_n) = (SRType_LSL, UInt(imm2));

                # Accept the unused nodes so we can have master race type checking.
                self.accept(node.left_expr)
                self.accept(node.right_expr)

                # Check that the lists are of the same type.
                assert self.get_type(node.left_expr) == self.get_type(node.right_expr)

                t = ""
                i = 0
                # For each of the left variables.
                for var in node.left_expr.values:
                    if var in self.symbol_table:
                        # Make the assignment.
                        t += "%s %s %s;\n" % (var, name_op[node.type], node.right_expr.values[i])

                    else:
                        # Declare it and initialize it.
                        self.symbol_table.add(str(var))
                        self.define_me.add(str(var))
                        t += "%s %s %s;\n" % (var, name_op[node.type], node.right_expr.values[i])

                    # Set the types of the assignee and the assigned.
                    self.set_type(var, ("int", 32))
                    self.set_type(node.right_expr.values[i], ("int", 32))

                    i += 1

                return t

            # Handle: (a, b) = SomeFunction(arguments)
            elif type(node.left_expr) is List and type(node.right_expr) is ProcedureCall:
                # Accept the unused nodes so we can have master race type checking.
                self.accept(node.left_expr)
                right_expr = self.accept(node.right_expr)

                # Check that the lists are of the same type.
                t1 = self.get_type(node.left_expr)
                t2 = self.get_type(node.right_expr)

                # We may have typing information on the function name.
                t3 = self.get_type(node.right_expr.name)

                if t1 != t2 and t1 != t3:            
                    print "DEBUG:"
                    print "DEBUG: List types are different: t1='%s' t2='%s' t3='%s'" % (t1, t2, t3)
                    print "DEBUG: type(node.left_expr)  = %r" % type(node.left_expr)
                    print "DEBUG: type(node.right_expr) = %r" % type(node.right_expr)
                    print "DEBUG: node.left_expr        = %r" % self.accept(node.left_expr)
                    print "DEBUG: node.right_expr       = %r" % self.accept(node.right_expr)

                    if type_check:
                        raise RuntimeError("List types are different: t1='%s' t2='%s' t3='%s'" % (t1, t2, t3))

                names = []
                acum = ""
                i = 0
                # For each of the left variables.
                for var in node.left_expr.values:
                    # Set a special name for the ignored values.
                    name = ("ignored_%d" % i) if type(var) is Ignore else str(var)

                    if not name in self.symbol_table:
                        # Declare it and initialize it.
                        self.symbol_table.add(name)
                        self.define_me.add(name)
                    
                    names.append(name)

                    if not type(var) is Ignore:
                        self.set_type(var, ("int", 32))

                    i += 1

                if len(node.left_expr.values) != len(names):
                    print "DEBUG:"
                    print "DEBUG: type(node.left_expr)  = %r" % type(node.left_expr)
                    print "DEBUG: type(node.right_expr) = %r" % type(node.right_expr)
                    print "DEBUG: node.left_expr        = %r" % self.accept(node.left_expr)
                    print "DEBUG: node.right_expr       = %r" % self.accept(node.right_expr)
                    print "DEBUG: node.left_expr.values = %r" % map(self.accept, node.left_expr.values)
                    print "DEBUG: names                 = %r" % names
                    print "DEBUG: len(node.left_expr.values) != len(names): %d != %d" % (len(node.left_expr.values), len(names))
                    
                    if type_check:
                        raise RuntimeError("len(node.left_expr.values) != len(names): %d != %d" % \
                            (len(node.left_expr.values), len(names)))

                acum += "std::tie(%s) = %s;\n" % (", ".join(names), right_expr)
                return acum

            # Handle: SomeArray[expression] = expression
            elif type(node.left_expr) is ArrayAccess:
                # An array write can be of two types:
                #     - Register write.
                #     - Memory write.

                # Get the name of the array.
                node_name = str(node.left_expr.name)
                
                # It is a register.
                if node_name in ["R"]:
                    return self.accept_RegularRegisterWrite(node)

                elif node_name in ["Rmode"]:
                    return self.accept_RmodeWrite(node)

                elif node_name in ["S"]:
                    return self.accept_SingleRegisterWrite(node)

                elif node_name in ["D", "Din"]:
                    return self.accept_DoubleRegisterWrite(node)

                elif node_name in ["Q", "Qin"]:
                    return self.accept_QuadRegisterWrite(node)

                elif node_name in ["Elem"]:
                    # TODO: This is just for testing.
                    return self.accept_ElementWrite(node)

                elif node_name in ["Mem", "MemA", "MemU", "MemA_unpriv", "MemU_unpriv", "MemA_with_priv", "MemU_with_priv"]:
                    return self.accept_MemoryWrite(node)


                return "// XXX: What is this? '%s'" % node

            left_expr = self.accept(node.left_expr)
            right_expr = self.accept(node.right_expr)

            # Assignment makes lhs inherit the type of rhs.
            self.set_type(node.left_expr, self.get_type(node.right_expr))

            # If the lhs is present at the symbol table we need not to initialize it.
            if left_expr in self.symbol_table:
                return "%s %s %s;" % (left_expr, name_op[node.type], right_expr)

            # Add the left symbol to the symbol table.
            self.symbol_table.add(left_expr)
            self.define_me.add(left_expr)

            # Declare it and initialize it.
            return "%s %s %s;" % (left_expr, name_op[node.type], right_expr)

        elif node.type == "idiv":
            type_ = "/"

        elif node.type == "imod":
            type_ = "%"

        elif node.type == "xor":
            type_ = "^"

        elif node.type == "and":
            type_ = "&&"

        elif node.type == "or":
            type_ = "||"

        else:
            type_ = name_op[node.type]

        left_expr = self.accept(node.left_expr)
        right_expr = self.accept(node.right_expr)

        if not node.type in ["and", "or", "eq", "ne", "gt", "lt", "gte", "lte", "in"]:
            left_expr_type = self.get_type(node.left_expr)
            right_expr_type = self.get_type(node.right_expr)

            if left_expr_type[0] != right_expr_type[0]:
                if type_check:
                    raise RuntimeError("Types do not match: t1='%s' t2='%s'" % (left_expr_type, right_expr_type))
            
                print "DEBUG:"
                print "DEBUG: Types differ in expression = %s" % (node)
                print "DEBUG: left_expr.type             = %r" % str(left_expr_type)
                print "DEBUG: right_expr.type            = %s" % str(right_expr_type)
                print "DEBUG: type(node.left_expr)       = %r" % type(node.left_expr)
                print "DEBUG: type(node.right_expr)      = %r" % type(node.right_expr)
                print "DEBUG: node.left_expr             = %r" % self.accept(node.left_expr)
                print "DEBUG: node.right_expr            = %r" % self.accept(node.right_expr)
            
            self.set_type(node, left_expr_type)

        else:
            self.set_type(node, ("int", 1))

        return "(%s %s %s)" % (left_expr, type_, right_expr)

    def accept_ProcedureCall(self, node):
        """
        We have no idea what type a procedure call
        returns but since this pseudocode defines
        a couple of functions we can actually list them
        and hard code the type.
        """
        arguments = []
        for arg in node.arguments:
            arguments.append(self.accept(arg))

        # Inherit the type of the function via its arguments.
        if str(node.name) in ["UInt", "ThumbExpandImm"]:
            # Assumption: the type in the manual is 'integer' so 32 bits.
            self.set_type(node, ("int", 32))

        elif str(node.name) in ["ZeroExtend", "FPZero"]:
            # If the argument is an integer then it is the size of the expression.
            argument = self.accept(node.arguments[1])
            if argument.isdigit():
                self.set_type(node, ("int", int(argument)))

        elif str(node.name) in ["ROR", "LSL", "FPNeg", "FPMul"]:
            # Inherit the type of the first argument.
            arg_type = self.get_type(node.arguments[0])
            if arg_type != ("unknown", None):
                self.set_type(node, arg_type)

        elif str(node.name) in ["Zeros", "Ones"]:
            # If the argument is an integer then it is the size of the generated integer.
            argument = self.accept(node.arguments[0])
            if argument.isdigit():
                self.set_type(node, ("int", int(argument)))
            
        elif str(node.name) in ["Int"]:
            # Integers are always 32 bits.
            self.set_type(node, ("int", 32))
            
            if arguments[1] == "unsigned":
                return "UInt(%s)" % (arguments[0])

            elif arguments[1] == "signed":
                arg_type = self.get_type(node.arguments[0])
                if arg_type == ("unknown", None):
                    print "DEBUG:"
                    print 'DEBUG: arg_type == ("unknown", None)'
                    print "DEBUG: node      = %s" % str(self.accept(node.arguments[0]))
                    print "DEBUG: node.name = %s" % (str(node.name))

                    if type_check:
                        raise RuntimeError("Sign extension (SInt) failed due to arg_type == ('unknown', None)")
    
                arg_bit_len = arg_type[1]
                return "SInt(%s, %s)" % (arguments[0], arg_bit_len)

            else:
                arg_type = self.get_type(node.arguments[0])
                if arg_type == ("unknown", None):
                    print "DEBUG:"
                    print 'DEBUG: arg_type == ("unknown", None)'
                    print "DEBUG: node      = %s" % str(self.accept(node.arguments[0]))
                    print "DEBUG: node.name = %s" % (str(node.name))

                    if type_check:
                        raise RuntimeError("Sign extension (SInt) failed due to arg_type == ('unknown', None)")

                arg_bit_len = arg_type[1]
                return "((%s) ? %s : %s)" % (arguments[1], "UInt(%s)" % arguments[0], "SInt(%s, %s)" % (arguments[0], arg_bit_len))

        elif str(node.name) in ["SInt"]:
            # Get the argument type.
            arg_type = self.get_type(node.arguments[0])
            if arg_type == ("unknown", None):
                print "DEBUG:"
                print 'DEBUG: arg_type == ("unknown", None)'
                print "DEBUG: node      = %s" % str(self.accept(node.arguments[0]))
                print "DEBUG: node.name = %s" % (str(node.name))

                if type_check:
                    raise RuntimeError("Sign extension (SInt) failed due to arg_type == ('unknown', None)")

            # Integers are always 32 bits.
            self.set_type(node, ("int", 32))

            # Get the bit lenght.
            arg_bit_len = arg_type[1]
            return "SInt(%s, %s)" % (arguments[0], arg_bit_len)

        elif str(node.name) in ["InITBlock", "LastInITBlock"]:
            self.set_type(node, ("int", 1))

        elif str(node.name) in ["DecodeImmShift", "ARMExpandImm_C", "ThumbExpandImm_C"]:
            self.set_type(node, ("list", 2))

        elif str(node.name) in ["NOT"]:
            # Inherit the type of the argument.
            assert len(node.arguments) == 1
            arg_type = self.get_type(node.arguments[0])
            self.set_type(node, arg_type)

            return "NOT(%s, %s)" % (", ".join(arguments), arg_type[1])

        elif str(node.name) == "Consistent":
            self.set_type(node, ("int", 1))
            # We replace Consistent(Rm) with (Rm == Rm_).
            return "(%s == %s_)" % (node.arguments[0], node.arguments[0])

        elif str(node.name) == "SignExtend":
            # Sign extend in c++ needs the bitsize of the bit string.
            arg_bit_len = self.get_type(node.arguments[0])[1]

            # The resulting size is the second argument.
            argument = self.accept(node.arguments[1])
            if argument.isdigit():
                self.set_type(node, ("int", int(argument)))

            return "SignExtend(%s, %s)" % (arguments[0], arg_bit_len)

        return "%s(%s)" % (node.name, ", ".join(arguments))

    def accept_RepeatUntil(self, node):
        t = "do {\n"
        for st in node.statements:
            t += "    %s;\n" % self.accept(st)

        t += "} while (%s);\n\n" % self.accept(node.condition)

        return t

    def accept_While(self, node):
        t = "while (%s) {\n" % self.accept(node.condition)
        for st in node.statements:
            t += "    %s\n" % self.accept(st)
        t += "}\n\n"

        return t

    def accept_For(self, node):
        from_ = self.accept(node.from_)
        to_ = self.accept(node.to)

        statements = []
        for st in node.statements:
            statements.append(self.accept(st))

        t = "for(unsigned i = %s; i < %s; ++i) {\n" % (from_, to_)
        for st in statements:
            t += "    %s\n" % st
        t += "}\n\n"

        return t

    def accept_If(self, node):
        def hint(condition, statements):
            # Set the reason why Undefined or Unpredictable instructions are "skipped".
            if type(statements[0]) in [Undefined, Unpredictable]:
                statements[0].reason = condition

            if len(statements) == 1 and type(statements[0]) in [Undefined, Unpredictable, See]:
                return "unlikely(%s)" % condition

            return condition

        t = "\nif (%s) {\n" % hint(self.accept(node.condition), node.if_statements)
        for st in node.if_statements:
            t += "    %s\n" % self.accept(st)
        t += "}"

        if len(node.else_statements):
            t += "\nelse {\n"
            for st in node.else_statements:
                t += "    %s\n" % self.accept(st)
            t += "}\n"

        t += "\n"

        return t

    def accept_BitExtraction(self, node):
        # The identifier may be an expression, evaluate it.
        node_name = self.accept(node.identifier)

        # The type is a one bit integer.
        if len(node.range) == 1:
            self.set_type(node, ("int", 1))
            return "get_bit(%s, %s)" % (node_name, self.accept(node.range[0]))

        # Accept the limits.
        hi_lim = self.accept(node.range[0])
        lo_lim = self.accept(node.range[1])
        
        # If both types are numbers we can get typing information.
        if type(node.range[0]) is NumberValue and type(node.range[1]) is NumberValue:
            bit_size = int(hi_lim) - int(lo_lim) + 1
            self.set_type(node, ("int", bit_size))
            return "get_bits(%s, %s, %s)" % (node_name, hi_lim, lo_lim)

        # Assume the bit extraction expression is a 32 bit expression.
        self.set_type(node, ("int", 32))
        return "get_bits(%s, %s, %s)" % (node_name, hi_lim, lo_lim)

    def accept_IfExpression(self, node):
        condition = self.accept(node.condition)
        trueValue = self.accept(node.trueValue)
        falseValue = self.accept(node.falseValue)

        trueValue_type = self.get_type(node.trueValue)
        falseValue_type = self.get_type(node.falseValue)

        # Set the type, since we've proved that both match.
        if trueValue_type[0] != falseValue_type[0]:
            if type_check:
                raise RuntimeError("Types do not match: t1='%s' t2='%s'" % (trueValue_type[0], falseValue_type[0]))

            print "DEBUG:"
            print "DEBUG: Types differ in expression = %s" % (node)
            print "DEBUG: trueValue.type             = %s" % str(trueValue_type)
            print "DEBUG: falseValue.type            = %s" % str(falseValue_type)
            print "DEBUG: type(node.condition)       = %r" % type(node.condition)
            print "DEBUG: type(node.trueValue)       = %r" % type(node.trueValue)
            print "DEBUG: type(node.falseValue)      = %r" % type(node.falseValue)
            print "DEBUG: node.condition             = %r" % self.accept(node.condition)
            print "DEBUG: node.trueValue             = %r" % self.accept(node.trueValue)
            print "DEBUG: node.falseValue            = %r" % self.accept(node.falseValue)

        self.set_type(node, falseValue_type)

        return "%s ? %s : %s" % (condition, trueValue, falseValue)

    def accept_CaseElement(self, node):
        # The special case is when we have a masked binary that we will interpret as a range.
        if type(node.value) is MaskedBinary:
            t = "// Values of %s\n" % node.value.value
            for val in cases(node.value.value):
                t += "case %s:\n" % val

        elif node.value == None:
            t = "default:\n"

        else:
            t = "case %s:\n" % self.accept(node.value)

        for st in node.statements:
            t += "    %s\n" % self.accept(st)
        t += "    break;\n"

        return t

    def accept_Case(self, node):
        t = "switch (%s) {\n" % self.accept(node.expr)
        for case in node.cases:
            t += indent(self.accept(case))

        t += "}\n\n"

        return t

    def accept_Undefined(self, node):
        self.set_type(node, ("unknown", None))
        return """return shared_ptr<ARMInstruction>(new UndefinedInstruction("Reason: %s"));""" % node.reason

    def accept_Unpredictable(self, node):
        self.set_type(node, ("unknown", None))
        return """return shared_ptr<ARMInstruction>(new UnpredictableInstruction("Reason: %s"));""" % node.reason

    def accept_See(self, node):
        self.set_type(node, ("unknown", None))
        return "return shared_ptr<ARMInstruction>(new SeeInstruction(\"%s\"));" % str(node.msg)

    def accept_ImplementationDefined(self, node):
        self.set_type(node, ("unknown", None))
        return "return shared_ptr<ARMInstruction>(new ImplementationDefinedInstruction());"

    def accept_SubArchitectureDefined(self, node):
        self.set_type(node, ("unknown", None))
        return "return shared_ptr<ARMInstruction>(new SubArchitectureDefinedInstruction());"

    def accept_Return(self, node):
        t = "return %s;" % self.accept(node.value)
        self.set_type(node, self.get_type(node.value))
        return t

    def accept_List(self, node):
        # We accept every element of the list.
        for element in node.values:
            self.accept(element)

        # Create the type list with the right number of elements. This is for type checking mostly.
        self.set_type(node, ("list", len(node.values)))

        # Lists are not representable in c++.
        return None

    def accept_Enumeration(self, node):
        raise Exception("Accepting an Enumeration, why?")

    def accept_MaskedBinary(self, node):
        raise Exception("Accepting a MaskedBinary, why?")

    def accept_Ignore(self, node):
        return None

def decode_case(x):
    assert "case" == x[0]
    assert "of" == x[2]
    assert "endcase" == x[4]

    case_variable = x[1]
    cases = x[3]

    t = []
    for case in cases:
        assert case[0] == "when" or case[0] == "otherwise"

        if case[0] == "when":
            value = case[1]
            statements = map(lambda x: x[0], case[2].asList())
            t.append(CaseElement(value, statements))

        elif case[0] == "otherwise":
            value = None
            statements = map(lambda x: x[0], case[1].asList())
            t.append(CaseElement(value, statements))

    return Case(case_variable, t)


def decode_repeat_until(x):
    return RepeatUntil(x[1], x[4])


def decode_for(x):
    return For(x[1], x[3], x[4])


def decode_while(x):
    return While(x[1], x[3])


def decode_unary(x):
    x = x[0]

    if len(x) != 2:
        raise "Invalid unary operation: %r" % x

    op_name = {"!": "negate", "-": "minus", "~": "invert", "+": "plus"}
    op = op_name[x[0]]
    return UnaryExpression(op, x[1])


op_name = {"+": "add", "-": "sub", "/": "div", "*": "mul",
           "<<": "lshift", ">>": "rshift", "DIV": "idiv", "MOD": "imod",
           "^": "xor", "||": "or", "&&": "and", "==": "eq", "!=": "ne",
           ">": "gt", "<": "lt", ">=": "gte", "<=": "lte", "IN": "in",
           "=": "assign", "EOR": "xor", ":": "concatenation", "AND": "and", "OR": "or"}

name_op = {v: k for k, v in op_name.items()}


def decode_binary(x):
    x = x[0]

    prev_ = x[0]
    for i in range(0, len(x) - 2, 2):
        op, next_ = x[i + 1], x[i + 2]
        prev_ = BinaryExpression(op_name[op], prev_, next_)

    return prev_


def decode_if_expression(x):
    assert "if" == x[0]
    assert "then" == x[2]
    assert "else" == x[4]
    return IfExpression(x[1], x[3], x[5])

def decode_if(x):
    assert "if" == x[0]
    assert "then" == x[2]
    return If(x[1], map(lambda y: y[0], list(x[3:])), [])

def decode_if_no_else(x):
    assert "if" == x[0]
    assert "then" == x[2]
    assert "endif" == x[4]

    cond, if_st = x[1], map(lambda y: y[0], x[3])
    assert type(if_st) == type([])
    
    return If(cond, if_st, [])

def decode_if_else(x):
    assert "if" == x[0]
    assert "then" == x[2]
    assert "else" == x[4]
    assert "endif" == x[6]

    cond, if_st, then_st = x[1], map(lambda y: y[0], x[3]), map(lambda y: y[0], x[5])

    assert type(if_st) == type([])
    assert type(then_st) == type([])

    return If(cond, if_st, then_st)


def decode_bit_extract(x):
    return BitExtraction(x[0][0], list(x[0][1:]))

def decode_array_access(x):
    if len(x[0]) == 2:
        name, expr1 = x[0]
        expr2 = None
        expr3 = None
        return ArrayAccess(name, expr1, expr2, expr3)

    elif len(x[0]) == 3:
        name, expr1, expr2 = x[0]
        expr3 = None
        return ArrayAccess(name, expr1, expr2, expr3)

    elif len(x[0]) == 4:
        name, expr1, expr2, expr3 = x[0]
        return ArrayAccess(name, expr1, expr2, expr3)

    print "DEBUG:", x[0], len(x[0])

def decode_masked_base2(x):
    return MaskedBinary(x[0])


def decode_list(x):
    return List(x[0:])

# Define the boolean values.
boolean = MatchFirst([TRUE, FALSE]).setParseAction(lambda x: BooleanValue(x[0] == "TRUE"))

# An identifier is a name.
identifier = Word(alphas + "_", alphanums + "_.").setParseAction(lambda x: Identifier(x[0]))

# Unary operators.
unary_operator = oneOf("! - ~ +")

# Bitstring concatenation operator.
bit_concat_operator = Literal(":")

# Product, division, etc.
mul_div_mod_operator = oneOf("* / MOD DIV")

# Binary add and sub.
add_sub_operator = oneOf("+ -")

# Binary shift operators.
shift_operator = oneOf("<< >>")

# Less than, less than or equal, etc.
lt_lte_gt_gte_operator = oneOf("< <= > >=")

# Equal or not equal operators.
eq_neq_operator = oneOf("== !=")

# Bitwise and operator.
bit_and_operator = oneOf("& AND")

# Bitwise eor operator.
bit_eor_operator = oneOf("^ EOR")

# Bitwise or operator.
bit_or_operator = oneOf("| OR")

# Logical and operator.
logical_and_operator = Literal("&&")

# Logical or operator.
logical_or_operator = Literal("||")

# Includes operator
in_operator = Literal("IN")

# Assignment operator.
assignment_operator = Literal("=")

# Use the already defined C multi-line comment and C++ inline comments.
comment = cppStyleComment

# Define an integer for base 2, 10 and 16 and make sure it is 32 bits long.
base_2_masked = (QUOTE + Word("01x") + QUOTE).setParseAction(decode_masked_base2)
base2_integer = (Literal("'") + Word("01") + Literal("'")).setParseAction(lambda s, l, t: NumberValue(int(t[1], 2) & 0xffffffff, len(t[1])))
base10_integer = Word(initChars=string.digits).setParseAction(lambda s, l, t: NumberValue(int(t[0]) & 0xffffffff))
base16_integer = Regex("0x[a-fA-F0-9]+").setParseAction(lambda s, l, t: NumberValue(int(t[0], 16) & 0xffffffff))

# Join all the supported numbers.
number = MatchFirst([base16_integer, base2_integer, base10_integer, base_2_masked])

# Enumeration ::= {var0, 1, 2} | "01x"
enum_atom = MatchFirst([identifier, number])
enum_elements = delimitedList(enum_atom)
enum = Group(LBRACE + enum_elements + RBRACE).setParseAction(lambda x: Enumeration(x[0][:])) ^ base_2_masked

# Ignore '-' value.
ignored = Literal("-").setParseAction(lambda: Ignore())

# Forward declaration of a function call.
procedure_call_expr = Forward()

# Forward declaration of a bit extraction call.
bit_extract_expr = Forward()

# Forward declaration of a array access expression.
array_access_expr = Forward()

# Forward declaration of an if expression.
if_expression = Forward()

# List: (a, b)
list_atom = MatchFirst([ignored, procedure_call_expr, array_access_expr, boolean, identifier, number])
list_elements = delimitedList(list_atom)
list_expr = (LPAR + list_elements + RPAR).setParseAction(decode_list)

# Atoms are the most basic elements of expressions.
atom = MatchFirst([procedure_call_expr, bit_extract_expr, if_expression, list_expr, \
    array_access_expr, boolean, identifier, number, enum, ignored])

# Define the order of precedence.
expr = operatorPrecedence(atom, [
    (unary_operator, 1, opAssoc.RIGHT, decode_unary ),
    (bit_concat_operator, 2, opAssoc.LEFT, decode_binary),
    (mul_div_mod_operator, 2, opAssoc.LEFT, decode_binary),
    (add_sub_operator, 2, opAssoc.LEFT, decode_binary),
    (shift_operator, 2, opAssoc.LEFT, decode_binary),
    (in_operator, 2, opAssoc.LEFT, decode_binary),
    (lt_lte_gt_gte_operator, 2, opAssoc.LEFT, decode_binary),
    (eq_neq_operator, 2, opAssoc.LEFT, decode_binary),
    (bit_and_operator, 2, opAssoc.LEFT, decode_binary),
    (bit_or_operator, 2, opAssoc.LEFT, decode_binary),
    (bit_eor_operator, 2, opAssoc.LEFT, decode_binary),
    (logical_and_operator, 2, opAssoc.LEFT, decode_binary),
    (logical_or_operator, 2, opAssoc.LEFT, decode_binary),
])

# Define a procedure call and its allowed arguments. We do this because things
# break if we get too recursive.
procedure_argument = operatorPrecedence(atom, [
    (unary_operator, 1, opAssoc.RIGHT, decode_unary ),
    (bit_concat_operator, 2, opAssoc.LEFT, decode_binary),
    (mul_div_mod_operator, 2, opAssoc.LEFT, decode_binary),
    (add_sub_operator, 2, opAssoc.LEFT, decode_binary),
    (shift_operator, 2, opAssoc.LEFT, decode_binary),
    (bit_and_operator, 2, opAssoc.LEFT, decode_binary),
    (bit_eor_operator, 2, opAssoc.LEFT, decode_binary),
])

# Operations being used by an array indexing expression.
array_index_atom = MatchFirst([array_access_expr, identifier, number])
array_index_expr = operatorPrecedence(array_index_atom, [
    (oneOf("* / %"), 2, opAssoc.LEFT, decode_binary),
    (oneOf("+ - >>"), 2, opAssoc.LEFT, decode_binary)
])

# Define a bit extraction expression.
bit_extract_expr <<= Group(
    MatchFirst([array_access_expr, identifier]) +
    LANGLE +
    delimitedList(array_index_expr, delim=":") +
    RANGLE
).setParseAction(decode_bit_extract)

# Define a array access expression
array_access_expr <<= Group(
    identifier +
    LBRACK +
    delimitedList(array_index_expr) + 
    RBRACK
).setParseAction(decode_array_access)

# Define a procedure call.
procedure_arguments = delimitedList(procedure_argument)
procedure_call_expr <<= Group(identifier + LPAR + Optional(procedure_arguments) + RPAR).setParseAction(
    lambda x: ProcedureCall(x[0][0], x[0][1:]))

# Define an if expression.
if_expression <<= (IF + expr + THEN + expr + ELSE + expr).setParseAction(decode_if_expression)

# Forward declaration of a generic statement.
statement = Forward()
statement_list = OneOrMore(statement + Optional(EOL))

# Simple statements.
undefined_statement = UNDEFINED.setParseAction(lambda: Undefined())
unpredictable_statement = UNPREDICTABLE.setParseAction(lambda: Unpredictable())
see_allowed = string.letters + string.digits + " -()/\","
see_statement = Group(SEE + Word(see_allowed + " ")).setParseAction(lambda x: See(x[0][1]))
implementation_defined_statement = Group(IMPLEMENTATION_DEFINED + Word(see_allowed)).setParseAction(
    lambda: ImplementationDefined())
subarchitecture_defined_statement = Group(SUBARCHITECTURE_DEFINED + Word(see_allowed)).setParseAction(
    lambda: SubArchitectureDefined())
return_statement = Group(RETURN + Optional(expr)).setParseAction(lambda x: Return(x[0][1]))
procedure_call_statement = procedure_call_expr

# Assignment statement.
assignment_statement = (expr + assignment_operator + expr).setParseAction(lambda x: decode_binary([x]))

# This is used for inline if statements with multiple statements.
inline_statement_list = OneOrMore(statement)

# Parse: if <cond> then st1; st2; st3; ... stn;
single_line_if_statement = (IF + expr + THEN + inline_statement_list).setParseAction(decode_if)

# Parse: if <cond> then <statements> else <statements> endif
multiline_if_statement = (IF + expr + THEN + ZeroOrMore(EOL) + Group(statement_list) + ELSE + ZeroOrMore(EOL) + Group(statement_list) + ENDIF).setParseAction(decode_if_else)

# This sucks. At this point I've continued with the grammar without caring too much.    
multiline_if_statement_no_else = (IF + expr + THEN + ZeroOrMore(EOL) + Group(statement_list) + ENDIF).setParseAction(decode_if_no_else)

# Two types of if statements.
if_statement = MatchFirst([multiline_if_statement, multiline_if_statement_no_else, single_line_if_statement])

# Define a case statement.
otherwise_case = Group(OTHERWISE + Optional(EOL) + Group(statement_list))
case_list = Group(OneOrMore(Group(WHEN + expr + Optional(EOL) + Group(statement_list))) + Optional(otherwise_case))
case_statement = (CASE + expr + OF + EOL + case_list + ENDCASE).setParseAction(decode_case)

# Repeat until statement.
repeat_until_statement = (REPEAT + EOL + statement_list + UNTIL + expr).setParseAction(decode_repeat_until)

# While statement.
while_statement = (WHILE + expr + DO + statement_list).setParseAction(decode_while)

# For statement.
for_statement = (FOR + assignment_statement + TO + expr + EOL + statement_list + ENDFOR).setParseAction(decode_for)

# Collect all statements. We have two kinds, the ones that end with a semicolon and other statements that do not.
t1 = MatchFirst([undefined_statement, unpredictable_statement, see_statement, \
    implementation_defined_statement, subarchitecture_defined_statement, \
    return_statement, procedure_call_statement, assignment_statement])

t2 = MatchFirst([if_statement, repeat_until_statement, while_statement, for_statement, case_statement])
statement <<= Group(MatchFirst([t1 + SEMI, t2]))

# Define a basic program.
program = statement_list

class OptionalToken(object):
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return "{%s}" % "".join(map(lambda x: str(x), self.name))

    def __repr__(self):
        return "Optional(name=%r)" % self.name

class MandatoryToken(object):
    def __init__(self, name, sign="", pound=""):
        self.name = name
        self.sign = sign
        self.pound = pound

    def __str__(self):
        return "%s%s<%s>" % (self.pound, self.sign, "".join(map(lambda x: str(x), self.name)))

    def __repr__(self):
        return "Mandatory('pound=%s sign=%s value=<%s>')" % (self.pound, self.sign, "".join(map(lambda x: str(x), self.name)))

def InstructionFormatParser():
    class OpcodeName(object):
        def __init__(self, name):
            self.name = name

        def __str__(self):
            return "%s" % "".join(map(lambda x: str(x), self.name))

        def __repr__(self):
            return "OpcodeName(name=%r)" % self.name

    class OpcodeArguments(object):
        def __init__(self, name):
            self.name = name

        def __str__(self):
            return "%s" % "".join(map(lambda x: str(x), self.name))

        def __repr__(self):
            return "OpcodeArguments(name=%r)" % self.name

    def decode_op_mandatory(s, locs, toks):
        #verbose("decode_op_mandatory", toks.asList())
        toks = toks.asList()

        if len(toks) == 3:
            assert toks[0] == "<" and toks[-1] == ">"
            return MandatoryToken(toks[1])

        if len(toks) == 4:
            assert toks[1] == "<" and toks[-1] == ">"

            if toks[0] == "#":
                return MandatoryToken(toks[2], pound=toks[0])

            return MandatoryToken(toks[2], sign=toks[0])

        if len(toks) == 5:
            assert toks[2] == "<" and toks[-1] == ">"
            return MandatoryToken(toks[3], sign=toks[1], pound=toks[0])

    def decode_op_optional(s, locs, toks):
        #verbose("decode_op_optional", toks.asList())
        toks = toks.asList()
        assert toks[0] == "{" and toks[-1] == "}"

        return OptionalToken(toks[1:-1])

    def decode_opcode_name(s, locs, toks):
        #verbose("decode_opcode", toks.asList())
        toks = toks.asList()
        return OpcodeName(toks)

    def decode_opcode_args(s, locs, toks):
        #verbose("decode_opcode", toks.asList())
        toks = toks.asList()
        return OpcodeArguments(toks)

    # We care about whitespaces to match the specification format.
    ParserElement.setDefaultWhitespaceChars("")

    # We do allow whitespaces.
    valid_chars = oneOf(list(alphanums + "[]_!., ^#"))
    string_token = Combine(OneOrMore(valid_chars))

    # Do not allow whitespaces.
    name = Combine(OneOrMore(oneOf(list(alphanums + "."))))

    # Parse a mandatory token:
    # mandatory_token ::= (#)? (+/-)? (-)? <[a-zA-Z]+>
    # There are no white spaces or any other qualifier.
    op_mandatory = Optional("#") + (Optional("+/-") ^ Optional("-")) + "<" + string_token + ">"
    op_mandatory.setParseAction(decode_op_mandatory)

    # Parse an optional token -> {??{??{??}}}
    op_optional = Forward()
    t = "{" + Optional(string_token) + Optional(op_mandatory) + Optional(op_optional) + "}"
    op_optional <<= t
    op_optional.setParseAction(decode_op_optional)

    # Parse de opcode name.
    opcode_name = name + ZeroOrMore(op_optional | op_mandatory | name)
    opcode_name.setParseAction(decode_opcode_name)

    # Parse the opcode arguments.
    opcode_args = Literal(" ") + OneOrMore(op_optional | op_mandatory | string_token)
    opcode_args.setParseAction(decode_opcode_args)

    ins_format = opcode_name + Optional(opcode_args)

    return ins_format
