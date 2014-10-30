"""
Python parser for the ARM Architecture Reference Manual (ARMv7-A and ARMv7-R edition)
pseudocode.
"""
import string

from pyparsing import *

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
        return "If: %s %s %s" % (str(self.condition), str(self.if_statements), str(self.else_statements))


class BitExtraction(BaseNode):
    def __init__(self, identifier_, range_):
        self.identifier = identifier_
        self.range = range_

    def __str__(self):
        return "BitExtraction: %s %s" % (str(self.identifier), str(self.range))


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
    def __str__(self):
        return "Undefined"


class Unpredictable(BaseNode):
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
            raise RuntimeError("Invalid type: %r (%s)" % (type(node), str(node)))

        return r


#from pydot import Dot, Node, Edge
import uuid


def create_node(node):
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


class TranslatorVisitor(Visitor):
    """
    Base class of all the translator visitor. This is used to
    gather the basic properties of a traslator.
    Every particular source to source translator should
    inherit from this.
    """

    def __init__(self):
        pass


def indent(lines):
    t = ""
    for l in lines.split("\n"):
        t += "    %s\n" % l

    return t


class SymbolTable(object):
    def __init__(self, input_vars):
        self.input_vars = input_vars
        self.var_bit_length = {}
        self.symbol_table = set()

        for input_var in self.input_vars:
            self.var_bit_length[input_var[0]] = input_var[1]
            self.symbol_table.add(input_var[0])

        def add_symbol(self):
            pass


class CPPTranslatorVisitor(TranslatorVisitor):
    """
    Implementation of a source to source translator that
    will spit compilable C++ code.
    """

    def __init__(self, input_vars):
        self.input_vars = input_vars
        self.var_bit_length = {}
        self.symbol_table = set()
        self.define_me = set()

        self.node_types = {}

        for input_var in self.input_vars:
            self.var_bit_length[input_var[0]] = input_var[1]
            self.symbol_table.add(input_var[0])
            self.set_type(Identifier(input_var[0]), ("unsigned", input_var[1]))

    def set_type(self, node, type_, override=False):
        if not self.node_types.has_key(str(node)):
            # print "// Adding node `%s' with type `%s'" % (str(node), type_)
            self.node_types[str(node)] = type_

        # XXX: Enable this for useful debugging information.
        # else:
        #     if self.get_type(node) != type_ and self.get_type(node) != ('unknown', None):
        #         print "    // DEBUG Type redefinition: e='%s' o='%s' n='%s'" % (str(node), str(self.get_type(node)), type_)

    def get_type(self, node):
        # Stupid hack.
        if not self.node_types.has_key(str(node)):
            if str(node) in self.symbol_table:
               return ("unsigned", self.var_bit_length[str(node)])

            return ("unknown", None)

        type_ = self.node_types[str(node)]
        # print "// Getting node `%s' type `%s'" % (str(node), type_)
        return type_

    def accept_BooleanValue(self, node):
        self.set_type(node, ("unsigned", 1))
        return str(node)

    def accept_Identifier(self, node):
        return str(node)

    def accept_NumberValue(self, node):
        self.set_type(node, ("unsigned", len(node)))
        return str(node)

    def accept_UnaryExpression(self, node):
        op_name = {"!": "negate", "-": "minus", "~": "invert", "+": "plus"}
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
            self.set_type(node, ("unsigned", 1))

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
                    if cases_[0] == 0:
                        return "(%s <= %d)" % (left_expr, cases_[-1])

                    else:
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

            # Since all constants have the same string representation, we need to
            # cheat a bit and use the bit_size instead of the inferred type.
            if type(node.right_expr) is NumberValue and right_expr_type[1] != node.right_expr.bit_size:
                right_expr_type = (right_expr_type[0], node.right_expr.bit_size)

            # Create a new type.
            result_expr_type = ("unsigned", left_expr_type[1] + right_expr_type[1])
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
                    self.set_type(var, ("unsigned", 32))
                    self.set_type(node.right_expr.values[i], ("unsigned", 32))

                    i += 1

                return t

            # Handle: (a, b) = SomeFunction(arguments)
            elif type(node.left_expr) is List and type(node.right_expr) is ProcedureCall:
                # It is safe to assume the types to be (uint32_t, uint32_t)
                # (-, shift_n) = DecodeImmShift('00', imm3:imm2);
                # (-, shift_n) = DecodeImmShift('00', imm5);
                # (-, shift_n) = DecodeImmShift('01', imm3:imm2);
                # (-, shift_n) = DecodeImmShift('01', imm5);
                # (-, shift_n) = DecodeImmShift('10', imm3:imm2);
                # (-, shift_n) = DecodeImmShift('10', imm5);
                # (-, shift_n) = DecodeImmShift('11', imm3:imm2);
                # (-, shift_n) = DecodeImmShift('11', imm5);
                # (imm32, carry) = ARMExpandImm_C(imm12, APSR.C);
                # (imm32, carry) = ThumbExpandImm_C(i:imm3:imm8, APSR.C);
                # (shift_t, shift_n) = DecodeImmShift(sh:'0', imm3:imm2);
                # (shift_t, shift_n) = DecodeImmShift(sh:'0', imm5);
                # (shift_t, shift_n) = DecodeImmShift(tb:'0', imm3:imm2);
                # (shift_t, shift_n) = DecodeImmShift(tb:'0', imm5);
                # (shift_t, shift_n) = DecodeImmShift(type, imm3:imm2);
                # (shift_t, shift_n) = DecodeImmShift(type, imm5);

                # Accept the unused nodes so we can have master race type checking.
                self.accept(node.left_expr)
                right_expr = self.accept(node.right_expr)

                # Check that the lists are of the same type.
                assert self.get_type(node.left_expr) == self.get_type(node.right_expr)

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
                        self.set_type(var, ("unsigned", 32))

                    i += 1

                assert len(node.left_expr.values) == len(names)

                acum += "std::tie(%s) = %s;\n" % (", ".join(names), right_expr)
                return acum

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

            assert left_expr_type[0] == right_expr_type[0]

            self.set_type(node, left_expr_type)

        else:
            self.set_type(node, ("unsigned", 1))

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

        if str(node.name) in ["UInt", "ThumbExpandImm"]:
            self.set_type(node, ("unsigned", 32))

        elif str(node.name) in ["InITBlock", "LastInITBlock"]:
            self.set_type(node, ("unsigned", 1))

        elif str(node.name) in ["DecodeImmShift", "ARMExpandImm_C", "ThumbExpandImm_C"]:
            self.set_type(node, ("list", 2))

        elif str(node.name) in ["NOT"]:
            # Inherit the type of the argument.
            assert len(node.arguments) == 1
            self.set_type(node, self.get_type(node.arguments[0]))

        elif str(node.name) == "Consistent":
            # We replace Consistent(Rm) with (Rm == Rm_).
            return "(%s == %s_)" % (node.arguments[0], node.arguments[0])

        return "%s(%s)" % (node.name, ", ".join(arguments))

    def accept_RepeatUntil(self, node):
        t = "do {\n"
        for st in node.statements:
            t += "    %s\n" % self.accept(st)

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
        t = "\nif (%s) {\n" % self.accept(node.condition)
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
        if len(node.range) == 1:
            # The type is a one bit integer.
            self.set_type(node, ("unsigned", 1))
            return "get_bit(%s, %s)" % (node.identifier, self.accept(node.range[0]))

        # We know that limits here are integers so we can get the size.
        hi_lim = self.accept(node.range[0])
        lo_lim = self.accept(node.range[1])

        assert type(node.range[0]) is Identifier or type(node.range[0]) is NumberValue
        assert type(node.range[1]) is Identifier or type(node.range[1]) is NumberValue

        if type(node.range[0]) is NumberValue and type(node.range[1]) is NumberValue:
            bit_size = int(hi_lim) - int(lo_lim) + 1
            assert bit_size > 0 and bit_size <= 32
            self.set_type(node, ("unsigned", bit_size))
            return "get_bits(%s, %s, %s)" % (node.identifier, hi_lim, lo_lim)

        else:
            print "// DEBUG: assuming type of expression to be 32 bits"
            self.set_type(node, ("unsigned", 32))
            return "get_bits(%s, %s, %s)" % (node.identifier, hi_lim, lo_lim)


    def accept_IfExpression(self, node):
        condition = self.accept(node.condition)
        trueValue = self.accept(node.trueValue)
        falseValue = self.accept(node.falseValue)

        trueValue_type = self.get_type(node.trueValue)
        falseValue_type = self.get_type(node.falseValue)

        # Set the type, since we've proved that both match.
        assert trueValue_type[0] == falseValue_type[0]
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
        return "return UndefinedInstruction();"

    def accept_Unpredictable(self, node):
        self.set_type(node, ("unknown", None))
        return "return UnpredictableInstruction();"

    def accept_See(self, node):
        self.set_type(node, ("unknown", None))
        return "return SeeInstruction(\"%s\");" % str(node.msg)

    def accept_ImplementationDefined(self, node):
        self.set_type(node, ("unknown", None))
        return "return ImplementationDefinedInstruction();"

    def accept_SubArchitectureDefined(self, node):
        self.set_type(node, ("unknown", None))
        return "return SubArchitectureDefinedInstruction();"

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
    return RepeatUntil(x[1], x[3])


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


def decode_masked_base2(x):
    return MaskedBinary(x[0])


def decode_list(x):
    return List(x[0:])

# Define the boolean values.
boolean = (TRUE ^ FALSE).setParseAction(lambda x: BooleanValue(x[0] == "TRUE"))

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
base2_integer = (Literal("'") + Word("01") + Literal("'")).setParseAction(
    lambda s, l, t: NumberValue(int(t[1], 2) & 0xffffffff, len(t[1])))
base10_integer = Word(initChars=string.digits).setParseAction(lambda s, l, t: NumberValue(int(t[0]) & 0xffffffff))
base16_integer = Regex("0x[a-fA-F0-9]+").setParseAction(lambda s, l, t: NumberValue(int(t[0], 16) & 0xffffffff))

# Join all the supported numbers.
number = (base2_integer ^ base10_integer ^ base16_integer ^ base_2_masked)

# Enumeration ::= {var0, 1, 2} | "01x"
enum_elements = delimitedList(identifier ^ number)
enum = Group(LBRACE + enum_elements + RBRACE).setParseAction(lambda x: Enumeration(x[0][:])) ^ base_2_masked

# Ignore '-' value.
ignored = Literal("-").setParseAction(lambda: Ignore())

# Forward declaration of a function call.
procedure_call_expr = Forward()

# Forward declaration of a bit extraction call.
bit_extract_expr = Forward()

# Forward declaration of an if expression.
if_expression = Forward()

# List: (a, b)
list_elements = delimitedList(boolean ^ identifier ^ number ^ ignored ^ procedure_call_expr)
list_expr = (LPAR + list_elements + RPAR).setParseAction(decode_list)

# Atoms are the most basic elements of expressions.
atom = boolean ^ identifier ^ number ^ enum ^ ignored ^ procedure_call_expr ^ bit_extract_expr ^ if_expression ^ list_expr

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

# Define a bit extraction expression.
bit_extract_expr <<= Group(
    identifier + LANGLE + (identifier ^ number) + Optional(COLON + (identifier ^ number)) + RANGLE).setParseAction(
    decode_bit_extract)

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
multiline_if_statement = (IF + expr + THEN + ZeroOrMore(EOL) + Group(statement_list) + ELSE + ZeroOrMore(EOL) + Group(statement_list) + ENDIF).setParseAction(
    decode_if_else)

# Two types of if statements.
if_statement = single_line_if_statement ^ multiline_if_statement

# Define a case statement.
otherwise_case = Group(OTHERWISE + Optional(EOL) + Group(statement_list))
case_list = Group(OneOrMore(Group(WHEN + expr + Optional(EOL) + Group(statement_list))) + Optional(otherwise_case))
case_statement = (CASE + expr + OF + EOL + case_list + ENDCASE).setParseAction(decode_case)

# Repeat until statement.
repeat_until_statement = (REPEAT + statement_list + UNTIL + expr).setParseAction(decode_repeat_until)

# While statement.
while_statement = (WHILE + expr + DO + statement_list).setParseAction(decode_while)

# For statement.
for_statement = (FOR + assignment_statement + TO + expr + statement_list).setParseAction(decode_for)

# Collect all statements. We have two kinds, the ones that end with a semicolon and other statements that do not.
statement <<= Group(((undefined_statement ^ unpredictable_statement ^ see_statement ^
                      implementation_defined_statement ^ subarchitecture_defined_statement ^ return_statement ^
                      procedure_call_statement ^ assignment_statement) + SEMI) ^
                    if_statement ^ repeat_until_statement ^ while_statement ^ for_statement ^ case_statement)

# Define a basic program.
program = statement_list


def test_specific():
    tests = []

    # PASS
    # tests.append("""if var == 1 then a();""")
    # tests.append("""if var == 1 then a(); b(); c(); d();""")
    # tests.append("""if var == 1 then a();\nb();""")
    # tests.append("""if var == 1 then a(); b();\nc();\nd();""")
    # tests.append("""case var_name of\nwhen 1 a(); b();\nwhen 2 c(); d();\nendcase""")

    p = """case type of
when '0010'
    regs = 4;
otherwise
    SEE "Related encodings";
endcase"""

    tests.append(p)

    for p in tests:
        print "# Testing:"
        print "--------------------------------"
        print "%s" % p
        print "--------------------------------"
        for s in program.parseString(p, parseAll=True):
            for a in s:
                print a
        print

    return True


def test_graph():
    p = "imm32 = 1 + b + c(3, 4 * 5);"
    ret = program.parseString(p, parseAll=True)
    visitor = GrapVisitor()

    for ast in ret:
        visitor.accept(ast[0])

    visitor.save("example.png")

def get_input_vars(input):
    input_vars = []

    for var in input.split():
        if not "#" in var:
            continue

        name, size = var.split("#")
        size = int(size)

        input_vars.append((name, size))

    return input_vars

def __validate_bit_patterns__(bit_patterns):
    cnt = 0
    for bit_pattern in bit_patterns:
        if not "#" in bit_pattern:
            cnt += len(bit_pattern)
        else:
            cnt += int(bit_pattern.split("#")[1])

    return cnt == 32 or cnt == 16


def __translate_bit_patterns__(bit_patterns):
    # Make sure the input patterns are valid.
    if not __validate_bit_patterns__(bit_patterns):
        raise RuntimeError("Invalid bit patters: %r" % bit_patterns)

    ret = []

    i = 31
    for bit_pattern in bit_patterns:
        # print "Decoding bit pattern: %r" % bit_pattern

        # Skip regular bits.
        if not "#" in bit_pattern:
            # print "  Skipping bits from [%d-%d]" % (i, i - len(bit_pattern) + 1)
            i -= len(bit_pattern)

        else:
            name, size = bit_pattern.split("#")
            size = int(size)

            # print "  Extracting bits into %s from [%d-%d]" % (name, i, i - size + 1)
            if size == 1:
                ret.append("unsigned %5s = get_bit(opcode, %2d);" % (name, i))
            else:
                ret.append("unsigned %5s = get_bits(opcode, %2d, %2d);" % (name, i, i - size + 1))

            i -= size

    return ret

def instruction_to_name(instruction):
    # (
    t = instruction["name"].replace(" ", "_").replace("(", "_").replace(")", "_").replace("-", "_").replace(",", "_").replace("/", "_").replace("#", "_")
    return t + "_" + instruction["encoding"].lower()

def test_transcoder():
    from ARMv7DecodingSpec import instructions

    pre = """
#include <iostream>
#include <tuple>

unsigned UInt(unsigned val) {
  return val;
}

unsigned get_bits(unsigned a, unsigned b, unsigned c) {
  return 0;
}

unsigned get_bit(unsigned a, unsigned b) {
  return 0;
}

unsigned ThumbExpandImm(unsigned a) {
  return 0;
}

unsigned ARMExpandImm(unsigned a) {
  return 0;
}

bool InITBlock() {
  return true;
}

bool LastInITBlock() {
  return true;
}

typedef unsigned uint32_t;

struct Instruction {
};

struct UnpredictableInstruction : public Instruction {
};

struct UndefinedInstruction : public Instruction {
};

struct SeeInstruction : public Instruction {
  SeeInstruction(const char *);
};

unsigned Concatenate(unsigned a, unsigned b, unsigned c) {
  return 0;
}

std::tuple<unsigned, unsigned> DecodeImmShift(unsigned a, unsigned b) {
  return std::tuple<unsigned, unsigned>(a, b);
}

std::tuple<unsigned, unsigned> ARMExpandImm_C(unsigned a, unsigned b) {
  return std::tuple<unsigned, unsigned>(a, b);
}

std::tuple<unsigned, unsigned> ThumbExpandImm_C(unsigned a, unsigned b) {
  return std::tuple<unsigned, unsigned>(a, b);
}

unsigned DecodeRegShift(unsigned a) {
    return 0;
}

unsigned ZeroExtend(unsigned a, unsigned b) {
  return 0;
}

unsigned SRType_LSL = 0;

struct status {
    unsigned C;
    unsigned LEN;
    unsigned STRIDE;
};

status APSR, FPSCR;

unsigned SignExtend(unsigned a, unsigned b) {
    return a;
}

unsigned AdvSIMDExpandImm(unsigned a, unsigned b, unsigned c) {
    return a;
}

unsigned NOT(unsigned a) {
    return a;
}

unsigned NOP() {
    return 0;
}

unsigned Consistent(unsigned a) {
    return a;
}


unsigned VBitOps_VBIT = 0;
unsigned VBitOps_VBIF = 0;
unsigned VBitOps_VBSL = 0;
unsigned InstrSet_ThumbEE = 0;
unsigned InstrSet_ARM = 0;
unsigned InstrSet_Thumb = 0;
unsigned VCGEtype_unsigned = 0;
unsigned VCGEtype_signed = 0;
unsigned VCGTtype_fp = 0;
unsigned VCGTtype_signed = 0;
unsigned VCGEtype_fp = 0;
unsigned VCGTtype_unsigned = 0;
unsigned VFPNegMul_VNMLA = 0;
unsigned VFPNegMul_VNMLS = 0;
unsigned VFPNegMul_VNMUL = 0;


unsigned CurrentInstrSet() {
    return 0;
}

unsigned ArchVersion() {
    return 0;
}

unsigned BitCount(unsigned a) {
    return 0;
}

unsigned Zeros(unsigned c) {
    return 0;
}

unsigned VFPExpandImm(unsigned a, unsigned b) {
    return 0;
}

#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)
"""
    print pre


    """
    unsigned shift_t;
    unsigned shift_n;
    std::tie(shift_t, shift_n) = DecodeImmShift(type, Concatenate(imm3, imm2, 2));

    esto esta mal!!!!!!
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE

    if (((((d == 13) || (d == 15)) || ((n == 13) || (n == 15))) || ((m == 13) || (m == 15)))) {
        return UnpredictableInstruction();
    }
    """

    i = 0
    limit = 0
    for instruction in instructions:
        if i < limit:
            i += 1
            continue

        input_vars = get_input_vars(instruction["pattern"])
        decoder = instruction["decoder"]

        print "// Translating: %d -> %s %s %s" % (i, instruction["name"], instruction["encoding"], instruction["pattern"])
        print "// Pseudocode:"

        for line in decoder.split("\n"):
            for line2 in line.split(";"):
                if not len(line2):
                    continue
                print "// " + line2.strip()

        print "// "
        print "// Translated code:"
        print "// " + ("-" * 80)

        print "Instruction decode_%s(uint32_t opcode) {" % instruction_to_name(instruction)
        ret = __translate_bit_patterns__(instruction["pattern"].split())
        for r in ret:
            print "    %s" % r

        ret = program.parseString(decoder, parseAll=True)
        visitor = CPPTranslatorVisitor(input_vars)

        body = ""
        for ast in ret:
            l = visitor.accept(ast[0])
            body += indent(l)
            if type(ast[0]) == ProcedureCall:
                body = body[:-1] + ";\n"

        #print "    // Local variables:"
        for var in visitor.define_me:
            print "    unsigned %s;" % var


        print body
        print "    Instruction ins;"
        print "    return ins;"
        print "}"

        i += 1

def test_all():
    from ARMv7DecodingSpec import instructions

    i = -1
    for ins in instructions:
        i += 1

        if not i % 10:
            print "Testing: %.4d - %.4d of %4d" % (i, i + 10, len(instructions))

        try:
            program.parseString(ins["decoder"], parseAll=True)
        except ParseException, e:
            print "Instruction name: ", ins["name"]
            print "Decoder:\n%s" % ins["decoder"]
            print "Error: %s" % e
            return False

    return True


def main():
    test_transcoder()

    if False:
        if not test_specific():
            print "Failed individual test cases."

    if False:
        if not test_all():
            print "Failed test of specification."

    return 0


if __name__ == '__main__':
    main()
