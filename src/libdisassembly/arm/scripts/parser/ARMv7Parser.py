"""
Python parser for the ARM Architecture Reference Manual (ARMv7-A and ARMv7-R edition)
pseudocode.
"""
import string
from pyparsing import *

from ast.nodes import *

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

    raise RuntimeError("Cannot decode '%s'" % str(x))

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

def parse_program(input):
    ret = program.parseString(input, parseAll=True)
    return map(lambda x: x[0], ret)

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
        toks = toks.asList()
        assert toks[0] == "{" and toks[-1] == "}"

        return OptionalToken(toks[1:-1])

    def decode_opcode_name(s, locs, toks):
        toks = toks.asList()
        return OpcodeName(toks)

    def decode_opcode_args(s, locs, toks):
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
