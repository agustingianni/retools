"""
Grammar for the ARMv7-A, ARMv7-R, ARMv8-A specification
pseudocode.
"""
import sys
import string
from pyparsing import *

from ast.nodes import *

# Avoid treating newlines as whitespaces.
ParserElement.setDefaultWhitespaceChars(" \t")

# Enable optimizations.
ParserElement.enablePackrat()

def DumpTokens(token_list):
    import pprint
    pprint.pprint(token_list)

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
    return For(x[1], x[3], [e[0] for e in x[4]])

def decode_while(x):
    return While(x[1], x[3])

def decode_unary(x):
    x = x[0]

    if len(x) != 2:
        raise "Invalid unary operation: %r" % x

    op_name = {"!": "negate", "-": "minus", "~": "invert", "+": "plus"}
    op = op_name[x[0]]
    return UnaryExpression(op, x[1])

def decode_binary(x):
    op_name = {"+": "add", "-": "sub", "/": "div", "*": "mul",
            "<<": "lshift", ">>": "rshift", "DIV": "idiv", "MOD": "imod",
            "^": "xor", "||": "or", "&&": "and", "==": "eq", "!=": "ne",
            ">": "gt", "<": "lt", ">=": "gte", "<=": "lte", "IN": "in",
            "=": "assign", "EOR": "xor", ":": "concatenation", "AND": "band", "OR": "bor"}

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

def decode_singleline_if_statement(a, b, x):
    assert "if" == x[0]
    assert "then" == x[2]
    return If(x[1], map(lambda y: y[0], list(x[3:])), [])

def decode_multiline_if_statement(s, l, x):
    # List of tuples in the form (expression, statements)
    conditional_statements = []

    # Collect indexes of 'if' and 'elsif' parts.
    indexes = [i for i, j in enumerate(x) if j in ["if", "elsif"]]
    for i in indexes:
        condition = x[i + 1]
        statements = map(lambda y: y[0], x[i + 3])
        conditional_statements.append((condition, statements))

    # Get the else statements if any.
    else_statements = map(lambda y: y[0], x[-2]) if x[-3] == "else" else []

    # HACK: Implement the correct mechanism here.
    cond = conditional_statements[0][0]
    if_st = conditional_statements[0][1]
    then_st = else_statements

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
    # Remove the initial quotes, ie.: "01x" -> 01x.
    value = x[0][1:-1]
    return MaskedBinary(value)

def decode_base2_integer(s, l, t):
    # Remove the initial quotes, ie.: "01x" -> 01x.
    value = t[0][1:-1]
    size = len(value)
    return NumberValue(int(value, 2) & 0xffffffff, len(value))

def decode_base10_integer(s, l, t):
    value = t[0]
    return NumberValue(int(value) & 0xffffffff)

def decode_base16_integer(s, l, t):
    value = t[0]
    return NumberValue(int(value, 16) & 0xffffffff)

def decode_identifier(x):
    return Identifier(x[0])

def decode_list(x):
    return List(x[0:])

def decode_var_type(x):
    variable_name = x[0]
    variable_size = str(x[1]) if len(x) > 1 else None
    return VariableType(variable_name, variable_size)

def decode_var_declaration(x):
    variable_type = x[0]
    variable_name = x[1]
    variable_value = x[3] if len(x) > 3 else None
    return VariableDeclaration(variable_type, variable_name, variable_value)

def decode_assertion_statement(x):
    return Assertion(x[1])

def decode_procedure_call_expr(x):
    return ProcedureCall(x[0][0], x[0][1:])

def decode_boolean(x):
    return BooleanValue(x[0] == "TRUE")

def decode_enum(x):
    return Enumeration(x[0][:])

def decode_ignore(x):
    return Ignore()

def decode_undefined(x):
    return Undefined()

def decode_unpredictable(x):
    return Unpredictable()

def decode_see(x):
    return See(x[0][1])

def decode_implementation_defined(x):
    return ImplementationDefined()

def decode_subarchitecture_defined(x):
    return SubArchitectureDefined()

def decode_return(x):
    return Return(x[0][1])

class ARMCodeParser():
    def __init__(self):
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
        CONSTANT = Keyword("constant")
        ASSERT = Keyword("assert")

        # Commonly used constants.
        TRUE = Keyword("TRUE")
        FALSE = Keyword("FALSE")
        UNKNOWN = Keyword("UNKNOWN")
        UNDEFINED = Keyword("UNDEFINED")
        UNPREDICTABLE = Keyword("UNPREDICTABLE")
        SEE = Keyword("SEE")
        IMPLEMENTATION_DEFINED = Keyword("IMPLEMENTATION_DEFINED")
        SUBARCHITECTURE_DEFINED = Keyword("SUBARCHITECTURE_DEFINED")

        # Define the boolean values.
        boolean = MatchFirst([TRUE, FALSE])
        boolean.setParseAction(decode_boolean)

        # An identifier is a name.
        identifier = Word(alphas + "_", alphanums + "_.")
        identifier.setParseAction(decode_identifier)

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
        relational_operator = oneOf("< <= > >= IN")

        # Equal or not equal operators.
        eq_neq_operator = oneOf("== !=")

        # Bitwise operators.
        bit_operator = oneOf("& AND | OR ^ EOR")

        # Logical operators.
        logical_operator = oneOf("&& ||")

        # Assignment operator.
        assignment_operator = Literal("=")

        # Define an integer for base 2, 10 and 16 and make sure it is 32 bits long.
        base_2_masked = Regex("[\'\"][01x]+[\'\"]").setParseAction(decode_masked_base2)
        base2_integer = Regex("\'[01x]+\'").setParseAction(decode_base2_integer)
        base10_integer = Regex("\d+").setParseAction(decode_base10_integer)
        base16_integer = Regex("0x[a-fA-F0-9]+").setParseAction(decode_base16_integer)

        # Join all the supported numbers.
        number = base16_integer | base2_integer | base10_integer | base_2_masked

        # Enumeration ::= {var0, 1, 2} | "01x"
        enum_atom = identifier | number
        enum_elements = delimitedList(enum_atom)
        enum = Group(LBRACE + enum_elements + RBRACE) ^ base_2_masked
        enum.setParseAction(decode_enum)

        # Ignore '-' value.
        ignored = Literal("-").setParseAction(decode_ignore)

        # Forward declaration of a function call.
        procedure_call_expr = Forward()

        # Forward declaration of a bit extraction call.
        bit_extract_expr = Forward()

        # Forward declaration of a array access expression.
        array_access_expr = Forward()

        # Forward declaration of an if expression.
        if_expression = Forward()

        # List: (a, b)
        list_atom = ignored | procedure_call_expr | array_access_expr | boolean | identifier | number
        list_elements = delimitedList(list_atom)
        list_expr = LPAR + list_elements + RPAR
        list_expr.setParseAction(decode_list)

        # Atoms are the most basic elements of expressions.
        atom = Or([
            boolean,
            number,
            ignored,
            identifier,
            if_expression,
            procedure_call_expr,
            array_access_expr,
            bit_extract_expr,
            list_expr,
            enum
        ])

        # Define the order of precedence.
        expr = infixNotation(atom, [
            (unary_operator, 1, opAssoc.RIGHT, decode_unary),
            (bit_concat_operator, 2, opAssoc.LEFT, decode_binary),
            (mul_div_mod_operator, 2, opAssoc.LEFT, decode_binary),
            (add_sub_operator, 2, opAssoc.LEFT, decode_binary),
            (shift_operator, 2, opAssoc.LEFT, decode_binary),
            (relational_operator, 2, opAssoc.LEFT, decode_binary),
            (eq_neq_operator, 2, opAssoc.LEFT, decode_binary),
            (bit_operator, 2, opAssoc.LEFT, decode_binary),
            (logical_operator, 2, opAssoc.LEFT, decode_binary),
        ])

        # Define a bit extraction expression-
        simplified_atom = Or([
            number,
            identifier,
            if_expression,
            procedure_call_expr,
            array_access_expr
        ])

        simplified_expr = infixNotation(simplified_atom, [
            (oneOf("*"), 2, opAssoc.LEFT, decode_binary),
            (oneOf("+ -"), 2, opAssoc.LEFT, decode_binary)
        ])

        # Define a simple index expression used in bit extraction expressions.
        bit_extract_idx_atom = number | identifier
        bit_extract_idx_expr = infixNotation(bit_extract_idx_atom, [
            (oneOf("*"), 2, opAssoc.LEFT, decode_binary),
            (oneOf("+ -"), 2, opAssoc.LEFT, decode_binary)
        ])

        bit_extract_expr <<= Group(simplified_expr + LANGLE + delimitedList(bit_extract_idx_expr, delim=":") + RANGLE)
        bit_extract_expr.setParseAction(decode_bit_extract)

        # Define a array access expression
        array_access_expr <<= Group(identifier + LBRACK + delimitedList(expr) + RBRACK)
        array_access_expr.setParseAction(decode_array_access)

        # Define a procedure call.
        procedure_arguments = delimitedList(expr)
        procedure_call_expr <<= Group(identifier + LPAR + Optional(procedure_arguments) + RPAR)
        procedure_call_expr.setParseAction(decode_procedure_call_expr)

        # Define an if expression.
        if_expression <<= IF + expr + THEN + expr + ELSE + expr
        if_expression.setParseAction(decode_if_expression)

        # Standard types used in ARMv8 pseudocode.
        single_bitstring = Keyword("bit")
        multi_bitstring = Keyword("bits") + LPAR + expr + RPAR
        bitstring_type = single_bitstring | multi_bitstring

        enum_types = Or([
            Keyword("AccType"),
            Keyword("BranchType"),
            Keyword("CompareOp"),
            Keyword("Constraint"),
            Keyword("CountOp"),
            Keyword("ExtendType"),
            Keyword("FPConvOp"),
            Keyword("FPExc"),
            Keyword("FPMaxMinOp"),
            Keyword("FPRounding"),
            Keyword("FPUnaryOp"),
            Keyword("ImmediateOp"),
            Keyword("LogicalOp"),
            Keyword("MBReqDomain"),
            Keyword("MBReqTypes"),
            Keyword("MemAtomicOp"),
            Keyword("MemBarrierOp"),
            Keyword("MemOp"),
            Keyword("MoveWideOp"),
            Keyword("PSTATEField"),
            Keyword("ReduceOp"),
            Keyword("ShiftType"),
            Keyword("SystemHintOp"),
            Keyword("VBitOp")
        ])

        # Simple variable types.
        variable_type = bitstring_type | INTEGER | BOOLEAN | enum_types
        variable_type.setParseAction(decode_var_type)

        # A variable declaration has an optional initialization part.
        variable = identifier + Optional(assignment_operator + expr)
        variable_declaration = Suppress(Optional(CONSTANT)) + variable_type + delimitedList(variable)
        variable_declaration.setParseAction(decode_var_declaration)

        # Assertion statement.
        assertion_statement = ASSERT + expr
        assertion_statement
        assertion_statement.setParseAction(decode_assertion_statement)

        # Forward declaration of a generic statement.
        statement = Forward()
        statement_list = OneOrMore(statement + Optional(EOL))

        see_allowed = string.letters + string.digits + " -()/\","
        see_statement = Group(SEE + Word(see_allowed + " "))
        see_statement.setParseAction(decode_see)

        undefined_statement = UNDEFINED
        undefined_statement.setParseAction(decode_undefined)

        unpredictable_statement = UNPREDICTABLE
        unpredictable_statement.setParseAction(decode_unpredictable)

        implementation_defined_statement = Group(IMPLEMENTATION_DEFINED + Word(see_allowed))
        implementation_defined_statement.setParseAction(decode_implementation_defined)

        subarchitecture_defined_statement = Group(SUBARCHITECTURE_DEFINED + Word(see_allowed))
        subarchitecture_defined_statement.setParseAction(decode_subarchitecture_defined)

        return_statement = Group(RETURN + Optional(expr))
        return_statement.setParseAction(decode_return)

        procedure_call_statement = procedure_call_expr

        # Assignment statement.
        assignment_statement = expr + assignment_operator + expr
        assignment_statement.setParseAction(lambda x: decode_binary([x]))

        # Parse: if <cond> then st1; st2; st3; ... stn;
        singleline_if_statements = OneOrMore(statement)
        singleline_if_statement = IF + expr + THEN + singleline_if_statements
        singleline_if_statement.setParseAction(decode_singleline_if_statement)

        # Parse a complete if/elsif/else statement.
        multiline_if_statement = IF + expr + THEN + OneOrMore(EOL) + Group(statement_list) \
            + ZeroOrMore(ELSIF + expr + THEN + OneOrMore(EOL) + Group(statement_list)) \
            + Optional(ELSE + OneOrMore(EOL) + Group(statement_list)) \
            + ENDIF

        multiline_if_statement.setParseAction(decode_multiline_if_statement)

        # Two types of if statements.
        if_statement = MatchFirst([multiline_if_statement, singleline_if_statement])

        # Define a case statement.
        otherwise_case = Group(OTHERWISE + Optional(EOL) + Group(statement_list))
        case_list = Group(OneOrMore(Group(WHEN + expr + Optional(EOL) + Group(statement_list))) + Optional(otherwise_case))
        case_statement = CASE + expr + OF + EOL + case_list + ENDCASE
        case_statement.setParseAction(decode_case)

        # Repeat until statement.
        repeat_until_statement = REPEAT + EOL + statement_list + UNTIL + expr
        repeat_until_statement.setParseAction(decode_repeat_until)

        # While statement.
        while_statement = WHILE + expr + DO + statement_list
        while_statement.setParseAction(decode_while)

        # For statement.
        for_statement = FOR + assignment_statement + TO + expr + EOL + Group(statement_list) + ENDFOR
        for_statement.setParseAction(decode_for)

        # Two kinds of statements: the ones that end with a semicolon and the ones that do not.
        t1 = MatchFirst([
            assertion_statement,
            variable_declaration,
            undefined_statement,
            unpredictable_statement,
            see_statement,
            implementation_defined_statement,
            subarchitecture_defined_statement,
            return_statement,
            procedure_call_statement,
            assignment_statement
        ])

        t2 = MatchFirst([
            if_statement,
            repeat_until_statement,
            while_statement,
            for_statement,
            case_statement
        ])

        statement <<= Group(MatchFirst([t1 + SEMI, t2]))

        # Define a basic program.
        self.program = statement_list

    def parse(self, code):
        try:
            ret = self.program.parseString(code, parseAll=True)
            return map(lambda x: x[0], ret)

        except ParseException, e:
            print "Error at line %u column %u" % (e.lineno - 1, e.column)
            for i, line in enumerate(code.split("\n")):
                if i == e.lineno - 1:
                    print '\033[91m'

                print "%3u: %s" % (i, line)
                if i == e.lineno - 1:
                    print '\033[0m',
                    print " " * (e.column - 3 + 5 if e.column != 0 else 0), "^"

            raise e

        return ret

if False:
    code = """(hola + hola() + 10)<31:0>"""
    code = "p = if BigEndian then value<63:32> else value<31:0>;"
    DumpTokens(ARMCodeParser().parse(code))
    sys.exit()


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
