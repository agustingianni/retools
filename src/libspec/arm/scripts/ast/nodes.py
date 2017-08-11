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
