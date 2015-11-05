from ast.nodes import *

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
        if not node:
            return

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

    def accept_ArrayAccess(self, node):
        self.accept(node.name)
        self.accept(node.expr1)
        self.accept(node.expr2)
        self.accept(node.expr3)

    def accept_BinaryExpression(self, node):
        self.accept(node.left_expr)
        self.accept(node.right_expr)

    def accept_BitExtraction(self, node):
        self.accept(node.identifier)
        for range in node.range:
            self.accept(range)

    def accept_BooleanValue(self, node):
        pass

    def accept_Case(self, node):
        self.accept(node.expr)
        for case in node.cases:
            self.accept(case)

    def accept_CaseElement(self, node):
        self.accept(node.value)
        for statement in node.statements:
            self.accept(statement)

    def accept_Enumeration(self, node):
        pass

    def accept_For(self, node):
        self.accept(node.from_.left_expr)
        self.accept(node.from_.right_expr)
        self.accept(node.to)
        for statement in node.statements:
            self.accept(statement)

    def accept_Identifier(self, node):
        pass

    def accept_If(self, node):
        self.accept(node.condition)
        for statement in node.if_statements:
            self.accept(statement)

        for statement in node.else_statements:
            self.accept(statement)

    def accept_IfExpression(self, node):
        self.accept(node.condition)
        self.accept(node.trueValue)
        self.accept(node.falseValue)

    def accept_Ignore(self, node):
        pass

    def accept_ImplementationDefined(self, node):
        pass

    def accept_List(self, node):
        for value in node.values:
            self.accept(value)

    def accept_MaskedBinary(self, node):
        pass

    def accept_NumberValue(self, node):
        pass

    def accept_ProcedureCall(self, node):
        for argument in node.arguments:
            self.accept(argument)

    def accept_RepeatUntil(self, node):
        for statement in node.statements:
            self.accept(statement)

        self.accept(node.condition)

    def accept_Return(self, node):
        self.accept(node.value)

    def accept_See(self, node):
        pass

    def accept_SubArchitectureDefined(self, node):
        pass

    def accept_UnaryExpression(self, node):
        self.accept(node.expr)

    def accept_Undefined(self, node):
        pass

    def accept_Unpredictable(self, node):
        pass

    def accept_While(self, node):
        self.accept(node.condition)
        for statement in node.statements:
            self.accept(statement)
