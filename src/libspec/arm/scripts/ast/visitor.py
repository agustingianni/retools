from ast.nodes import *

class Visitor(object):
    """
    Abstract base class that collects generic properties of
    the visitor pattern.
    """

    def accept(self, parent, node):
        """
        Main dispatcher of the visitor. It will route the 'accept' call
        to the particular accept method associated with the type.
        """
        if not node:
            return

        if type(node) is BooleanValue:
            r = self.accept_BooleanValue(parent, node)

        elif type(node) is Identifier:
            r = self.accept_Identifier(parent, node)

        elif type(node) is NumberValue:
            r = self.accept_NumberValue(parent, node)

        elif type(node) is List:
            r = self.accept_List(parent, node)

        elif type(node) is Enumeration:
            r = self.accept_Enumeration(parent, node)

        elif type(node) is UnaryExpression:
            r = self.accept_UnaryExpression(parent, node)

        elif type(node) is BinaryExpression:
            r = self.accept_BinaryExpression(parent, node)

        elif type(node) is ProcedureCall:
            r = self.accept_ProcedureCall(parent, node)

        elif type(node) is RepeatUntil:
            r = self.accept_RepeatUntil(parent, node)

        elif type(node) is While:
            r = self.accept_While(parent, node)

        elif type(node) is For:
            r = self.accept_For(parent, node)

        elif type(node) is If:
            r = self.accept_If(parent, node)

        elif type(node) is BitExtraction:
            r = self.accept_BitExtraction(parent, node)

        elif type(node) is ArrayAccess:
            r = self.accept_ArrayAccess(parent, node)

        elif type(node) is MaskedBinary:
            r = self.accept_MaskedBinary(parent, node)

        elif type(node) is Ignore:
            r = self.accept_Ignore(parent, node)

        elif type(node) is IfExpression:
            r = self.accept_IfExpression(parent, node)

        elif type(node) is CaseElement:
            r = self.accept_CaseElement(parent, node)

        elif type(node) is Case:
            r = self.accept_Case(parent, node)

        elif type(node) is Undefined:
            r = self.accept_Undefined(parent, node)

        elif type(node) is Unpredictable:
            r = self.accept_Unpredictable(parent, node)

        elif type(node) is See:
            r = self.accept_See(parent, node)

        elif type(node) is ImplementationDefined:
            r = self.accept_ImplementationDefined(parent, node)

        elif type(node) is SubArchitectureDefined:
            r = self.accept_SubArchitectureDefined(parent, node)

        elif type(node) is Return:
            r = self.accept_Return(parent, node)

        elif type(node) is VariableType:
            r = self.accept_VariableType(parent, node)

        elif type(node) is VariableDeclaration:
            r = self.accept_VariableDeclaration(parent, node)

        elif type(node) is Assertion:
            r = self.accept_Assertion(parent, node)

        else:
            raise RuntimeError("Invalid type: '%r' (%s)" % (type(node), str(node)))

        return r

    def accept_ArrayAccess(self, parent, node):
        self.accept(node, node.name)
        self.accept(node, node.expr1)
        self.accept(node, node.expr2)
        self.accept(node, node.expr3)

    def accept_BinaryExpression(self, parent, node):
        self.accept(node, node.left_expr)
        self.accept(node, node.right_expr)

    def accept_BitExtraction(self, parent, node):
        self.accept(node, node.identifier)
        for rg in node.range:
            self.accept(node, rg)

    def accept_BooleanValue(self, parent, node):
        pass

    def accept_Case(self, parent, node):
        self.accept(node, node.expr)
        for case in node.cases:
            self.accept(node, case)

    def accept_CaseElement(self, parent, node):
        self.accept(node, node.value)
        for statement in node.statements:
            self.accept(node, statement)

    def accept_Enumeration(self, parent, node):
        pass

    def accept_For(self, parent, node):
        self.accept(node, node.from_.left_expr)
        self.accept(node, node.from_.right_expr)
        self.accept(node, node.to)
        for statement in node.statements:
            self.accept(node, statement)

    def accept_Identifier(self, parent, node):
        pass

    def accept_If(self, parent, node):
        self.accept(node, node.condition)
        for statement in node.if_statements:
            self.accept(node, statement)

        for statement in node.else_statements:
            self.accept(node, statement)

    def accept_IfExpression(self, parent, node):
        self.accept(node, node.condition)
        self.accept(node, node.trueValue)
        self.accept(node, node.falseValue)

    def accept_Ignore(self, parent, node):
        pass

    def accept_ImplementationDefined(self, parent, node):
        pass

    def accept_List(self, parent, node):
        for value in node.values:
            self.accept(node, value)

    def accept_MaskedBinary(self, parent, node):
        pass

    def accept_NumberValue(self, parent, node):
        pass

    def accept_ProcedureCall(self, parent, node):
        for argument in node.arguments:
            self.accept(node, argument)

    def accept_RepeatUntil(self, parent, node):
        for statement in node.statements:
            self.accept(node, statement)

        self.accept(node, node.condition)

    def accept_Return(self, parent, node):
        self.accept(node, node.value)

    def accept_See(self, parent, node):
        pass

    def accept_SubArchitectureDefined(self, parent, node):
        pass

    def accept_UnaryExpression(self, parent, node):
        self.accept(node, node.expr)

    def accept_Undefined(self, parent, node):
        pass

    def accept_Unpredictable(self, parent, node):
        pass

    def accept_While(self, parent, node):
        self.accept(node, node.condition)
        for statement in node.statements:
            self.accept(node, statement)

    def accept_VariableType(self, parent, node):
        self.accept(node, node.name)
        self.accept(node, node.size)

    def accept_VariableDeclaration(self, parent, node):
        self.accept(node, node.type)
        self.accept(node, node.name)
        self.accept(node, node.value)

    def accept_Assertion(self, parent, node):
        self.accept(node, node.expression)
