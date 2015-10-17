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
