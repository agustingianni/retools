from ast.visitor import Visitor

class TransformationPass(Visitor):
    """
    The transformation passes are destructive on the input AST statements,
    that is, it modifies the AST representation.
    """
    def transform(self, ast_statements):
        """
        Apply the transformation routines to all the AST statements.
        """
        for statement in ast_statements:
            self.accept(statement)

class SimpleFunctionOptimization(TransformationPass):
    """
    A simple optimization pass that removes some of the parts
    of the pseudocode that are not really used by the generated code.
    """
    name = "SimpleFunctionOptimization"
    description = "Simplify simple function calls when we can."

    def accept_ProcedureCall(self, node):
        if node.name.name == "IsZeroBit":
            print "IsZeroBit node -> %r" % node

        elif node.name.name == "get_bit":
            print "get_bit node -> %r" % node

class IdentifierRenamer(TransformationPass):
    """
    Change the names of all the identifiers in the AST.
    """
    name = "IdentifierRenamer"
    description = "Chage the names of certain identifiers in the AST."

    def __init__(self, identifiers, prefix):
        self.identifiers = set(identifiers)
        self.prefix = prefix

    def accept_ArrayAccess(self, node):
        """
        The only array accesses are on the operation specification of ARMv7.
        They are used to access different kinds of registers and memory.
        Since we access memory via the context class and not the instruction
        class, we must not change the name of a memory access so we avoid
        'accepting' the Identifier of an ArrayAccess.
        """
        self.accept(node.expr1)
        self.accept(node.expr2)
        self.accept(node.expr3)

    def accept_Identifier(self, node):
        """
        The identifiers in the specification are not part of an object. The
        task of this is to change the right identifiers to be part of the
        ARMInstruction object being used.
        """
        if node.name in self.identifiers:
            node.name = self.prefix + node.name
