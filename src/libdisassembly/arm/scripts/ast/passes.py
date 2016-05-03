from ast.visitor import Visitor
from ast.nodes import List, ProcedureCall, ArrayAccess, If, Identifier, BinaryExpression

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
            self.accept(None, statement)

def MakeAssignmentStatement(lhs, rhs):
    return BinaryExpression("assign", lhs, rhs)

class ListAssignmentRewriter(TransformationPass):
    name = "ListAssignmentRewriter"
    description = "Fixes untranslatable list assignments."

    def __init__(self):
        self.cur_temp = 0

    def accept_AssignmentStatement(self, parent, node):
        # Match only assignments to lists.
        if type(node.left_expr) is List and type(node.right_expr) is ProcedureCall:
            needs_update = False
            new_assignments = []
            new_list_values = []
            
            # Iterate all the values from the 'List'.
            for val in node.left_expr.values:
                if not type(val) is ArrayAccess:
                    new_list_values.append(val)
                    continue

                # Create a new temporary.
                ident = Identifier("tmp_%d" % self.cur_temp)
                self.cur_temp += 1

                # Append the new AST node.
                new_list_values.append(ident)

                # Assign the temp to the real destination.
                new_assignment = MakeAssignmentStatement(val, ident)

                # Append the new assignment statement.
                new_assignments.append(new_assignment)

                needs_update = True

            if not needs_update:
                return

            # Replace the old elements of the 'List' node.
            node.left_expr.values = new_list_values

            # If the type is 'If' we need to find the branch.
            if type(parent) is If:
                new_statements = []
                for st in parent.if_statements:
                    new_statements.append(st)

                    if node == st:
                        new_statements.extend(new_assignments)

                parent.if_statements = new_statements

                new_statements = []
                for st in parent.else_statements:
                    new_statements.append(st)

                    if node == st:
                        new_statements.extend(new_assignments)

                parent.else_statements = new_statements
            

    def accept_BinaryExpression(self, parent, node):
        if node.type == "assign":
            return self.accept_AssignmentStatement(parent, node)

        self.accept(node, node.left_expr)
        self.accept(node, node.right_expr)

class SimpleFunctionOptimization(TransformationPass):
    """
    A simple optimization pass that removes some of the parts
    of the pseudocode that are not really used by the generated code.
    """
    name = "SimpleFunctionOptimization"
    description = "Simplify simple function calls when we can."

    def accept_ProcedureCall(self, parent, node):
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

    def accept_ArrayAccess(self, parent, node):
        """
        The only array accesses are on the operation specification of ARMv7.
        They are used to access different kinds of registers and memory.
        Since we access memory via the context class and not the instruction
        class, we must not change the name of a memory access so we avoid
        'accepting' the Identifier of an ArrayAccess.
        """
        self.accept(node, node.expr1)
        self.accept(node, node.expr2)
        self.accept(node, node.expr3)

    def accept_Identifier(self, parent, node):
        """
        The identifiers in the specification are not part of an object. The
        task of this is to change the right identifiers to be part of the
        ARMInstruction object being used.
        """
        if node.name in self.identifiers:
            node.name = self.prefix + node.name
