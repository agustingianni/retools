import uuid
from pydot import Dot, Node, Edge

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
