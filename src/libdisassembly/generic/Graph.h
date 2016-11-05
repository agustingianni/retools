/*
 * DirectedGraph.h
 *
 *  Created on: Mar 18, 2016
 *      Author: anon
 */

#ifndef SRC_LIBDISASSEMBLY_GENERIC_DIRECTEDGRAPH_H_
#define SRC_LIBDISASSEMBLY_GENERIC_DIRECTEDGRAPH_H_

#include <set>

template<typename NodeType>
class GraphEdge {
private:
    NodeType m_source;
    NodeType m_target;

public:
    GraphEdge(NodeType n1, NodeType n2) :
            m_source{n1}, m_target{n2} {
    }

    const NodeType &getSource() const {
        return m_source;
    }

    const NodeType &getTarget() const {
        return m_target;
    }
};

template<typename NodeType>
class GraphNode {
private:
    std::set<NodeType> m_children;
    std::set<NodeType> m_parents;

public:
    const std::set<NodeType> &getChildren() const {
        return m_children;
    }

    const std::set<NodeType> &getParents() const {
        return m_parents;
    }
};

template<typename NodeType, typename EdgeType>
class Graph {
private:
    std::set<NodeType> m_nodes;
    std::set<EdgeType> m_edges;

public:
    void addNode(NodeType &node) {
        m_nodes.insert(node);
    }

    void removeNode(NodeType &node) {
        m_nodes.erase(node);
    }

    void addEdge(EdgeType &edge) {
        m_edges.insert(edge);
    }

    void addEdge(NodeType &n1, NodeType &n2) {
        addNode(n1);
        addNode(n2);

        EdgeType edge(n1, n2);
        addEdge(edge);
    }

    void removeEdge(EdgeType &edge) {
        m_edges.erase(edge);
    }

    const std::set<NodeType> &getNodes() const {
        return m_nodes;
    }

    const std::set<EdgeType> &getEdges() const {
        return m_edges;
    }

    size_t edgeCount() const {
        return m_edges.size();
    }

    size_t nodeCount() const {
        return m_nodes.size();
    }

};

#endif /* SRC_LIBDISASSEMBLY_GENERIC_DIRECTEDGRAPH_H_ */
