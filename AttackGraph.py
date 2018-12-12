"""
AttackGraph is a class that represents attack graphs used to model
vulnerabilities and the dependencies among them in a network. It has four
properties:
    graph        - a networkx directed graph representing the basic structure
                   of the attack graph
    dependencies - a dictionary where nodes in graph are keys and their values
                   are either the higher-order functions 'all' or 'any', or None
    exploited    - a dictionary where keys are nodes in the graph and values are
                   Booleans that represent if the nodes have been exploited
    info         - a dictionary where keys are nodes in the graph and values are
                   strings that contain descriptions of the nodes
"""
import networkx

class AttackGraph:
    def __init__(self):
        self.graph        = networkx.DiGraph()
        self.dependencies = {}
        self.exploited    = {}
        self.info         = {}

    """
    generate_graph is a method that builds an attack graph. There are three main
    steps in doing this: adding all nodes to the graph, adding edges to the graph,
    and adding node dependency functions to dependencies.
    """
    def generate_graph(self):
        # add all of the nodes to the attack graph
        for i in range(9):
            self.graph.add_node(i, priority=1)

        # add all of the edges to the attack graph
        for node in self.graph.nodes():
            if node == 0 or node == 1:
                self.graph.add_edge(node,3)
            if node == 1 or node == 2:
                self.graph.add_edge(node,4)
            if node == 3 or node == 4:
                self.graph.add_edge(node,6)
            if node == 5 or node == 6 or node == 7:
                self.graph.add_edge(node,8)

        # assign dependency functions to appropriate nodes
        inDegrees = self.in_degrees()
        for node in self.graph.nodes():
            if not inDegrees[node] == 0:
                if node == 3 or node == 4 or node == 8:
                    self.dependencies[node] = all
                else:
                    self.dependencies[node] = any
            else:
                self.dependencies[node] = None

    """
    in_degrees is a method that returns a dictionary mapping nodes to the number
    of directed edges of which a node is the destination.
    """
    def in_degrees(self):
        inDegrees = {}
        for node in self.graph.nodes():
            inDegrees[node] = 0
        for source, dest in self.graph.edges():
            inDegrees[dest] += 1
        return inDegrees

    """
    edit_info is a method that populates info with descriptions of each node
    """
    def edit_info(self):
        self.info = {0 : "Running ftpd on machine x.y.z.5",
                     1 : "x.y.z.5 accessible through internet",
                     2 : "Running Pragma Fortress SSH 4.0.7.20 on machine x.y.z.5",
                     3 : "Buffer Overflow in ftp daemon on x.y.z.5",
                     4 : "Buffer Overflow in SSH service on x.y.z.5",
                     5 : "LICQ 1.0.2 running on x.y.z.6",
                     6 : "Root access on x.y.z.5",
                     7 : "x.y.z.6 is accessible from x.y.z.5",
                     8 : "LICQ vulnerability allowing arbitrary code injection on x.y.z.6"
                    }

    """
    attack is a method that takes a list of exploited nodes damage and runs an
    attack simulation on the graph based on dependencies. exploited is then
    updated to reflect the areas affected by the attack.
    """
    def attack(self, damage):
        # determine if a vulnerability node has been affected by the attack
        def attack_cascade(node):
            if self.exploited[node]:
                for src, dest in self.graph.edges():
                    if src == node:
                        attack_cascade(dest)
            sources = []
            for src, dest in self.graph.edges():
                if dest == node:
                    sources.append(src)
            if self.dependencies[node] is not None:
                if self.dependencies[node]([self.exploited[x] for x in sources]):
                    self.exploited[node] = True

        # initialize exploited
        for node in self.graph.nodes():
            if node in damage:
                self.exploited[node] = True
            else:
                self.exploited[node] = False

        # run attack through each dependent node
        for node in self.dependencies.keys():
            attack_cascade(node)
    """
    parents is a method that returns a list of nodes which the current node is
    dependent on. For now, it does so by checking the graph's edges, which
    increases runtime. If runtime is a probelem, include parent nodes in the
    attributes of the nodes in graph instead.
    """
    def parents(self, node):
        results = []
        for src, dest in self.graph.edges():
            if dest == node:
                results.append(src)
        return results
