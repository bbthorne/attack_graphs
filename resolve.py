from AttackGraph import *
"""
resolve takes an exploited AttackGraph and returns a list of which vulnerabilities
to address in order of priority. With the current implementation of AttackGraph,
it does so in O(n^4) (at least it's p-time). This could be lowered to O(n^2)
with a tweak in the AttackGraph parent representation. 
"""
def resolve(attackGraph):
    def resolve_tally(node):
        parents = attackGraph.parents(node)
        for parent in parents:
            if attackGraph.exploited[parent]:
                priorities[parent] += attackGraph.graph.node[node]['priority']
                resolve_tally(parent)

    priorities = {}
    for node, attacked in attackGraph.exploited.items():
        if attacked:
            priorities[node] = 0

    for node in priorities.keys():
        resolve_tally(node)
        priorities[node] += attackGraph.graph.node[node]['priority']

    return list(priorities.keys())

if __name__ == "__main__":
    attackGraph = AttackGraph()
    attackGraph.generate_graph()
    attackGraph.edit_info()
    attackGraph.attack([0,1,5,7])

    action = resolve(attackGraph)
    print([attackGraph.info[x] for x in action])
