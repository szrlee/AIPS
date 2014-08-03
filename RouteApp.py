#!/usr/bin python2
# -*- coding: UTF-8 -*- #


"""def get_tree_graph():
    #return graph
    pass
According to POX wiki ,method spanning_tree  returns it as dictionary like
  {s1:([(s2,port1),(s3,port2),...]),s2:([(s1,port),...]),...}
  #port refers to the port of s1 which connects to s2
A graph example for path searching.
graph = {'A': ['B', 'C'],'B': ['C', 'D'],
             'C': ['D'],
             'D': ['C'],
             'E': ['F'],
             'F': ['C']}"""


def find_shortest_route(graph, start, end, path=[]):
    #find the shortest path from start to end ,including ports INFO from one node to another
    path = path + [start]
    if start == end:
        return path
    if not graph. has_key(start):
        return None
    shortest = []

    #Analyze the contents,([('h1', 'port11'), ('h2', 'port12'), ('s2', 'port13')])
    start_list = graph[start]
    for item in start_list:
        if item[0] not in path:
            newpath = find_shortest_route(graph, item[0], end, path)
            if newpath:
                if not shortest or len(newpath) < len(shortest):
                    shortest = newpath

    return shortest


def get_shortest_route(graph, start, end):
    path = []
    route = find_shortest_route(graph, start, end)
    #add the port info from one node to another

    for index in range(0, len(route)-1):
        for item in graph[route[index]]:
            #Contents ([('h1', 'port11'), ('h2', 'port12'), ('s2', 'port13')])
            if item[0] == route[index+1]:
                path = path + [(route[index], item[1])]
                break
    path += [route[-1]]
    return path

if __name__ == '__main__':
    graph = {'h1': ([('s1', 'porth1_s1')]), 'h2': ([('s3', 'porth2_s3')]),
             's1': ([('h1', 'ports1_h1'), ('s2', 'ports1_s2')]),
             's2': ([('s1', 'ports2_s1'), ('s3', 'ports2_s3')]),
             's3': ([('s2', 'ports3_s2'), ('h2', 'ports3_h2')])
            }

    print get_shortest_route(graph, 'h1', 'h2')





