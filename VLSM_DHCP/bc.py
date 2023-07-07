# -*- coding: utf-8 -*-
"""
Created on Fri Apr  7 13:14:12 2023

@author: Ramprasad
"""

# Using a Python dictionary to act as an adjacency list
graph = {
  '1' : ['2','6'],
  '3' : ['6', '4'],
  '5' : ['4'],
  '2' : ['4','5'],
  '4' : ['3'],
  '6' : ['3','5']
}

visited = [] # List for visited nodes.
queue = []     #Initialize a queue
le=[]
lf=['1','2','3','4','5','6']
print("Before The Entire Broadcasting Process the Initial Values\n inside the Two Data Structures Include:")
print("le : ",le)
print("lf : ",lf)
def bfs(visited, graph, node): #function for BFS
  visited.append(node)
  queue.append(node)
  le.append(node)
  lf.remove(node)
  i=1
  f=0
  while queue:          # Creating loop to visit each node
    m = queue.pop(0)
    #print(iter,"\n")
    
    #print (m,":",end=" ") 
    for neighbour in graph[m]:
        if neighbour not in le: 
            le.append(neighbour)
            lf.remove(neighbour)
            
    if(len(lf)!=0):
        print (m,":",end=" ")
        print("After ",i," iteration le and lf are As follows:")
        print("le- ",le)
        print("lf- ",lf)

    else:
        if(f!=1):
            print (m,":",end=" ")
            print("After ",i-1," iteration le and lf are As follows:")
            print("le- ",le)
            print("lf- ",lf)
            f=1
        break
    i+=1
    
    for neighbour in graph[m]:
      if neighbour not in visited:
        visited.append(neighbour)
        queue.append(neighbour)
    

# Driver Code
#print("Following is the Breadth-First Search")
bfs(visited, graph, '1')    # function calling