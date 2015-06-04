package graph

import (
	"container/list"
	"errors"
)

// Vertex is a vertex for DAG.
type Vertex struct {
	Value interface{}
}

// DAG is a Directed Acyclic Graph implemented with an adjacency list.
type DAG struct {
	Root      *Vertex
	Adjacency map[*Vertex]*list.List
}

// NewDAG constructs a new graph with a single root vertex.
func NewDAG(v interface{}) *DAG {
	root := &Vertex{Value: v}
	return &DAG{
		Root:      root,
		Adjacency: map[*Vertex]*list.List{root: list.New()},
	}
}

// Add inserts a vertex holding a value v in the graph.
func (g *DAG) Add(v interface{}) *Vertex {
	vert := &Vertex{Value: v}
	g.Adjacency[vert] = list.New()
	return vert
}

// Get returns the vertex for the corresponding value.
func (g *DAG) Get(v interface{}) (*Vertex, bool) {
	for vert := range g.Adjacency {
		if v == vert.Value {
			return vert, true
		}
	}
	return nil, false
}

// AddEdge inserts an directed edge between two vertecies.
func (g *DAG) AddEdge(to, from *Vertex) error {
	if _, ok := g.Adjacency[to]; !ok {
		return errors.New("to vertex not found")
	}

	l, ok := g.Adjacency[from]
	if !ok {
		return errors.New("from vertex not found")
	}

	l.PushBack(to)
	return g.cyclicCheck()
}

func (g *DAG) cyclicCheck() error {
	visited := make(map[*Vertex]bool, len(g.Adjacency))
	visiting := make(map[*Vertex]bool, len(g.Adjacency))

	var walker WalkFunc
	walker = func(v *Vertex) error {
		if visited[v] {
			return nil
		}

		if visiting[v] && !visited[v] {
			return errors.New("cycle detected")
		}

		visiting[v] = true
		if err := g.walk(v, walker); err != nil {
			return err
		}
		visited[v] = true

		return nil
	}

	return walker(g.Root)
}

// WalkFunc is a common func for all graph walking methods.
type WalkFunc func(*Vertex) error

func (g *DAG) walk(v *Vertex, fn WalkFunc) error {
	if edges := g.Adjacency[v]; edges != nil {
		for e := edges.Front(); e != nil; e = e.Next() {
			if err := fn(e.Value.(*Vertex)); err != nil {
				return err
			}
		}
	}
	return nil
}

// ReverseDFS walks the graph in reverse depth-first order.
func (g *DAG) ReverseDFS(fn WalkFunc) error {
	return g.rdfs(g.Root, make(map[*Vertex]bool, len(g.Adjacency)), fn)
}

func (g *DAG) rdfs(v *Vertex, visited map[*Vertex]bool, fn WalkFunc) error {
	visited[v] = true

	walker := func(v *Vertex) error {
		if visited[v] {
			return nil
		}
		return g.rdfs(v, visited, fn)
	}

	if err := g.walk(v, walker); err != nil {
		return err
	}
	return fn(v)
}
