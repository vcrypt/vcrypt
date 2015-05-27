package graph

import (
	"container/list"
	"reflect"
	"testing"
)

func TestDAG(t *testing.T) {
	tests := []struct {
		Root      string
		Adjacency map[string][]string

		OrderRDFS []string
	}{
		// chain:  A -> B -> C -> D -> E -> F
		{
			Root: "A",
			Adjacency: map[string][]string{
				"A": []string{"B"},
				"B": []string{"C"},
				"C": []string{"D"},
				"D": []string{"E"},
				"E": []string{"F"},
			},
			OrderRDFS: []string{"F", "E", "D", "C", "B", "A"},
		},
		// diamond:  A -> B ->-
		//             |      |
		//             -> C --> D
		{
			Root: "A",
			Adjacency: map[string][]string{
				"A": []string{"B", "C"},
				"B": []string{"D"},
				"C": []string{"D"},
			},
			OrderRDFS: []string{"D", "B", "C", "A"},
		},
		// binary tree:  A -> B -> D
		//                 |    |
		//                 |    -> E
		//                 |
		//                 -> C -> F
		//                      |
		//                      -> G
		{
			Root: "A",
			Adjacency: map[string][]string{
				"A": []string{"B", "C"},
				"B": []string{"D", "E"},
				"C": []string{"F", "G"},
			},
			OrderRDFS: []string{"D", "E", "B", "F", "G", "C", "A"},
		},
	}

	for _, test := range tests {
		dag, err := testDAG(test.Root, test.Adjacency)
		if err != nil {
			t.Error(err)
			continue
		}

		gotRDFS := []string{}
		dag.ReverseDFS(func(v interface{}) error {
			gotRDFS = append(gotRDFS, v.(string))
			return nil
		})

		if !reflect.DeepEqual(gotRDFS, test.OrderRDFS) {
			t.Errorf("want ReverseRDFS order %v, got %v", test.OrderRDFS, gotRDFS)
		}
	}

}

func testList(keys ...string) *list.List {
	l := list.New()
	return l
}

func testDAG(root string, adjacency map[string][]string) (*DAG, error) {
	dag := NewDAG(root)
	return dag, buildDAG(dag, root, adjacency)
}

func buildDAG(dag *DAG, from string, adjacency map[string][]string) error {
	for _, to := range adjacency[from] {
		if err := dag.AddEdge(to, from); err != nil {
			return err
		}
	}

	for _, to := range adjacency[from] {
		if err := buildDAG(dag, to, adjacency); err != nil {
			return err
		}
	}

	return nil
}
