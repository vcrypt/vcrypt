package graph

import (
	"strings"
	"testing"
)

func TestLines(t *testing.T) {
	tests := []struct {
		nodes []*Node
		lines []string
	}{
		// 2-way split
		{
			nodes: []*Node{
				&Node{Marker: '1', ID: id(1), Edges: edges(2, 3)},
				&Node{Marker: '2', ID: id(2)},
				&Node{Marker: '3', ID: id(3)},
			},
			lines: []string{
				`1   `,
				`|\  `,
				`| 2 `,
				`3   `,
			},
		},
		// 3-way split
		{
			nodes: []*Node{
				&Node{Marker: '1', ID: id(1), Edges: edges(2, 3, 4)},
				&Node{Marker: '2', ID: id(2)},
				&Node{Marker: '3', ID: id(3)},
				&Node{Marker: '4', ID: id(4)},
			},
			lines: []string{
				`1-.   `,
				`|\ \  `,
				`| | 2 `,
				`| 3   `,
				`4     `,
			},
		},
		// 4-way split
		{
			nodes: []*Node{
				&Node{Marker: '1', ID: id(1), Edges: edges(2, 3, 4, 5)},
				&Node{Marker: '2', ID: id(2)},
				&Node{Marker: '3', ID: id(3)},
				&Node{Marker: '4', ID: id(4)},
				&Node{Marker: '5', ID: id(5)},
			},
			lines: []string{
				`1---.   `,
				`|\ \ \  `,
				`| | | 2 `,
				`| | 3   `,
				`| 4     `,
				`5       `,
			},
		},
		// 2-way then 2-way splits
		{
			nodes: []*Node{
				&Node{Marker: '1', ID: id(1), Edges: edges(2, 3)},
				&Node{Marker: '2', ID: id(2)},
				&Node{Marker: '3', ID: id(3), Edges: edges(4, 5)},
				&Node{Marker: '4', ID: id(4)},
				&Node{Marker: '5', ID: id(5)},
			},
			lines: []string{
				`1   `,
				`|\  `,
				`| 2 `,
				`3   `,
				`|\  `,
				`| 4 `,
				`5   `,
			},
		},
		// 2-way merge
		{
			nodes: []*Node{
				&Node{Marker: '1', ID: id(1), Edges: edges(2, 2)},
				&Node{Marker: '2', ID: id(2)},
			},
			lines: []string{
				`1 `,
				`|\`,
				`|/`,
				`2 `,
			},
		},
		// 3-way merge
		{
			nodes: []*Node{
				&Node{Marker: '1', ID: id(1), Edges: edges(2, 2, 2)},
				&Node{Marker: '2', ID: id(2)},
			},
			lines: []string{
				`1-. `,
				`|\ \`,
				`| |/`,
				`|/| `,
				`|/  `,
				`2   `,
			},
		},
		// 4-way merge
		{
			nodes: []*Node{
				&Node{Marker: '1', ID: id(1), Edges: edges(2, 2, 2, 2)},
				&Node{Marker: '2', ID: id(2)},
			},
			lines: []string{
				`1---. `,
				`|\ \ \`,
				`| |_|/`,
				`|/| | `,
				`| |/  `,
				`|/|   `,
				`|/    `,
				`2     `,
			},
		},
	}

	for _, test := range tests {
		lines, err := Lines(test.nodes)
		if err != nil {
			t.Error(err)
			continue
		}

		want := strings.Join(test.lines, "\n\t")
		got := strings.Join(lines, "\n\t")
		if want != got {
			t.Errorf("want graph:\n\t%s\ngot:\n\t%s", want, got)
		}
	}
}

func id(id int) []byte {
	return []byte{byte(id)}
}

func edges(ids ...int) [][]byte {
	edges := [][]byte{}
	for _, edge := range ids {
		edges = append(edges, id(edge))
	}
	return edges
}
