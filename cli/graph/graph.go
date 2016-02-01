package graph

import "bytes"

// Lines is a textual multi-line representation of the node graph.
func Lines(nodes []*Node) ([]string, error) {
	if len(nodes) == 0 {
		return []string{}, nil
	}

	g := &graph{
		slots: [][]byte{nodes[0].ID},
		nodes: nodes,
	}

	return g.table().lines()
}

// Node is a node (vertex) of a graph.
type Node struct {
	ID     []byte
	Edges  [][]byte
	Marker rune
	Detail string
}

// String returns a string representation of the node.
func (n *Node) String() string {
	return string(n.Marker)
}

type graph struct {
	slots [][]byte
	nodes []*Node
}

func (g *graph) table() table {
	tbl := table{}
	for _, node := range g.nodes {
		tbl = append(tbl, g.formatInboundEdgeRows(node)...)
		tbl = append(tbl, g.formatTargetRows(node)...)
		tbl = append(tbl, g.formatOutboundEdgeRows(node)...)
	}
	return tbl
}

func (g *graph) formatInboundEdgeRows(node *Node) []row {
	rows := []row{}
	for {
		switch {
		case g.nonAdjacent(node.ID):
			// | |_|/   | |_|_|/   | |_|_|_|/   | | |_|_|/ /
			// |/| |    |/| | |    |/| | | |    | |/| | | |

			idx, idxOther := g.contract(node.ID)
			rows = append(rows, g.lateralRow(idx, idxOther))
			rows = append(rows, g.contractionRow(idx, false))

		case g.nearlyAdjacent(node.ID):
			// | |/   | | |/   | | |/ /
			// |/|    | |/|    | |/| /

			idx, _ := g.contract(node.ID)
			rows = append(rows, g.contractionRow(idx+1, true))
			rows = append(rows, g.doubleContractionRow(idx))
		case g.adjacent(node.ID):
			// |/   | |/   | |/ /

			idx, _ := g.contract(node.ID)
			rows = append(rows, g.contractionRow(idx, true))
		default:
			return rows
		}
	}
}

func (g *graph) nonAdjacent(id []byte) bool {
	if len(g.slots) < 3 {
		return false
	}

	for i, idX := range g.slots[:len(g.slots)-3] {
		for _, idY := range g.slots[i+3:] {
			if equal(id, idX, idY) {
				return true
			}
		}
	}

	return false
}

func (g *graph) nearlyAdjacent(id []byte) bool {
	if len(g.slots) <= 2 {
		return false
	}

	idX := g.slots[0]
	for _, idY := range g.slots[2:] {
		if equal(id, idX, idY) {
			return true
		}

		idX = idY
	}

	return false
}

func (g *graph) adjacent(id []byte) bool {
	if len(g.slots) <= 1 {
		return false
	}

	idX := g.slots[0]
	for _, idY := range g.slots[1:] {
		if equal(id, idX, idY) {
			return true
		}

		idX = idY
	}

	return false
}

func (g *graph) contractionRow(idx int, shiftLeft bool) row {
	r := row{}
	for i := range g.slots {
		switch {
		case i < idx:
			r.cells = append(r.cells, vertEdge, spacer)
		case i == idx:
			r.cells = append(r.cells, vertEdge, conEdge)
		case shiftLeft:
			r.cells = append(r.cells, spacer, conEdge)
		default:
			r.cells = append(r.cells, vertEdge, spacer)
		}
	}
	return r
}

func (g graph) lateralRow(idxTo, idxFrom int) row {
	r := row{}
	for i := range g.slots {
		switch {
		case i <= idxTo:
			r.cells = append(r.cells, vertEdge, spacer)
		case i == idxFrom-1:
			r.cells = append(r.cells, vertEdge, conEdge)
		case i < idxFrom:
			r.cells = append(r.cells, vertEdge, latEdge)
		default:
			r.cells = append(r.cells, spacer, conEdge)
		}
	}
	return r
}

func (g graph) doubleContractionRow(idx int) row {
	r := row{}
	for i := range g.slots {
		switch {
		case i < idx:
			r.cells = append(r.cells, vertEdge, spacer)
		case i == idx:
			r.cells = append(r.cells, vertEdge, conEdge)
		case i == idx+1:
			r.cells = append(r.cells, vertEdge, spacer)
		default:
			r.cells = append(r.cells, conEdge, spacer)
		}
	}
	return r
}

func (g *graph) contract(id []byte) (idxTo, idxFrom int) {
	idxTo = -1
	for i, v := range g.slots {
		if equal(id, v) {
			if idxTo == -1 {
				idxTo = i
			}
			idxFrom = i
		}
	}

	if idxFrom < len(g.slots)-1 {
		for i, v := range g.slots[idxFrom+1:] {
			g.slots[i-1] = v
		}
	}

	g.slots = g.slots[:len(g.slots)-1]
	return
}

func (g *graph) formatTargetRows(node *Node) []row {
	idx, rows := g.index(node.ID), []row{}
	if len(node.Edges) > 2 && idx != len(g.slots)-1 {
		//           | | \
		//           | |  \
		//  | \      | |   \
		//  |  \     | |    \
		//  *-. \    | *---. \

		rows = append(rows, g.halfShiftRow(idx))
		for i := 0; i < len(node.Edges)-2; i++ {
			rows = append(rows, g.shiftRow(idx, i))
		}
	}

	//  *        | * \        | *-. \
	rows = append(rows, g.targetRow(idx, node))
	return rows
}

func (g *graph) halfShiftRow(idx int) row {
	r := row{}
	for i := range g.slots {
		switch {
		case i > idx+1:
			r.cells = append(r.cells, expEdge, spacer)
		default:
			r.cells = append(r.cells, vertEdge, spacer)
		}
	}
	return r
}

func (g *graph) targetRow(idx int, node *Node) row {
	r := row{
		detail: node.Detail,
	}
	for i := range g.slots {
		switch {
		case i < idx:
			r.cells = append(r.cells, vertEdge, spacer)
		case i == idx:
			if len(node.Edges) < 3 {
				r.cells = append(r.cells, node, spacer)
				continue
			}

			r.cells = append(r.cells, node, horizEdge)
			for i := 0; i < len(node.Edges)-3; i++ {
				r.cells = append(r.cells, horizEdge, horizEdge)
			}
			r.cells = append(r.cells, cornerEdge, spacer)
		case i == idx+1 && len(node.Edges) < 3:
			r.cells = append(r.cells, vertEdge, spacer)
		case len(node.Edges) < 2:
			r.cells = append(r.cells, vertEdge, spacer)
		default:
			r.cells = append(r.cells, expEdge, spacer)
		}
	}
	return r
}

func (g graph) shiftRow(idx int, spaces int) row {
	r := row{}
	for i := range g.slots {
		switch {
		case i < idx:
			r.cells = append(r.cells, vertEdge, spacer)
		case i == idx:
			r.cells = append(r.cells, vertEdge, spacer)
			for i := 0; i < spaces; i++ {
				r.cells = append(r.cells, spacer)
			}
		default:
			r.cells = append(r.cells, spacer, expEdge)
		}
	}
	return r
}

func (g *graph) formatOutboundEdgeRows(node *Node) []row {
	idx, rows := g.index(node.ID), []row{}
	g.expand(idx, node.Edges)

	switch len(node.Edges) {
	case 0: // sink
		// *   * |   | * |
		//      /    |  /
		if len(g.slots) > idx {
			rows = append(rows, g.sinkRow(idx))
		}
	case 1:
	default:
		// *    *-.    *-. \    *---.    | *---. \
		// |\   |\ \   |\ \ \   |\ \ \   | |\ \ \ \

		rows = append(rows, g.expansionRow(idx, len(node.Edges)))
	}
	return rows
}

func (g graph) sinkRow(idx int) row {
	r := row{}
	for i := range g.slots {
		switch {
		case i < idx:
			r.cells = append(r.cells, vertEdge, spacer)
		default:
			r.cells = append(r.cells, spacer, conEdge)
		}
	}
	return r
}

func (g graph) expansionRow(idx, edgeCount int) row {
	r := row{}
	for i := range g.slots {
		switch {
		case i < idx:
			r.cells = append(r.cells, vertEdge, spacer)
		case i == idx:
			r.cells = append(r.cells, vertEdge, expEdge)
		case i != len(g.slots)-1:
			r.cells = append(r.cells, spacer, expEdge)
		}
	}
	return r
}

func (g *graph) expand(idx int, edges [][]byte) {
	slots := [][]byte{}

	if idx > 0 {
		slots = append(slots, g.slots[:idx]...)
	}

	for i := len(edges) - 1; i >= 0; i-- {
		slots = append(slots, edges[i])
	}

	if i := idx + 1; i < len(g.slots) {
		slots = append(slots, g.slots[i:]...)
	}

	g.slots = slots
}

func (g *graph) index(id []byte) int {
	for i, v := range g.slots {
		if equal(id, v) {
			return i
		}
	}
	panic("id missing from graph")
}

func equal(v []byte, vs ...[]byte) bool {
	for _, x := range vs {
		if !bytes.Equal(v, x) {
			return false
		}
	}
	return true
}
