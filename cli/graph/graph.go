package graph

import (
	"bytes"

	"github.com/vcrypt/vcrypt"
)

// PlanLines is a textual representation of the plan graph.
func PlanLines(plan *vcrypt.Plan) ([]string, error) {
	rootID, err := plan.Nodes[0].Digest()
	if err != nil {
		return nil, err
	}

	g := &graph{
		rootID, // initial state
	}

	tbl := table{}
	walker := func(node *vcrypt.Node) error {
		id, err := node.Digest()
		if err != nil {
			return err
		}

		tbl = append(tbl, g.formatInboundEdgeRows(id)...)
		tbl = append(tbl, g.formatTargetRows(id, &nodeCell{node}, len(node.Inputs))...)

		edges := make([][]byte, 0, len(node.Inputs))
		for i := len(node.Inputs); i > 0; i-- {
			edges = append(edges, node.Inputs[i-1])
		}
		tbl = append(tbl, g.formatOutboundEdgeRows(id, edges)...)

		return nil
	}

	if err := plan.BFS(walker); err != nil {
		return nil, err
	}
	return tbl.lines()
}

type graph [][]byte

func (g *graph) formatInboundEdgeRows(id []byte) []row {
	rows := []row{}
	for {
		switch {
		case g.nonAdjacent(id):
			// | |_|/   | |_|_|/   | |_|_|_|/   | | |_|_|/ /
			// |/| |    |/| | |    |/| | | |    | |/| | | |

			idx, idxOther := g.contract(id)
			rows = append(rows, g.lateralRow(idx, idxOther))
			rows = append(rows, g.contractionRow(idx, false))

		case g.nearlyAdjacent(id):
			// | |/   | | |/   | | |/ /
			// |/|    | |/|    | |/| /

			idx, _ := g.contract(id)
			rows = append(rows, g.contractionRow(idx+1, true))
			rows = append(rows, g.doubleContractionRow(idx))
		case g.adjacent(id):
			// |/   | |/   | |/ /

			idx, _ := g.contract(id)
			rows = append(rows, g.contractionRow(idx, true))
		default:
			return rows
		}
	}
}

func (g graph) nonAdjacent(id []byte) bool {
	if len(g) < 3 {
		return false
	}

	for i, idX := range g[:len(g)-3] {
		for _, idY := range g[i+3:] {
			if equal(id, idX, idY) {
				return true
			}
		}
	}

	return false
}

func (g graph) nearlyAdjacent(id []byte) bool {
	if len(g) <= 2 {
		return false
	}

	idX := g[0]
	for _, idY := range g[2:] {
		if equal(id, idX, idY) {
			return true
		}

		idX = idY
	}

	return false
}

func (g graph) adjacent(id []byte) bool {
	if len(g) <= 1 {
		return false
	}

	idX := g[0]
	for _, idY := range g[1:] {
		if equal(id, idX, idY) {
			return true
		}

		idX = idY
	}

	return false
}

func (g graph) contractionRow(idx int, shiftLeft bool) row {
	r := row{}
	for i := range g {
		switch {
		case i < idx:
			r = append(r, vertEdge, spacer)
		case i == idx:
			r = append(r, vertEdge, conEdge)
		case shiftLeft:
			r = append(r, spacer, conEdge)
		default:
			r = append(r, vertEdge, spacer)
		}
	}
	return r
}

func (g graph) lateralRow(idxTo, idxFrom int) row {
	r := row{}
	for i := range g {
		switch {
		case i <= idxTo:
			r = append(r, vertEdge, spacer)
		case i == idxFrom-1:
			r = append(r, vertEdge, conEdge)
		case i < idxFrom:
			r = append(r, vertEdge, latEdge)
		default:
			r = append(r, spacer, conEdge)
		}
	}
	return r
}

func (g graph) doubleContractionRow(idx int) row {
	r := row{}
	for i := range g {
		switch {
		case i < idx:
			r = append(r, vertEdge, spacer)
		case i == idx:
			r = append(r, vertEdge, conEdge)
		case i == idx+1:
			r = append(r, vertEdge, spacer)
		default:
			r = append(r, conEdge, spacer)
		}
	}
	return r
}

func (g *graph) contract(id []byte) (idxTo, idxFrom int) {
	idxTo = -1
	for i, v := range *g {
		if equal(id, v) {
			if idxTo == -1 {
				idxTo = i
			}
			idxFrom = i
		}
	}

	if idxFrom < len(*g)-1 {
		for i, v := range (*g)[idxFrom+1:] {
			(*g)[i-1] = v
		}
	}

	*g = (*g)[:len(*g)-1]
	return
}

func (g *graph) formatTargetRows(id []byte, target cell, edgeCount int) []row {
	idx, rows := g.index(id), []row{}
	if edgeCount > 2 && idx != len(*g)-1 {
		//           | | \
		//           | |  \
		//  | \      | |   \
		//  |  \     | |    \
		//  *-. \    | *---. \

		rows = append(rows, g.halfShiftRow(idx))
		for i := 0; i < edgeCount-2; i++ {
			rows = append(rows, g.shiftRow(idx, i))
		}
	}

	//  *        | * \        | *-. \
	rows = append(rows, g.targetRow(idx, target, edgeCount))
	return rows
}

func (g graph) halfShiftRow(idx int) row {
	r := row{}
	for i := range g {
		switch {
		case i > idx+1:
			r = append(r, expEdge, spacer)
		default:
			r = append(r, vertEdge, spacer)
		}
	}
	return r
}

func (g graph) targetRow(idx int, target cell, edgeCount int) row {
	r := row{}
	for i := range g {
		switch {
		case i < idx:
			r = append(r, vertEdge, spacer)
		case i == idx:
			if edgeCount < 3 {
				r = append(r, target, spacer)
				continue
			}

			r = append(r, target, horizEdge)
			for i := 0; i < edgeCount-3; i++ {
				r = append(r, horizEdge, horizEdge)
			}
			r = append(r, cornerEdge, spacer)
		case i == idx+1 && edgeCount < 3:
			r = append(r, vertEdge, spacer)
		case edgeCount < 2:
			r = append(r, vertEdge, spacer)
		default:
			r = append(r, expEdge, spacer)
		}
	}
	return r
}

func (g graph) shiftRow(idx int, spaces int) row {
	r := row{}
	for i := range g {
		switch {
		case i < idx:
			r = append(r, vertEdge, spacer)
		case i == idx:
			r = append(r, vertEdge, spacer)
			for i := 0; i < spaces; i++ {
				r = append(r, spacer)
			}
		default:
			r = append(r, spacer, expEdge)
		}
	}
	return r
}

func (g *graph) formatOutboundEdgeRows(id []byte, edges [][]byte) []row {
	idx, rows := g.index(id), []row{}
	g.expand(idx, edges)

	switch len(edges) {
	case 0: // sink
		// *   * |   | * |
		//      /    |  /
		if len(*g) > idx {
			rows = append(rows, g.sinkRow(idx))
		}
	case 1:
	default:
		// *    *-.    *-. \    *---.    | *---. \
		// |\   |\ \   |\ \ \   |\ \ \   | |\ \ \ \

		rows = append(rows, g.expansionRow(idx, len(edges)))
	}
	return rows
}

func (g graph) sinkRow(idx int) row {
	r := row{}
	for i := range g {
		switch {
		case i < idx:
			r = append(r, vertEdge, spacer)
		default:
			r = append(r, spacer, conEdge)
		}
	}
	return r
}

func (g graph) expansionRow(idx, edgeCount int) row {
	r := row{}
	for i := range g {
		switch {
		case i < idx:
			r = append(r, vertEdge, spacer)
		case i == idx:
			r = append(r, vertEdge, expEdge)
		case i != len(g)-1:
			r = append(r, spacer, expEdge)
		}
	}
	return r
}

func (g *graph) expand(idx int, edges [][]byte) {
	gg := graph{}

	if idx > 0 {
		gg = append(gg, (*g)[:idx]...)
	}

	gg = append(gg, edges...)

	if i := idx + 1; i < len(*g) {
		gg = append(gg, (*g)[i:]...)
	}

	*g = gg
}

func (g graph) index(id []byte) int {
	for i, v := range g {
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
