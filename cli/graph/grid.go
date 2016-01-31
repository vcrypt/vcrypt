package graph

type table []row

func (t table) lines() ([]string, error) {
	max := 0
	for _, r := range t {
		if l := len(r.cells); l > max {
			max = l
		}
	}

	for i := range t {
		for j := len(t[i].cells); j < max; j++ {
			t[i].cells = append(t[i].cells, spacer)
		}
	}

	lines := make([]string, 0, len(t))
	for _, r := range t {
		lines = append(lines, r.String())
	}
	return lines, nil // TODO
}

type row struct {
	cells  []cell
	detail string
}

func (r row) String() string {
	line := ""
	for _, c := range r.cells {
		line += c.String()
	}
	return line + r.detail
}

var (
	spacer = runeCell(' ')

	conEdge    = runeCell('/')
	cornerEdge = runeCell('.')
	expEdge    = runeCell('\\')
	horizEdge  = runeCell('-')
	latEdge    = runeCell('_')
	vertEdge   = runeCell('|')
)

type cell interface {
	String() string
}

type runeCell rune

func (r runeCell) String() string {
	return string(r)
}
