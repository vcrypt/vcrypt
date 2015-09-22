package vcrypt

import (
	"reflect"
	"sort"
	"testing"

	"github.com/benburkert/vcrypt/config"
	"github.com/benburkert/vcrypt/internal/test"
)

var (
	// [secretbox "master key"] -> [secretbox "op 1 key"] -> [input "op 1 input"]
	//                          |                         |
	//                          |                         -> [material "op 1 data"]
	//                          |
	//                          -> [secretbox "op 2 key"] -> [input "op 2 input"]
	//                                                    |
	//                                                    -> [material "op 2 data"]
	twoManGraph = buildGraph(test.TwoManPlanConfig)

	// [secretbox "step 3"] -> [input "step 3 input"]
	//                      |
	//                      -> [secretbox "step 2"] -> [input "step 2 input"]
	//                                              |
	//                                              -> [secretbox "step 1"] -> [input "step 1 input"]
	//                                                                      |
	//                                                                      -> [material]
	twoPartyGraph = buildGraph(test.TwoPartyPlanConfig)

	// [secretbox "top"] -> [input "top input"]
	//                   |
	//                   -> [mux] -> [secretbox "left"]  -> [input "left input"]
	//                            |                      |
	//                            |                      -> [demux] -> [secretbox "bottom"] -> [input "bottom input"]
	//                            |                      |                                  |
	//                            -> [secretbox "right"] -> [input "right input"]           -> [material "bottom data"]
	diamondGraph = buildGraph(test.DiamondPlanConfig)

	// [sss "five-of-seven"] -> [openpgp "alice@example.com"] -> [openpgp-key "alice@example.com"]
	//                       |                                |
	//                       |                                -> [material]
	//                       |
	//                       -> [openpgp "bob@example.com"] -> [openpgp-key "bob@example.com"]
	//                       |                              |
	//                       |                              -> [material]
	//                       |
	//                       -> [openpgp "claire@example.com"] -> [openpgp-key "claire@example.com"]
	//                       |                                 |
	//                       |                                 -> [material]
	//                       |
	//                       -> [openpgp "david@example.com"] -> [openpgp-key "david@example.com"]
	//                       |                                |
	//                       |                                -> [material]
	//                       |
	//                       -> [openpgp "emily@example.com"] -> [openpgp-key "emily@example.com"]
	//                       |                                |
	//                       |                                -> [material]
	//                       |
	//                       -> [openpgp "frank@example.com"] -> [openpgp-key "frank@example.com"]
	//                       |                                |
	//                       |                                -> [material]
	//                       |
	//                       -> [openpgp "gloria@example.com"] -> [openpgp-key "gloria@example.com"]
	//                                                         |
	//                                                         -> [material]
	dnsSecGraph = buildGraph(test.DNSSecConfig)
)

func TestGraph(t *testing.T) {
	tests := []struct {
		*Graph
		nodes []string
	}{
		{
			Graph: twoManGraph,
			nodes: []string{
				"",               // [secretbox "master key"]
				"operator 1 key", // [secretbox "op 1 key"]
				"operator 2 key", // [secretbox "op 2 key"]
				"op 1 secret",    // [input "op 1 input"]
				"op 2 secret",    // [input "op 2 input"]
				"",               // [material "op 1 data"]
				"",               // [material "op 2 data"]
			},
		},
		{
			Graph: twoPartyGraph,
			nodes: []string{
				"",                   // [secretbox "step 3"]
				"",                   // [secretbox "step 2"]
				"",                   // [secretbox "step 1"]
				"party 1 password 2", // [input "step 3 input"]
				"party 2 password",   // [input "step 2 input"]
				"party 1 password 1", // [input "step 1 input"]
				"",                   // [material]
			},
		},
		{
			Graph: diamondGraph,
			nodes: []string{
				"step 3",           // [secretbox "top"]
				"",                 // [mux]
				"step 2a",          // [secretbox "left"]
				"step 2b",          // [secretbox "right"]
				"",                 // [demux]
				"step 1",           // [secretbox "bottom"]
				"step 3 password",  // [input "top input"]
				"step 2a password", // [input "left input"]
				"step 2b password", // [input "right input"]
				"step 1 password",  // [input "bottom input"]
				"",                 // [material "bottom data"]
			},
		},
		{
			Graph: dnsSecGraph,
			nodes: []string{
				"", // [sss "five-of-seven"]
				"", // [openpgp "alice@example.com"]
				"", // [openpgp "bob@example.com"]
				"", // [openpgp "claire@example.com"]
				"", // [openpgp "david@example.com"]
				"", // [openpgp "emily@example.com"]
				"", // [openpgp "frank@example.com"]
				"", // [openpgp "gloria@example.com"]
				"", // [openpgp-key "alice@example.com"]
				"", // [openpgp-key "bob@example.com"]
				"", // [openpgp-key "claire@example.com"]
				"", // [openpgp-key "david@example.com"]
				"", // [openpgp-key "emily@example.com"]
				"", // [openpgp-key "frank@example.com"]
				"", // [openpgp-key "gloria@example.com"]
				test.OpenPGPKeys["alice"].KeyID,  // [material "alice@example.com"]
				test.OpenPGPKeys["bob"].KeyID,    // [material "bob@example.com"]
				test.OpenPGPKeys["claire"].KeyID, // [material "claire@example.com"]
				test.OpenPGPKeys["david"].KeyID,  // [material "david@example.com"]
				test.OpenPGPKeys["emily"].KeyID,  // [material "emily@example.com"]
				test.OpenPGPKeys["frank"].KeyID,  // [material "frank@example.com"]
				test.OpenPGPKeys["gloria"].KeyID, // [material "gloria@example.com"]
			},
		},
	}

	for _, test := range tests {
		nodes, err := test.Graph.Nodes()
		if err != nil {
			t.Fatal(err)
		}

		want := test.nodes[:]
		sort.Strings(want)

		if len(nodes) != len(test.nodes) {
			t.Errorf("want len(nodes) = %d, got %d", len(test.nodes), len(nodes))
			continue
		}

		got := make([]string, 0, len(nodes))
		for _, node := range nodes {
			comment, err := node.Comment()
			if err != nil {
				t.Error(err)
			}

			got = append(got, comment)
		}

		sort.Strings(got)
		if !reflect.DeepEqual(want, got) {
			t.Errorf("want nodes %q, got %q", want, got)
		}
	}
}

func buildGraph(data []byte) *Graph {
	cp := config.Plan{}
	if err := config.Unmarshal(data, &cp); err != nil {
		panic(err)
	}

	g, err := build(cp)
	if err != nil {
		panic(err)
	}
	return g
}
