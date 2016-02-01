package vcrypt

import (
	"reflect"
	"sort"
	"testing"

	"github.com/vcrypt/vcrypt/config"
	"github.com/vcrypt/vcrypt/internal/test"
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

	// [sss "master-key"] -> [rsa "president"] -> [ssh-key "alice@acme.bank"]
	//                    |                    |
	//                    |                    -> [material "alice material"]
	//                    |
	//                    -> [sss "vp-quorum"] -> [*vote "bob:quorum"]
	//                    |                    |
	//                    |                    -> [*vote "claire:quorum"]
	//                    |                    |
	//                    |                    -> [*vote "david:quorum"]
	//                    |
	//                    -> [xor "vp-consensus"] -> [*vote "bob:consenus"]
	//                    |                       |
	//                    |                       -> [*vote "claire:consensus"]
	//                    |                       |
	//                    |                       -> [*vote "david:consensus"]
	//                    |
	//                    -> [sss "so-quorum"] -> [*vote "emily:quorum"]
	//                    |                    |
	//                    |                    -> [*vote "frank:quorum"]
	//                    |                    |
	//                    |                    -> [*vote "gloria:quorum"]
	//                    |
	//                    -> [xor "so-consensus"] -> [*vote "emily:consenus"]
	//                                            |
	//                                            -> [*vote "frank:consensus"]
	//                                            |
	//                                            -> [*vote "gloria:consensus"]
	//
	//
	// [*vote "<name>:quorum] : [secretbox "<name> quorum vote"] ------> [material "<name> quorum material"]
	//                                                                |
	//                                                                -> [demux "<name> votes"] -> [rsa "<name>"] -> [ssh-key "<name>@acme.bank"]
	//                                                                |                                           |
	//                                                                |                                           -> [material "<name> material"]
	//                                                                |
	// [*vote "<name>:conensus] : [secretbox "<name> consensus vote"] -> [material "<name> consensus material"]
	//
	acmeBankGraph = buildGraph(test.AcmeBankConfig)
)

func TestGraph(t *testing.T) {
	tests := []struct {
		*Graph
		nodes []string
	}{
		{
			Graph: twoManGraph,
			nodes: []string{
				"master key",     // [secretbox "master key"]
				"operator 1 key", // [secretbox "op 1 key"]
				"operator 2 key", // [secretbox "op 2 key"]
				"op 1 secret",    // [input "op 1 input"]
				"op 2 secret",    // [input "op 2 input"]
				"op 1 material",  // [material "op 1 material"]
				"op 2 material",  // [material "op 2 material"]
			},
		},
		{
			Graph: twoPartyGraph,
			nodes: []string{
				"step 3",             // [secretbox "step 3"]
				"step 2",             // [secretbox "step 2"]
				"step 1",             // [secretbox "step 1"]
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
				"bottom material",  // [material "bottom material"]
			},
		},
		{
			Graph: dnsSecGraph,
			nodes: []string{
				"five-of-seven",                       // [sss "five-of-seven"]
				"alice@example.com",                   // [openpgp "alice@example.com"]
				"bob@example.com",                     // [openpgp "bob@example.com"]
				"claire@example.com",                  // [openpgp "claire@example.com"]
				"david@example.com",                   // [openpgp "david@example.com"]
				"emily@example.com",                   // [openpgp "emily@example.com"]
				"frank@example.com",                   // [openpgp "frank@example.com"]
				"gloria@example.com",                  // [openpgp "gloria@example.com"]
				test.Users["alice"].OpenPGPKey.KeyID,  // [openpgp-key "alice@example.com"]
				test.Users["bob"].OpenPGPKey.KeyID,    // [openpgp-key "bob@example.com"]
				test.Users["claire"].OpenPGPKey.KeyID, // [openpgp-key "claire@example.com"]
				test.Users["david"].OpenPGPKey.KeyID,  // [openpgp-key "david@example.com"]
				test.Users["emily"].OpenPGPKey.KeyID,  // [openpgp-key "emily@example.com"]
				test.Users["frank"].OpenPGPKey.KeyID,  // [openpgp-key "frank@example.com"]
				test.Users["gloria"].OpenPGPKey.KeyID, // [openpgp-key "gloria@example.com"]
				"alice material",                      // [material "alice@example.com"]
				"bob material",                        // [material "bob@example.com"]
				"claire material",                     // [material "claire@example.com"]
				"david material",                      // [material "david@example.com"]
				"emily material",                      // [material "emily@example.com"]
				"frank material",                      // [material "frank@example.com"]
				"gloria material",                     // [material "gloria@example.com"]
			},
		},
		{
			Graph: acmeBankGraph,
			nodes: []string{
				"master-key",                // [sss "master-key"]
				"president",                 // [rsa "president"]
				"alice@acme.bank",           // [ssh-key "alice@acme.bank"]
				"vp-quorum",                 // [sss "vp-quorum"]
				"so-quorum",                 // [sss "so-quorum"]
				"vp-consensus",              // [sss "vp-consensus"]
				"so-consensus",              // [sss "so-consensus"]
				"bob quorum vote",           // [secretbox "bob quorum vote"]
				"bob consensus vote",        // [secretbox "bob consensus vote"]
				"bob votes",                 // [demux "bob votes"]
				"bob",                       // [rsa "bob"]
				"bob@acme.bank",             // [ssh-key "bob@acme.bank"]
				"claire quorum vote",        // [secretbox "claire quorum vote"]
				"claire consensus vote",     // [secretbox "claire consensus vote"]
				"claire votes",              // [demux "claire votes"]
				"claire",                    // [rsa "claire"]
				"claire@acme.bank",          // [ssh-key "claire@acme.bank"]
				"david quorum vote",         // [secretbox "david quorum vote"]
				"david consensus vote",      // [secretbox "david consensus vote"]
				"david votes",               // [demux "david votes"]
				"david",                     // [rsa "david"]
				"david@acme.bank",           // [ssh-key "david@acme.bank"]
				"emily quorum vote",         // [secretbox "emily quorum vote"]
				"emily consensus vote",      // [secretbox "emily consensus vote"]
				"emily votes",               // [demux "emily votes"]
				"emily",                     // [rsa "emily"]
				"emily@acme.bank",           // [ssh-key "emily@acme.bank"]
				"frank quorum vote",         // [secretbox "frank quorum vote"]
				"frank consensus vote",      // [secretbox "frank consensus vote"]
				"frank votes",               // [demux "frank votes"]
				"frank",                     // [rsa "frank"]
				"frank@acme.bank",           // [ssh-key "frank@acme.bank"]
				"gloria quorum vote",        // [secretbox "gloria quorum vote"]
				"gloria consensus vote",     // [secretbox "gloria consensus vote"]
				"gloria votes",              // [demux "gloria votes"]
				"gloria",                    // [rsa "gloria"]
				"gloria@acme.bank",          // [ssh-key "gloria@acme.bank"]
				"alice material",            // [material "alice material"]
				"bob quorum material",       // [material "bob quorum material"]
				"bob consensus material",    // [material "bob consensus material"]
				"bob material",              // [material "bob material"]
				"claire quorum material",    // [material "claire quorum material"]
				"claire consensus material", // [material "claire consensus material"]
				"claire material",           // [material "claire material"]
				"david quorum material",     // [material "david quorum material"]
				"david consensus material",  // [material "david consensus material"]
				"david material",            // [material "david material"]
				"emily quorum material",     // [material "emily quorum material"]
				"emily consensus material",  // [material "emily consensus material"]
				"emily material",            // [material "emily material"]
				"frank quorum material",     // [material "frank quorum material"]
				"frank consensus material",  // [material "frank consensus material"]
				"frank material",            // [material "frank material"]
				"gloria quorum material",    // [material "gloria quorum material"]
				"gloria consensus material", // [material "gloria consensus material"]
				"gloria material",           // [material "gloria material"]
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
