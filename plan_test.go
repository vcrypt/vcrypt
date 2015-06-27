package vcrypt

import (
	"reflect"
	"testing"

	"github.com/benburkert/vcrypt/internal/test"
)

var (
	twoManPlan   = buildPlan(twoManGraph, "two-man rule plan")
	twoPartyPlan = buildPlan(twoPartyGraph, "two-party lock plan")
	diamondPlan  = buildPlan(diamondGraph, "diamond plan")
	dnsSecPlan   = buildPlan(dnsSecGraph, "DNSSEC root key plan")
)

func TestPlan(t *testing.T) {
	tests := []struct {
		*Plan
		*Graph
	}{
		{
			Plan:  twoManPlan,
			Graph: twoManGraph,
		},
		{
			Plan:  twoPartyPlan,
			Graph: twoPartyGraph,
		},
		{
			Plan:  diamondPlan,
			Graph: diamondGraph,
		},
		{
			Plan:  dnsSecPlan,
			Graph: dnsSecGraph,
		},
	}

	for _, tst := range tests {
		plan, graph := tst.Plan, tst.Graph

		ufp, err := plan.Digest()
		if err != nil {
			t.Fatal(err)
		}

		seal, err := plan.AddSeal(test.Sealer)
		if err != nil {
			t.Fatal(err)
		}

		data, err := plan.sealData()
		if err != nil {
			t.Fatal(err)
		}

		if err := seal.Check(data); err != nil {
			t.Fatal(err)
		}

		sfp, err := plan.Digest()
		if err != nil {
			t.Fatal(err)
		}

		if reflect.DeepEqual(ufp, sfp) {
			t.Errorf("plan digest unchanged by seal")
		}

		nodes, err := graph.Nodes()
		if err != nil {
			t.Fatal(err)
		}

		wfp, err := nodes[0].Digest()
		if err != nil {
			t.Fatal(err)
		}

		gfp, err := plan.Nodes[0].Digest()
		if err != nil {
			t.Fatal(err)
		}

		if !reflect.DeepEqual(wfp, gfp) {
			t.Errorf("root node digests did not match %#v", nodes[0])
		}
	}
}

func buildPlan(g *Graph, desc string) *Plan {
	plan, err := NewPlan(g, desc)
	if err != nil {
		panic(err)
	}
	return plan
}
