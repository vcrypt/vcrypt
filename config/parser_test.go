package config

import (
	"reflect"
	"testing"

	"github.com/vcrypt/vcrypt/internal/test"
)

func TestParser(t *testing.T) {
	tests := []struct {
		data []byte
		want []*section
	}{
		{
			data: test.DiamondPlanConfig,
			want: []*section{
				{
					Type: "",
					Values: map[string][]string{
						"comment": {"Diamond shaped plan"},
						"root":    {"top"},
					},
				},
				{
					ID:   "top",
					Type: "secretbox",
					Values: map[string][]string{
						"comment": {"step 3"},
						"edge":    {"top password", "mux"},
					},
				},
				{
					Type: "mux",
					Values: map[string][]string{
						"edge": {"left", "right"},
					},
				},
				{
					ID:   "left",
					Type: "secretbox",
					Values: map[string][]string{
						"comment": {"step 2a"},
						"edge":    {"left password", "demux"},
					},
				},
				{
					ID:   "right",
					Type: "secretbox",
					Values: map[string][]string{
						"comment": {"step 2b"},
						"edge":    {"right password", "demux"},
					},
				},
				{
					Type: "demux",
					Values: map[string][]string{
						"edge": {"bottom"},
					},
				},
				{
					ID:   "bottom",
					Type: "secretbox",
					Values: map[string][]string{
						"comment": {"step 1"},
						"edge":    {"bottom password", "bottom material"},
					},
				},
				{
					ID:   "top password",
					Type: "password",
					Values: map[string][]string{
						"comment": {"step 3 password"},
					},
				},
				{
					ID:   "left password",
					Type: "password",
					Values: map[string][]string{
						"comment": {"step 2a password"},
					},
				},
				{
					ID:   "right password",
					Type: "password",
					Values: map[string][]string{
						"comment": {"step 2b password"},
					},
				},
				{
					ID:   "bottom password",
					Type: "password",
					Values: map[string][]string{
						"comment": {"step 1 password"},
					},
				},
				{
					ID:     "bottom material",
					Type:   "material",
					Values: map[string][]string{},
				},
			},
		},
		{
			data: test.TwoManPlanConfig,
			want: []*section{
				{
					Type: "",
					Values: map[string][]string{
						"comment": {"Two-man rule plan"},
						"root":    {"master key"},
					},
				},
				{
					ID:   "master key",
					Type: "secretbox",
					Values: map[string][]string{
						"edge": {"op 1 key", "op 2 key"},
					},
				},
				{
					ID:   "op 1 key",
					Type: "secretbox",
					Values: map[string][]string{
						"comment": {"operator 1 key"},
						"edge":    {"op 1 password", "op 1 material"},
					},
				},
				{
					ID:   "op 2 key",
					Type: "secretbox",
					Values: map[string][]string{
						"comment": {"operator 2 key"},
						"edge":    {"op 2 password", "op 2 material"},
					},
				},
				{
					ID:   "op 1 password",
					Type: "password",
					Values: map[string][]string{
						"comment": {"op 1 secret"},
					},
				},
				{
					ID:   "op 2 password",
					Type: "password",
					Values: map[string][]string{
						"comment": {"op 2 secret"},
					},
				},
				{
					ID:     "op 1 material",
					Type:   "material",
					Values: map[string][]string{},
				},
				{
					ID:     "op 2 material",
					Type:   "material",
					Values: map[string][]string{},
				},
			},
		},
		{
			data: test.TwoPartyPlanConfig,
			want: []*section{
				{
					Type: "",
					Values: map[string][]string{
						"comment": {"Two-party 3 step plan"},
						"root":    {"step 3"},
					},
				},
				{
					ID:   "step 3",
					Type: "secretbox",
					Values: map[string][]string{
						"edge": {"step 3 password", "step 2"},
					},
				},
				{
					ID:   "step 2",
					Type: "secretbox",
					Values: map[string][]string{
						"edge": {"step 2 password", "step 1"},
					},
				},
				{
					ID:   "step 1",
					Type: "secretbox",
					Values: map[string][]string{
						"edge": {"step 1 password", "material"},
					},
				},
				{
					ID:   "step 3 password",
					Type: "password",
					Values: map[string][]string{
						"comment": {"party 1 password 2"},
					},
				},
				{
					ID:   "step 2 password",
					Type: "password",
					Values: map[string][]string{
						"comment": {"party 2 password"},
					},
				},
				{
					ID:   "step 1 password",
					Type: "password",
					Values: map[string][]string{
						"comment": {"party 1 password 1"},
					},
				},
				{
					Type:   "material",
					Values: map[string][]string{},
				},
			},
		},
		{
			data: test.DNSSecConfig,
			want: []*section{
				{
					Type: "",
					Values: map[string][]string{
						"comment": {"DNSSEC Root Key"},
						"root":    {"five-of-seven"},
					},
				},
				{
					ID:   "five-of-seven",
					Type: "sss",
					Values: map[string][]string{
						"max-shares":      {"7"},
						"required-shares": {"5"},
						"edge": {
							"alice@example.com",
							"bob@example.com",
							"claire@example.com",
							"david@example.com",
							"emily@example.com",
							"frank@example.com",
							"gloria@example.com",
						},
					},
				},
				{
					ID:   "alice@example.com",
					Type: "openpgp",
					Values: map[string][]string{
						"publickey": {test.OpenPGPKeys["alice"].Public},
						"edge":      {"alice material", test.OpenPGPKeys["alice"].KeyID},
					},
				},
				{
					ID:   "bob@example.com",
					Type: "openpgp",
					Values: map[string][]string{
						"publickey": {test.OpenPGPKeys["bob"].Public},
						"edge":      {"bob material", test.OpenPGPKeys["bob"].KeyID},
					},
				},
				{
					ID:   "claire@example.com",
					Type: "openpgp",
					Values: map[string][]string{
						"publickey": {test.OpenPGPKeys["claire"].Public},
						"edge":      {"claire material", test.OpenPGPKeys["claire"].KeyID},
					},
				},
				{
					ID:   "david@example.com",
					Type: "openpgp",
					Values: map[string][]string{
						"publickey": {test.OpenPGPKeys["david"].Public},
						"edge":      {"david material", test.OpenPGPKeys["david"].KeyID},
					},
				},
				{
					ID:   "emily@example.com",
					Type: "openpgp",
					Values: map[string][]string{
						"publickey": {test.OpenPGPKeys["emily"].Public},
						"edge":      {"emily material", test.OpenPGPKeys["emily"].KeyID},
					},
				},
				{
					ID:   "frank@example.com",
					Type: "openpgp",
					Values: map[string][]string{
						"publickey": {test.OpenPGPKeys["frank"].Public},
						"edge":      {"frank material", test.OpenPGPKeys["frank"].KeyID},
					},
				},
				{
					ID:   "gloria@example.com",
					Type: "openpgp",
					Values: map[string][]string{
						"publickey": {test.OpenPGPKeys["gloria"].Public},
						"edge":      {"gloria material", test.OpenPGPKeys["gloria"].KeyID},
					},
				},
				{
					ID:   test.OpenPGPKeys["alice"].KeyID,
					Type: "openpgp-key",
					Values: map[string][]string{
						"comment": {test.OpenPGPKeys["alice"].KeyID},
						"keyid":   {test.OpenPGPKeys["alice"].KeyID},
					},
				},
				{
					ID:   test.OpenPGPKeys["bob"].KeyID,
					Type: "openpgp-key",
					Values: map[string][]string{
						"comment": {test.OpenPGPKeys["bob"].KeyID},
						"keyid":   {test.OpenPGPKeys["bob"].KeyID},
					},
				},
				{
					ID:   test.OpenPGPKeys["claire"].KeyID,
					Type: "openpgp-key",
					Values: map[string][]string{
						"comment": {test.OpenPGPKeys["claire"].KeyID},
						"keyid":   {test.OpenPGPKeys["claire"].KeyID},
					},
				},
				{
					ID:   test.OpenPGPKeys["david"].KeyID,
					Type: "openpgp-key",
					Values: map[string][]string{
						"comment": {test.OpenPGPKeys["david"].KeyID},
						"keyid":   {test.OpenPGPKeys["david"].KeyID},
					},
				},
				{
					ID:   test.OpenPGPKeys["emily"].KeyID,
					Type: "openpgp-key",
					Values: map[string][]string{
						"comment": {test.OpenPGPKeys["emily"].KeyID},
						"keyid":   {test.OpenPGPKeys["emily"].KeyID},
					},
				},
				{
					ID:   test.OpenPGPKeys["frank"].KeyID,
					Type: "openpgp-key",
					Values: map[string][]string{
						"comment": {test.OpenPGPKeys["frank"].KeyID},
						"keyid":   {test.OpenPGPKeys["frank"].KeyID},
					},
				},
				{
					ID:   test.OpenPGPKeys["gloria"].KeyID,
					Type: "openpgp-key",
					Values: map[string][]string{
						"comment": {test.OpenPGPKeys["gloria"].KeyID},
						"keyid":   {test.OpenPGPKeys["gloria"].KeyID},
					},
				},
				{
					ID:     "alice material",
					Type:   "material",
					Values: map[string][]string{},
				},
				{
					ID:     "bob material",
					Type:   "material",
					Values: map[string][]string{},
				},
				{
					ID:     "claire material",
					Type:   "material",
					Values: map[string][]string{},
				},
				{
					ID:     "david material",
					Type:   "material",
					Values: map[string][]string{},
				},
				{
					ID:     "emily material",
					Type:   "material",
					Values: map[string][]string{},
				},
				{
					ID:     "frank material",
					Type:   "material",
					Values: map[string][]string{},
				},
				{
					ID:     "gloria material",
					Type:   "material",
					Values: map[string][]string{},
				},
			},
		},
	}

	for _, test := range tests {
		got, err := parse(test.data)
		if err != nil {
			t.Fatal(err)
		}

		if len(test.want) != len(got) {
			t.Errorf("want len(sections) = %d, got %d", len(test.want), len(got))
		}

		for i, want := range test.want {
			if !reflect.DeepEqual(want, got[i]) {
				t.Errorf("want parsed section %+v, got %+v", want, got[i])
			}
		}
	}
}
