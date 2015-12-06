package config

import (
	"reflect"
	"testing"

	"github.com/vcrypt/vcrypt/internal/test"
)

func TestUnmarshal(t *testing.T) {
	tests := []struct {
		data []byte
		plan Plan
	}{
		{
			data: test.DiamondPlanConfig,
			plan: Plan{
				Comment: "Diamond shaped plan",
				Root:    "top",
				SecretBoxes: map[string]SecretBox{
					"top": {
						Comment:   "step 3",
						EdgeSlice: []string{"top password", "mux"},
					},
					"left": {
						Comment:   "step 2a",
						EdgeSlice: []string{"left password", "demux"},
					},
					"right": {
						Comment:   "step 2b",
						EdgeSlice: []string{"right password", "demux"},
					},
					"bottom": {
						Comment:   "step 1",
						EdgeSlice: []string{"bottom password", "bottom material"},
					},
				},
				Muxes: map[string]Mux{
					"mux": {
						EdgeSlice: []string{"left", "right"},
					},
				},
				Demuxes: map[string]Demux{
					"demux": {
						EdgeSlice: []string{"bottom"},
					},
				},
				Passwords: map[string]Password{
					"top password":    {"step 3 password"},
					"left password":   {"step 2a password"},
					"right password":  {"step 2b password"},
					"bottom password": {"step 1 password"},
				},
				Materials: map[string]Marker{
					"bottom material": {},
				},
			},
		},
		{
			data: test.TwoManPlanConfig,
			plan: Plan{
				Comment: "Two-man rule plan",
				Root:    "master key",
				SecretBoxes: map[string]SecretBox{
					"master key": {
						EdgeSlice: []string{"op 1 key", "op 2 key"},
					},
					"op 1 key": {
						Comment:   "operator 1 key",
						EdgeSlice: []string{"op 1 password", "op 1 material"},
					},
					"op 2 key": {
						Comment:   "operator 2 key",
						EdgeSlice: []string{"op 2 password", "op 2 material"},
					},
				},
				Passwords: map[string]Password{
					"op 1 password": {"op 1 secret"},
					"op 2 password": {"op 2 secret"},
				},
				Materials: map[string]Marker{
					"op 1 material": {},
					"op 2 material": {},
				},
			},
		},
		{
			data: test.TwoPartyPlanConfig,
			plan: Plan{
				Comment: "Two-party 3 step plan",
				Root:    "step 3",
				SecretBoxes: map[string]SecretBox{
					"step 3": {
						EdgeSlice: []string{"step 3 password", "step 2"},
					},
					"step 2": {
						EdgeSlice: []string{"step 2 password", "step 1"},
					},
					"step 1": {
						EdgeSlice: []string{"step 1 password", "material"},
					},
				},
				Passwords: map[string]Password{
					"step 3 password": {"party 1 password 2"},
					"step 2 password": {"party 2 password"},
					"step 1 password": {"party 1 password 1"},
				},
				Materials: map[string]Marker{
					"material": {},
				},
			},
		},
		{
			data: test.DNSSecConfig,
			plan: Plan{
				Comment: "DNSSEC Root Key",
				Root:    "five-of-seven",
				SSSs: map[string]SSS{
					"five-of-seven": {
						N: 7,
						K: 5,
						EdgeSlice: []string{
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
				OpenPGPs: map[string]OpenPGP{
					"alice@example.com": {
						PublicKeys: []string{test.OpenPGPKeys["alice"].Public},
						EdgeSlice:  []string{"alice material", test.OpenPGPKeys["alice"].KeyID},
					},
					"bob@example.com": {
						PublicKeys: []string{test.OpenPGPKeys["bob"].Public},
						EdgeSlice:  []string{"bob material", test.OpenPGPKeys["bob"].KeyID},
					},
					"claire@example.com": {
						PublicKeys: []string{test.OpenPGPKeys["claire"].Public},
						EdgeSlice:  []string{"claire material", test.OpenPGPKeys["claire"].KeyID},
					},
					"david@example.com": {
						PublicKeys: []string{test.OpenPGPKeys["david"].Public},
						EdgeSlice:  []string{"david material", test.OpenPGPKeys["david"].KeyID},
					},
					"emily@example.com": {
						PublicKeys: []string{test.OpenPGPKeys["emily"].Public},
						EdgeSlice:  []string{"emily material", test.OpenPGPKeys["emily"].KeyID},
					},
					"frank@example.com": {
						PublicKeys: []string{test.OpenPGPKeys["frank"].Public},
						EdgeSlice:  []string{"frank material", test.OpenPGPKeys["frank"].KeyID},
					},
					"gloria@example.com": {
						PublicKeys: []string{test.OpenPGPKeys["gloria"].Public},
						EdgeSlice:  []string{"gloria material", test.OpenPGPKeys["gloria"].KeyID},
					},
				},
				OpenPGPKeys: map[string]OpenPGPKey{
					test.OpenPGPKeys["alice"].KeyID: {
						Comment: test.OpenPGPKeys["alice"].KeyID,
						KeyIDs:  []string{test.OpenPGPKeys["alice"].KeyID},
					},
					test.OpenPGPKeys["bob"].KeyID: {
						Comment: test.OpenPGPKeys["bob"].KeyID,
						KeyIDs:  []string{test.OpenPGPKeys["bob"].KeyID},
					},
					test.OpenPGPKeys["claire"].KeyID: {
						Comment: test.OpenPGPKeys["claire"].KeyID,
						KeyIDs:  []string{test.OpenPGPKeys["claire"].KeyID},
					},
					test.OpenPGPKeys["david"].KeyID: {
						Comment: test.OpenPGPKeys["david"].KeyID,
						KeyIDs:  []string{test.OpenPGPKeys["david"].KeyID},
					},
					test.OpenPGPKeys["emily"].KeyID: {
						Comment: test.OpenPGPKeys["emily"].KeyID,
						KeyIDs:  []string{test.OpenPGPKeys["emily"].KeyID},
					},
					test.OpenPGPKeys["frank"].KeyID: {
						Comment: test.OpenPGPKeys["frank"].KeyID,
						KeyIDs:  []string{test.OpenPGPKeys["frank"].KeyID},
					},
					test.OpenPGPKeys["gloria"].KeyID: {
						Comment: test.OpenPGPKeys["gloria"].KeyID,
						KeyIDs:  []string{test.OpenPGPKeys["gloria"].KeyID},
					},
				},
				Materials: map[string]Marker{
					"alice material":  {},
					"bob material":    {},
					"claire material": {},
					"david material":  {},
					"emily material":  {},
					"frank material":  {},
					"gloria material": {},
				},
			},
		},
	}

	for _, test := range tests {
		var got Plan
		if err := Unmarshal(test.data, &got); err != nil {
			t.Fatal(err)
		}

		want := test.plan
		if !reflect.DeepEqual(want, got) {
			t.Errorf("want plan config %+v, got %+v", want, got)
		}
	}
}
