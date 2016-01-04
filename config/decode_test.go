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
						PublicKeys: []string{test.Users["alice"].OpenPGPKey.Public},
						EdgeSlice:  []string{"alice material", test.Users["alice"].OpenPGPKey.KeyID},
					},
					"bob@example.com": {
						PublicKeys: []string{test.Users["bob"].OpenPGPKey.Public},
						EdgeSlice:  []string{"bob material", test.Users["bob"].OpenPGPKey.KeyID},
					},
					"claire@example.com": {
						PublicKeys: []string{test.Users["claire"].OpenPGPKey.Public},
						EdgeSlice:  []string{"claire material", test.Users["claire"].OpenPGPKey.KeyID},
					},
					"david@example.com": {
						PublicKeys: []string{test.Users["david"].OpenPGPKey.Public},
						EdgeSlice:  []string{"david material", test.Users["david"].OpenPGPKey.KeyID},
					},
					"emily@example.com": {
						PublicKeys: []string{test.Users["emily"].OpenPGPKey.Public},
						EdgeSlice:  []string{"emily material", test.Users["emily"].OpenPGPKey.KeyID},
					},
					"frank@example.com": {
						PublicKeys: []string{test.Users["frank"].OpenPGPKey.Public},
						EdgeSlice:  []string{"frank material", test.Users["frank"].OpenPGPKey.KeyID},
					},
					"gloria@example.com": {
						PublicKeys: []string{test.Users["gloria"].OpenPGPKey.Public},
						EdgeSlice:  []string{"gloria material", test.Users["gloria"].OpenPGPKey.KeyID},
					},
				},
				OpenPGPKeys: map[string]OpenPGPKey{
					test.Users["alice"].OpenPGPKey.KeyID: {
						Comment: test.Users["alice"].OpenPGPKey.KeyID,
						KeyIDs:  []string{test.Users["alice"].OpenPGPKey.KeyID},
					},
					test.Users["bob"].OpenPGPKey.KeyID: {
						Comment: test.Users["bob"].OpenPGPKey.KeyID,
						KeyIDs:  []string{test.Users["bob"].OpenPGPKey.KeyID},
					},
					test.Users["claire"].OpenPGPKey.KeyID: {
						Comment: test.Users["claire"].OpenPGPKey.KeyID,
						KeyIDs:  []string{test.Users["claire"].OpenPGPKey.KeyID},
					},
					test.Users["david"].OpenPGPKey.KeyID: {
						Comment: test.Users["david"].OpenPGPKey.KeyID,
						KeyIDs:  []string{test.Users["david"].OpenPGPKey.KeyID},
					},
					test.Users["emily"].OpenPGPKey.KeyID: {
						Comment: test.Users["emily"].OpenPGPKey.KeyID,
						KeyIDs:  []string{test.Users["emily"].OpenPGPKey.KeyID},
					},
					test.Users["frank"].OpenPGPKey.KeyID: {
						Comment: test.Users["frank"].OpenPGPKey.KeyID,
						KeyIDs:  []string{test.Users["frank"].OpenPGPKey.KeyID},
					},
					test.Users["gloria"].OpenPGPKey.KeyID: {
						Comment: test.Users["gloria"].OpenPGPKey.KeyID,
						KeyIDs:  []string{test.Users["gloria"].OpenPGPKey.KeyID},
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
