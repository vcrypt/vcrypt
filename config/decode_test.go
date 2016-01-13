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
		{
			data: test.AcmeBankConfig,
			plan: Plan{
				Comment: "Acme Bank Master Key Recovery Plan",
				Root:    "master-key",
				MSPs: map[string]MSP{
					"master-key": {
						Predicate: "((president & (vp-quorum | so-quorum)) | (vp-quorum & so-quorum) | vp-consensus | so-consensus)",
						EdgeSlice: []string{
							"president",
							"vp-quorum",
							"so-quorum",
							"vp-consensus",
							"so-consensus",
						},
					},
				},
				SSSs: map[string]SSS{
					"vp-quorum": {
						N: 3,
						K: 2,
						EdgeSlice: []string{
							"bob quorum vote",
							"claire quorum vote",
							"david quorum vote",
						},
					},
					"so-quorum": {
						N: 3,
						K: 2,
						EdgeSlice: []string{
							"emily quorum vote",
							"frank quorum vote",
							"gloria quorum vote",
						},
					},
				},
				XORs: map[string]XOR{
					"vp-consensus": {
						EdgeSlice: []string{
							"bob consensus vote",
							"claire consensus vote",
							"david consensus vote",
						},
					},
					"so-consensus": {
						EdgeSlice: []string{
							"emily consensus vote",
							"frank consensus vote",
							"gloria consensus vote",
						},
					},
				},
				SecretBoxes: map[string]SecretBox{
					"bob quorum vote": {
						EdgeSlice: []string{
							"bob votes",
							"bob quorum material",
						},
					},
					"bob consensus vote": {
						EdgeSlice: []string{
							"bob votes",
							"bob consensus material",
						},
					},
					"claire quorum vote": {
						EdgeSlice: []string{
							"claire votes",
							"claire quorum material",
						},
					},
					"claire consensus vote": {
						EdgeSlice: []string{
							"claire votes",
							"claire consensus material",
						},
					},
					"david quorum vote": {
						EdgeSlice: []string{
							"david votes",
							"david quorum material",
						},
					},
					"david consensus vote": {
						EdgeSlice: []string{
							"david votes",
							"david consensus material",
						},
					},
					"emily quorum vote": {
						EdgeSlice: []string{
							"emily votes",
							"emily quorum material",
						},
					},
					"emily consensus vote": {
						EdgeSlice: []string{
							"emily votes",
							"emily consensus material",
						},
					},
					"frank quorum vote": {
						EdgeSlice: []string{
							"frank votes",
							"frank quorum material",
						},
					},
					"frank consensus vote": {
						EdgeSlice: []string{
							"frank votes",
							"frank consensus material",
						},
					},
					"gloria quorum vote": {
						EdgeSlice: []string{
							"gloria votes",
							"gloria quorum material",
						},
					},
					"gloria consensus vote": {
						EdgeSlice: []string{
							"gloria votes",
							"gloria consensus material",
						},
					},
				},
				Demuxes: map[string]Demux{
					"bob votes": {
						EdgeSlice: []string{
							"bob",
						},
					},
					"claire votes": {
						EdgeSlice: []string{
							"claire",
						},
					},
					"david votes": {
						EdgeSlice: []string{
							"david",
						},
					},
					"emily votes": {
						EdgeSlice: []string{
							"emily",
						},
					},
					"frank votes": {
						EdgeSlice: []string{
							"frank",
						},
					},
					"gloria votes": {
						EdgeSlice: []string{
							"gloria",
						},
					},
				},
				RSAs: map[string]RSA{
					"president": {
						SSHKey: test.Users["alice"].SSHKey.Public,
						EdgeSlice: []string{
							"alice@acme.bank",
							"alice material",
						},
					},
					"bob": {
						SSHKey: test.Users["bob"].SSHKey.Public,
						EdgeSlice: []string{
							"bob@acme.bank",
							"bob material",
						},
					},
					"claire": {
						SSHKey: test.Users["claire"].SSHKey.Public,
						EdgeSlice: []string{
							"claire@acme.bank",
							"claire material",
						},
					},
					"david": {
						SSHKey: test.Users["david"].SSHKey.Public,
						EdgeSlice: []string{
							"david@acme.bank",
							"david material",
						},
					},
					"emily": {
						SSHKey: test.Users["emily"].SSHKey.Public,
						EdgeSlice: []string{
							"emily@acme.bank",
							"emily material",
						},
					},
					"frank": {
						SSHKey: test.Users["frank"].SSHKey.Public,
						EdgeSlice: []string{
							"frank@acme.bank",
							"frank material",
						},
					},
					"gloria": {
						SSHKey: test.Users["gloria"].SSHKey.Public,
						EdgeSlice: []string{
							"gloria@acme.bank",
							"gloria material",
						},
					},
				},
				SSHKeys: map[string]SSHKey{
					"alice@acme.bank": {
						Fingerprint: test.Users["alice"].SSHKey.Fingerprint,
					},
					"bob@acme.bank": {
						AuthorizedKey: test.Users["bob"].SSHKey.Public,
					},
					"claire@acme.bank": {
						Fingerprint: test.Users["claire"].SSHKey.Fingerprint,
					},
					"david@acme.bank": {
						AuthorizedKey: test.Users["david"].SSHKey.Public,
					},
					"emily@acme.bank": {
						Fingerprint: test.Users["emily"].SSHKey.Fingerprint,
					},
					"frank@acme.bank": {
						AuthorizedKey: test.Users["frank"].SSHKey.Public,
					},
					"gloria@acme.bank": {
						Fingerprint: test.Users["gloria"].SSHKey.Fingerprint,
					},
				},
				Materials: map[string]Marker{
					"alice material":            {},
					"bob quorum material":       {},
					"bob consensus material":    {},
					"bob material":              {},
					"claire quorum material":    {},
					"claire consensus material": {},
					"claire material":           {},
					"david quorum material":     {},
					"david consensus material":  {},
					"david material":            {},
					"emily quorum material":     {},
					"emily consensus material":  {},
					"emily material":            {},
					"frank quorum material":     {},
					"frank consensus material":  {},
					"frank material":            {},
					"gloria quorum material":    {},
					"gloria consensus material": {},
					"gloria material":           {},
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
