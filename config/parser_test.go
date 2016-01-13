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
						"publickey": {test.Users["alice"].OpenPGPKey.Public},
						"edge":      {"alice material", test.Users["alice"].OpenPGPKey.KeyID},
					},
				},
				{
					ID:   "bob@example.com",
					Type: "openpgp",
					Values: map[string][]string{
						"publickey": {test.Users["bob"].OpenPGPKey.Public},
						"edge":      {"bob material", test.Users["bob"].OpenPGPKey.KeyID},
					},
				},
				{
					ID:   "claire@example.com",
					Type: "openpgp",
					Values: map[string][]string{
						"publickey": {test.Users["claire"].OpenPGPKey.Public},
						"edge":      {"claire material", test.Users["claire"].OpenPGPKey.KeyID},
					},
				},
				{
					ID:   "david@example.com",
					Type: "openpgp",
					Values: map[string][]string{
						"publickey": {test.Users["david"].OpenPGPKey.Public},
						"edge":      {"david material", test.Users["david"].OpenPGPKey.KeyID},
					},
				},
				{
					ID:   "emily@example.com",
					Type: "openpgp",
					Values: map[string][]string{
						"publickey": {test.Users["emily"].OpenPGPKey.Public},
						"edge":      {"emily material", test.Users["emily"].OpenPGPKey.KeyID},
					},
				},
				{
					ID:   "frank@example.com",
					Type: "openpgp",
					Values: map[string][]string{
						"publickey": {test.Users["frank"].OpenPGPKey.Public},
						"edge":      {"frank material", test.Users["frank"].OpenPGPKey.KeyID},
					},
				},
				{
					ID:   "gloria@example.com",
					Type: "openpgp",
					Values: map[string][]string{
						"publickey": {test.Users["gloria"].OpenPGPKey.Public},
						"edge":      {"gloria material", test.Users["gloria"].OpenPGPKey.KeyID},
					},
				},
				{
					ID:   test.Users["alice"].OpenPGPKey.KeyID,
					Type: "openpgp-key",
					Values: map[string][]string{
						"comment": {test.Users["alice"].OpenPGPKey.KeyID},
						"keyid":   {test.Users["alice"].OpenPGPKey.KeyID},
					},
				},
				{
					ID:   test.Users["bob"].OpenPGPKey.KeyID,
					Type: "openpgp-key",
					Values: map[string][]string{
						"comment": {test.Users["bob"].OpenPGPKey.KeyID},
						"keyid":   {test.Users["bob"].OpenPGPKey.KeyID},
					},
				},
				{
					ID:   test.Users["claire"].OpenPGPKey.KeyID,
					Type: "openpgp-key",
					Values: map[string][]string{
						"comment": {test.Users["claire"].OpenPGPKey.KeyID},
						"keyid":   {test.Users["claire"].OpenPGPKey.KeyID},
					},
				},
				{
					ID:   test.Users["david"].OpenPGPKey.KeyID,
					Type: "openpgp-key",
					Values: map[string][]string{
						"comment": {test.Users["david"].OpenPGPKey.KeyID},
						"keyid":   {test.Users["david"].OpenPGPKey.KeyID},
					},
				},
				{
					ID:   test.Users["emily"].OpenPGPKey.KeyID,
					Type: "openpgp-key",
					Values: map[string][]string{
						"comment": {test.Users["emily"].OpenPGPKey.KeyID},
						"keyid":   {test.Users["emily"].OpenPGPKey.KeyID},
					},
				},
				{
					ID:   test.Users["frank"].OpenPGPKey.KeyID,
					Type: "openpgp-key",
					Values: map[string][]string{
						"comment": {test.Users["frank"].OpenPGPKey.KeyID},
						"keyid":   {test.Users["frank"].OpenPGPKey.KeyID},
					},
				},
				{
					ID:   test.Users["gloria"].OpenPGPKey.KeyID,
					Type: "openpgp-key",
					Values: map[string][]string{
						"comment": {test.Users["gloria"].OpenPGPKey.KeyID},
						"keyid":   {test.Users["gloria"].OpenPGPKey.KeyID},
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
		{
			data: test.AcmeBankConfig,
			want: []*section{
				{
					Type: "",
					Values: map[string][]string{
						"comment": {"Acme Bank Master Key Recovery Plan"},
						"root":    {"master-key"},
					},
				},
				{
					ID:   "master-key",
					Type: "msp",
					Values: map[string][]string{
						"predicate": {"((president & (vp-quorum | so-quorum)) | (vp-quorum & so-quorum) | vp-consensus | so-consensus)"},
						"edge": {
							"president",
							"vp-quorum",
							"so-quorum",
							"vp-consensus",
							"so-consensus",
						},
					},
				},
				{
					ID:   "president",
					Type: "rsa",
					Values: map[string][]string{
						"ssh-key": {test.Users["alice"].SSHKey.Public},
						"edge": {
							"alice@acme.bank",
							"alice material",
						},
					},
				},
				{
					ID:   "alice@acme.bank",
					Type: "ssh-key",
					Values: map[string][]string{
						"fingerprint": {test.Users["alice"].SSHKey.Fingerprint},
					},
				},
				{
					ID:   "vp-quorum",
					Type: "sss",
					Values: map[string][]string{
						"max-shares":      {"3"},
						"required-shares": {"2"},
						"edge": {
							"bob quorum vote",
							"claire quorum vote",
							"david quorum vote",
						},
					},
				},
				{
					ID:   "so-quorum",
					Type: "sss",
					Values: map[string][]string{
						"max-shares":      {"3"},
						"required-shares": {"2"},
						"edge": {
							"emily quorum vote",
							"frank quorum vote",
							"gloria quorum vote",
						},
					},
				},
				{
					ID:   "vp-consensus",
					Type: "xor",
					Values: map[string][]string{
						"edge": {
							"bob consensus vote",
							"claire consensus vote",
							"david consensus vote",
						},
					},
				},
				{
					ID:   "so-consensus",
					Type: "xor",
					Values: map[string][]string{
						"edge": {
							"emily consensus vote",
							"frank consensus vote",
							"gloria consensus vote",
						},
					},
				},
				{
					ID:   "bob quorum vote",
					Type: "secretbox",
					Values: map[string][]string{
						"edge": {
							"bob votes",
							"bob quorum material",
						},
					},
				},
				{
					ID:   "bob consensus vote",
					Type: "secretbox",
					Values: map[string][]string{
						"edge": {
							"bob votes",
							"bob consensus material",
						},
					},
				},
				{
					ID:   "bob votes",
					Type: "demux",
					Values: map[string][]string{
						"edge": {"bob"},
					},
				},
				{
					ID:   "bob",
					Type: "rsa",
					Values: map[string][]string{
						"ssh-key": {test.Users["bob"].SSHKey.Public},
						"edge": {
							"bob@acme.bank",
							"bob material",
						},
					},
				},
				{
					ID:   "bob@acme.bank",
					Type: "ssh-key",
					Values: map[string][]string{
						"authorized-key": {test.Users["bob"].SSHKey.Public},
					},
				},
				{
					ID:   "claire quorum vote",
					Type: "secretbox",
					Values: map[string][]string{
						"edge": {
							"claire votes",
							"claire quorum material",
						},
					},
				},
				{
					ID:   "claire consensus vote",
					Type: "secretbox",
					Values: map[string][]string{
						"edge": {
							"claire votes",
							"claire consensus material",
						},
					},
				},
				{
					ID:   "claire votes",
					Type: "demux",
					Values: map[string][]string{
						"edge": {"claire"},
					},
				},
				{
					ID:   "claire",
					Type: "rsa",
					Values: map[string][]string{
						"ssh-key": {test.Users["claire"].SSHKey.Public},
						"edge": {
							"claire@acme.bank",
							"claire material",
						},
					},
				},
				{
					ID:   "claire@acme.bank",
					Type: "ssh-key",
					Values: map[string][]string{
						"fingerprint": {test.Users["claire"].SSHKey.Fingerprint},
					},
				},
				{
					ID:   "david quorum vote",
					Type: "secretbox",
					Values: map[string][]string{
						"edge": {
							"david votes",
							"david quorum material",
						},
					},
				},
				{
					ID:   "david consensus vote",
					Type: "secretbox",
					Values: map[string][]string{
						"edge": {
							"david votes",
							"david consensus material",
						},
					},
				},
				{
					ID:   "david votes",
					Type: "demux",
					Values: map[string][]string{
						"edge": {"david"},
					},
				},
				{
					ID:   "david",
					Type: "rsa",
					Values: map[string][]string{
						"ssh-key": {test.Users["david"].SSHKey.Public},
						"edge": {
							"david@acme.bank",
							"david material",
						},
					},
				},
				{
					ID:   "david@acme.bank",
					Type: "ssh-key",
					Values: map[string][]string{
						"authorized-key": {test.Users["david"].SSHKey.Public},
					},
				},
				{
					ID:   "emily quorum vote",
					Type: "secretbox",
					Values: map[string][]string{
						"edge": {
							"emily votes",
							"emily quorum material",
						},
					},
				},
				{
					ID:   "emily consensus vote",
					Type: "secretbox",
					Values: map[string][]string{
						"edge": {
							"emily votes",
							"emily consensus material",
						},
					},
				},
				{
					ID:   "emily votes",
					Type: "demux",
					Values: map[string][]string{
						"edge": {"emily"},
					},
				},
				{
					ID:   "emily",
					Type: "rsa",
					Values: map[string][]string{
						"ssh-key": {test.Users["emily"].SSHKey.Public},
						"edge": {
							"emily@acme.bank",
							"emily material",
						},
					},
				},
				{
					ID:   "emily@acme.bank",
					Type: "ssh-key",
					Values: map[string][]string{
						"fingerprint": {test.Users["emily"].SSHKey.Fingerprint},
					},
				},
				{
					ID:   "frank quorum vote",
					Type: "secretbox",
					Values: map[string][]string{
						"edge": {
							"frank votes",
							"frank quorum material",
						},
					},
				},
				{
					ID:   "frank consensus vote",
					Type: "secretbox",
					Values: map[string][]string{
						"edge": {
							"frank votes",
							"frank consensus material",
						},
					},
				},
				{
					ID:   "frank votes",
					Type: "demux",
					Values: map[string][]string{
						"edge": {"frank"},
					},
				},
				{
					ID:   "frank",
					Type: "rsa",
					Values: map[string][]string{
						"ssh-key": {test.Users["frank"].SSHKey.Public},
						"edge": {
							"frank@acme.bank",
							"frank material",
						},
					},
				},
				{
					ID:   "frank@acme.bank",
					Type: "ssh-key",
					Values: map[string][]string{
						"authorized-key": {test.Users["frank"].SSHKey.Public},
					},
				},
				{
					ID:   "gloria quorum vote",
					Type: "secretbox",
					Values: map[string][]string{
						"edge": {
							"gloria votes",
							"gloria quorum material",
						},
					},
				},
				{
					ID:   "gloria consensus vote",
					Type: "secretbox",
					Values: map[string][]string{
						"edge": {
							"gloria votes",
							"gloria consensus material",
						},
					},
				},
				{
					ID:   "gloria votes",
					Type: "demux",
					Values: map[string][]string{
						"edge": {"gloria"},
					},
				},
				{
					ID:   "gloria",
					Type: "rsa",
					Values: map[string][]string{
						"ssh-key": {test.Users["gloria"].SSHKey.Public},
						"edge": {
							"gloria@acme.bank",
							"gloria material",
						},
					},
				},
				{
					ID:   "gloria@acme.bank",
					Type: "ssh-key",
					Values: map[string][]string{
						"fingerprint": {test.Users["gloria"].SSHKey.Fingerprint},
					},
				},
				{
					ID:     "alice material",
					Type:   "material",
					Values: map[string][]string{},
				},
				{
					ID:     "bob quorum material",
					Type:   "material",
					Values: map[string][]string{},
				},
				{
					ID:     "bob consensus material",
					Type:   "material",
					Values: map[string][]string{},
				},
				{
					ID:     "bob material",
					Type:   "material",
					Values: map[string][]string{},
				},
				{
					ID:     "claire quorum material",
					Type:   "material",
					Values: map[string][]string{},
				},
				{
					ID:     "claire consensus material",
					Type:   "material",
					Values: map[string][]string{},
				},
				{
					ID:     "claire material",
					Type:   "material",
					Values: map[string][]string{},
				},
				{
					ID:     "david quorum material",
					Type:   "material",
					Values: map[string][]string{},
				},
				{
					ID:     "david consensus material",
					Type:   "material",
					Values: map[string][]string{},
				},
				{
					ID:     "david material",
					Type:   "material",
					Values: map[string][]string{},
				},
				{
					ID:     "emily quorum material",
					Type:   "material",
					Values: map[string][]string{},
				},
				{
					ID:     "emily consensus material",
					Type:   "material",
					Values: map[string][]string{},
				},
				{
					ID:     "emily material",
					Type:   "material",
					Values: map[string][]string{},
				},
				{
					ID:     "frank quorum material",
					Type:   "material",
					Values: map[string][]string{},
				},
				{
					ID:     "frank consensus material",
					Type:   "material",
					Values: map[string][]string{},
				},
				{
					ID:     "frank material",
					Type:   "material",
					Values: map[string][]string{},
				},
				{
					ID:     "gloria quorum material",
					Type:   "material",
					Values: map[string][]string{},
				},
				{
					ID:     "gloria consensus material",
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
