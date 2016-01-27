package graph

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/vcrypt/vcrypt"
	"github.com/vcrypt/vcrypt/internal/test"
)

func TestPlanLines(t *testing.T) {
	tests := []struct {
		config string
		lines  []string
	}{
		// 2-way split
		{
			config: `root = secretbox
								 [secretbox]
								 edge = password
								 edge = material
								 [password]
								 [material]`,
			lines: []string{
				`*   0000000000000001 [secretbox]  `,
				`|\  `,
				`| * 0000000000000002 [password]   `,
				`*   0000000000000003 [material]   `,
			},
		},
		// 3-way split
		{
			config: `root = xor
								 [xor]
								 edge = a
								 edge = b
								 edge = c
								 [password "a"]
								 [password "b"]
								 [password "c"]`,
			lines: []string{
				`*-.   0000000000000001 [xor]        `,
				`|\ \  `,
				`| | * 0000000000000002 [password]   a`,
				`| *   0000000000000003 [password]   b`,
				`*     0000000000000004 [password]   c`,
			},
		},
		// 4-way split
		{
			config: `root = xor
								 [xor]
								 edge = a
								 edge = b
								 edge = c
								 edge = d
								 [password "a"]
								 [password "b"]
								 [password "c"]
								 [password "d"]`,
			lines: []string{
				`*---.   0000000000000001 [xor]        `,
				`|\ \ \  `,
				`| | | * 0000000000000002 [password]   a`,
				`| | *   0000000000000003 [password]   b`,
				`| *     0000000000000004 [password]   c`,
				`*       0000000000000005 [password]   d`,
			},
		},
		// 2-way then 2-way splits
		{
			config: `root = xor
								 [xor]
								 edge = a
								 edge = b
								 [password "a"]
								 [xor "b"]
								 edge = c
								 edge = d
								 [password "c"]
								 [password "d"]`,
			lines: []string{
				`*   0000000000000001 [xor]        `,
				`|\  `,
				`| * 0000000000000002 [password]   a`,
				`*   0000000000000003 [xor]        b`,
				`|\  `,
				`| * 0000000000000004 [password]   c`,
				`*   0000000000000005 [password]   d`,
			},
		},
		// 2-way merge
		{
			config: `root = demux
						 [demux]
						 edge = mux
						 edge = mux
						 [mux]`,
			lines: []string{
				`* 0000000000000001 [demux]      `,
				`|\`,
				`|/`,
				`* 0000000000000002 [mux]        `,
			},
		},
		// 3-way merge
		{
			config: `root = demux
						 [demux]
						 edge = mux
						 edge = mux
						 edge = mux
						 [mux]`,
			lines: []string{
				`*-. 0000000000000001 [demux]      `,
				`|\ \`,
				`| |/`,
				`|/| `,
				`|/  `,
				`*   0000000000000002 [mux]        `,
			},
		},
		// 4-way merge
		{
			config: `root = demux
					 [demux]
					 edge = mux
					 edge = mux
					 edge = mux
					 edge = mux
					 [mux]`,
			lines: []string{
				`*---. 0000000000000001 [demux]      `,
				`|\ \ \`,
				`| |_|/`,
				`|/| | `,
				`| |/  `,
				`|/|   `,
				`|/    `,
				`*     0000000000000002 [mux]        `,
			},
		},
		// two-man plan
		{
			config: string(test.TwoManPlanConfig),
			lines: []string{
				`*       0000000000000001 [secretbox]  master key`,
				`|\      `,
				`| *     0000000000000002 [secretbox]  operator 1 key`,
				`| |\    `,
				`* | \   0000000000000003 [secretbox]  operator 2 key`,
				`|\ \ \  `,
				`| | | * 0000000000000004 [password]   op 1 secret`,
				`| | *   0000000000000005 [material]   op 1 material`,
				`| *     0000000000000006 [password]   op 2 secret`,
				`*       0000000000000007 [material]   op 2 material`,
			},
		},
		// diamond plan
		{
			config: string(test.DiamondPlanConfig),
			lines: []string{
				`*       0000000000000001 [secretbox]  step 3`,
				`|\      `,
				`| *     0000000000000002 [password]   step 3 password`,
				`*       0000000000000003 [mux]        `,
				`|\      `,
				`| *     0000000000000004 [secretbox]  step 2a`,
				`| |\    `,
				`* | \   0000000000000005 [secretbox]  step 2b`,
				`|\ \ \  `,
				`| | | * 0000000000000006 [password]   step 2a password`,
				`| |/    `,
				`|/|     `,
				`* |     0000000000000007 [demux]      `,
				`| *     0000000000000008 [password]   step 2b password`,
				`*       0000000000000009 [secretbox]  step 1`,
				`|\      `,
				`| *     000000000000000a [password]   step 1 password`,
				`*       000000000000000b [material]   bottom material`,
			},
		},
		// dnssec plan
		{
			config: string(test.DNSSecConfig),
			lines: []string{
				`*---------.                 0000000000000001 [sss]        five-of-seven`,
				`|\ \ \ \ \ \                `,
				`| | | | | | *               0000000000000002 [openpgp]    alice@example.com`,
				`| | | | | | |\              `,
				`| | | | | * | \             0000000000000003 [openpgp]    bob@example.com`,
				`| | | | | |\ \ \            `,
				`| | | | * | \ \ \           0000000000000004 [openpgp]    claire@example.com`,
				`| | | | |\ \ \ \ \          `,
				`| | | * | \ \ \ \ \         0000000000000005 [openpgp]    david@example.com`,
				`| | | |\ \ \ \ \ \ \        `,
				`| | * | \ \ \ \ \ \ \       0000000000000006 [openpgp]    emily@example.com`,
				`| | |\ \ \ \ \ \ \ \ \      `,
				`| * | \ \ \ \ \ \ \ \ \     0000000000000007 [openpgp]    frank@example.com`,
				`| |\ \ \ \ \ \ \ \ \ \ \    `,
				`* | \ \ \ \ \ \ \ \ \ \ \   0000000000000008 [openpgp]    gloria@example.com`,
				`|\ \ \ \ \ \ \ \ \ \ \ \ \  `,
				`| | | | | | | | | | | | | * 0000000000000009 [material]   alice material`,
				`| | | | | | | | | | | | *   000000000000000a [openpgpkey] F3720A7A58FA44A8`,
				`| | | | | | | | | | | *     000000000000000b [material]   bob material`,
				`| | | | | | | | | | *       000000000000000c [openpgpkey] 0E83208839AE031B`,
				`| | | | | | | | | *         000000000000000d [material]   claire material`,
				`| | | | | | | | *           000000000000000e [openpgpkey] A1641E773F0379EF`,
				`| | | | | | | *             000000000000000f [material]   david material`,
				`| | | | | | *               0000000000000010 [openpgpkey] C42B14885269CBCE`,
				`| | | | | *                 0000000000000011 [material]   emily material`,
				`| | | | *                   0000000000000012 [openpgpkey] C832AA780A48050C`,
				`| | | *                     0000000000000013 [material]   frank material`,
				`| | *                       0000000000000014 [openpgpkey] 16C069B4992CFE6C`,
				`| *                         0000000000000015 [material]   gloria material`,
				`*                           0000000000000016 [openpgpkey] F483DFBB9B4F72EF`,
			},
		},
		// acme bank plan
		{
			config: string(test.AcmeBankConfig),
			lines: []string{
				`*-----.                                       0000000000000001 [sss]        master-key`,
				`|\ \ \ \                                      `,
				`| | | | *                                     0000000000000002 [rsa]        president`,
				`| | | | |\                                    `,
				`| | | | | \                                   `,
				`| | | |  \ \                                  `,
				`| | | *-. \ \                                 0000000000000003 [sss]        vp quorum`,
				`| | | |\ \ \ \                                `,
				`| | | | \ \ \ \                               `,
				`| | |  \ \ \ \ \                              `,
				`| | *-. \ \ \ \ \                             0000000000000004 [sss]        so quorum`,
				`| | |\ \ \ \ \ \ \                            `,
				`| | | \ \ \ \ \ \ \                           `,
				`| |  \ \ \ \ \ \ \ \                          `,
				`| *-. \ \ \ \ \ \ \ \                         0000000000000005 [xor]        vp consensus`,
				`| |\ \ \ \ \ \ \ \ \ \                        `,
				`| | \ \ \ \ \ \ \ \ \ \                       `,
				`|  \ \ \ \ \ \ \ \ \ \ \                      `,
				`*-. \ \ \ \ \ \ \ \ \ \ \                     0000000000000006 [xor]        so consensus`,
				`|\ \ \ \ \ \ \ \ \ \ \ \ \                    `,
				`| | | | | | | | | | | | | *                   0000000000000007 [secret]     alice@acme.bank`,
				`| | | | | | | | | | | | *                     0000000000000008 [material]   alice material`,
				`| | | | | | | | | | | *                       0000000000000009 [secretbox]  bob quorum vote`,
				`| | | | | | | | | | | |\                      `,
				`| | | | | | | | | | * | \                     000000000000000a [secretbox]  claire quorum vote`,
				`| | | | | | | | | | |\ \ \                    `,
				`| | | | | | | | | * | \ \ \                   000000000000000b [secretbox]  david quorum vote`,
				`| | | | | | | | | |\ \ \ \ \                  `,
				`| | | | | | | | * | \ \ \ \ \                 000000000000000c [secretbox]  emily quorum vote`,
				`| | | | | | | | |\ \ \ \ \ \ \                `,
				`| | | | | | | * | \ \ \ \ \ \ \               000000000000000d [secretbox]  frank quorum vote`,
				`| | | | | | | |\ \ \ \ \ \ \ \ \              `,
				`| | | | | | * | \ \ \ \ \ \ \ \ \             000000000000000e [secretbox]  gloria quorum vote`,
				`| | | | | | |\ \ \ \ \ \ \ \ \ \ \            `,
				`| | | | | * | \ \ \ \ \ \ \ \ \ \ \           000000000000000f [secretbox]  bob consensus vote`,
				`| | | | | |\ \ \ \ \ \ \ \ \ \ \ \ \          `,
				`| | | | * | \ \ \ \ \ \ \ \ \ \ \ \ \         0000000000000010 [secretbox]  claire consensus vote`,
				`| | | | |\ \ \ \ \ \ \ \ \ \ \ \ \ \ \        `,
				`| | | * | \ \ \ \ \ \ \ \ \ \ \ \ \ \ \       0000000000000011 [secretbox]  david consensus vote`,
				`| | | |\ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \      `,
				`| | * | \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \     0000000000000012 [secretbox]  emily consensus vote`,
				`| | |\ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \    `,
				`| * | \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \   0000000000000013 [secretbox]  frank consensus vote`,
				`| |\ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \  `,
				`* | \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ 0000000000000014 [secretbox]  gloria consensus vote`,
				`|\ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \`,
				`| | | | | | | | | | | | |_|_|_|_|_|_|_|_|_|_|/`,
				`| | | | | | | | | | | |/| | | | | | | | | | | `,
				`| | | | | | | | | | | * | | | | | | | | | | | 0000000000000015 [demux]      bob votes`,
				`| | | | | | | | | | | | | | | | | | | | | | * 0000000000000016 [material]   bob quorum material`,
				`| | | | | | | | | | |_|_|_|_|_|_|_|_|_|_|/    `,
				`| | | | | | | | | |/| | | | | | | | | | |     `,
				`| | | | | | | | | * | | | | | | | | | | |     0000000000000017 [demux]      claire votes`,
				`| | | | | | | | | | | | | | | | | | | | *     0000000000000018 [material]   claire quorum material`,
				`| | | | | | | | |_|_|_|_|_|_|_|_|_|_|/        `,
				`| | | | | | | |/| | | | | | | | | | |         `,
				`| | | | | | | * | | | | | | | | | | |         0000000000000019 [demux]      david votes`,
				`| | | | | | | | | | | | | | | | | | *         000000000000001a [material]   david quorum material`,
				`| | | | | | |_|_|_|_|_|_|_|_|_|_|/            `,
				`| | | | | |/| | | | | | | | | | |             `,
				`| | | | | * | | | | | | | | | | |             000000000000001b [demux]      emily votes`,
				`| | | | | | | | | | | | | | | | *             000000000000001c [material]   emily quorum material`,
				`| | | | |_|_|_|_|_|_|_|_|_|_|/                `,
				`| | | |/| | | | | | | | | | |                 `,
				`| | | * | | | | | | | | | | |                 000000000000001d [demux]      frank votes`,
				`| | | | | | | | | | | | | | *                 000000000000001e [material]   frank quorum material`,
				`| | |_|_|_|_|_|_|_|_|_|_|/                    `,
				`| |/| | | | | | | | | | |                     `,
				`| * | | | | | | | | | | |                     000000000000001f [demux]      gloria votes`,
				`| | | | | | | | | | | | *                     0000000000000020 [material]   gloria quorum material`,
				`| | | | | | | | | | * |                       0000000000000021 [material]   bob consensus material`,
				`| | | | | | | | | |  /                        `,
				`| | | | | | | | * | |                         0000000000000022 [material]   claire consensus material`,
				`| | | | | | | |  / /                          `,
				`| | | | | | * | | |                           0000000000000023 [material]   david consensus material`,
				`| | | | | |  / / /                            `,
				`| | | | * | | | |                             0000000000000024 [material]   emily consensus material`,
				`| | | |  / / / /                              `,
				`| | * | | | | |                               0000000000000025 [material]   frank consensus material`,
				`| |  / / / / /                                `,
				`* | | | | | |                                 0000000000000026 [material]   gloria consensus material`,
				` / / / / / /                                  `,
				`| | | | | *                                   0000000000000027 [rsa]        bob`,
				`| | | | | |\                                  `,
				`| | | | * | \                                 0000000000000028 [rsa]        claire`,
				`| | | | |\ \ \                                `,
				`| | | * | \ \ \                               0000000000000029 [rsa]        david`,
				`| | | |\ \ \ \ \                              `,
				`| | * | \ \ \ \ \                             000000000000002a [rsa]        emily`,
				`| | |\ \ \ \ \ \ \                            `,
				`| * | \ \ \ \ \ \ \                           000000000000002b [rsa]        frank`,
				`| |\ \ \ \ \ \ \ \ \                          `,
				`* | \ \ \ \ \ \ \ \ \                         000000000000002c [rsa]        gloria`,
				`|\ \ \ \ \ \ \ \ \ \ \                        `,
				`| | | | | | | | | | | *                       000000000000002d [secret]     bob@acme.bank`,
				`| | | | | | | | | | *                         000000000000002e [material]   bob material`,
				`| | | | | | | | | *                           000000000000002f [secret]     claire@acme.bank`,
				`| | | | | | | | *                             0000000000000030 [material]   claire material`,
				`| | | | | | | *                               0000000000000031 [secret]     david@acme.bank`,
				`| | | | | | *                                 0000000000000032 [material]   david material`,
				`| | | | | *                                   0000000000000033 [secret]     emily@acme.bank`,
				`| | | | *                                     0000000000000034 [material]   emily material`,
				`| | | *                                       0000000000000035 [secret]     frank@acme.bank`,
				`| | *                                         0000000000000036 [material]   frank material`,
				`| *                                           0000000000000037 [secret]     gloria@acme.bank`,
				`*                                             0000000000000038 [material]   gloria material`,
			},
		},
	}

	for _, test := range tests {
		plan, err := vcrypt.BuildPlan(bytes.NewBufferString(test.config))
		if err != nil {
			t.Fatal(err)
		}

		lines, err := PlanLines(plan, nil)
		if err != nil {
			t.Error(err)
			continue
		}
		scrubDigests(lines)

		want := strings.Join(test.lines, "\n\t")
		got := strings.Join(lines, "\n\t")
		if want != got {
			t.Errorf("want graph:\n\t%s\ngot:\n\t%s", want, got)
		}
	}
}

var digestReg = regexp.MustCompile(" [0-9a-fA-F]{16} ")

func scrubDigests(lines []string) {
	count := 0
	for i, line := range lines {
		if digestReg.MatchString(line) {
			count++
			lines[i] = digestReg.ReplaceAllString(line, fmt.Sprintf(" %0.16x ", count))
		}
	}
}
