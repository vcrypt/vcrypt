package vcrypt

import "testing"

func TestVault(t *testing.T) {
	tests := []struct {
		*Plan

		comment string
	}{
		{
			Plan:    twoManPlan,
			comment: "two man rule",
		},
	}

	for _, test := range tests {
		vault, err := NewVault(test.Plan, test.comment)
		if err != nil {
			t.Fatal(err)
		}

		if fp, err := vault.Digest(); err == nil {
			t.Errorf("unlocked vault has digest: %v", fp)
		}
	}
}
