package vcrypt

import (
	"reflect"
	"strings"
	"testing"
)

func TestArmorRoundTrip(t *testing.T) {
	tests := []struct {
		msg    Message
		header string
	}{
		{
			msg:    diamondPlan,
			header: "-----BEGIN VCRYPT PLAN-----",
		},
		{
			msg:    diamondVault.Materials[0],
			header: "-----BEGIN VCRYPT MATERIAL-----",
		},
		{
			msg:    diamondVault,
			header: "-----BEGIN VCRYPT VAULT-----",
		},
	}

	for _, test := range tests {
		data, err := Armor(test.msg)
		if err != nil {
			t.Fatal(err)
		}

		wfp, err := test.msg.Digest()
		if err != nil {
			t.Fatal(err)
		}

		if !strings.Contains(string(data), test.header) {
			hdr := strings.Split(string(data), "\n")[0]
			t.Errorf("want armor header %q, got %q", test.header, hdr)
		}

		if cmnt := test.msg.Comment(); cmnt != "" {
			if !strings.Contains(string(data), "Comment: "+cmnt+"\n") {
				t.Errorf("want Message Comment %q, got none", cmnt)
			}
		}

		got, rest, err := Unarmor(data)
		if err != nil {
			t.Fatal(err)
		}
		if len(rest) != 0 {
			t.Errorf("unexpected extra armor data: %q", rest)
		}

		gfp, err := got.Digest()
		if err != nil {
			t.Fatal(err)
		}

		if !reflect.DeepEqual(wfp, gfp) {
			t.Errorf("want msg.Digest = %v, got %v", wfp, gfp)
		}
	}
}
