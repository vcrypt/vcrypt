package config

import (
	"errors"
	"testing"

	"github.com/vcrypt/vcrypt/internal/test"
	"github.com/vcrypt/vcrypt/secret"
)

func TestSSHKey(t *testing.T) {
	tests := []struct {
		config SSHKey

		secret *secret.SSHKey
		err    error
	}{
		// authorized_keys formatted public key & comment
		{
			config: SSHKey{
				AuthorizedKey: test.Users["alice"].SSHKey.Public,
			},
			secret: mustSSHKey(test.Users["alice"].SSHKey.Fingerprint, "alice"),
		},
		// fingerprint of public key
		{
			config: SSHKey{
				Fingerprint: test.Users["bob"].SSHKey.Fingerprint,
			},
			secret: mustSSHKey(test.Users["bob"].SSHKey.Fingerprint, ""),
		},
		// errors
		{
			config: SSHKey{},
			err:    errors.New("ssh secret requires either authorized-key or fingerprint"),
		},
		{
			config: SSHKey{
				Fingerprint: "DEADBEEF",
			},
			err: errors.New("invalid ssh key fingerprint"),
		},
		{
			config: SSHKey{
				Fingerprint: "MD5:DEADBEEF",
			},
			err: errors.New(`unsupported hash algorithm "MD5"`),
		},
	}

	for _, test := range tests {
		sec, err := test.config.Secret()
		if err != nil {
			if test.err != nil {
				if err.Error() != test.err.Error() {
					t.Errorf("want error %q, got %q", test.err.Error(), err.Error())
				}
			} else {
				t.Error(err)
			}
			continue
		}

		if *test.secret != *sec.(*secret.SSHKey) {
			t.Errorf("want SSHKey secret %+v, got %+v", test.secret, sec)
		}
	}
}

func mustSSHKey(fingerprint, comment string) *secret.SSHKey {
	sshKey, err := secret.NewSSHKey(fingerprint, comment)
	if err != nil {
		panic(err)
	}
	return sshKey
}
