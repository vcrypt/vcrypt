package secret

import (
	"bytes"
	"testing"
)

func TestSSHKey(t *testing.T) {
	sec, err := NewSSHKey(sshFingerprint, "test SSHKey secret")
	if err != nil {
		t.Fatal(err)
	}

	buf := bytes.NewBufferString(sshPrivate)
	if _, err := sec.Load(buf); err != nil {
		t.Error(err)
	}
}

var (
	sshFingerprint = "SHA256:iQBZ9fVdCXB3kxCzkXLB3Er5wb6mJQGs4DsiZKBHLMI"
	sshPrivate     = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAtrIzGg4LhZmE9tdPZz3gqyk9b95d30rZ99svb5eHVGX/U7yO
tWdpprJeKl1yUGfOSnAguhHmAhXg3A0kpwOdzOiLYIu4+/2gVilzW0wIXeb8KCs0
+97dOV72j8yMus2ylxQb/6nwlwOVh6+sSINW5lSEXFBGcF945n1UGefThv+WF4J6
VyAR0pqLb9q7IoUemu+S0G11EHQOR1EeiCHi+qOmNfkf3xtf6Lblode9xhKrKhHY
58LTDfi2jjvMYr6qR5qgIVW0esSuTpbcNst7scNTXYW5PEtdmX/L/LIwxsnoz4Ro
hwkdYrDvoJjdm0OnZvHiZaqAC+HeuZFAGP4W0wIDAQABAoIBAGUl69z1AbQJ9u+i
7Tc/ru+UeYtCFb7Wdi8fjve9cRNtFRuLPYd5pajBABl8exnBHxlfUv8xgaKN8lxi
enRtMCSOavwc32HEXczWTiOxyMAUbm7e3QrFrL1isieTHCcgU0wJuiamM6moNlVV
EZFkBeynxlBFsXntocYahUGCdD48u2VrPGz6m1/liCcmgyD7XtFPMFH192g6qxnU
f9FBteAv+ECKsaRLpxJuA4ubmx1R3LajbDkHX9CuToVB6geNx/SXvf3IO3fMSGEI
PoLWliutp/LWL82m8nr+2kQcYiLV6GG1VTxa7k7BKSeD8e47FdqKNJguRgehSH+P
SDM1SKECgYEA4prc+nvAdvLoYLuV1OZhZxuJf71V5aguqeFDlacjGF2fgYO3Y7D8
PAQcLB+cq26LFD1++Vkkl/yd1zaHg9wNFMKPQtZOp0Q7+KGifa4SkAfqRRxVHKAY
/vIYSqEeSWpt1bFdUFB/YV3DPx+fDTg/nrlV1Vd7F8L2HvqyHPihrzcCgYEAzmU0
LQY/y+fYfd54XB74AKwIDmGzrG6bOCvrNJFmJVVDad1GNPoD2qvCDUmuJBY+52/5
Nqy0k5IsK8Uzp0Gi4ktjrjG5oWCWFecWS4wZ6Wr/x1RsDnVCbVDIPaH48z9nXnHK
QJYm/uvX0XZM3E8rLUxxBNN2rheYEgjQdqxxi0UCgYEAvbt+1LezMaU3Dm9iB62R
1nwHB46nEjBcSd8T8ITN7MPPHukDLxRsTW//iq45Roy7JIpM+0g5TIy2OBEvLCee
SEiTHRpFJuYJ9KaZX/PVFQWbkJwlY19lLmnUDwCSVFQpfKgSAoIz9XlFVmAKk04K
bsKtbIDfzshtvQiZA4rmDccCgYBd6xOJAXT6Vm/fJuLiGH2F4MJxuOfHqTUcpG+N
JjSy/E+G1tfht3sVgF73KPYDGdRaAEwJIyGwnS1YZY4Rp/50txWO6LWtx4PER7mP
exs3aicmDzZ0hctKbx4PXaspFUr2YRVFuo3YJn24pPporeXZ4RT0uz0gD0B1xGkH
94RbeQKBgQChsIMSNuIIhrkcX4SpzXUG82baBbNHlC6Tb2Jg6YFHeOlS6QRqrHHz
Ao6w/o702N9NJwSsuPhyK99Wea8RZMdf8JenDn4MX5EjPkE+YpNHGNjCTQN+Youq
btfWPgycntg6bMczNYjhVdSqdy70ACuw1RuSqNIw05tnzf+1zU78Sg==
-----END RSA PRIVATE KEY-----`
)
