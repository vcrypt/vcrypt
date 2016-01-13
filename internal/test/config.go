package test

var (
	// DiamondPlanConfig is a diamond shaped password plan
	DiamondPlanConfig = []byte(`
# [secretbox "top"] -> [password "top password"]
#                   |
#                   -> [mux] -> [secretbox "left"]  -> [password "left password"]
#                            |                      |
#                            |                      -> [demux] -> [secretbox "bottom"] -> [password "bottom password"]
#                            |                      |                                  |
#                            -> [secretbox "right"] -> [password "right password"]     -> [material "bottom material"]

comment = Diamond shaped plan
root = top

[secretbox "top"]
comment = step 3
edge = top password
edge = mux

[mux]
edge = left
edge = right

[secretbox "left"]
comment = step 2a
edge = left password
edge = demux

[secretbox "right"]
comment = step 2b
edge = right password
edge = demux

[demux]
edge = bottom

[secretbox "bottom"]
comment = step 1
edge = bottom password
edge = bottom material

[password "top password"]
comment = step 3 password

[password "left password"]
comment = step 2a password

[password "right password"]
comment = step 2b password

[password "bottom password"]
comment = step 1 password

[material "bottom material"]
`)

	// TwoManPlanConfig represents a two-man encryption scheme plan
	TwoManPlanConfig = []byte(`
# [secretbox "master key"] -> [secretbox "op 1 key"] -> [password "op 1 password"]
#                          |                         |
#                          |                         -> [material "op 1 material"]
#                          |
#                          -> [secretbox "op 2 key"] -> [password "op 2 password"]
#                                                    |
#                                                    -> [material "op 2 material"]

comment = Two-man rule plan
root = master key

[secretbox "master key"]
edge = op 1 key
edge = op 2 key

[secretbox "op 1 key"]
comment = operator 1 key
edge = op 1 password
edge = op 1 material

[secretbox "op 2 key"]
comment = operator 2 key
edge = op 2 password
edge = op 2 material

[password "op 1 password"]
comment = op 1 secret

[password "op 2 password"]
comment = op 2 secret

[material "op 1 material"]

[material "op 2 material"]
`)

	// TwoPartyPlanConfig is a request-approve-unlock encryption plan
	TwoPartyPlanConfig = []byte(`
# [secretbox "step 3"] -> [password "step 3 password"]
#                      |
#                      -> [secretbox "step 2"] -> [password "step 2 password"]
#                                              |
#                                              -> [secretbox "step 1"] -> [password "step 1 password"]
#                                                                      |
#                                                                      -> [material]

comment = Two-party 3 step plan
root = step 3

[secretbox "step 3"]
edge = step 3 password
edge = step 2

[secretbox "step 2"]
edge = step 2 password
edge = step 1

[secretbox "step 1"]
edge = step 1 password
edge = material

[password "step 3 password"]
comment = party 1 password 2

[password "step 2 password"]
comment = party 2 password

[password "step 1 password"]
comment = party 1 password 1

[material]
`)

	// DNSSecConfig is a multi-party m-of-n OpenPGP encryption plan inspired by
	// the DNSSEC root key.
	DNSSecConfig = []byte(`
# [sss "five-of-seven"] -> [openpgp "alice@example.com"] -> [openpgp-key "alice@example.com"]
#                       |                                |
#                       |                                -> [material]
#                       |
#                       -> [openpgp "bob@example.com"] -> [openpgp-key "bob@example.com"]
#                       |                              |
#                       |                              -> [material]
#                       |
#                       -> [openpgp "claire@example.com"] -> [openpgp-key "claire@example.com"]
#                       |                                 |
#                       |                                 -> [material]
#                       |
#                       -> [openpgp "david@example.com"] -> [openpgp-key "david@example.com"]
#                       |                                |
#                       |                                -> [material]
#                       |
#                       -> [openpgp "emily@example.com"] -> [openpgp-key "emily@example.com"]
#                       |                                |
#                       |                                -> [material]
#                       |
#                       -> [openpgp "frank@example.com"] -> [openpgp-key "frank@example.com"]
#                       |                                |
#                       |                                -> [material]
#                       |
#                       -> [openpgp "gloria@example.com"] -> [openpgp-key "gloria@example.com"]
#                                                         |
#                                                         -> [material]

comment = DNSSEC Root Key
root = five-of-seven

[sss "five-of-seven"]
max-shares = 7
required-shares = 5
edge = alice@example.com
edge = bob@example.com
edge = claire@example.com
edge = david@example.com
edge = emily@example.com
edge = frank@example.com
edge = gloria@example.com

[openpgp "alice@example.com"]
publickey = "` + Users["alice"].OpenPGPKey.Public + `"
edge = alice material
edge = ` + Users["alice"].OpenPGPKey.KeyID + `

[openpgp "bob@example.com"]
publickey = "` + Users["bob"].OpenPGPKey.Public + `"
edge = bob material
edge = ` + Users["bob"].OpenPGPKey.KeyID + `

[openpgp "claire@example.com"]
publickey = "` + Users["claire"].OpenPGPKey.Public + `"
edge = claire material
edge = ` + Users["claire"].OpenPGPKey.KeyID + `

[openpgp "david@example.com"]
publickey = "` + Users["david"].OpenPGPKey.Public + `"
edge = david material
edge = ` + Users["david"].OpenPGPKey.KeyID + `

[openpgp "emily@example.com"]
publickey = "` + Users["emily"].OpenPGPKey.Public + `"
edge = emily material
edge = ` + Users["emily"].OpenPGPKey.KeyID + `

[openpgp "frank@example.com"]
publickey = "` + Users["frank"].OpenPGPKey.Public + `"
edge = frank material
edge = ` + Users["frank"].OpenPGPKey.KeyID + `

[openpgp "gloria@example.com"]
publickey = "` + Users["gloria"].OpenPGPKey.Public + `"
edge = gloria material
edge = ` + Users["gloria"].OpenPGPKey.KeyID + `

[openpgp-key "` + Users["alice"].OpenPGPKey.KeyID + `"]
comment = ` + Users["alice"].OpenPGPKey.KeyID + `
keyid = ` + Users["alice"].OpenPGPKey.KeyID + `

[openpgp-key "` + Users["bob"].OpenPGPKey.KeyID + `"]
comment = ` + Users["bob"].OpenPGPKey.KeyID + `
keyid = ` + Users["bob"].OpenPGPKey.KeyID + `

[openpgp-key "` + Users["claire"].OpenPGPKey.KeyID + `"]
comment = ` + Users["claire"].OpenPGPKey.KeyID + `
keyid = ` + Users["claire"].OpenPGPKey.KeyID + `

[openpgp-key "` + Users["david"].OpenPGPKey.KeyID + `"]
comment = ` + Users["david"].OpenPGPKey.KeyID + `
keyid = ` + Users["david"].OpenPGPKey.KeyID + `

[openpgp-key "` + Users["emily"].OpenPGPKey.KeyID + `"]
comment = ` + Users["emily"].OpenPGPKey.KeyID + `
keyid = ` + Users["emily"].OpenPGPKey.KeyID + `

[openpgp-key "` + Users["frank"].OpenPGPKey.KeyID + `"]
comment = ` + Users["frank"].OpenPGPKey.KeyID + `
keyid = ` + Users["frank"].OpenPGPKey.KeyID + `

[openpgp-key "` + Users["gloria"].OpenPGPKey.KeyID + `"]
comment = ` + Users["gloria"].OpenPGPKey.KeyID + `
keyid = ` + Users["gloria"].OpenPGPKey.KeyID + `

[material "alice material"]

[material "bob material"]

[material "claire material"]

[material "david material"]

[material "emily material"]

[material "frank material"]

[material "gloria material"]

`)
	// AcmeBankConfig is a nested SSS plan with ssh keys.
	AcmeBankConfig = []byte(`
# [sss "master-key"] -> [rsa "president"] -> [ssh-key "alice@acme.bank"]
#                    |                    |
#                    |                    -> [material "alice material"]
#                    |
#                    -> [sss "vp quorum"] -> [*vote "bob:quorum"]
#                    |                    |
#                    |                    -> [*vote "claire:quorum"]
#                    |                    |
#                    |                    -> [*vote "david:quorum"]
#                    |
#                    -> [xor "vp consensus"] -> [*vote "bob:consenus"]
#                    |                       |
#                    |                       -> [*vote "claire:consensus"]
#                    |                       |
#                    |                       -> [*vote "david:consensus"]
#                    |
#                    -> [sss "so quorum"] -> [*vote "emily:quorum"]
#                    |                    |
#                    |                    -> [*vote "frank:quorum"]
#                    |                    |
#                    |                    -> [*vote "gloria:quorum"]
#                    |
#                    -> [xor "so consensus"] -> [*vote "emily:consenus"]
#                                            |
#                                            -> [*vote "frank:consensus"]
#                                            |
#                                            -> [*vote "gloria:consensus"]
#
#
# [*vote "<name>:quorum] : [secretbox "<name> quorum vote"] ------> [material "<name> quorum material"]
#                                                                |
#                                                                -> [demux "<name> votes"] -> [rsa "<name>"] -> [ssh-key "<name>@acme.bank"]
#                                                                |                                           |
#                                                                |                                           -> [material "<name> material"]
#                                                                |
# [*vote "<name>:conensus] : [secretbox "<name> consensus vote"] -> [material "<name> consensus material"]
#

comment = Acme Bank Master Key Recovery Plan
root = master-key

[sss "master-key"]
max-shares = 5
required-shares = 3
edge = president
edge = vp quorum
edge = so quorum
edge = vp consensus
edge = so consensus

[rsa "president"]
ssh-key = "` + Users["alice"].SSHKey.Public + `"
edge = alice@acme.bank
edge = alice material

[ssh-key "alice@acme.bank"]
fingerprint = ` + Users["alice"].SSHKey.Fingerprint + `

[sss "vp quorum"]
max-shares = 3
required-shares = 2
edge = bob quorum vote
edge = claire quorum vote
edge = david quorum vote

[sss "so quorum"]
max-shares = 3
required-shares = 2
edge = emily quorum vote
edge = frank quorum vote
edge = gloria quorum vote

[xor "vp consensus"]
edge = bob consensus vote
edge = claire consensus vote
edge = david consensus vote

[xor "so consensus"]
edge = emily consensus vote
edge = frank consensus vote
edge = gloria consensus vote

[secretbox "bob quorum vote"]
edge = bob votes
edge = bob quorum material

[secretbox "bob consensus vote"]
edge = bob votes
edge = bob consensus material

[demux "bob votes"]
edge = bob

[rsa "bob"]
ssh-key = "` + Users["bob"].SSHKey.Public + `"
edge = bob@acme.bank
edge = bob material

[ssh-key "bob@acme.bank"]
authorized-key = ` + Users["bob"].SSHKey.Public + `

[secretbox "claire quorum vote"]
edge = claire votes
edge = claire quorum material

[secretbox "claire consensus vote"]
edge = claire votes
edge = claire consensus material

[demux "claire votes"]
edge = claire

[rsa "claire"]
ssh-key = "` + Users["claire"].SSHKey.Public + `"
edge = claire@acme.bank
edge = claire material

[ssh-key "claire@acme.bank"]
fingerprint = ` + Users["claire"].SSHKey.Fingerprint + `

[secretbox "david quorum vote"]
edge = david votes
edge = david quorum material

[secretbox "david consensus vote"]
edge = david votes
edge = david consensus material

[demux "david votes"]
edge = david

[rsa "david"]
ssh-key = "` + Users["david"].SSHKey.Public + `"
edge = david@acme.bank
edge = david material

[ssh-key "david@acme.bank"]
authorized-key = ` + Users["david"].SSHKey.Public + `

[secretbox "emily quorum vote"]
edge = emily votes
edge = emily quorum material

[secretbox "emily consensus vote"]
edge = emily votes
edge = emily consensus material

[demux "emily votes"]
edge = emily

[rsa "emily"]
ssh-key = "` + Users["emily"].SSHKey.Public + `"
edge = emily@acme.bank
edge = emily material

[ssh-key "emily@acme.bank"]
fingerprint = ` + Users["emily"].SSHKey.Fingerprint + `

[secretbox "frank quorum vote"]
edge = frank votes
edge = frank quorum material

[secretbox "frank consensus vote"]
edge = frank votes
edge = frank consensus material

[demux "frank votes"]
edge = frank

[rsa "frank"]
ssh-key = "` + Users["frank"].SSHKey.Public + `"
edge = frank@acme.bank
edge = frank material

[ssh-key "frank@acme.bank"]
authorized-key = ` + Users["frank"].SSHKey.Public + `

[secretbox "gloria quorum vote"]
edge = gloria votes
edge = gloria quorum material

[secretbox "gloria consensus vote"]
edge = gloria votes
edge = gloria consensus material

[demux "gloria votes"]
edge = gloria

[rsa "gloria"]
ssh-key = "` + Users["gloria"].SSHKey.Public + `"
edge = gloria@acme.bank
edge = gloria material

[ssh-key "gloria@acme.bank"]
fingerprint = ` + Users["gloria"].SSHKey.Fingerprint + `

[material "alice material"]

[material "bob quorum material"]

[material "bob consensus material"]

[material "bob material"]

[material "claire quorum material"]

[material "claire consensus material"]

[material "claire material"]

[material "david quorum material"]

[material "david consensus material"]

[material "david material"]

[material "emily quorum material"]

[material "emily consensus material"]

[material "emily material"]

[material "frank quorum material"]

[material "frank consensus material"]

[material "frank material"]

[material "gloria quorum material"]

[material "gloria consensus material"]

[material "gloria material"]
`)
)
