# DNSSEC

An example of a multi-party vault inspired by the DNSSEC root key.

        [sss "five-of-seven"] -> [openpgp "alice@example.com"] -> [openpgp-key "alice@example.com"]
                              |                                |
                              |                                -> [material]
                              |
                              -> [openpgp "bob@example.com"] -> [openpgp-key "bob@example.com"]
                              |                              |
                              |                              -> [material]
                              |
                              -> [openpgp "claire@example.com"] -> [openpgp-key "claire@example.com"]
                              |                                 |
                              |                                 -> [material]
                              |
                              -> [openpgp "david@example.com"] -> [openpgp-key "david@example.com"]
                              |                                |
                              |                                -> [material]
                              |
                              -> [openpgp "emily@example.com"] -> [openpgp-key "emily@example.com"]
                              |                                |
                              |                                -> [material]
                              |
                              -> [openpgp "frank@example.com"] -> [openpgp-key "frank@example.com"]
                              |                                |
                              |                                -> [material]
                              |
                              -> [openpgp "gloria@example.com"] -> [openpgp-key "gloria@example.com"]
                                                                |
                                                                -> [material]

# Parties

* Key Officers: Alice, Bob, Claire, David, Emily, Frank & Gloria
* Operator: rebuilds the root key

# Instructions

### Part 1 - Lock `root.key` to `dnssec.vault`

Start by generating a root key:

        $ openssl genrsa -out root.key 2048
        > Generating RSA private key, 2048 bit long modulus
        > ..........................................................................................................................................+++
        > ................................................................................+++
        > e is 65537 (0x10001)

Build the vcrypt plan from the plan config:

        $ vcrypt build -in dnssec.conf -out dnssec.plan
        $ vcrypt inspect -in dnssec.plan
        > plan 4365f5f69d84923f666556d716e2579018cd9e07ebe23b76c6f389edc908b718
        >
        >   DNSSEC Root Key
        >
        > 3ab411d0d45fe093 [sss]
        > b00e404ae1e734c1 [openpgp]
        > 0183a8fd056f479c [openpgp]
        > 3a5141c12d32ba91 [openpgp]
        > 74b2b57779d8e59d [openpgp]
        > fdc4f78ba686a06b [openpgp]
        > 776ddb3c218f2cd5 [openpgp]
        > bd32bef5d7e537bb [openpgp]
        > 247a018f565c02fe [material]
        > ad295bdaca638b37 [openpgpkey] F3720A7A58FA44A8
        > 9ec6d104d8af9c3a [material]
        > a2b31c743320124b [openpgpkey] 0E83208839AE031B
        > 9e5e03d8db9b7608 [material]
        > e212414702856dc3 [openpgpkey] A1641E773F0379EF
        > 6106d3a0f001b744 [material]
        > 822dde0d82151610 [openpgpkey] C42B14885269CBCE
        > c302979369fb66fc [material]
        > ce990e6dd5f5714e [openpgpkey] C832AA780A48050C
        > 7ce3b56073b34949 [material]
        > 46db065337827222 [openpgpkey] 16C069B4992CFE6C
        > 828268cca79c8738 [material]
        > 133a250141d5c743 [openpgpkey] F483DFBB9B4F72EF

Encrypt `root.key` into `dnssec.vault`:

        $ vcrypt lock -plan dnssec.plan -in root.key -out dnssec.vault -db.dir tmp
        $ vcrypt inspect -in dnssec.vault
        > vault 258d3d73f7ad5c1241d997433e8c291ac7b7006ff5ba462d5a1f25fb98dd754a
        >
        >   3ab411d0d45fe093 [sss]
        >   b00e404ae1e734c1 [openpgp]
        >   0183a8fd056f479c [openpgp]
        >   3a5141c12d32ba91 [openpgp]
        >   74b2b57779d8e59d [openpgp]
        >   fdc4f78ba686a06b [openpgp]
        >   776ddb3c218f2cd5 [openpgp]
        >   bd32bef5d7e537bb [openpgp]
        >   247a018f565c02fe [material]
        >   ad295bdaca638b37 [openpgpkey] F3720A7A58FA44A8
        >   9ec6d104d8af9c3a [material]
        >   a2b31c743320124b [openpgpkey] 0E83208839AE031B
        >   9e5e03d8db9b7608 [material]
        >   e212414702856dc3 [openpgpkey] A1641E773F0379EF
        >   6106d3a0f001b744 [material]
        >   822dde0d82151610 [openpgpkey] C42B14885269CBCE
        >   c302979369fb66fc [material]
        >   ce990e6dd5f5714e [openpgpkey] C832AA780A48050C
        >   7ce3b56073b34949 [material]
        >   46db065337827222 [openpgpkey] 16C069B4992CFE6C
        >   828268cca79c8738 [material]
        >   133a250141d5c743 [openpgpkey] F483DFBB9B4F72EF

### Part 2 - Solve & export five of Officer's key share

As each Officer, unlock & export the key shares:

        $ vcrypt unlock -in dnssec.vault -openpgp.dir alice -db.dir alice
        $ vcrypt export -in dnssec.vault -out alice.share -db.dir alice -id b00e404ae1e734c1

        $ vcrypt unlock -in dnssec.vault -openpgp.dir bob -db.dir bob
        $ vcrypt export -in dnssec.vault -out bob.share -db.dir bob -id 0183a8fd056f479c

        $ vcrypt unlock -in dnssec.vault -openpgp.dir claire -db.dir claire
        $ vcrypt export -in dnssec.vault -out claire.share -db.dir claire -id 3a5141c12d32ba91

        $ vcrypt unlock -in dnssec.vault -openpgp.dir david -db.dir david
        $ vcrypt export -in dnssec.vault -out david.share -db.dir david -id 74b2b57779d8e59d

        $ vcrypt unlock -in dnssec.vault -openpgp.dir emily -db.dir emily
        $ vcrypt export -in dnssec.vault -out emily.share -db.dir emily -id fdc4f78ba686a06b

### Part 3 - As the Operator, import key shares & rebuild `root.key`

        $ vcrypt import -vault dnssec.vault -in alice.share
        $ vcrypt import -vault dnssec.vault -in bob.share
        $ vcrypt import -vault dnssec.vault -in claire.share
        $ vcrypt import -vault dnssec.vault -in david.share
        $ vcrypt import -vault dnssec.vault -in emily.share

        $ vcrypt inspect -in dnssec.vault
        > vault 258d3d73f7ad5c1241d997433e8c291ac7b7006ff5ba462d5a1f25fb98dd754a
        >
        >   3ab411d0d45fe093 [sss]
        > S b00e404ae1e734c1 [openpgp]
        > S 0183a8fd056f479c [openpgp]
        > S 3a5141c12d32ba91 [openpgp]
        > S 74b2b57779d8e59d [openpgp]
        > S fdc4f78ba686a06b [openpgp]
        >   776ddb3c218f2cd5 [openpgp]
        >   bd32bef5d7e537bb [openpgp]
        >   247a018f565c02fe [material]
        >   ad295bdaca638b37 [openpgpkey] F3720A7A58FA44A8
        >   9ec6d104d8af9c3a [material]
        >   a2b31c743320124b [openpgpkey] 0E83208839AE031B
        >   9e5e03d8db9b7608 [material]
        >   e212414702856dc3 [openpgpkey] A1641E773F0379EF
        >   6106d3a0f001b744 [material]
        >   822dde0d82151610 [openpgpkey] C42B14885269CBCE
        >   c302979369fb66fc [material]
        >   ce990e6dd5f5714e [openpgpkey] C832AA780A48050C
        >   7ce3b56073b34949 [material]
        >   46db065337827222 [openpgpkey] 16C069B4992CFE6C
        >   828268cca79c8738 [material]
        >   133a250141d5c743 [openpgpkey] F483DFBB9B4F72EF

        $ vcrypt unlock -in dnssec.vault -out copy.key
        $ shasum -a 256 root.key copy.key
        > a178582614f747c89b88c589b6acf19f67b6734ade35d90904546fb1e722527a  root.key
        > a178582614f747c89b88c589b6acf19f67b6734ade35d90904546fb1e722527a  copy.key
