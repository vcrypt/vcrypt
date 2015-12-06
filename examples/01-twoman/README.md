# Two-Man Rule

        [secretbox "master key"] -> [secretbox "operator A key"] -> [password "operator A password"]
                                 |                               |
                                 |                               -> [material "operator A material"]
                                 |
                                 -> [secretbox "operator B key"] -> [password "operator B password"]
                                                                 |
                                                                 -> [material "operator B material"]

# Parties

* Key Operator A: holds key #1 password
* Key Operator B: holds key #2 password
* Console Operator: accesses the master key

# Instructions

### Part 1 - Lock the master key

Start by building the plan from `twoman.conf` config:

        vcrypt build -in twoman.conf -out twoman.plan

Next inspect the plan (the digests will not match):

        $ vcrypt inspect -in twoman.plan
        > plan 710f62fa3fc0bc87a621f1e07676e39efeafa4466b2f9429b85c049b9fbb74ef
        >
        >   Two-man rule plan
        >
        > 4616706815e87510 [secretbox]
        > 14e79e2ea9c2a61f [secretbox]  operator 1 key
        > 61e2a56712c9c369 [secretbox]  operator 2 key
        > 251de75c2413a92d [password]   operator A secret
        > 3cd863b3e14de857 [material]
        > 46c5d3f9dc2124d0 [password]   operator B secret
        > d9b5b171fc03f03e [material]

After verifying the plan, encrypt the master key in a vault:

        $ vcrypt lock -plan twoman.plan -in master.key -out twoman.vault
        > password for 'operator A secret': <tango niner>
        > password for 'operator B secret': <alpha zulu>

Then inspect the vault:

        $ vcrypt inspect -in twoman.vault
        > vault aab28ce6f8c94f09ec5d42fbfce1c2a8dc67120f225c84f6eec7183c4689fcdf
        >
        > S 4616706815e87510 [secretbox]
        > S 14e79e2ea9c2a61f [secretbox]  operator 1 key
        > S 61e2a56712c9c369 [secretbox]  operator 2 key
        >   251de75c2413a92d [password]   operator A secret
        >   3cd863b3e14de857 [material]
        >   46c5d3f9dc2124d0 [password]   operator B secret
        >   d9b5b171fc03f03e [material]

The `S` marks nodes that have been solved and ready for export. The vault can
be sent to the Operators.

### Part 2 - Unlock the master key

Start by unlocking key #1 as Operator A (enter nothing for 'operator B secret'):

        $ vcrypt unlock -in twoman.vault -db.dir op-A-db
        > password for 'operator A secret': <tango niner>
        > password for 'operator B secret':

Check that 'operator 1 key' is solved:

        $ vcrypt inspect -in twoman.vault -db.dir op-A-db
        > vault aab28ce6f8c94f09ec5d42fbfce1c2a8dc67120f225c84f6eec7183c4689fcdf
        >
        >   4616706815e87510 [secretbox]
        > S 14e79e2ea9c2a61f [secretbox]  operator 1 key
        >   61e2a56712c9c369 [secretbox]  operator 2 key
        >   251de75c2413a92d [password]   operator A secret
        >   3cd863b3e14de857 [material]
        >   46c5d3f9dc2124d0 [password]   operator B secret
        >   d9b5b171fc03f03e [material]

Export the 'operator 1 key' material and send it to the Console Operator (be
sure to update the id):

        vcrypt export -in twoman.vault -db.dir op-A-db -id 14e79e2ea9c2a61f -out op-A.key

Repeat for Operator B:

        $ vcrypt unlock -in twoman.vault -db.dir op-B-db
        > password for 'operator A secret':
        > password for 'operator B secret': <alpha zulu>
        $ vcrypt inspect -in twoman.vault -db.dir op-B-db
        > vault aab28ce6f8c94f09ec5d42fbfce1c2a8dc67120f225c84f6eec7183c4689fcdf
        >
        >   4616706815e87510 [secretbox]
        >   14e79e2ea9c2a61f [secretbox]  operator 1 key
        > S 61e2a56712c9c369 [secretbox]  operator 2 key
        >   251de75c2413a92d [password]   operator A secret
        >   3cd863b3e14de857 [material]
        >   46c5d3f9dc2124d0 [password]   operator B secret
        >   d9b5b171fc03f03e [material]
        $ vcrypt export -in twoman.vault -db.dir op-B-db -id 14e79e2ea9c2a61f -out op-B.key

As the Console Operator, import `op-A.key` & `op-B.key`, and unlock the vault
(skip the password prompts):

        $ vcrypt import -vault twoman.vault -in op-A.key -db.dir console-db
        $ vcrypt import -vault twoman.vault -in op-B.key -db.dir console-db
        $ vcrypt unlock -in twoman.vault -db.dir console-db
        > password for 'operator A secret':
        > password for 'operator B secret':
        > 0000
