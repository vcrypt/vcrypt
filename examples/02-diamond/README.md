# Diamond Plan

A diamond shaped plan that requires the top & bottom secrets along with either
the left or right.


             [top]
               /\
              /  \
             /    \
            /      \
           /        \
        [left]    [right]
           \        /
            \      /
             \    /
              \  /
               \/
            [bottom]

# Instructions

### Step 1 - Build the diamond plan

Build & inspect `diamond.plan` from `diamond.conf`:

        $ vcrypt build -in diamond.conf -out diamond.plan
        $ vcrypt inspect -in diamond.plan
        > plan a44e625ecb6543ff925b9175ede62e4c68830cf79a2e0319b1374213735c35c5
        >
        >   Diamond shaped plan
        >
        > 51f2ecad8d51eed4 [secretbox]  step 3
        > 9a32295bc45f654e [password]   step 3 password
        > 86ea1c02972907d6 [mux]
        > 0e32a5de0a18bdf9 [secretbox]  step 2a
        > 2ed111b69c133069 [secretbox]  step 2b
        > bd271eda4d587cf8 [password]   step 2a password
        > 693cd6028bb4778b [demux]
        > 61b081b5ac295546 [password]   step 2b password
        > 6f2f3da06950f06f [secretbox]  step 1
        > 8e25c48ed0639afc [password]   step 1 password
        > 7149dc039c7e8ae0 [material]

### Step 2 - Encrypt the secret

Encrypt the contents of `secret` with `diamond.plan`:

        $ vcrypt lock -plan diamond.plan -in secret -out diamond.vault -db.dir tmp
        > password for 'step 3 password': <top>
        > password for 'step 2a password': <left>
        > password for 'step 2b password': <right>
        > password for 'step 1 password': <bottom>
        $ vcrypt inspect -in diamond.vault
        > vault 55bbbb187a2a9add159e40786dfc16be3c34893b19b316fbe262b97fa408649b
        >
        >   51f2ecad8d51eed4 [secretbox]  step 3
        >   9a32295bc45f654e [password]   step 3 password
        >   86ea1c02972907d6 [mux]
        >   0e32a5de0a18bdf9 [secretbox]  step 2a
        >   2ed111b69c133069 [secretbox]  step 2b
        >   bd271eda4d587cf8 [password]   step 2a password
        >   693cd6028bb4778b [demux]
        >   61b081b5ac295546 [password]   step 2b password
        >   6f2f3da06950f06f [secretbox]  step 1
        >   8e25c48ed0639afc [password]   step 1 password
        >   7149dc039c7e8ae0 [material]

### Step 3 - Decrypt the secret

Unlock the secret, but skip the password for 'step 2a':

        $ vcrypt unlock -in diamond.vault
        > password for 'step 1 password': <bottom>
        > password for 'step 2a password':
        > password for 'step 2b password': <right>
        > password for 'step 3 password': <top>
        > d14m0nd
