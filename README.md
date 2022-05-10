# Vanity Onion Address
## What's this

Vanity address searching toy for onion v3, which is implemented in rust.

By using this toy, you can obtain tor onion v3 address such like:  
`aaaaa4y4q52uqlld3pqqtjwsejk2nd2feerakqc3aqx63sy5neud2wid.onion`  
`wwwww3bvw3dwylsh3h64wlo4527yzrbannopaxj3rl2z2iwgr7emktid.onion`  

* The performance is not optimized yet and config flexibility is poor, so you may well use [mkp224o](https://github.com/cathugger/mkp224o) or anything other than this in practice.  


## How to use

```bash
$ git clone <this repo>
$ cd <project>
$ cargo run -r -- <target string like: `aaaaa`, `wwwww`>

# output will be ↓
# address: wwwww3bvw3dwylsh3h64wlo4527yzrbannopaxj3rl2z2iwgr7emktid.onion
# commands:
# $ echo PT0gZWQyNTUxOXYxLXBXXXXXXXXXXXXXXXXXXXXXXXXXXXX | base64 -d > hs_ed25519_public_key
# $ echo PT0gZWQyNTUxOXYxLXNXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX | base64 -d > hs_ed25519_private_key

# then move to hidden_service directory, (in ubuntu default)
$ cd /var/lib/tor/hidden_service
# backup existing keys if you need.
$ cp hs_ed25519_public_key hs_ed25519_public_key_bk && cp hs_ed25519_secret_key hs_ed25519_secret_key_bk
# overwrite existing keys with new keys using commands displayed above
$ echo PT0gZWQyNTUxOXYxLXBXXXXXXXXXXXXXXXXXXXXXXXXXXXX | base64 -d > hs_ed25519_public_key
$ echo PT0gZWQyNTUxOXYxLXNXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX | base64 -d > hs_ed25519_private_key
# restart tor service and check your onion address
$ systemctl restart tor
$ cat /var/lib/tor/hidden_service/hostname
# wwwww3bvw3dwylsh3h64wlo4527yzrbannopaxj3rl2z2iwgr7emktid.onion
```

## How it works
multi-threaded bruteforce


## Contribution
is welcome. improve this. tip me.
