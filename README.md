# envseal

encrypt secrets at rest, inject at runtime. no plaintext on disk.

## install

```bash
npm install -g envseal
```

## usage

### passphrase mode (dev/laptop)

```bash
envseal init
envseal set DATABASE_URL "postgres://..."
envseal set STRIPE_KEY "sk_live_..."
envseal run -- node server.js    # prompts for passphrase, injects env
```

### keyfile mode (servers)

```bash
cd ~/projects/myapp
envseal keygen              # generates ~/.envseal/keys/myapp.key (auto-named after directory)
envseal init --keyfile
envseal set DATABASE_URL "postgres://..."   # auto-finds key, no config needed
envseal run -- node server.js               # just works

# in systemd unit - zero interaction
# ExecStart=envseal run -- node server.js
```

key is stored in `~/.envseal/keys/<project-dir>.key`, vault is `.envseal.vault` in project dir. separated by default.

### other commands

```bash
envseal get KEY              # decrypt single value
envseal list                 # show key names (not values)
envseal rm KEY               # remove a secret
envseal export               # decrypt all as KEY=VALUE on stdout
envseal import .env          # bulk import from .env file
envseal keygen --out PATH    # custom key location
```

## key resolution

in keyfile mode, envseal looks for the key in order:

1. `ENVSEAL_KEY` env var (base64 key directly)
2. `ENVSEAL_KEY_FILE` env var (path to key file)
3. `~/.envseal/keys/<project-dir-name>.key` (auto-resolve)

in passphrase mode, same lookup order, then falls back to interactive prompt. `ENVSEAL_PASSPHRASE` env var skips the prompt.

## how it works

secrets are encrypted with AES-256-GCM. in passphrase mode, the encryption key is derived via scrypt. in keyfile mode, the key is a random 256-bit value.

the vault (`.envseal.vault`) stores key names in plaintext, values as encrypted blobs. `envseal run` decrypts everything in memory, passes secrets as env vars to the child process, then exits. nothing plaintext touches disk.

zero dependencies - uses only node's built-in `crypto` module.

## vault format

```json
{
  "version": 2,
  "keyMode": "keyfile",
  "secrets": {
    "DATABASE_URL": { "iv": "...", "data": "...", "tag": "..." }
  }
}
```

## security model

protects secrets at rest and from automated exfiltration. scanners grepping for `.env`, `sk-`, `ghp_`, private keys find nothing.

in keyfile mode, key and vault are in different locations with different permissions. attacker needs both.

not a defense against an active attacker with same-UID shell access. they can read `/proc/<pid>/environ` or attach a debugger. no userspace tool prevents that.

## license

MIT
