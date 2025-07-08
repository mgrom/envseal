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
# generate key and store it separately
envseal keygen --out /etc/envseal/keys/myapp.key
envseal init --keyfile

# set secrets (picks up key automatically or via env)
ENVSEAL_KEY_FILE=/etc/envseal/keys/myapp.key envseal set DATABASE_URL "postgres://..."

# in systemd unit — no interaction needed
# Environment=ENVSEAL_KEY_FILE=/etc/envseal/keys/myapp.key
# ExecStart=envseal run -- node server.js
```

### other commands

```bash
envseal get KEY              # decrypt single value
envseal list                 # show key names (not values)
envseal rm KEY               # remove a secret
envseal export               # decrypt all → KEY=VALUE on stdout
envseal import .env          # bulk import from .env file
```

## key resolution

keyfile mode looks for the key in order:

1. `ENVSEAL_KEY` env var (base64 key)
2. `ENVSEAL_KEY_FILE` env var (path to key file)
3. `.envseal.key` in cwd or parent directories

passphrase mode tries the above first, then prompts interactively. you can also set `ENVSEAL_PASSPHRASE` to skip the prompt.

## how it works

secrets are encrypted with AES-256-GCM. in passphrase mode, the key is derived via scrypt. in keyfile mode, the key is a random 256-bit value stored separately from the vault.

the vault (`.envseal.vault`) stores key names in plaintext and values as encrypted blobs. `envseal run` decrypts everything in memory, passes secrets as environment variables to the child process, then exits. nothing plaintext touches disk.

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

protects secrets at rest and from automated exfiltration (scanners grepping for `.env`, `sk-`, `ghp_`, private keys). an attacker with disk access sees encrypted blobs, not plaintext.

in keyfile mode, the key and vault live in different locations with different permissions — attacker needs both.

**not** a defense against an active attacker with same-UID shell access — they can read process memory or attach a debugger. no userspace tool can prevent that.

## license

MIT
