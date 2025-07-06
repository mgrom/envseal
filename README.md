# envseal

encrypt secrets at rest, inject as environment variables at runtime.

## install

```
npm install -g envseal
```

## usage

```bash
envseal init                        # create .envseal.vault
envseal set DB_URL "postgres://..."  # encrypt a secret
envseal get DB_URL                   # decrypt and print
envseal list                         # show key names
envseal rm DB_URL                    # remove a secret
envseal export                       # decrypt all → KEY=VALUE on stdout
envseal import .env                  # bulk import from dotenv file
envseal run -- node server.js        # inject secrets and exec command
```

passphrase is read from `/dev/tty` so piped commands work. set `ENVSEAL_PASSPHRASE` env var to skip the prompt (useful for CI).

## how it works

secrets are encrypted with AES-256-GCM. the encryption key is derived from your passphrase using scrypt (N=2^15, r=8, p=1). each value gets its own random IV.

## vault format

`.envseal.vault` is a JSON file:

```json
{
  "version": 1,
  "salt": "base64...",
  "secrets": {
    "KEY": { "iv": "...", "data": "...", "tag": "..." }
  }
}
```

the vault is discovered by walking up from the current directory (like `.git`).

key names are plaintext. values are encrypted. salt is generated on `init`.

## security

protects secrets at rest and from automated exfiltration. not a defense against an active attacker with same-UID shell access.

## license

MIT
