"""
envseal - Python binding for @boltpl/envseal vault.

Reads .envseal.vault natively (same AES-256-GCM + scrypt format as Node CLI).

Usage:
    import envseal
    envseal.load()                          # load all secrets into os.environ
    envseal.load(passphrase="mypass")       # explicit passphrase
    envseal.load(key_file="path/to.key")    # keyfile mode

    secrets = envseal.get_all()             # get as dict without touching env
    val = envseal.get("DB_PASSWORD")        # get single secret
"""

import os
import json
import base64
import hashlib
import getpass
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

VAULT_FILE = ".envseal.vault"
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32


def _find_vault(start: str = None) -> str:
    """Walk up from cwd to find .envseal.vault."""
    d = Path(start or os.getcwd())
    while True:
        candidate = d / VAULT_FILE
        if candidate.exists():
            return str(candidate)
        parent = d.parent
        if parent == d:
            raise FileNotFoundError(f"no {VAULT_FILE} found")
        d = parent


def _read_vault(vault_path: str) -> dict:
    with open(vault_path) as f:
        vault = json.load(f)
    if vault.get("version", 1) < 2:
        vault["version"] = 2
        vault["keyMode"] = "passphrase"
    if vault["version"] != 2:
        raise ValueError(f"unsupported vault version: {vault['version']}")
    return vault


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=KEY_LEN,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        backend=default_backend(),
    )
    return kdf.derive(passphrase.encode())


def _resolve_key(vault: dict, passphrase: str = None, key_buf: bytes = None) -> bytes:
    if vault["keyMode"] == "keyfile":
        if not key_buf:
            raise ValueError("keyfile mode but no key provided")
        return key_buf
    if not passphrase:
        raise ValueError("passphrase required")
    salt = base64.b64decode(vault["salt"])
    return _derive_key(passphrase, salt)


def _decrypt(enc: dict, key: bytes) -> str:
    iv = base64.b64decode(enc["iv"])
    data = base64.b64decode(enc["data"])
    tag = base64.b64decode(enc["tag"])
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, data + tag, None)
    return plaintext.decode()


def _get_credentials(vault: dict, passphrase: str = None, key_file: str = None) -> bytes:
    """Resolve decryption key from args, env, keyfile, or prompt."""
    # Explicit key file
    if key_file:
        raw = Path(key_file).read_text().strip()
        return base64.b64decode(raw)

    # ENVSEAL_KEY env (raw base64)
    env_key = os.environ.get("ENVSEAL_KEY")
    if env_key:
        return base64.b64decode(env_key)

    # ENVSEAL_KEY_FILE env
    env_key_file = os.environ.get("ENVSEAL_KEY_FILE")
    if env_key_file:
        raw = Path(env_key_file).read_text().strip()
        return base64.b64decode(raw)

    # Auto key: ~/.envseal/keys/<project>.key
    project = Path.cwd().name
    auto_key = Path.home() / ".envseal" / "keys" / f"{project}.key"
    if auto_key.exists():
        raw = auto_key.read_text().strip()
        return base64.b64decode(raw)

    # Keyfile mode requires a key
    if vault["keyMode"] == "keyfile":
        raise ValueError("keyfile mode but no key found (set ENVSEAL_KEY or ENVSEAL_KEY_FILE)")

    # Passphrase mode
    if passphrase:
        return _resolve_key(vault, passphrase=passphrase)

    # ENVSEAL_PASSPHRASE env
    env_pass = os.environ.get("ENVSEAL_PASSPHRASE")
    if env_pass:
        return _resolve_key(vault, passphrase=env_pass)

    # Interactive prompt
    pp = getpass.getpass("envseal passphrase: ")
    return _resolve_key(vault, passphrase=pp)


def get_all(
    vault_path: str = None,
    passphrase: str = None,
    key_file: str = None,
) -> dict:
    """Decrypt all secrets from vault. Returns dict."""
    vp = vault_path or _find_vault()
    vault = _read_vault(vp)
    key = _get_credentials(vault, passphrase, key_file)
    result = {}
    for name, enc in vault.get("secrets", {}).items():
        result[name] = _decrypt(enc, key)
    return result


def get(
    name: str,
    vault_path: str = None,
    passphrase: str = None,
    key_file: str = None,
) -> str:
    """Decrypt a single secret."""
    vp = vault_path or _find_vault()
    vault = _read_vault(vp)
    enc = vault.get("secrets", {}).get(name)
    if not enc:
        raise KeyError(f"secret not found: {name}")
    key = _get_credentials(vault, passphrase, key_file)
    return _decrypt(enc, key)


def load(
    vault_path: str = None,
    passphrase: str = None,
    key_file: str = None,
    override: bool = True,
) -> dict:
    """Load all secrets into os.environ.

    Args:
        vault_path: Path to .envseal.vault (auto-detected if None)
        passphrase: Explicit passphrase
        key_file: Path to key file
        override: If True, override existing env vars

    Returns:
        Dict of loaded secrets.
    """
    secrets = get_all(vault_path, passphrase, key_file)
    for k, v in secrets.items():
        if override or k not in os.environ:
            os.environ[k] = v
    return secrets
