#!/usr/bin/env python3
"""
SSHTP - Secure SSH Trust Pass

A lightweight OpenSSH wrapper that provides:
- Encrypted SSH password vault (AES-256-GCM)
- Master passphrase unlock
- Optional pepper via environment variable SSHTP_PEPPER (unset by default)
- Host key pinning (TOFU + strict verification) with multi-key support
- Fast one-shot command execution (--cmd)
- Stable interactive sessions (uses sshpass -e when password auth is required)
- Prefer SSH key for interactive mode; fallback to password
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import stat
import subprocess
import sys
import time
from shutil import which
from typing import Dict, Optional, Tuple


from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


APP_DIR = os.path.expanduser("~/.sshtp")
VAULT_PATH = os.path.join(APP_DIR, "vault.json")

KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12


def exit_with(message: str, code: int = 1) -> None:
    if message:
        print(message)
    raise SystemExit(code)


def require_command(name: str) -> None:
    if which(name) is None:
        exit_with(f"Missing dependency: {name}", 10)


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8")


def b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text.encode("utf-8"))


def ensure_app_dir() -> None:
    os.makedirs(APP_DIR, exist_ok=True)
    try:
        os.chmod(APP_DIR, 0o700)
    except Exception:
        pass


def load_vault() -> Dict:
    ensure_app_dir()
    if not os.path.exists(VAULT_PATH):
        return {"version": 4, "created_at": int(time.time()), "entries": {}, "hostkeys": {}}
    with open(VAULT_PATH, "r", encoding="utf-8") as f:
        vault = json.load(f)
    vault.setdefault("version", 4)
    vault.setdefault("created_at", int(time.time()))
    vault.setdefault("entries", {})
    vault.setdefault("hostkeys", {})
    return vault


def save_vault(vault: Dict) -> None:
    ensure_app_dir()
    tmp = VAULT_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(vault, f, indent=2, sort_keys=True)
    os.replace(tmp, VAULT_PATH)
    try:
        os.chmod(VAULT_PATH, 0o600)
    except Exception:
        pass


def prompt_master_passphrase(confirm: bool = False) -> str:
    p1 = getpass.getpass("Master passphrase: ")
    if not p1:
        exit_with("Empty master passphrase is not allowed.", 1)
    if confirm:
        p2 = getpass.getpass("Confirm passphrase: ")
        if p1 != p2:
            exit_with("Passphrase mismatch.", 1)
    return p1


def scrypt_params() -> Dict[str, int]:
    n = int(os.environ.get("SSHTP_SCRYPT_N", str(2**15)))
    r = int(os.environ.get("SSHTP_SCRYPT_R", "8"))
    p = int(os.environ.get("SSHTP_SCRYPT_P", "1"))

    if n < 2**14:
        n = 2**14
    if r < 1:
        r = 1
    if p < 1:
        p = 1

    return {"n": n, "r": r, "p": p}


def derive_key(master: str, salt: bytes, params: Dict[str, int]) -> bytes:
    pepper = os.environ.get("SSHTP_PEPPER", "")
    material = (master + pepper).encode("utf-8")

    kdf = Scrypt(
        salt=salt,
        length=KEY_LEN,
        n=int(params["n"]),
        r=int(params["r"]),
        p=int(params["p"]),
    )
    return kdf.derive(material)


def encrypt_secret(master: str, plaintext: str, params: Dict[str, int]) -> Tuple[bytes, bytes, bytes]:
    salt = os.urandom(SALT_LEN)
    key = derive_key(master, salt, params)
    aes = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    ciphertext = aes.encrypt(nonce, plaintext.encode("utf-8"), None)
    return salt, nonce, ciphertext


def decrypt_secret(master: str, salt: bytes, nonce: bytes, ciphertext: bytes, params: Dict[str, int]) -> str:
    key = derive_key(master, salt, params)
    aes = AESGCM(key)
    plaintext = aes.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


def decrypt_or_prompt_server_password(entry: Dict) -> str:
    master = prompt_master_passphrase(confirm=False)
    params = entry["kdf"]["params"]
    enc = entry["enc"]

    try:
        return decrypt_secret(
            master,
            b64d(enc["salt_b64"]),
            b64d(enc["nonce_b64"]),
            b64d(enc["ct_b64"]),
            params,
        )
    except Exception:
        print("Master passphrase is incorrect or vault entry is not decryptable.")
        server_pw = getpass.getpass("Server password (one-time fallback, not stored): ")
        if not server_pw:
            exit_with("Empty server password. Aborting.", 1)
        return server_pw


def host_id(host: str, port: int) -> str:
    return f"{host}:{port}"


def fingerprint_sha256_from_keybytes(key_bytes: bytes) -> str:
    digest = hashlib.sha256(key_bytes).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def ssh_keyscan_fingerprints(host: str, port: int, timeout: int) -> Dict[str, str]:
    require_command("ssh-keyscan")

    result: Dict[str, str] = {}
    for key_type in ("ed25519", "ecdsa", "rsa"):
        proc = subprocess.run(
            ["ssh-keyscan", "-T", str(timeout), "-p", str(port), "-t", key_type, host],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip() and not ln.startswith("#")]
        for line in lines:
            parts = line.split()
            if len(parts) < 3:
                continue
            seen_type = parts[1]
            key_b64 = parts[2]
            try:
                key_bytes = base64.b64decode(key_b64.encode("ascii"))
            except Exception:
                continue
            result[seen_type] = fingerprint_sha256_from_keybytes(key_bytes)

    if not result:
        exit_with("ssh-keyscan returned no host keys (ed25519/ecdsa/rsa).", 11)
    return result


def verify_or_pin_hostkeys(vault: Dict, host: str, port: int, seen_keys: Dict[str, str], accept_new: bool) -> None:
    hkdb = vault.setdefault("hostkeys", {})
    hid = host_id(host, port)

    pinned = hkdb.get(hid)
    now = int(time.time())

    if pinned is None:
        if not accept_new:
            print("Host keys are not pinned yet (first-time connect).")
            print(f"Host: {hid}")
            for kt, fp in seen_keys.items():
                print(f"Seen: {kt} {fp}")
            print("Re-run with: --accept-new")
            exit_with("", 2)

        hkdb[hid] = {"keys": dict(seen_keys), "added_at": now, "seen_at": now}
        save_vault(vault)
        print(f"Pinned host keys for {hid}: {len(seen_keys)} key(s)")
        return

    pinned_keys: Dict[str, str] = pinned.get("keys", {})
    if not pinned_keys:
        pinned_keys = {}

    match_found = False
    for kt, fp in seen_keys.items():
        if pinned_keys.get(kt) == fp:
            match_found = True
            break

    if not match_found:
        print("Host key mismatch. Possible MITM or server key changed.")
        print(f"Host: {hid}")
        print("Pinned keys:")
        for kt, fp in pinned_keys.items():
            print(f"  {kt} {fp}")
        print("Seen keys:")
        for kt, fp in seen_keys.items():
            print(f"  {kt} {fp}")
        exit_with("", 3)

    pinned["seen_at"] = now
    hkdb[hid] = pinned
    save_vault(vault)


def key_candidates() -> Tuple[str, ...]:
    return ("~/.ssh/id_ed25519", "~/.ssh/id_ed25519_sk", "~/.ssh/id_rsa")


def find_ssh_key() -> Optional[str]:
    for p in key_candidates():
        fp = os.path.expanduser(p)
        if os.path.exists(fp) and os.path.isfile(fp):
            return fp
    return None


def ssh_base_args(host: str, port: int, user: str, timeout: int) -> list[str]:
    return [
        "ssh",
        "-tt",
        "-p",
        str(port),
        "-o",
        "RequestTTY=force",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        f"ConnectTimeout={timeout}",
        "-o",
        "BatchMode=no",
        "-o",
        "NumberOfPasswordPrompts=1",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "ServerAliveInterval=30",
        "-o",
        "ServerAliveCountMax=3",
        "-o",
        "LogLevel=ERROR",
        f"{user}@{host}",
    ]


def run_ssh_with_key(host: str, port: int, user: str, timeout: int, key_path: str, cmd: Optional[str]) -> int:
    base = ssh_base_args(host, port, user, timeout)
    base = base[:-1] + [
        "-i",
        key_path,
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "PubkeyAuthentication=yes",
        base[-1],
    ]
    if cmd:
        base += ["--", cmd]
        return subprocess.run(base).returncode
    return subprocess.call(base)


def run_ssh_password_cmd(host: str, port: int, user: str, timeout: int, password: str, cmd: str) -> int:
    require_command("sshpass")
    base = ssh_base_args(host, port, user, timeout)
    base = base[:-1] + [
        "-o",
        "PreferredAuthentications=password",
        "-o",
        "PubkeyAuthentication=no",
        base[-1],
    ]
    base += ["--", cmd]
    proc = subprocess.run(["sshpass", "-d", "0"] + base, input=password + "\n", text=True)
    return proc.returncode


def run_ssh_password_interactive(host: str, port: int, user: str, timeout: int, password: str) -> int:
    require_command("sshpass")
    base = ssh_base_args(host, port, user, timeout)
    base = base[:-1] + [
        "-o",
        "PreferredAuthentications=password",
        "-o",
        "PubkeyAuthentication=no",
        base[-1],
    ]
    env = os.environ.copy()
    env["SSHPASS"] = password
    try:
        return subprocess.call(["sshpass", "-e"] + base, env=env)
    finally:
        env.pop("SSHPASS", None)


def format_epoch(ts: Optional[int]) -> str:
    if not ts:
        return "-"
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(ts)))
    except Exception:
        return "-"


def perm_str(path: str) -> str:
    try:
        m = os.stat(path).st_mode
        return oct(stat.S_IMODE(m))
    except Exception:
        return "unknown"


def is_perm_ok(path: str, expected: int) -> bool:
    try:
        m = os.stat(path).st_mode
        return stat.S_IMODE(m) == expected
    except Exception:
        return False


def confirm_accept_new(host: str, port: int, seen_keys: Dict[str, str], assume_yes: bool) -> None:
    if assume_yes:
        return
    print("You are about to pin host keys for a new host (TOFU).")
    print(f"Host: {host}:{port}")
    print("Keys that will be pinned:")
    for kt, fp in sorted(seen_keys.items()):
        print(f"  {kt} {fp}")
    answer = input('Type "YES" to continue: ').strip()
    if answer != "YES":
        exit_with("Aborted by user.", 1)


def cmd_init(_: argparse.Namespace) -> None:
    vault = load_vault()
    save_vault(vault)
    print(f"Vault initialized at {VAULT_PATH}")


def cmd_add(args: argparse.Namespace) -> None:
    vault = load_vault()
    if args.name in vault["entries"] and not args.force:
        exit_with(f"Entry '{args.name}' already exists. Use --force to overwrite.", 1)

    master = prompt_master_passphrase(confirm=args.confirm)
    server_pw = getpass.getpass(f"SSH password for {args.user}@{args.host}:{args.port}: ")
    if not server_pw:
        exit_with("Empty server password. Aborting.", 1)

    params = scrypt_params()
    salt, nonce, ct = encrypt_secret(master, server_pw, params)

    vault["entries"][args.name] = {
        "host": args.host,
        "user": args.user,
        "port": int(args.port),
        "created_at": int(time.time()),
        "kdf": {"name": "scrypt", "params": params},
        "enc": {"alg": "AES-256-GCM", "salt_b64": b64e(salt), "nonce_b64": b64e(nonce), "ct_b64": b64e(ct)},
        "note": args.note or "",
    }
    save_vault(vault)
    print(f"Saved entry '{args.name}' (encrypted).")


def cmd_list(_: argparse.Namespace) -> None:
    vault = load_vault()
    entries = vault.get("entries", {})
    if not entries:
        print("No entries.")
        return
    for name, e in entries.items():
        hid = host_id(e["host"], int(e.get("port", 22)))
        pinned = "pinned" if hid in vault.get("hostkeys", {}) else "not-pinned"
        print(f"{name}: {e['user']}@{e['host']}:{e.get('port', 22)} ({pinned})")


def cmd_status(_: argparse.Namespace) -> None:
    vault = load_vault()
    entries = vault.get("entries", {})
    if not entries:
        print("No entries.")
        return

    print("Alias  Target                      PinnedKeys  LastSeen              Created")
    print("-----  --------------------------  ---------  --------------------  --------------------")
    for name, e in sorted(entries.items(), key=lambda x: x[0]):
        host = e.get("host", "?")
        user = e.get("user", "?")
        port = int(e.get("port", 22))
        hid = host_id(host, port)

        hk = vault.get("hostkeys", {}).get(hid, {})
        keys = hk.get("keys", {}) if isinstance(hk, dict) else {}
        key_count = len(keys) if isinstance(keys, dict) else 0

        last_seen = format_epoch(hk.get("seen_at") if isinstance(hk, dict) else None)
        created = format_epoch(e.get("created_at"))

        target = f"{user}@{host}:{port}"
        print(f"{name:<5}  {target:<26}  {key_count:<9}  {last_seen:<20}  {created}")


def cmd_show(args: argparse.Namespace) -> None:
    vault = load_vault()
    entry = vault.get("entries", {}).get(args.name)
    if entry is None:
        exit_with(f"Entry '{args.name}' not found.", 1)

    host = entry.get("host", "?")
    user = entry.get("user", "?")
    port = int(entry.get("port", 22))
    hid = host_id(host, port)

    print(f"Alias:   {args.name}")
    print(f"Target:  {user}@{host}:{port}")
    print(f"Created: {format_epoch(entry.get('created_at'))}")
    note = entry.get("note") or ""
    print(f"Note:    {note if note else '-'}")

    kdf = entry.get("kdf", {})
    kdf_name = kdf.get("name", "?")
    kdf_params = kdf.get("params", {}) if isinstance(kdf.get("params", {}), dict) else {}
    print("KDF:")
    print(f"  Name: {kdf_name}")
    if kdf_params:
        for k in sorted(kdf_params.keys()):
            print(f"  {k}: {kdf_params[k]}")

    hk = vault.get("hostkeys", {}).get(hid)
    if not hk:
        print("Host keys: not pinned")
        return

    print("Host keys:")
    print(f"  Added:    {format_epoch(hk.get('added_at'))}")
    print(f"  LastSeen: {format_epoch(hk.get('seen_at'))}")
    keys = hk.get("keys", {})
    if isinstance(keys, dict) and keys:
        for kt, fp in sorted(keys.items()):
            print(f"  {kt} {fp}")
    else:
        print("  (no keys stored)")


def cmd_remove(args: argparse.Namespace) -> None:
    vault = load_vault()
    if args.name not in vault.get("entries", {}):
        exit_with(f"Entry '{args.name}' not found.", 1)
    del vault["entries"][args.name]
    save_vault(vault)
    print(f"Removed entry '{args.name}'")


def cmd_doctor(_: argparse.Namespace) -> None:
    print("SSHTP doctor report")
    print()

    deps = ["ssh", "sshpass", "ssh-keyscan"]
    ok = True

    print("Dependencies:")
    for d in deps:
        path = which(d)
        if path:
            print(f"  {d}: OK ({path})")
        else:
            print(f"  {d}: MISSING")
            ok = False

    print()
    print("Paths:")
    print(f"  APP_DIR:   {APP_DIR}")
    print(f"  VAULT:     {VAULT_PATH}")
    print()

    print("Permissions:")
    if os.path.isdir(APP_DIR):
        p = perm_str(APP_DIR)
        good = is_perm_ok(APP_DIR, 0o700)
        print(f"  {APP_DIR}: {p} ({'OK' if good else 'recommended 0o700'})")
        if not good:
            ok = False
    else:
        print(f"  {APP_DIR}: not found (run: python sshtp.py init)")
        ok = False

    if os.path.isfile(VAULT_PATH):
        p = perm_str(VAULT_PATH)
        good = is_perm_ok(VAULT_PATH, 0o600)
        print(f"  {VAULT_PATH}: {p} ({'OK' if good else 'recommended 0o600'})")
        if not good:
            ok = False
    else:
        print(f"  {VAULT_PATH}: not found (run: python sshtp.py init)")
        ok = False

    print()
    print("SSH keys:")
    k = find_ssh_key()
    if k:
        print(f"  Found: {k}")
    else:
        print("  No default key found in ~/.ssh (id_ed25519/id_ed25519_sk/id_rsa)")
        print("  This is fine if you use password auth, but key auth is recommended.")

    print()
    print("Environment:")
    pepper = os.environ.get("SSHTP_PEPPER", "")
    print(f"  SSHTP_PEPPER: {'SET' if pepper else 'UNSET (default)'}")

    print()
    if ok:
        print("Result: OK")
        raise SystemExit(0)
    print("Result: ISSUES FOUND")
    raise SystemExit(1)


def cmd_run(args: argparse.Namespace) -> None:
    vault = load_vault()
    entry = vault.get("entries", {}).get(args.name)
    if entry is None:
        exit_with(f"Entry '{args.name}' not found.", 1)

    host = entry["host"]
    user = entry["user"]
    port = int(entry.get("port", 22))

    seen_keys = ssh_keyscan_fingerprints(host, port, args.timeout)

    hid = host_id(host, port)
    pinned_exists = hid in vault.get("hostkeys", {})
    if args.accept_new and not pinned_exists:
        confirm_accept_new(host, port, seen_keys, assume_yes=args.yes)

    verify_or_pin_hostkeys(vault, host, port, seen_keys, accept_new=args.accept_new)

    if args.cmd:
        password = decrypt_or_prompt_server_password(entry)
        rc = run_ssh_password_cmd(host, port, user, args.timeout, password, args.cmd)
        raise SystemExit(rc)

    if args.prefer_key:
        key_path = find_ssh_key()
        if key_path:
            rc = run_ssh_with_key(host, port, user, args.timeout, key_path, cmd=None)
            if rc == 0:
                raise SystemExit(0)
            print(f"Key auth failed using {key_path}. Falling back to password.")

    password = decrypt_or_prompt_server_password(entry)
    rc = run_ssh_password_interactive(host, port, user, args.timeout, password)
    raise SystemExit(rc)


def build_parser() -> argparse.ArgumentParser:
    description = (
        "SSHTP - Secure SSH Trust Pass\n"
        "\n"
        "A lightweight OpenSSH wrapper that provides:\n"
        "  - Encrypted SSH password vault (AES-256-GCM)\n"
        "  - Master passphrase unlock\n"
        "  - Optional pepper via environment variable SSHTP_PEPPER (unset by default)\n"
        "  - Host key pinning (TOFU + strict verification) with multi-key support\n"
        "  - Fast one-shot command execution (--cmd)\n"
        "  - Stable interactive sessions (uses sshpass -e when password auth is required)\n"
        "\n"
        "Behavior:\n"
        "  - Prompts for the Master passphrase first.\n"
        "  - If decryption fails, asks for the real server password as a one-time fallback\n"
        "    (fallback password is not stored).\n"
    )

    epilog = (
        "Examples:\n"
        "  Initialize vault:\n"
        "    python sshtp.py init\n"
        "\n"
        "  Add a new connection:\n"
        "    python sshtp.py add --name kaito --host 43.133.39.234 --user ubuntu --port 22 --confirm\n"
        "\n"
        "  First connect (pin host keys):\n"
        "    python sshtp.py kaito --accept-new\n"
        "\n"
        "  Interactive connect:\n"
        "    python sshtp.py kaito\n"
        "\n"
        "  Run a command and exit:\n"
        "    python sshtp.py kaito --cmd \"uptime && whoami\"\n"
        "\n"
        "  Diagnostics:\n"
        "    python sshtp.py doctor\n"
        "\n"
        "Environment:\n"
        "  SSHTP_PEPPER      Optional extra secret for KDF input (default: unset/empty).\n"
        "  SSHTP_SCRYPT_N    Scrypt N parameter (default: 32768). Example: 65536.\n"
        "  SSHTP_SCRYPT_R    Scrypt r parameter (default: 8).\n"
        "  SSHTP_SCRYPT_P    Scrypt p parameter (default: 1).\n"
    )

    parser = argparse.ArgumentParser(
        prog="sshtp.py",
        description=description,
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subs = parser.add_subparsers(dest="action", required=False, metavar="COMMAND")

    p_init = subs.add_parser(
        "init",
        help="Initialize the vault file (~/.sshtp/vault.json).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_init.set_defaults(func=cmd_init)

    p_add = subs.add_parser(
        "add",
        help="Add or overwrite an encrypted SSH password entry in the vault.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_add.add_argument("--name", required=True, metavar="ALIAS", help="Connection alias (example: kaito).")
    p_add.add_argument("--host", required=True, metavar="HOST", help="SSH server hostname or IP address.")
    p_add.add_argument("--user", required=True, metavar="USER", help="SSH username for the connection.")
    p_add.add_argument("--port", type=int, default=22, metavar="PORT", help="SSH port number (default: 22).")
    p_add.add_argument("--note", metavar="TEXT", help="Optional note stored with the entry (no secrets).")
    p_add.add_argument("--force", action="store_true", help="Overwrite the entry if it already exists.")
    p_add.add_argument("--confirm", action="store_true", help="Require typing the master passphrase twice.")
    p_add.set_defaults(func=cmd_add)

    p_list = subs.add_parser(
        "list",
        help="List saved connection entries and pin status.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_list.set_defaults(func=cmd_list)

    p_status = subs.add_parser(
        "status",
        help="Show a compact summary (targets, pinned keys, last seen).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_status.set_defaults(func=cmd_status)

    p_show = subs.add_parser(
        "show",
        help="Show details for one entry (no secrets).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_show.add_argument("--name", required=True, metavar="ALIAS", help="Connection alias to show.")
    p_show.set_defaults(func=cmd_show)

    p_remove = subs.add_parser(
        "remove",
        help="Remove a connection entry from the vault.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_remove.add_argument("--name", required=True, metavar="ALIAS", help="Connection alias to remove.")
    p_remove.set_defaults(func=cmd_remove)

    p_doctor = subs.add_parser(
        "doctor",
        help="Check dependencies and file permissions for common issues.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_doctor.set_defaults(func=cmd_doctor)

    p_run = subs.add_parser(
        "run",
        help="Connect to a saved entry (interactive) or run a command (--cmd).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Run a saved connection.\n"
            "\n"
            "Interactive mode:\n"
            "  - Tries SSH key auth first (if --prefer-key is enabled and a key exists).\n"
            "  - If key auth fails, falls back to password auth.\n"
            "\n"
            "Command mode (--cmd):\n"
            "  - Uses password auth to execute the command and exit.\n"
        ),
    )
    p_run.add_argument("--name", required=True, metavar="ALIAS", help="Connection alias to use (example: kaito).")
    p_run.add_argument("--cmd", metavar="COMMAND", help="Remote command to run and exit (non-interactive).")
    p_run.add_argument(
        "--accept-new",
        action="store_true",
        help="TOFU pinning: allow pinning host keys if this host:port is not pinned yet.",
    )
    p_run.add_argument(
        "--yes",
        action="store_true",
        help='Non-interactive approval for --accept-new (skips "Type YES" prompt).',
    )
    p_run.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SECONDS",
        help="Network timeout in seconds for key scanning and SSH connect (default: 10).",
    )
    p_run.add_argument(
        "--prefer-key",
        action="store_true",
        default=True,
        help="Prefer SSH key authentication for interactive sessions (default: enabled).",
    )
    p_run.add_argument(
        "--no-prefer-key",
        dest="prefer_key",
        action="store_false",
        help="Disable SSH key preference and go directly to password authentication.",
    )
    p_run.add_argument(
        "--backend",
        choices=["openssh"],
        default="openssh",
        metavar="NAME",
        help="Compatibility option. Only 'openssh' is supported. This flag is ignored.",
    )
    p_run.set_defaults(func=cmd_run)

    return parser


def shortcut_mode(argv: list[str]) -> list[str]:
    reserved = {"init", "add", "list", "status", "show", "remove", "doctor", "run"}
    if len(argv) >= 2 and not argv[1].startswith("-") and argv[1] not in reserved:
        return ["run", "--name", argv[1]] + argv[2:]
    return argv[1:]


def main() -> None:
    require_command("ssh")
    require_command("ssh-keyscan")
    require_command("sshpass")

    parser = build_parser()
    args_list = shortcut_mode(sys.argv)

    if not args_list:
        parser.print_help()
        raise SystemExit(0)

    args = parser.parse_args(args_list)
    args.func(args)


if __name__ == "__main__":
    main()
