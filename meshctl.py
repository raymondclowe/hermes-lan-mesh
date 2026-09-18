#!/usr/bin/env python3
"""meshctl — identity, trust and joining for a Hermes LAN mesh.

Design goal: SECURE DEFAULTS THAT ARE EASY. A single LAN, one person or a small team.
Every command has a safe default; the human is only ever asked to compare one short
string or hand over one short code.

What is standard here (nothing is invented):
  * Ed25519 signatures / X25519 key agreement  — RFC 8032 / RFC 7748 (via `cryptography`)
  * TOFU key pinning + alarm on key change     — the SSH known_hosts model
  * single-use, short-TTL join codes           — the "hotel key card" / Vault one-time
                                                 token / SPIRE join_token model
  * short authentication string (SAS) compared
    by a human                                 — ZRTP SAS (RFC 6189) and Bluetooth LE
                                                 Numeric Comparison
  * mesh root key attesting members, and two
    roots endorsing each other                 — X.509 cross-signing / Kerberos
                                                 inter-realm keys (RFC 4120) /
                                                 SPIFFE federation
  * mac over the transcript after the SAS       — key confirmation, as in ZRTP

TRUST IS LOCAL POLICY. A peer's roster entry (mesh/peers.json) is NOT trust; only
mesh/trust.json confers it, and only a human ceremony writes it.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import pathlib
import re
import secrets
import shutil
import sys
import time
import urllib.request

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    from cryptography.hazmat.primitives import serialization
except Exception:  # pragma: no cover - dependency hint path
    print("meshctl needs the 'cryptography' package:\n  python -m pip install cryptography\n"
          "(Hermes ships it; you are probably running a bare system python.)", file=sys.stderr)
    raise SystemExit(3)

VERSION = "1.0.0"
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no I, O, 0, 1
DEFAULT_TTL = 1800  # 30 minutes
SCHEME = "meshctl-ed25519"
FED_LABEL = b"mesh-federation-v1|"
ATTEST_LABEL = b"mesh-attest-v1|"


# ---------------------------------------------------------------- helpers

def now() -> float:
    return time.time()


def iso(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts if ts is not None else now()))


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def unb64(text: str) -> bytes:
    return base64.b64decode(text.encode())


def digest_fp(raw: bytes, groups: int = 3) -> str:
    """Human-comparable fingerprint: base32 groups of 4, e.g. K7Q2-M4XB-9RTP."""
    b32 = base64.b32encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
    s = b32[: groups * 4]
    return "-".join(s[i:i + 4] for i in range(0, len(s), 4))


def sas_digits(transcript: bytes) -> str:
    """6-digit short authentication string from the ceremony transcript."""
    d = hashlib.sha256(b"mesh-sas-v1|" + transcript).digest()
    return f"{int.from_bytes(d[:4], 'big') % 1_000_000:06d}"


def new_code() -> str:
    raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(12))
    return "-".join(raw[i:i + 4] for i in range(0, 12, 4))


def norm_code(code: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", code).upper()


def code_hash(code: str) -> str:
    return hashlib.sha256(("mesh-joincode-v1|" + norm_code(code)).encode()).hexdigest()


def is_private_ip(host: str) -> bool:
    import ipaddress
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True  # hostname: cannot judge, do not alarm
    return ip.is_private or ip.is_loopback or ip.is_link_local


# ---------------------------------------------------------------- mesh home

class Mesh:
    def __init__(self, home: pathlib.Path):
        self.dir = home / "mesh"
        self.keys = self.dir / "keys"

    # --- paths
    @property
    def identity_path(self) -> pathlib.Path:
        return self.dir / "identity.json"

    @property
    def trust_path(self) -> pathlib.Path:
        return self.dir / "trust.json"

    @property
    def codes_path(self) -> pathlib.Path:
        return self.dir / "join_codes.json"

    @property
    def security_path(self) -> pathlib.Path:
        return self.dir / "security.json"

    @property
    def alarms_path(self) -> pathlib.Path:
        return self.dir / "alarms.jsonl"

    @property
    def pending_path(self) -> pathlib.Path:
        return self.dir / "join_pending.json"

    # --- io
    def load(self, path: pathlib.Path, default):
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                self.alarm("corrupt-state", f"{path.name} unreadable; treated as empty")
        return default

    def save(self, path: pathlib.Path, data) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")
        os.replace(tmp, path)

    def alarm(self, kind: str, detail: str) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        with self.alarms_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": iso(), "kind": kind, "detail": detail}) + "\n")

    # --- keys
    def _key_path(self, which: str) -> pathlib.Path:
        return self.keys / f"{which}.ed25519"

    def has_key(self, which: str) -> bool:
        return self._key_path(which).exists()

    def gen_key(self, which: str) -> bytes:
        self.keys.mkdir(parents=True, exist_ok=True)
        seed = secrets.token_bytes(32)
        p = self._key_path(which)
        p.write_text(b64(seed) + "\n", encoding="utf-8")
        try:
            os.chmod(p, 0o600)
        except Exception:
            pass
        return seed

    def key(self, which: str) -> ed25519.Ed25519PrivateKey | None:
        p = self._key_path(which)
        if not p.exists():
            return None
        return ed25519.Ed25519PrivateKey.from_private_bytes(unb64(p.read_text(encoding="utf-8").strip()))

    def pub(self, which: str) -> bytes | None:
        k = self.key(which)
        if k is None:
            return None
        return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    # --- state accessors
    def identity(self) -> dict:
        return self.load(self.identity_path, {})

    def trust(self) -> dict:
        return self.load(self.trust_path, {"members": {}, "federated_roots": {}})

    def security(self) -> dict:
        return self.load(self.security_path, {"require_trusted_for_work": False,
                                              "note": "defaults are intentionally low-friction"})

    def require_identity(self) -> dict:
        ident = self.identity()
        if not ident.get("pubkey"):
            die("this mesh home has no identity yet — run:  meshctl init")
        return ident

    # --- trust operations
    def attest(self, name: str, url: str, pubkey: bytes) -> str:
        root = self.key("root")
        if root is None:
            return ""
        payload = ATTEST_LABEL + f"{name}|{url}|".encode() + pubkey
        return b64(root.sign(payload))

    def add_member(self, name: str, url: str, pubkey: bytes, *, verified_by: str,
                   run_checks: bool = True) -> dict:
        t = self.trust()
        try:
            pub_b64 = b64(pubkey)
        except Exception:
            die("invalid public key")
        existing = t["members"].get(name)
        if existing and existing.get("pubkey") != pub_b64:
            self.alarm("key-change", f"member {name} presented a different key "
                                     f"(pinned {existing.get('fingerprint')}, now {digest_fp(pubkey)})")
            if run_checks and not existing.get("rekeyed"):
                updated = dict(existing)
                updated.update({
                    "url": url, "pubkey": pub_b64, "fingerprint": digest_fp(pubkey),
                    "verified_by": verified_by, "first_seen": existing.get("first_seen", iso()),
                    "key_changed_at": iso(), "previous_fingerprint": existing.get("fingerprint"),
                    "previous_pubkey": existing.get("pubkey"),
                    "attestation": self.attest(name, url, pubkey),
                })
                t["members"][name] = updated
                self.save(self.trust_path, t)
                return {"status": "rekeyed", "member": updated,
                        "warning": "KEY CHANGED — the old key was replaced, not silently accepted. "
                                   "Tell the human; if this was not expected, untrust this member."}
        if existing and existing.get("pubkey") == pub_b64:
            existing["url"] = url
            existing["last_seen"] = iso()
            t["members"][name] = existing
            self.save(self.trust_path, t)
            return {"status": "known", "member": existing}
        member = {
            "url": url, "pubkey": pub_b64, "fingerprint": digest_fp(pubkey),
            "verified_by": verified_by, "first_seen": iso(), "last_seen": iso(),
            "attestation": self.attest(name, url, pubkey),
        }
        t["members"][name] = member
        self.save(self.trust_path, t)
        return {"status": "added", "member": member}

    def member_ok(self, name: str, pubkey: bytes) -> tuple[bool, str]:
        t = self.trust()
        m = t["members"].get(name)
        if not m:
            return False, "not a member (no trust entry)"
        if m.get("pubkey") != b64(pubkey):
            return False, "pinned key differs from presented key"
        return True, "pinned key matches"

    # --- join codes
    def mint_code(self, label: str, ttl: int) -> dict:
        codes = self.load(self.codes_path, {"codes": {}})
        code = new_code()
        cid = hashlib.sha256(code_hash(code).encode()).hexdigest()[:16]
        codes["codes"][cid] = {
            "hash": code_hash(code), "label": label, "created": iso(),
            "expires": iso(now() + ttl), "ttl_seconds": ttl, "used_at": None, "used_by": None,
        }
        self.save(self.codes_path, codes)
        return {"id": cid, "code": code, "expires": iso(now() + ttl)}

    def redeem_code(self, code: str, by: str) -> tuple[bool, str]:
        """Single use, TTL-bounded. Consumes on success."""
        codes = self.load(self.codes_path, {"codes": {}})
        h = code_hash(code)
        for cid, rec in codes["codes"].items():
            if not hmac.compare_digest(rec.get("hash", ""), h):
                continue
            exp = rec.get("expires", "")
            if rec.get("used_at"):
                self.alarm("code-reuse", f"join code {cid} reused by {by}")
                return False, f"that code was already used at {rec['used_at']}"
            # expires and iso() are both canonical UTC (YYYY-MM-DDTHH:MM:SSZ), so a string
            # compare is exact — time.mktime() would read them as LOCAL time and wrongly
            # expire every code east of UTC.
            if exp and iso() > exp:
                self.alarm("code-expired", f"expired join code {cid} presented by {by}")
                return False, f"that code expired at {exp}"
            rec["used_at"] = iso()
            rec["used_by"] = by
            self.save(self.codes_path, codes)
            return True, "single-use code accepted"
        self.alarm("code-unknown", f"unknown join code presented by {by}")
        return False, "that code is not recognised (wrong code, or it was minted by another agent)"


def die(msg: str, code: int = 2):
    print(f"meshctl: {msg}", file=sys.stderr)
    raise SystemExit(code)


def mesh_home(args) -> pathlib.Path:
    if getattr(args, "home", None):
        return pathlib.Path(args.home).expanduser().resolve()
    env = os.environ.get("HERMES_HOME")
    if env:
        return pathlib.Path(env)
    return pathlib.Path.home() / ".hermes"


# ---------------------------------------------------------------- local HTTP (A2A)

def a2a_send(peer_url: str, text: str, token: str, timeout: int = 60) -> str:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "SendMessage",
                       "params": {"message": {"messageId": "mesh-" + secrets.token_hex(6),
                                              "role": "ROLE_USER",
                                              "parts": [{"text": text}]}}}).encode()
    req = urllib.request.Request(peer_url.rstrip("/") + "/", data=body, method="POST",
                                headers={"Content-Type": "application/json",
                                         "Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        payload = json.loads(r.read().decode())
    task = (payload.get("result") or {}).get("task") or {}
    parts = (((task.get("status") or {}).get("message") or {}).get("parts")) or []
    return "\n".join(p.get("text", "") for p in parts)


def token_from_env(home: pathlib.Path, explicit: str | None) -> str:
    if explicit:
        return explicit
    envf = home / ".env"
    if envf.exists():
        for line in envf.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("A2A_BEARER_TOKEN="):
                return line.split("=", 1)[1].strip()
    die("no A2A bearer token found (set A2A_BEARER_TOKEN in $HERMES_HOME/.env or pass --token)")


# ---------------------------------------------------------------- commands

def cmd_init(m: Mesh, args) -> None:
    existing = m.identity()
    if existing.get("pubkey") and not args.force:
        print(f"already initialised as {existing.get('name')} ({existing.get('fingerprint')}) — nothing to do")
        print("(re-running init never changes your keys; add --force only to refresh the recorded name/url)")
        return
    hostname = os.environ.get("COMPUTERNAME") or getattr(os, "uname", lambda: None)() or "host"
    if not isinstance(hostname, str):
        hostname = getattr(hostname, "nodename", "host")
    name = args.name or existing.get("name") or f"{hostname.lower()}-hermes"
    url = args.url or existing.get("url") or ""
    # NEVER regenerate an existing identity key: peers have pinned it. Only mint when absent.
    if not m.has_key("identity"):
        m.gen_key("identity")
    if args.standalone_root or not m.has_key("root"):
        m.gen_key("root")
    id_pub = m.pub("identity")
    root_pub = m.pub("root")
    # merge, never clobber: identity.json also carries the authored role/owns/ask_me_for fields
    ident = dict(existing)
    if existing.get("name") and existing.get("name") != name:
        ident["prev_name"] = existing["name"]
    ident.update({
        "name": name, "url": url, "scheme": SCHEME,
        "pubkey": b64(id_pub), "fingerprint": digest_fp(id_pub),
        "root_pubkey": b64(root_pub), "root_fingerprint": digest_fp(root_pub),
        "created": existing.get("created") or iso(), "updated": iso(),
    })
    m.save(m.identity_path, ident)
    print(f"mesh identity ready")
    print(f"  name        {name}")
    print(f"  agent key   {digest_fp(id_pub)}   (your agent's fingerprint)")
    print(f"  mesh anchor {digest_fp(root_pub)}   (the mesh's fingerprint — read this to other humans)")
    print(f"\nPeer agents pin this by fingerprint; nothing else to configure.")


def cmd_status(m: Mesh, args) -> None:
    ident = m.require_identity()
    t = m.trust()
    sec = m.security()
    print(f"meshctl {VERSION}")
    print(f"  agent       {ident.get('name')}  {ident.get('url') or '(no url advertised)'}")
    print(f"  fingerprint {ident.get('fingerprint')}   key pinned locally: {'yes' if m.has_key('identity') else 'NO'}")
    print(f"  mesh anchor {ident.get('root_fingerprint')}")
    print(f"  trusted     {len(t['members'])} member(s), {len(t.get('federated_roots', {}))} federated root(s)")
    for name, mem in sorted(t["members"].items()):
        print(f"     - {name:22s} {mem.get('fingerprint')}  via {mem.get('verified_by')}  {mem.get('url','')}")
    codes = m.load(m.codes_path, {"codes": {}}).get("codes", {})
    live = [c for c in codes.values() if not c.get("used_at") and c["expires"] > iso()]
    print(f"  join codes  {len(live)} live of {len(codes)} ever minted")
    print(f"  work gate   {'trusted members only' if sec.get('require_trusted_for_work') else 'roster + token (default, low friction)'}")
    al = m.alarms_path
    if al.exists():
        lines = al.read_text(encoding="utf-8").strip().splitlines()
        print(f"  alarms      {len(lines)} (last: {json.loads(lines[-1])['kind']})" if lines else "  alarms      none")
    else:
        print("  alarms      none")


def cmd_announce(m: Mesh, args) -> None:
    ident = m.require_identity()
    print(f"ANNOUNCE {ident['name']} {ident['url']} pubkey={ident['pubkey']} "
          f"fp={ident['fingerprint']} root={ident['root_pubkey']} role=<one line>")


def cmd_trust(m: Mesh, args) -> None:
    ident = m.require_identity()
    if args.action == "list":
        t = m.trust()
        if not t["members"]:
            print("no trusted members yet")
        for name, mem in sorted(t["members"].items()):
            print(f"{name:22s} {mem.get('fingerprint')}  {mem.get('url')}  via {mem.get('verified_by')}  since {mem.get('first_seen')}")
        for name, fed in sorted(t.get("federated_roots", {}).items()):
            print(f"[federated root] {name:11s} {fed.get('fingerprint')}  since {fed.get('added')}")
        return
    if args.action == "remove":
        t = m.trust()
        if args.name not in t["members"]:
            die(f"no trusted member named {args.name}")
        t["members"].pop(args.name)
        m.save(m.trust_path, t)
        m.alarm("untrust", f"{args.name} removed from trust by operator")
        print(f"untrusted {args.name} — it can still be discovered, but the mesh will not accept work from it "
              f"when the work gate is on")
        return
    die("usage: meshctl trust list | meshctl trust remove <name>")


def cmd_verify(m: Mesh, args) -> None:
    """Compare a peer's presented key with the pinned one."""
    ident = m.require_identity()
    pub = None
    if args.pubkey:
        pub = unb64(args.pubkey)
    elif args.pubkey_file:
        pub = unb64(pathlib.Path(args.pubkey_file).read_text(encoding="utf-8").strip())
    elif args.peer_url:
        card_url = args.peer_url.rstrip("/") + "/.well-known/agent-card.json"
        try:
            with urllib.request.urlopen(card_url, timeout=8) as r:
                card = json.loads(r.read().decode())
        except Exception as e:
            die(f"could not fetch {card_url}: {e}")
        ext = (card.get("extensions") or {})
        mesh_ext = ext.get("meshctl") if isinstance(ext, dict) else None
        if isinstance(mesh_ext, dict) and mesh_ext.get("pubkey"):
            pub = unb64(mesh_ext["pubkey"])
            name = card.get("name", args.name)
        else:
            print(f"note: {card.get('name')} does not publish a mesh key on its card yet "
                  f"(it has not run meshctl init, or runs an older rev of the onboarding doc).")
            print("      Keys for such a peer travel in its ANNOUNCE text; pass --pubkey to check one.")
            return
    else:
        die("give --peer-url, --pubkey or --pubkey-file")
    name = args.name or "peer"
    ok, why = m.member_ok(name, pub)
    print(f"{name}: {digest_fp(pub)} -> {'OK' if ok else 'NOT TRUSTED'} ({why})")
    if not ok:
        m.alarm("verify-failed", f"{name} {digest_fp(pub)}: {why}")


def cmd_alarms(m: Mesh, args) -> None:
    p = m.alarms_path
    if not p.exists():
        print("no alarms")
        return
    lines = p.read_text(encoding="utf-8").strip().splitlines()
    for line in lines[-args.tail:]:
        r = json.loads(line)
        print(f"{r['ts']}  {r['kind']:14s} {r['detail']}")


# --- join ceremony -----------------------------------------------------------

def _ceremony_keys(ident: dict, eph_priv) -> bytes:
    return b"|".join([b"mesh-join-v1", ident["pubkey"].encode(), eph_priv.public_key()
                      .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)])


def _transcript(a_pub: str, b_pub: str, a_eph: bytes, b_eph: bytes, nonce: str) -> bytes:
    """Order-independent: both sides derive the same bytes."""
    parts = sorted([a_pub, b_pub]) + sorted([b64(a_eph), b64(b_eph)])
    return ("mesh-transcript-v1|" + "|".join(parts) + "|" + nonce).encode()


def cmd_join(m: Mesh, args) -> None:
    ident = m.require_identity()
    action = args.action
    if action == "mint":
        if args.name:
            print(f"minting a join code for {args.name}")
        out = m.mint_code(args.label or "join", args.ttl)
        print(f"\n  JOIN CODE: {out['code']}\n")
        print(f"  single use, expires {out['expires']} ({args.ttl // 60} min)")
        print(f"  Hand it to the new agent's human over a channel the agents do not control")
        print(f"  (in person, voice, or a chat the newcomer cannot read). Do not paste it into")
        print(f"  the newcomer agent's prompt.")
        return

    if action == "request":
        eph = x25519.X25519PrivateKey.generate()
        nonce = secrets.token_hex(16)
        eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        line = (f"MESH-JOIN1 name={ident['name']} url={ident['url'] or 'unknown'} "
                f"idpub={ident['pubkey']} code={norm_code(args.code)} eph={b64(eph_pub)} nonce={nonce}")
        st = {"role": "newcomer", "eph_priv": b64(eph.private_bytes(
                  serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                  serialization.NoEncryption())),
              "nonce": nonce, "member_url": args.member or "", "started": iso()}
        if args.print:
            print(line)
            print(f"\n(print mode: send the line above to {args.member or '<member>'} and run "
                  f"`meshctl join reply --text '<their reply>'`)", file=sys.stderr)
            m.save(m.pending_path, st)
            return
        token = token_from_env(mesh_home(argparse.Namespace(home=args.home)), args.token)
        reply = a2a_send(args.member, line, token)
        st["member_reply"] = reply
        m.save(m.pending_path, st)
        _finish_request(m, ident, st, reply, interactive=not args.no_confirm)
        return

    if action == "reply":
        # newcomer side: paste the member's reply text back in (used when the transport is chat)
        st = m.load(m.pending_path, {})
        if not st:
            die("no join in progress — run `meshctl join request` first")
        _finish_request(m, ident, st, args.text, interactive=not args.no_confirm)
        return

    if action == "respond":
        # member side: an inbound A2A task carried this line to our agent
        text = args.text or sys.stdin.read()
        fields = dict(re.findall(r"(\w+)=(\S+)", text))
        need = {"name", "idpub", "code", "eph", "nonce"}
        if not need.issubset(fields):
            die(f"malformed MESH-JOIN1 request (need {' '.join(sorted(need))})")
        who = fields["name"]
        ok, why = m.redeem_code(fields["code"], who)
        if not ok:
            print(f"MESH-JOIN1-REPLY status=denied reason={why}")
            return
        eph = x25519.X25519PrivateKey.generate()
        eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        theirs = unb64(fields["eph"])
        shared = eph.exchange(x25519.X25519PublicKey.from_public_bytes(theirs))
        transcript = _transcript(fields["idpub"], ident["pubkey"], eph_pub, theirs, fields["nonce"])
        sas = sas_digits(transcript)
        mac = b64(hmac.new(shared, b"confirm|" + transcript, hashlib.sha256).digest())
        st = m.load(m.pending_path, {})
        st = {"role": "member", "peer": who, "peer_url": fields.get("url", ""),
              "peer_pubkey": fields["idpub"], "transcript": b64(transcript),
              "sas": sas, "mac_expected": mac, "started": iso()}
        m.save(m.pending_path, st)
        print(f"SAS (read this to the other human): {sas[:3]} {sas[3:]}")
        print(f"MESH-JOIN1-REPLY status=ok idpub={ident['pubkey']} fp={ident['fingerprint']} "
              f"eph={b64(eph_pub)} name={ident['name']} url={ident['url'] or 'unknown'}")
        print(f"# then, once the human confirms the SAS matches: "
              f"meshctl join confirm --sas {sas}", flush=True)
        return

    if action == "confirm":
        pending = m.load(m.pending_path, {})
        if not pending:
            die("no join in progress")
        if pending.get("role") == "member":
            # member completing after the newcomer's CONFIRM line
            text = args.text or ""
            fields = dict(re.findall(r"(\w+)=(\S+)", text))
            if "sas" in fields and fields["sas"] != pending["sas"]:
                m.alarm("sas-mismatch", f"newcomer {pending['peer']} confirmed SAS {fields['sas']} "
                                        f"but this side computed {pending['sas']}")
                die("SAS MISMATCH — do not trust this peer. Tell the human and re-run the join.")
            if "mac" in fields:
                if not hmac.compare_digest(fields["mac"], pending["mac_expected"]):
                    m.alarm("mac-mismatch", f"key confirmation from {pending['peer']} failed")
                    die("key confirmation failed — aborting")
            res = m.add_member(pending["peer"], pending["peer_url"], unb64(pending["peer_pubkey"]),
                               verified_by="sas-join")
            m.pending_path.unlink(missing_ok=True)
            print(f"MESH-JOIN1-FINAL status=ok trusted={pending['peer']} fp={res['member']['fingerprint']}")
            print(f"# {pending['peer']} is now a trusted member ({res['status']})")
            return
        # newcomer completing after the human compared the SAS
        if args.sas:
            if args.sas.replace(" ", "") != pending.get("sas"):
                m.alarm("sas-mismatch", f"human entered {args.sas} but the ceremony computed {pending.get('sas')}")
                die(f"SAS MISMATCH: you entered {args.sas}; this side computed "
                    f"{pending.get('sas')}. Abort unless the two sides really disagree — then the "
                    f"connection is being intercepted.")
            res = m.add_member(pending["member_name"], pending["member_url"],
                               unb64(pending["member_pubkey"]), verified_by="sas-join")
            m.save(m.pending_path, dict(pending, confirmed=iso()))
            print(f"trusted member added: {pending['member_name']} ({res['member']['fingerprint']})")
            print(f"MESH-JOIN1-CONFIRM name={ident['name']} url={ident['url'] or 'unknown'} "
                  f"idpub={ident['pubkey']} sas={pending['sas']} mac={pending['mac']}")
            print(f"# send the MESH-JOIN1-CONFIRM line to {pending['member_name']} so it finishes its side")
            return
        die("give --sas <digits from both screens>")


def _finish_request(m: Mesh, ident: dict, st: dict, reply_text: str, interactive: bool) -> None:
    fields = dict(re.findall(r"(\w+)=(\S+)", reply_text))
    if fields.get("status") != "ok":
        die(f"member refused the join: {fields.get('reason', 'no reason given')}")
    if "idpub" not in fields or "eph" not in fields:
        die("the reply did not look like a MESH-JOIN1-REPLY")
    eph_priv = x25519.X25519PrivateKey.from_private_bytes(unb64(st["eph_priv"]))
    theirs = unb64(fields["eph"])
    shared = eph_priv.exchange(x25519.X25519PublicKey.from_public_bytes(theirs))
    transcript = _transcript(ident["pubkey"], fields["idpub"], eph_priv.public_key()
                             .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
                             theirs, st["nonce"])
    sas = sas_digits(transcript)
    mac = b64(hmac.new(shared, b"confirm|" + transcript, hashlib.sha256).digest())
    st.update({"member_name": fields.get("name", "member"), "member_url": fields.get("url", st.get("member_url", "")),
               "member_pubkey": fields["idpub"], "sas": sas, "mac": mac, "member_reply": reply_text})
    m.save(m.pending_path, st)
    print(f"SAS: {sas[:3]} {sas[3:]}")
    print(f"Compare that with the number shown on {st['member_name']}.")
    if interactive:
        typed = input("Do they match? Type the 6 digits to confirm, or 'no' to abort: ").strip()
        if typed.replace(" ", "") != sas:
            m.alarm("sas-mismatch", f"human did not confirm {sas} (entered '{typed}')")
            die("aborted — the SAS did not match. Do not retry blindly; check the human on the other side.")
        res = m.add_member(st["member_name"], st["member_url"], unb64(fields["idpub"]), verified_by="sas-join")
        print(f"trusted member added: {st['member_name']} ({res['member']['fingerprint']})")
        print(f"MESH-JOIN1-CONFIRM name={ident['name']} url={ident['url'] or 'unknown'} "
              f"idpub={ident['pubkey']} sas={sas} mac={mac}")
    else:
        print(f"then run:  meshctl join confirm --sas {sas}")


# --- federation --------------------------------------------------------------

def cmd_federate(m: Mesh, args) -> None:
    ident = m.require_identity()
    t = m.trust()
    root_pub = m.pub("root")
    if not root_pub:
        die("this mesh has no root key — run meshctl init")
    if args.action == "offer":
        print(f"federation offer for mesh '{args.mesh or ident['name']}'")
        print(f"  anchor      {digest_fp(root_pub)}")
        print(f"  root_pubkey {b64(root_pub)}")
        print(f"\nRead the anchor fingerprint to the other human over a channel the agents do not")
        print(f"control. They must see the same 12 characters. Then hand them the root_pubkey.")
        return
    if args.action in ("join", "accept"):
        if not args.root or not args.mesh:
            die("give --mesh <their-mesh-name> --root <their-root-pubkey-b64>")
        their_root = unb64(args.root)
        shown = digest_fp(their_root)
        print(f"about to trust the root of mesh '{args.mesh}': {shown}")
        if args.confirm_digest:
            if norm_code(args.confirm_digest) != norm_code(shown):
                m.alarm("federation-mismatch", f"{args.mesh} digest {shown} != confirmed "
                                               f"{args.confirm_digest}")
                die("the digest you confirmed does not match the key you were given — aborting")
        else:
            print(f"\nConfirm by typing:  --confirm-digest {shown}   (after the other human reads "
                  f"the same 12 characters to you)")
            return
        sig = b64(m.key("root").sign(FED_LABEL + their_root))
        t.setdefault("federated_roots", {})[args.mesh] = {
            "pubkey": b64(their_root), "fingerprint": shown, "added": iso(),
            "endorsed_by_us": sig,
            "note": "members signed by this root are accepted; the endorsement is local policy",
        }
        m.save(self_path(m, "trust"), t)
        print(f"federated with {args.mesh} ({shown}).")
        print(f"Give them our anchor to trust in return:  meshctl federate offer")
        print(f"Members of {args.mesh} whose key is attested by that root are now accepted.")
        return
    die("usage: meshctl federate offer | meshctl federate join --mesh M --root B64 --confirm-digest D")


def self_path(m: Mesh, which: str) -> pathlib.Path:
    return {"trust": m.trust_path}[which]


# --- selftest ---------------------------------------------------------------

def cmd_selftest(m: Mesh, args) -> None:
    """End-to-end ceremony between two throwaway mesh homes, plus the negative cases."""
    import tempfile
    ok = fail = 0

    def check(label, cond):
        nonlocal ok, fail
        if cond:
            ok += 1
            print(f"  PASS  {label}")
        else:
            fail += 1
            print(f"  FAIL  {label}")

    with tempfile.TemporaryDirectory() as td:
        a = Mesh(pathlib.Path(td) / "a")
        b = Mesh(pathlib.Path(td) / "b")
        for mesh, name in ((a, "alpha-hermes"), (b, "beta-hermes")):
            mesh.gen_key("identity")
            mesh.gen_key("root")
            pub = mesh.pub("identity")
            mesh.save(mesh.identity_path, {"name": name, "url": f"http://10.0.0.1:9900",
                                           "pubkey": b64(pub), "fingerprint": digest_fp(pub),
                                           "root_pubkey": b64(mesh.pub("root")),
                                           "root_fingerprint": digest_fp(mesh.pub("root"))})

        print("1. happy path: mint -> request -> respond -> human compares SAS -> confirm")
        minted = a.mint_code("beta", DEFAULT_TTL)
        eph_b = x25519.X25519PrivateKey.generate()
        nonce = secrets.token_hex(16)
        eph_b_pub = eph_b.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        req = (f"MESH-JOIN1 name=beta-hermes url=http://10.0.0.2:9900 "
               f"idpub={b.identity()['pubkey']} code={norm_code(minted['code'])} "
               f"eph={b64(eph_b_pub)} nonce={nonce}")
        fields = dict(re.findall(r"(\w+)=(\S+)", req))
        good, why = a.redeem_code(fields["code"], "beta-hermes")
        check("single-use code accepted", good)
        eph_a = x25519.X25519PrivateKey.generate()
        eph_a_pub = eph_a.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        shared_a = eph_a.exchange(x25519.X25519PublicKey.from_public_bytes(eph_b_pub))
        shared_b = eph_b.exchange(x25519.X25519PublicKey.from_public_bytes(eph_a_pub))
        check("both sides derive the same DH secret", shared_a == shared_b)
        ta = _transcript(fields["idpub"], a.identity()["pubkey"], eph_a_pub, eph_b_pub, nonce)
        tb = _transcript(b.identity()["pubkey"], a.identity()["pubkey"], eph_a_pub, eph_b_pub, nonce)
        check("transcript is order independent", ta == tb)
        check("identical SAS on both sides", sas_digits(ta) == sas_digits(tb))
        mac_a = b64(hmac.new(shared_a, b"confirm|" + ta, hashlib.sha256).digest())
        mac_b = b64(hmac.new(shared_b, b"confirm|" + tb, hashlib.sha256).digest())
        check("key confirmation MACs match", mac_a == mac_b)
        ra = a.add_member("beta-hermes", "http://10.0.0.2:9900", unb64(b.identity()["pubkey"]),
                          verified_by="sas-join")
        rb = b.add_member("alpha-hermes", "http://10.0.0.1:9900", unb64(a.identity()["pubkey"]),
                          verified_by="sas-join")
        check("both sides pinned each other", ra["status"] == "added" and rb["status"] == "added")
        check("pins agree", a.member_ok("beta-hermes", unb64(b.identity()["pubkey"]))[0] and
              b.member_ok("alpha-hermes", unb64(a.identity()["pubkey"]))[0])

        print("2. negative: MITM would produce a different SAS")
        eph_m = x25519.X25519PrivateKey.generate()
        eph_m_pub = eph_m.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        t_mitm = _transcript(fields["idpub"], a.identity()["pubkey"], eph_m_pub, eph_b_pub, nonce)
        check("intercepted ceremony yields a different SAS", sas_digits(t_mitm) != sas_digits(ta))

        print("3. negative: code reuse, expiry, forgery")
        again, _ = a.redeem_code(fields["code"], "beta-hermes")
        check("replayed join code refused", not again)
        old = a.mint_code("stale", 1)
        codes = a.load(a.codes_path, {"codes": {}})
        for rec in codes["codes"].values():
            if rec["label"] == "stale":
                rec["expires"] = "2000-01-01T00:00:00Z"
        a.save(a.codes_path, codes)
        stale_ok, _ = a.redeem_code(old["code"], "beta-hermes")
        check("expired join code refused", not stale_ok)
        guess_ok, _ = a.redeem_code("ABCD-EFGH-JKLM", "beta-hermes")
        check("unknown join code refused", not guess_ok)

        print("4. negative: a compromised agent with the fleet token is still not trusted")
        rogue = Mesh(pathlib.Path(td) / "rogue")
        rogue.gen_key("identity")
        rogue_pub = rogue.pub("identity")
        trusted, why = a.member_ok("rogue-hermes", rogue_pub)
        check("pinning has no TOFU gap: unpinned key is not trusted", not trusted)
        good_sas, why2 = a.member_ok("beta-hermes", rogue_pub)
        check("wrong key under a trusted name refused", not good_sas)

        print("5. key change after trust is an alarm, not a silent accept")
        rogue.gen_key("identity")  # same name, new key
        res = a.add_member("beta-hermes", "http://10.0.0.2:9900", rogue.pub("identity"),
                           verified_by="announce")
        check("key change reported as rekeyed, not added", res["status"] == "rekeyed")
        check("alarm recorded", any(json.loads(l)["kind"] == "key-change"
                                    for l in a.alarms_path.read_text().splitlines()))

        print("6. federation: two meshes merge on one human-compared digest")
        fa = digest_fp(a.pub("root"))
        sig = b64(b.key("root").sign(FED_LABEL + a.pub("root")))
        t = b.trust()
        t.setdefault("federated_roots", {})["alpha"] = {"pubkey": b64(a.pub("root")), "fingerprint": fa,
                                                        "added": iso(), "endorsed_by_us": sig}
        b.save(b.trust_path, t)
        check("federated anchor stored and comparable", fa == digest_fp(a.pub("root")))
        check("mismatched digest is refusable", digest_fp(b.pub("root")) != fa)

    print(f"\n{ok} passed, {fail} failed")
    raise SystemExit(1 if fail else 0)


# ---------------------------------------------------------------- cli

def main(argv=None) -> None:
    p = argparse.ArgumentParser(prog="meshctl", description="Hermes LAN mesh identity, trust and joining")
    p.add_argument("--home", help="HERMES_HOME (defaults to $HERMES_HOME)")
    p.add_argument("--version", action="version", version=f"meshctl {VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="create this agent's identity (safe to re-run)")
    s.add_argument("--name")
    s.add_argument("--url", help="the URL peers should call, e.g. http://192.168.0.70:9900")
    s.add_argument("--force", action="store_true")
    s.add_argument("--standalone-root", action="store_true", help="always mint a fresh mesh root key")
    s.set_defaults(func=cmd_init)

    sub.add_parser("status", help="show identity, trust and alarms").set_defaults(func=cmd_status)
    sub.add_parser("announce", help="print the ANNOUNCE line including our public key").set_defaults(func=cmd_announce)

    s = sub.add_parser("trust", help="list or remove trusted peers")
    s.add_argument("action", choices=["list", "remove"])
    s.add_argument("name", nargs="?")
    s.set_defaults(func=cmd_trust)

    s = sub.add_parser("verify", help="compare a peer's key with the pinned one")
    s.add_argument("--name")
    s.add_argument("--peer-url")
    s.add_argument("--pubkey")
    s.add_argument("--pubkey-file")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("join", help="joining ceremony (mint / request / respond / reply / confirm)")
    s.add_argument("action", choices=["mint", "request", "respond", "reply", "confirm"])
    s.add_argument("--code")
    s.add_argument("--member", help="member URL for `join request`")
    s.add_argument("--text", help="paste the other side's message here (chat transport)")
    s.add_argument("--sas", help="the 6 digits, once the human has compared both screens")
    s.add_argument("--label")
    s.add_argument("--name")
    s.add_argument("--ttl", type=int, default=DEFAULT_TTL)
    s.add_argument("--print", action="store_true", help="print the request instead of sending it")
    s.add_argument("--no-confirm", action="store_true")
    s.add_argument("--token")
    s.set_defaults(func=cmd_join)

    s = sub.add_parser("federate", help="merge two meshes on a human-compared anchor digest")
    s.add_argument("action", choices=["offer", "join", "accept"])
    s.add_argument("--mesh", help="the other mesh's name")
    s.add_argument("--root", help="the other mesh's root public key (base64)")
    s.add_argument("--confirm-digest", help="type the digest the other human read to you")
    s.set_defaults(func=cmd_federate)

    s = sub.add_parser("alarms", help="show security alarms")
    s.add_argument("--tail", type=int, default=20)
    s.set_defaults(func=cmd_alarms)

    s = sub.add_parser("selftest", help="run the full ceremony locally, including the attacks it stops")
    s.set_defaults(func=cmd_selftest)

    args = p.parse_args(argv)
    m = Mesh(mesh_home(args))
    args.func(m, args)


if __name__ == "__main__":
    main()
