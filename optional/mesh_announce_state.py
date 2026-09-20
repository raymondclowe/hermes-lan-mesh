#!/usr/bin/env python3
"""Push this agent's work state to every live peer (prototype: work-state gossip).

Unlike mesh_heartbeat.py — which announces only until a peer has acked, because every ANNOUNCE
costs the receiving agent a full LLM turn — this is the explicit "tell everyone what I am doing"
call. Run it when the state actually changed (finished a job, went idle, took on a queue), not
blindly on every beat: the exchange is expensive on the receiving side, so it must carry news.

Usage:
  python3 mesh_announce_state.py                  # every live peer in peers.json
  python3 mesh_announce_state.py <url> [<url>...] # explicit targets
  python3 mesh_announce_state.py --dry-run        # print the text, send nothing
"""
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.request

H = pathlib.Path(os.environ.get("HERMES_HOME") or pathlib.Path.home() / ".hermes")
PEERS = H / "mesh" / "peers.json"
TOKEN = os.environ.get("MESH_TOKEN", "hermes-lan-mesh-open")


def env_token() -> str:
    f = H / ".env"
    if f.exists():
        for line in f.read_text().splitlines():
            if line.startswith("A2A_BEARER_TOKEN="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return TOKEN


def build() -> str:
    d = json.loads(PEERS.read_text(encoding="utf-8"))
    me = d.get("me", {})
    ident = json.loads((H / "mesh" / "identity.json").read_text(encoding="utf-8"))
    owns = ident.get("owns")
    owns = "; ".join(owns) if isinstance(owns, list) else (owns or "")
    ask = ident.get("ask_me_for")
    ask = "; ".join(ask) if isinstance(ask, list) else (ask or "")
    sys.path.insert(0, str(H / "scripts"))
    try:
        import mesh_state
        work = " " + mesh_state.line()
    except Exception as e:  # never let a state read break the announce
        work = ""
        print("(no work block: %s: %s)" % (type(e).__name__, e), file=sys.stderr)
    return (f"ANNOUNCE {me.get('name')} {me.get('url')}{work} "
            f"role={ident.get('role', '')} owns={owns} ask_me_for={ask}")


def send(url: str, text: str) -> tuple:
    body = json.dumps({"jsonrpc": "2.0", "id": "state-announce", "method": "SendMessage",
                       "params": {"message": {"role": "user", "messageId": "state-announce",
                                              "parts": [{"kind": "text", "text": text}]}}}).encode()
    req = urllib.request.Request(url.rstrip("/") + "/", data=body, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "Authorization": "Bearer " + env_token()})
    try:
        with urllib.request.urlopen(req, timeout=150) as r:
            reply = json.dumps(json.loads(r.read().decode() or "{}"))[:300]
        return 200, ("ACK" if re.search(r"\back\b", reply, re.I) else "reply"), reply
    except urllib.error.HTTPError as e:
        return e.code, "HTTPError", e.read().decode(errors="replace")[:200]
    except Exception as e:
        return 0, type(e).__name__, str(e)[:200]


def targets() -> list:
    d = json.loads(PEERS.read_text(encoding="utf-8"))
    me_url = (d.get("me", {}).get("url") or "").rstrip("/")
    out = []
    for name, rec in (d.get("peers") or {}).items():
        if rec.get("status") in ("renamed", "dead", "superseded"):
            continue
        url = (rec.get("url") or "").rstrip("/")
        if url and url != me_url:
            out.append(url)
    return sorted(set(out))


def main() -> int:
    text = build()
    args = [a for a in sys.argv[1:]]
    if "--dry-run" in args:
        print(text)
        return 0
    urls = [a for a in args if a.startswith("http")] or targets()
    if not urls:
        print("no targets")
        return 1
    for url in urls:
        code, kind, detail = send(url, text)
        print(f"{url}\t{code}\t{kind}\t{detail[:200]}")
    import re as _re
    m = _re.search(r"work=(\S+)", text)
    print("work block sent: " + (m.group(1) if m else "(none)"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
