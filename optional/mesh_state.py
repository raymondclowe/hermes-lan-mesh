"""Work-state gossip for the LAN mesh (prototype, op3).

Identity gossip answers "who is there"; this answers "who is busy, and what can they take".
The block rides on the existing ANNOUNCE line as ONE space-free field so it stays inside the
doc's `ANNOUNCE <name> <url> key=value ...` grammar and older peers simply ignore it:

    work=open:49,ready:2,wait:74,load:1.47,ts:2026-09-20T09:30:00Z

Keys (all cheap local reads, no agent turn):
  open   tasks not done/archived on this box's Kanban (the Attention board's own store)
  ready  claimable now (ready/scheduled)
  wait   parked on a human (blocked/review)
  load   1-minute load average, 2dp — the "don't send me a heavy job" signal (Unix)
  cpu    CPU busy %, Windows only — Windows has no load average, so it ships `cpu` instead and the
         two must never be compared with one threshold
  ts     UTC timestamp of the snapshot (peers must age it out, never trust it as current)

Usage:
  python3 mesh_state.py --line                      # the work= token, nothing else
  python3 mesh_state.py --json                      # same snapshot as JSON
  python3 mesh_state.py --ingest <name> "<text>"    # record a peer's block into peers.json
  python3 mesh_state.py --show                      # what we currently hold for each peer

--ingest is what the receiving agent calls on any inbound ANNOUNCE (or ACK carrying a block):
it is additive, never overwrites identity fields, and never writes trust state. A work block is
peer folklore, not authority — it must never drive a bind/token/firewall change.
"""
from __future__ import annotations

import datetime
import json
import os
import pathlib
import re
import sqlite3
import sys
import urllib.request

def _resolve_home() -> pathlib.Path:
    """Locate the Hermes home on any of the mesh's platforms. HERMES_HOME is not exported in a
    non-interactive SSH session, and on Windows the default home is %LOCALAPPDATA%\\hermes, not
    ~/.hermes — pick the first candidate that actually carries a mesh roster."""
    cands = []
    if os.environ.get("HERMES_HOME"):
        cands.append(pathlib.Path(os.environ["HERMES_HOME"]))
    cands.append(pathlib.Path.home() / ".hermes")
    if os.environ.get("LOCALAPPDATA"):
        cands.append(pathlib.Path(os.environ["LOCALAPPDATA"]) / "hermes")
    cands.append(pathlib.Path.home() / "AppData" / "Local" / "hermes")
    for c in cands:
        if (c / "mesh" / "peers.json").exists():
            return c
    return cands[0]


H = _resolve_home()
# The Kanban store that backs the Attention board lives at the Hermes ROOT, not the profile:
# $HERMES_HOME/kanban.db can exist as a 0-byte placeholder and shadow the real one, so probe
# candidates and take the first that actually carries tasks rows.
KANBAN_CANDIDATES = [H / "kanban.db", H.parent / "kanban.db",
                     pathlib.Path.home() / ".hermes" / "kanban.db"]
PEERS = H / "mesh" / "peers.json"
STALE_SECONDS = 3600  # a work block older than this is history, not state

WORK_RE = re.compile(r"\bwork=(\S+)")


def utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _kanban_rows() -> list:
    for path in KANBAN_CANDIDATES:
        try:
            if not path.exists() or path.stat().st_size == 0:
                continue
            c = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
            rows = c.execute("select status, count(*) from tasks group by 1").fetchall()
            c.close()
            if rows:
                return rows
        except Exception:
            continue
    return []


def _counts() -> dict:
    rows = _kanban_rows()
    if not rows:
        return {}
    d = {str(s): int(n) for s, n in rows}
    open_n = sum(n for s, n in d.items() if s not in ("done", "archived"))
    return {
        "open": open_n,
        "ready": d.get("ready", 0) + d.get("scheduled", 0),
        "wait": d.get("blocked", 0) + d.get("review", 0),
        "run": d.get("running", 0),
    }


def _load_metric() -> dict:
    """Busy-ness signal, named for what it actually is. `load` = 1-min load average (Unix);
    Windows has no load average, so it reports `cpu` = CPU busy % over a short sample. Consumers
    must not compare the two blindly (see --idle thresholds).

    Platform gate is deliberate: psutil exists on Windows and its getloadavg() is a STUB that
    returns 0.0 — trusting it reported every Windows box as idle, which is worse than no signal."""
    if os.name != "nt":
        try:
            return {"load": round(os.getloadavg()[0], 2)}
        except Exception:
            pass
        try:
            import psutil  # present in some venvs
            return {"load": round(psutil.getloadavg()[0], 2)}
        except Exception:
            pass
    try:  # Windows: sample kernel+user vs idle time via GetSystemTimes
        import ctypes
        import time as _t

        class _FT(ctypes.Structure):
            _fields_ = [("lo", ctypes.c_ulong), ("hi", ctypes.c_ulong)]

        def snap():
            idle, kern, user = _FT(), _FT(), _FT()
            ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kern),
                                                  ctypes.byref(user))
            v = lambda f: (f.hi << 32) | f.lo  # noqa: E731
            return v(idle), v(kern) + v(user)

        i0, t0 = snap()
        _t.sleep(0.4)  # short windows are noisy: a false 'idle' is the one error that matters here
        i1, t1 = snap()
        di, dt = i1 - i0, t1 - t0
        if dt:
            return {"cpu": round(100.0 * (dt - di) / dt, 1)}
    except Exception:
        pass
    return {}


def snapshot() -> dict:
    s = dict(_load_metric())
    s["ts"] = utcnow()
    s.update(_counts())
    return s


def line() -> str:
    return "work=" + ",".join(f"{k}:{v}" for k, v in snapshot().items())


def parse(text: str) -> dict | None:
    """Extract a work= block from any peer text. Tolerant by design: peers implement the join doc
    independently, so accept unknown keys, reject values that are not scalars."""
    m = WORK_RE.search(text or "")
    if not m:
        return None
    out = {}
    for pair in m.group(1).split(","):
        if ":" not in pair:
            continue
        k, v = pair.split(":", 1)
        k = k.strip()[:16]
        v = v.strip().strip(";.,'\"")[:40]
        if not k or not v:
            continue
        out[k] = int(v) if re.fullmatch(r"-?\d+", v) else (
            float(v) if re.fullmatch(r"-?\d+\.\d+", v) else v)
    return out or None


def _read() -> dict:
    try:
        return json.loads(PEERS.read_text(encoding="utf-8"))
    except Exception:
        return {"peers": {}}


def _write(d: dict) -> None:
    tmp = PEERS.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, indent=2) + "\n", encoding="utf-8")
    tmp.replace(PEERS)


def ingest(name: str, text: str) -> dict | None:
    blk = parse(text)
    if not blk:
        print(f"no work= block in text for {name}")
        return None
    d = _read()
    peers = d.setdefault("peers", {})
    entry = peers.setdefault(name, {"url": "", "status": "unknown"})
    entry["work"] = blk
    entry["work_seen"] = utcnow()
    entry["work_source"] = "announce"
    d["updated"] = utcnow()
    _write(d)
    print(f"recorded work for {name}: {json.dumps(blk, sort_keys=True)}")
    return blk


def show() -> None:
    d = _read()
    now = datetime.datetime.now(datetime.timezone.utc)
    for name, v in sorted((d.get("peers") or {}).items()):
        w, seen = v.get("work"), v.get("work_seen")
        age = "?"
        if seen:
            try:
                age = f"{int((now - datetime.datetime.strptime(seen, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)).total_seconds())}s"
            except Exception:
                pass
        state = "unknown"
        if isinstance(w, dict):
            state = "STALE" if age != "?" and age != "?" and age.endswith("s") and int(age[:-1]) > STALE_SECONDS else "fresh"
        print(f"{name}\t{v.get('status')}\twork={json.dumps(w, sort_keys=True) if w else '-'}\tseen={age}\t{state}")


def idle_peers(load_max: float = 1.0, cpu_max: float = 50.0) -> list:
    """Peers with a fresh block under the busy threshold — candidates to route work to. `load` is a
    Unix load average and `cpu` a Windows busy-percent, so each gets its own threshold; they are
    never compared to each other."""
    d = _read()
    out = []
    for name, v in sorted((d.get("peers") or {}).items()):
        w = v.get("work")
        if not isinstance(w, dict) or v.get("status") in ("renamed", "dead", "superseded"):
            continue
        metric = None
        if isinstance(w.get("load"), (int, float)) and float(w["load"]) <= load_max:
            metric = f"load:{w['load']}"
        elif isinstance(w.get("cpu"), (int, float)) and float(w["cpu"]) <= cpu_max:
            metric = f"cpu:{w['cpu']}"
        if metric:
            out.append((name, w.get("open"), metric, w.get("ts")))
    return out


def main() -> int:
    a = sys.argv[1:]
    if not a:
        print(line())
        return 0
    if a[0] == "--line":
        print(line())
    elif a[0] == "--json":
        print(json.dumps(snapshot(), sort_keys=True))
    elif a[0] == "--ingest":
        if len(a) < 3:
            print("usage: mesh_state.py --ingest <peer-name> \"<text>\"", file=sys.stderr)
            return 2
        return 0 if ingest(a[1], a[2]) else 1
    elif a[0] == "--show":
        show()
    elif a[0] == "--idle":
        for row in idle_peers():
            print("\t".join(str(x) for x in row))
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
