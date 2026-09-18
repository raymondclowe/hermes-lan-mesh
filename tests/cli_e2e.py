"""Drive the real meshctl CLI through a complete join ceremony in two throwaway homes.

This is the end-to-end proof: separate processes, real files, the SAS the human would read.
"""
import pathlib, re, subprocess, sys, tempfile, os

MESHCTL = r"C:/Users/raymo/hermes-lan-mesh/meshctl.py"
PY = sys.executable


def run(home, *args, stdin=None):
    cmd = [PY, MESHCTL, "--home", str(home), *args]
    r = subprocess.run(cmd, capture_output=True, text=True, input=stdin, timeout=120)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def field(text, key):
    m = re.search(rf"{key}\s*[:=]\s*(\S+)", text)
    return m.group(1) if m else None


def sas_of(text):
    m = re.search(r"SAS[^:]*:\s*(\d{3})\s+(\d{3})", text)
    return (m.group(1) + m.group(2)) if m else None


td = pathlib.Path(tempfile.mkdtemp(prefix="meshcli-"))
A = td / "member-home"
B = td / "newcomer-home"
ok = fail = 0


def check(label, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1; print(f"  PASS  {label}")
    else:
        fail += 1; print(f"  FAIL  {label} {extra}")


print("member side: init + mint")
rc, out = run(A, "init", "--name", "alpha-hermes", "--url", "http://10.0.0.1:9900")
check("member init", rc == 0, out)
fp1 = field(out, "agent key")
# init must be safe to re-run: same keys, authored fields preserved
ident_path = A / "mesh" / "identity.json"
import json as _json
_d = _json.loads(ident_path.read_text(encoding="utf-8"))
_d["role"] = "test role that must survive"; _d["owns"] = ["thing"]
ident_path.write_text(_json.dumps(_d, indent=2), encoding="utf-8")
rc, out2 = run(A, "init", "--force", "--name", "alpha-hermes", "--url", "http://10.0.0.1:9900")
_d2 = _json.loads(ident_path.read_text(encoding="utf-8"))
check("re-running init keeps the same key", field(out2, "agent key") == fp1, f"{fp1} -> {field(out2,'agent key')}")
check("authored fields survive init", _d2.get("role") == "test role that must survive" and _d2.get("owns") == ["thing"])
rc, mint = run(A, "join", "mint", "--label", "beta", "--ttl", "1800")
code = field(mint, "JOIN CODE")
check("join code minted", rc == 0 and bool(code) and code.count("-") == 2, mint)

print("newcomer side: init + request (print mode, so no transport needed)")
rc, out = run(B, "init", "--name", "beta-hermes", "--url", "http://10.0.0.2:9900")
check("newcomer init", rc == 0, out)
rc, req = run(B, "join", "request", "--code", code, "--member", "http://10.0.0.1:9900",
              "--print", "--no-confirm")
req_line = next((l for l in req.splitlines() if l.startswith("MESH-JOIN1 ")), "")
check("MESH-JOIN1 request built", rc == 0 and req_line.startswith("MESH-JOIN1 "), req)

print("member side: respond (validates the code, prints the SAS a human would read)")
rc, resp = run(A, "join", "respond", "--text", req_line)
reply_line = next((l for l in resp.splitlines() if l.startswith("MESH-JOIN1-REPLY")), "")
sas_a = sas_of(resp)
check("member accepted the code and produced a reply", rc == 0 and reply_line and sas_a, resp)

print("newcomer side: reply (computes the SAS locally)")
rc, rep = run(B, "join", "reply", "--text", reply_line, "--no-confirm")
sas_b = sas_of(rep)
check("both sides show the same SAS", bool(sas_a and sas_b) and sas_a == sas_b, f"{sas_a} vs {sas_b}")

print("human types the digits: wrong then right")
rc_bad, bad = run(B, "join", "confirm", "--sas", "000000")
check("wrong SAS refused", rc_bad != 0 and "MISMATCH" in bad, bad)
rc, conf = run(B, "join", "confirm", "--sas", sas_b.replace(" ", ""))
check("newcomer pins the member", rc == 0 and "trusted member added" in conf, conf)
confirm_line = next((l for l in conf.splitlines() if l.startswith("MESH-JOIN1-CONFIRM")), "")

print("member side: confirm (key confirmation MAC verified, code consumed)")
rc, fin = run(A, "join", "confirm", "--text", confirm_line)
check("member pins the newcomer", rc == 0 and "MESH-JOIN1-FINAL status=ok" in fin, fin)

print("verify both ends + the attacks that must still fail")
rc, ta = run(A, "trust", "list")
check("member trust list has beta-hermes", "beta-hermes" in ta, ta)
rc, tb = run(B, "trust", "list")
check("newcomer trust list has alpha-hermes", "alpha-hermes" in tb, tb)
rc, again = run(A, "join", "respond", "--text", req_line)
check("replayed code refused on the member", "status=denied" in again, again)
rc, stale = run(A, "join", "respond",
                "--text", re.sub(r"code=\S+", "code=" + "AAAA-BBBB-CCCC", req_line))
check("unknown code refused on the member", "status=denied" in stale, stale)
rc, al = run(A, "alarms")
check("alarms recorded for the refusals", "code-reuse" in al or "code-unknown" in al, al)

print("untrust works and is reversible only by a human action")
rc, un = run(A, "trust", "remove", "beta-hermes")
check("untrust succeeds", rc == 0 and "untrusted beta-hermes" in un, un)
rc, ta2 = run(A, "trust", "list")
check("beta-hermes gone from trust", "beta-hermes" not in ta2, ta2)

print(f"\n{ok} passed, {fail} failed   (homes under {td})")
sys.exit(1 if fail else 0)
