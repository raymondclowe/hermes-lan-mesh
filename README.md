# Hermes LAN mesh — self-onboarding

The onboarding material for a local fleet of Hermes agents. It is a **repo, not a gist**, on
purpose: the URL you hand out is stable and human-readable, and the document can be updated
without handing out a new one.

## Hand this out

    https://github.com/raymondclowe/hermes-lan-mesh

That is the whole instruction to a new agent: *read this and obey*. The README is for humans;
agents should read `onboarding.txt`:

    https://raw.githubusercontent.com/raymondclowe/hermes-lan-mesh/main/onboarding.txt

**Nothing else is required to join.** No keys to mint, no codes to carry, no ceremony — read the
document, run the steps, and you are in the mesh. That simplicity is a deliberate decision, not
an oversight: see `SECURITY.md`.

## What is in here

- **`onboarding.txt`** — the canonical, agent-facing document. Steps 1–10, the fixed-token rule,
  the container rules, the recorded traps, and the report format. Plain text; the only file an
  agent needs.
- **`SECURITY.md`** — why there is no ceremony, what the boundary actually is (the firewall, and
  the token-is-not-a-secret rule), the hard rules that survive, the accepted residual risks, and
  the list of approaches considered and rejected. **Read it before proposing any security work.**
- **`optional/`** — working, unused tooling: `meshctl.py` (Ed25519 identity, key pinning, a
  human-verified join, mesh federation, alarms) plus its end-to-end test. A full trust model was
  built and then scrapped as overkill for a home LAN. It is kept because it works (17/17 and
  18/18 passing) and there is no reason to delete it — but **it is not part of onboarding, it is
  not required, and nobody should run it unless the operator asks for it by name.**

## Quickstart

Read `onboarding.txt` and follow steps 1–9. The short version for a person:

    identity   <machine-name>-hermes, fixed forever
    listener   A2A_HOST=0.0.0.0, A2A_PORT=9900, A2A_BEARER_TOKEN=hermes-lan-mesh-open
    firewall   allow TCP 9900 from your own subnet only  ← this is the actual boundary
    discovery  sweep your own subnet for port 9900, announce, keep peers.json
    heartbeat  a cron job that re-announces on change (mesh-heartbeat)

## Self-update

The document carries its own repo path and a `rev` number in the facts block at the top, so an
agent handed an old copy can refresh itself without a human relaying a new URL:

    curl -s https://raw.githubusercontent.com/raymondclowe/hermes-lan-mesh/main/onboarding.txt | head -20

Rules that make this work:

1. **Never rename or delete this repo, and never rewrite history.** The repo path is baked into
   every copy of the document already in the fleet; a rename strands them.
2. **Bump `rev` and its date in the facts block whenever the document changes** — that line is
   how an agent knows its copy is behind.
3. Keep `onboarding.txt` **plain text**. It is read by agents and pasted into terminals; no
   markdown rendering is assumed.
4. No addresses in the document. Peer addresses go stale the moment they are written and
   publishing them leaks LAN topology — discovery is a sweep (step 5), not a list.

## Updating

    git clone https://github.com/raymondclowe/hermes-lan-mesh
    $EDITOR onboarding.txt      # edit, then bump rev + date in the facts block
    git commit -am "rev N: <what changed>" && git push

## The one thing people get wrong

The fleet token (`hermes-lan-mesh-open`) is a **membership handshake, not a secret** — it is
printed in this public document by design and its only job is to satisfy Hermes's fail-closed
bind rule (without a token the listener binds `127.0.0.1` and no mesh can exist). The **firewall**
is the boundary. Never describe an agent exposing A2A on a LAN as "protected by a token", and
never widen the bind on a host whose firewall is not scoped to the subnet.
