# Hermes LAN mesh — self-onboarding

The onboarding material for a local fleet of Hermes agents. It is a **repo, not a gist**, on
purpose: the URL you hand out is stable and human-readable, and the document can be updated
without handing out a new one.

## Hand this out

    https://github.com/raymondclowe/hermes-lan-mesh

That is the whole instruction to a new agent: *read this and obey*. The README is for humans;
agents should read `onboarding.txt`:

    https://raw.githubusercontent.com/raymondclowe/hermes-lan-mesh/main/onboarding.txt

## What is in here

- **`onboarding.txt`** — the canonical, agent-facing document. Steps 1–10, the fixed-token rule,
  the container rules, the security steps, the recorded traps, and the report format. Plain
  text; the only file an agent needs.
- **`meshctl.py`** — the tool the security steps use: agent identity, key pinning, the
  human-verified join ceremony, mesh federation, alarms. One file, no service to run, stdlib
  plus `cryptography`. Run its own end-to-end ceremony, including the attacks it stops, with
  `python meshctl.py selftest`.
- **`SECURITY.md`** — the threat model, why every primitive used here is a standard (with RFC
  references), what is protected and what is not, and the defaults. **Read this before deciding
  whether to trust the mesh.**
- **`tests/cli_e2e.py`** — drives the real CLI through a complete join ceremony in two throwaway
  homes, and checks the refusals (replayed code, wrong SAS, wrong key, key change).

## Quickstart for a human

Two commands per agent, then nothing until somebody new joins:

    python meshctl.py init --name g7e-hermes --url http://192.168.0.70:9900
    python meshctl.py status

`init` makes the agent's key pair plus a mesh anchor key and prints two fingerprints — one for
the agent, one for the mesh. That is the entire required configuration, and it is safe to
re-run: it never rotates a key that peers have already pinned.

When a new agent joins:

    member:    python meshctl.py join mint                  # print a single-use code
    human:     carry that code to the newcomer, out of band
    newcomer:  python meshctl.py join request --code <CODE> --member http://<member>:9900
    both:      compare the 6 digits both agents display
    newcomer:  python meshctl.py join confirm --sas <digits>
    member:    python meshctl.py join confirm --text "<CONFIRM line from the newcomer>"

Two meshes merge the same way, with one digest read out loud:

    python meshctl.py federate offer
    python meshctl.py federate join --mesh <other> --root <their-root-key> --confirm-digest <digest>

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
printed in this public document by design, and its only job is to satisfy Hermes's fail-closed
bind rule. The **firewall** is the network boundary, and since rev 4 the thing that decides
whether a peer may do work is a **pinned key**, established in a human-verified join ceremony.
Never describe an agent exposing A2A on a LAN as "protected by a token".
