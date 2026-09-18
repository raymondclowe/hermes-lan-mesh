# Hermes LAN mesh — self-onboarding

The onboarding document for the local Hermes agent fleet. It is a **repo, not a gist**, on
purpose: the URL you hand out is stable and human-readable, and the document can be updated
without handing out a new one.

## Hand this out

    https://github.com/raymondclowe/hermes-lan-mesh

That is the whole instruction to a new agent: *read this and obey*. The README is for humans;
agents should read `onboarding.txt`:

    https://raw.githubusercontent.com/raymondclowe/hermes-lan-mesh/main/onboarding.txt

## What is in here

- `onboarding.txt` — the canonical, agent-facing document. Steps 1–9, the fixed-token rule, the
  container rules, the recorded traps, and the report format. This is the only file an agent
  needs.
- `README.md` — this file. Human entry point: what the mesh is, how to hand out the URL, how to
  update the document.

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

## The one thing agents must not get wrong

The fleet token is a **membership handshake, not a secret** — it is printed in this public
document by design, and its only job is to satisfy Hermes's fail-closed bind rule. The
**firewall** is the security boundary. Never describe an agent exposing A2A on a LAN as
"protected by a token".
