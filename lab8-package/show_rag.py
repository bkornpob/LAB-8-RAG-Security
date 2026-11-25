#!/usr/bin/env python3
"""Per turn: the question, WHICH chunks were retrieved, what flagged, and what came out.

  python3 show_rag.py rag-raw-1.jsonl                       every turn
  python3 show_rag.py rag-raw-1.jsonl --attacks             only attack turns and any flagged turn
  python3 show_rag.py rag-raw-1.jsonl --turn 9 --full       one turn, untruncated reply
  python3 show_rag.py rag-raw-1.jsonl --raw raw.jsonl       show the exact replies (needs RAW_LOG=raw.jsonl at run time)

Warnings on a retrieved chunk:  ABOVE-ROLE = its level is higher than the role may read,
                                UNTRUSTED   = its document is not on the curated list (CURATED, default manifest-clean.json),
                                MODIFIED    = it is on the curated list, but the document's hash changed.
The trace redacts replies that carry the canary. --raw is the only way to see them, and that file is sensitive.
"""
import argparse, json, os, sys

CURATED = os.environ.get("CURATED", "manifest-clean.json")


def load_curated():
    try:
        with open(CURATED, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        print(f"warning: curated list {CURATED} not found or unreadable: every document will show UNTRUSTED",
              file=sys.stderr)
        return {}
ROLE_LEVELS = {"guest": ("public",), "staff": ("public", "internal"), "chef": ("public", "internal", "restricted")}


def read(path):
    out = []
    for line in open(path, encoding="utf-8"):
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


def group(records):
    turns = {}
    for r in records:
        if r["stage"] == "session":
            continue
        t = turns.setdefault((r["session_id"], r["turn"]),
                             {"sid": r["session_id"], "turn": r["turn"], "prompt": "", "label": "-", "role": "-",
                              "chunks": [], "reply": "", "blocked": None, "flags": {}, "recs": [], "dropped": {},
                              "failclosed": None})
        t["recs"].append(r)
        p, ty = r["payload"], r["type"]
        for k, v in r["flags"].items():
            if v:
                t["flags"].setdefault(r["stage"], set()).add(k)
        if ty == "input.received":
            t["prompt"], t["label"], t["role"] = p.get("prompt", ""), p.get("label") or "-", p.get("role", "-")
        elif ty == "retrieval.result":
            t["chunks"] = p.get("chunks", [])
        elif ty == "guard.retrieval":
            t["dropped"] = {k: v["dropped"] for k, v in (p.get("layers") or {}).items() if v.get("dropped")}
            t["failclosed"] = p.get("reason") if p.get("enforced") else None
        elif ty == "output.sent":
            t["reply"], t["blocked"] = p.get("reply", ""), p.get("blocked")
    return list(turns.values())


def category(records):
    """The Lab 6 classification, when correlate.py is next to this script (it is optional)."""
    try:
        import correlate
        return {k: correlate.classify(v) for k, v in correlate.by_turn(records).items()}
    except Exception:
        return {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--attacks", action="store_true", help="attack turns and flagged turns only")
    ap.add_argument("--turn", type=int, help="only turn number N (the # in show_turns.py)")
    ap.add_argument("--full", action="store_true", help="do not cut long replies")
    ap.add_argument("--raw", help="raw.jsonl written by rag_chat.py with RAW_LOG=raw.jsonl")
    a = ap.parse_args()

    records = read(a.log)
    cur = load_curated()
    cats = category(records)
    rawrecs = {(r["session_id"], r["turn"]): r for r in read(a.raw)} if a.raw else {}
    raw = {k: v["reply"] for k, v in rawrecs.items()}
    for n, t in enumerate(group(records), 1):
        flagged = any(t["flags"].get(s) for s in ("input", "output"))
        if a.turn and n != a.turn:
            continue
        if a.attacks and not (t["label"] == "attack" or flagged):
            continue
        key = (t["sid"], t["turn"])
        allowed = ROLE_LEVELS.get(t["role"], ())
        print(f"#{n:<3} [{t['label']}] {cats.get(key, '-')}   role={t['role']}"
              + (f"   blocked={t['blocked']}" if t["blocked"] else ""))
        print(f"  Q: {t['prompt']}")
        for c in t["chunks"]:
            warn = []
            if c["level"] not in allowed:
                warn.append("ABOVE-ROLE")
            if c["doc_id"] not in cur:
                warn.append("UNTRUSTED")
            elif cur[c["doc_id"]] != c["doc_sha256"]:
                warn.append("MODIFIED")
            print(f"  retrieved: {c['chunk_id']:<34} {c['level']:<10} {c['source']:<17} score={c['score']}"
                  + ("   <-- " + ", ".join(warn) if warn else ""))
        if not t["chunks"]:
            print("  retrieved: (none)")
        for layer, ids in t["dropped"].items():
            print(f"  kept out by {layer}: {', '.join(ids)}")
        if t["failclosed"]:
            print(f"  fail-closed: {t['failclosed']}")
        fl = "  ".join(f"{s}={','.join(sorted(v))}" for s, v in t["flags"].items() if v)
        print(f"  flags: {fl or '-'}")
        reply, tag = t["reply"], "A"
        if key in raw:
            reply, tag = raw[key], "A (raw)"
        elif reply.startswith("[REDACTED"):
            tag = "A (redacted by the trace; use --raw to see it)"
        flat = reply.replace("\n", " ⏎ ")
        if not a.full and len(flat) > 300:
            flat = flat[:300] + " ... (--full for all)"
        print(f"  {tag}: {flat}")
        if "model_raw" in rawrecs.get(key, {}):
            print(f"  model raw (replaced by the {t['blocked']} layer): " + (lambda m: m if a.full or len(m) <= 300 else m[:300] + " ... (--full for all)")(rawrecs[key]["model_raw"].replace("\n", " ⏎ ")))
        print()


if __name__ == "__main__":
    main()
