#!/usr/bin/env python3
"""Step 2: docs/<level>/<name>.md -> chunks -> embeddings -> index.json (+ manifest.json of document hashes).

Every chunk carries its access metadata: doc_id, level, source, and the sha256 of the whole source document.
The directory name is the access level (public | internal | restricted).
A document may start with a line `source: <name>`; it is metadata, not content.

Env: DOCS=docs  INDEX=index.json  MANIFEST=manifest.json  EMBED_MODEL=nomic-embed-text  CHUNK_CHARS=900
     SCAN=0|1  1 = content scan: a document with an injection phrase or invisible characters in any chunk is
               quarantined (not indexed, not in the manifest) and listed in QUARANTINE (default quarantine.json).
               Use a separate INDEX for it, e.g. INDEX=index-scan.json
"""
import hashlib, json, os, re, sys, time
from pathlib import Path

import audit_rag, rag_store

DOCS = Path(os.environ.get("DOCS", "docs"))
INDEX = os.environ.get("INDEX", "index.json")
MANIFEST = os.environ.get("MANIFEST", "manifest.json")
CHUNK_CHARS = int(os.environ.get("CHUNK_CHARS", "900"))
SCAN = os.environ.get("SCAN", "0") == "1"
QUARANTINE = os.environ.get("QUARANTINE", "quarantine.json")


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def split_chunks(text, limit):
    """Merge paragraphs up to `limit` characters, so a short document stays in one or two chunks."""
    chunks, cur = [], ""
    for para in re.split(r"\n\s*\n", text.strip()):
        para = para.strip()
        if not para:
            continue
        if cur and len(cur) + len(para) + 2 > limit:
            chunks.append(cur)
            cur = ""
        while len(para) > limit:                           # one very long paragraph: cut it
            chunks.append(para[:limit])
            para = para[limit:]
        cur = (cur + "\n\n" + para) if cur else para
    if cur:
        chunks.append(cur)
    return chunks


def load_docs():
    docs = []
    for level in rag_store.LEVELS:
        for path in sorted((DOCS / level).glob("*.md")):
            raw = path.read_bytes()
            text = raw.decode("utf-8")
            m = re.match(r"source:\s*(\S+)\s*\n", text)
            source = m.group(1) if m else "unknown"
            body = text[m.end():] if m else text
            title = next((l[2:].strip() for l in body.splitlines() if l.startswith("# ")), path.stem)
            docs.append({"doc_id": f"{level}/{path.stem}", "level": level, "source": source,
                         "title": title, "sha256": sha256(raw), "body": body})
    return docs


def main():
    docs = load_docs()
    if not docs:
        sys.exit(f"no documents under {DOCS}/ (expected {DOCS}/public, {DOCS}/internal, {DOCS}/restricted)")

    quarantined = []
    if SCAN:                                               # content scan: one bad chunk quarantines the whole document
        kept = []
        for d in docs:
            found = {}
            for n, piece in enumerate(split_chunks(d["body"], CHUNK_CHARS)):
                for why in audit_rag.scan_chunk(piece):
                    found.setdefault(why, []).append(f"{d['doc_id']}#{n}")
            if found:
                quarantined.append({"doc_id": d["doc_id"], "sha256": d["sha256"], "reasons": found})
            else:
                kept.append(d)
        docs = kept
        with open(QUARANTINE, "w", encoding="utf-8") as f:
            json.dump(quarantined, f, indent=2)
    chunks = []
    for d in docs:
        for n, piece in enumerate(split_chunks(d["body"], CHUNK_CHARS)):
            chunks.append({"chunk_id": f"{d['doc_id']}#{n}", "doc_id": d["doc_id"], "level": d["level"],
                           "source": d["source"], "sha256": d["sha256"], "text": piece,
                           "_embed_text": f"{d['title']}\n{piece}"})      # the title helps retrieval

    try:
        vectors = rag_store.embed([c["_embed_text"] for c in chunks])
        digest = rag_store.model_digest(rag_store.EMBED_MODEL)
    except Exception as e:
        sys.exit(f"embedding failed: {e}\n(is Ollama running, and did you `ollama pull {rag_store.EMBED_MODEL}`?)")
    for c, v in zip(chunks, vectors):
        c["embedding"] = v
        del c["_embed_text"]

    index = {"embed_model": rag_store.EMBED_MODEL, "embed_digest": digest, "dims": len(vectors[0]),
             "chunk_chars": CHUNK_CHARS, "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "chunks": chunks}
    with open(INDEX, "w", encoding="utf-8") as f:
        json.dump(index, f)
    with open(MANIFEST, "w", encoding="utf-8") as f:
        json.dump({d["doc_id"]: d["sha256"] for d in docs}, f, indent=2, sort_keys=True)

    print(f"{'doc_id':<34} {'level':<11} {'source':<17} chunks")
    for d in docs:
        print(f"{d['doc_id']:<34} {d['level']:<11} {d['source']:<17} "
              f"{sum(1 for c in chunks if c['doc_id'] == d['doc_id'])}")
    for q in quarantined:
        print(f"QUARANTINED {q['doc_id']:<30} {', '.join(q['reasons'])}")
    print(f"\n{len(chunks)} chunks, {len(docs)} docs, {index['dims']} dims -> {INDEX}, {MANIFEST}"
          + (f", {len(quarantined)} quarantined -> {QUARANTINE}" if SCAN else ""))
    print(f"embedding model {index['embed_model']} digest {(digest or 'unknown')[:12]}")


if __name__ == "__main__":
    main()
