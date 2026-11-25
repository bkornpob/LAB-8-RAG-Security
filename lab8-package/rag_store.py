"""Tiny RAG helpers shared by ingest.py and rag_chat.py: embed, search, load the index.
No dependencies: the corpus is small, so plain-Python cosine similarity is enough.

Env: OLLAMA_URL (default http://localhost:11434), EMBED_MODEL (default nomic-embed-text)
"""
import json, math, os, urllib.request

BASE = os.environ.get("OLLAMA_URL", "http://localhost:11434")
EMBED_MODEL = os.environ.get("EMBED_MODEL", "nomic-embed-text")
LEVELS = ("public", "internal", "restricted")
# Which levels each role may read. Recorded in the trace from the start, enforced in the access-control step.
ROLE_LEVELS = {"guest": ("public",), "staff": ("public", "internal"), "chef": ("public", "internal", "restricted")}


def _call(path, body=None, timeout=120):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def _prefix(model, kind):
    """nomic-embed-text is trained with task prefixes; other embedding models take the text as is."""
    if "nomic" in model:
        return "search_document: " if kind == "doc" else "search_query: "
    return ""


def embed(texts, model=EMBED_MODEL, kind="doc"):
    """texts -> list of vectors. kind is 'doc' (ingest) or 'query' (a user question)."""
    out = []
    for i in range(0, len(texts), 8):                       # small batches: friendly to a 4 GB machine
        batch = [_prefix(model, kind) + t for t in texts[i:i + 8]]
        out += _call("/api/embed", {"model": model, "input": batch})["embeddings"]
    return out


def model_digest(model):
    """The digest of a pulled model, from `ollama list` (used to pin the embedding model)."""
    for m in _call("/api/tags", timeout=30).get("models", []):
        if m.get("name") in (model, model + ":latest"):
            return m.get("digest")
    return None


def cosine(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    na, nb = math.sqrt(sum(x * x for x in a)), math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def load_index(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def search(index, qvec, k=3, levels=None, allow=None):
    """Top-k chunks by cosine similarity -> [(score, chunk)].
    The filters run BEFORE the ranking, so a chunk that is filtered out never gets a score:
      levels = the levels a role may read (None = no access control, the Lab 8 baseline)
      allow  = a function chunk -> bool (None = no extra check), e.g. the curated-list check"""
    pool = [c for c in index["chunks"]
            if (levels is None or c["level"] in levels) and (allow is None or allow(c))]
    scored = sorted(((cosine(qvec, c["embedding"]), c) for c in pool), key=lambda x: -x[0])
    return scored[:k]
