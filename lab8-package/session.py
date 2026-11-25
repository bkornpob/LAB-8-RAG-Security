"""A thin session: stamps ids and order, emits events, and never waits on the auditors.
Lab 8: each stage can have several auditors (the RAG auditor runs after the Lab 5 one). A failing auditor is
loud (audit_error) but does not throw away the flags the other auditors raised."""
import os, sys, threading, uuid

import audit_input, audit_intent, audit_output, trace_store
from events import make_event

try:
    import audit_rag                                    # Lab 8; AUDIT_RAG=0 turns it off (= the Lab 7 audit)
except ImportError:
    audit_rag = None

AUDITORS = {"input": [audit_input], "intent": [audit_intent], "output": [audit_output]}
if audit_rag and os.environ.get("AUDIT_RAG", "1") == "1":
    for _stage in AUDITORS:
        AUDITORS[_stage].append(audit_rag)


def or_merge(base, extra):
    """A flag raised by one auditor is never switched off by another."""
    out = dict(base)
    for k, v in extra.items():
        out[k] = bool(out.get(k)) or bool(v)
    return out


class Session:
    def __init__(self, log):
        self.log = log
        self.sid = str(uuid.uuid4())
        self.turn = 0
        self.seq = 0
        self.events = []
        self.threads = []
        self.seen = {"input": set(), "intent": set(), "output": set()}
        self._m = threading.Lock()

    def new_turn(self):
        self.turn += 1

    def emit(self, stage, type_, payload):
        self.seq += 1                                   # true order, stamped here
        ev = make_event(self.sid, self.turn, self.seq, stage, type_, payload)
        self.events.append(ev)
        t = threading.Thread(target=self._audit, args=(ev, list(self.events)))
        t.start()                                       # fire and continue: no waiting
        self.threads.append(t)
        return ev

    def _audit(self, ev, history):
        flags = {}
        if os.environ.get("AUDIT_BREAK") == ev["stage"]:    # lab step: prove audit failures are visible
            flags = {"audit_error": True}
            print(f"[audit] {ev['stage']} auditor failed: injected fault", file=sys.stderr)
        else:
            for mod in AUDITORS.get(ev["stage"], []):
                try:
                    flags = or_merge(flags, mod.audit(ev, history))   # history = read-only events so far
                except Exception as e:                  # fail open for the chat, loud in the trace
                    flags["audit_error"] = True
                    print(f"[audit] {ev['stage']} auditor {mod.__name__} failed: {e}", file=sys.stderr)
        try:
            trace_store.append(self.log, ev, flags)
        except Exception as e:
            print(f"[audit] could not write trace: {e}", file=sys.stderr)
        with self._m:
            if ev["stage"] in self.seen:
                self.seen[ev["stage"]].update(k for k, v in flags.items() if v)

    def close(self):
        for t in self.threads:
            t.join()
        self.seq += 1
        ev = make_event(self.sid, self.turn, self.seq, "session", "session.closed",
                        {"events": self.seq - 1})
        trace_store.append(self.log, ev, {})

    def summary(self):
        def f(stage):
            return "[" + ", ".join(sorted(self.seen[stage])) + "]"
        return (f"[audit] session={self.sid[:8]} input={f('input')} "
                f"intent={f('intent')} output={f('output')}")
