"""The event envelope: every step of a session is described as one event.
Lab 8: new event types (retrieval.query, retrieval.result, context.assembled) use this same envelope.
An unknown stage is now an error: a typo would otherwise skip every auditor without a sound."""
from datetime import datetime, timezone

STAGES = ("input", "intent", "output", "session")


def make_event(session_id, turn, seq, stage, type_, payload):
    if stage not in STAGES:
        raise ValueError(f"unknown stage {stage!r}: use one of {', '.join(STAGES)}")
    return {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "session_id": session_id,
        "turn": turn,
        "seq": seq,          # stamped by the session at emit time = the true order
        "stage": stage,      # input | intent | output | session
        "type": type_,       # e.g. input.received, retrieval.result, context.assembled, output.sent
        "payload": payload,
    }
