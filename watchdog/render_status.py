#!/usr/bin/env python3
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def gate_label(*values):
    text = " ".join(str(v or "") for v in values).upper()
    if "LEAKAGE" in text:
        return "Leakage check"
    if "HOSTILE" in text:
        return "Hostile audit"
    if "PROOF_BLIND" in text or "RECONSTRUCTION" in text or "BLIND_" in text:
        return "Proof-blind reconstruction"
    if "COMPAR" in text:
        return "Comparison"
    if "FINAL" in text or "DELIVER" in text:
        return "Final reconciliation / delivery"
    if "CHECKPOINT" in text or "EPOCH_BOUNDARY" in text:
        return "Checkpoint / epoch boundary"
    if "RECOVER" in text:
        return "Recovery"
    if "SEARCH" in text or "RESEARCH" in text:
        return "Research / search"
    return "Active work"


def execution_label(value):
    return {
        "running": "Active",
        "checkpointed": "Checkpointed",
        "completed": "Completed",
        "interrupted": "Interrupted",
        "blocked": "Blocked",
        "expired": "Expired",
        "paused": "Paused",
    }.get(str(value or "").lower(), "Unknown")


def lease_label(value):
    return {
        "active": "Active",
        "released": "Released",
        "inactive": "Inactive",
    }.get(str(value or "").lower(), "Unknown")


def recovery_label(hb):
    if hb.get("work_event_takeover_observed") is True and hb.get("execution_stopped") is not True:
        return "Active takeover"
    if hb.get("recovery_armed") is True:
        return "Armed"
    return "Not armed"


def bool_label(value):
    return "Yes" if value is True else "No"


def safe_cell(value):
    if value is None or value == "":
        return "—"
    return str(value).replace("|", "\\|").replace("\n", " ")


def render(hb, owner, pointer, generated_at=None):
    generated_at = generated_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    current_gate = gate_label(hb.get("phase"), hb.get("next_unfinished_action"))
    next_gate = gate_label(hb.get("next_unfinished_action"))
    active = hb.get("active_assignments")
    active_count = len(active) if isinstance(active, list) else 0
    campaign = hb.get("campaign_id") or pointer.get("campaign_id") or owner.get("campaign_id")
    generation = hb.get("lease_generation")
    if generation is None:
        generation = owner.get("generation")

    rows = [
        ("Campaign", campaign),
        ("Execution", execution_label(hb.get("status"))),
        ("Current gate", current_gate),
        ("Next gate", next_gate),
        ("Checkpoint", hb.get("checkpoint_id") or pointer.get("checkpoint_id")),
        ("Generation", generation),
        ("Lease", lease_label(owner.get("status"))),
        ("Active assignments", active_count),
        ("Recovery", recovery_label(hb)),
        ("Last heartbeat (UTC)", hb.get("last_heartbeat_utc")),
        ("Lease expires (UTC)", owner.get("lease_expires_utc")),
        ("Terminal delivery complete", bool_label(hb.get("terminal_delivery_complete"))),
    ]

    lines = [
        "# McKay workflow status",
        "",
        f"_Generated from public watchdog coordination state at {safe_cell(generated_at)}._",
        "",
        "| Field | Status |",
        "| --- | --- |",
    ]
    for key, value in rows:
        lines.append(f"| {safe_cell(key)} | {safe_cell(value)} |")
    lines += [
        "",
        "> This page intentionally contains only non-mathematical coordination metadata. "
        "It does not publish research prompts, candidate statements, proofs, audits, private paths, "
        "source documents, or mathematical results.",
        "",
        "The file is regenerated automatically when the public heartbeat, ownership, or active-campaign binding changes.",
        "",
    ]
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--heartbeat", default="watchdog/heartbeat.json")
    p.add_argument("--owner", default="watchdog/owner.json")
    p.add_argument("--active", default="watchdog/active-campaign.json")
    p.add_argument("--output", default="watchdog/STATUS.md")
    args = p.parse_args()

    hb = load_json(Path(args.heartbeat))
    owner = load_json(Path(args.owner))
    pointer = load_json(Path(args.active))
    Path(args.output).write_text(render(hb, owner, pointer), encoding="utf-8")


if __name__ == "__main__":
    main()
