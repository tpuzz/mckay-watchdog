#!/usr/bin/env python3
"""Bounded, fail-closed supervisor for the current McKay fine-product workflow.

The supervisor emits recovery requests only. It never reads private state,
claims ownership, or performs research/editorial work.
"""
import argparse
import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import re
import sys
import time
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

CAMPAIGN_PREFIX = "mckay-fine-"
TERMINAL_TITLE_PREFIX = "MCKAY_FINE_WORKFLOW_TERMINAL"
RECOVERY_TITLE_PREFIX = "MCKAY_FINE_WORKFLOW_STALE"
INFRA_TITLE_PREFIX = "MCKAY_FINE_INFRA_FAILURE"
TEST_TITLE_PREFIX = "MCKAY_FINE_RECOVERY_TEST"
TEST_FIXTURE_ID = "mckay-fine-infra-20261027T162721Z-fixture-v1"
TEST_FIXTURE_SHA256 = "7248d120d38df01009eac3b1542bf3d13ac273698be0aaedfef21693cb04d492"
STALE_SECONDS = 1200
POLL_SECONDS = 60
ACK_TIMEOUT_SECONDS = 360
MAX_RECOVERY_ATTEMPTS = 3


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("Missing timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timestamp has no timezone")
    return parsed.astimezone(timezone.utc)


def campaign_id(hb, owner):
    """Return the exact current campaign when the public state is coherent."""
    if not isinstance(hb, dict) or not isinstance(owner, dict):
        return None
    h_campaign = hb.get("campaign_id")
    o_campaign = owner.get("campaign_id")
    if not isinstance(h_campaign, str) or h_campaign != o_campaign:
        return None
    if not h_campaign.startswith(CAMPAIGN_PREFIX):
        return None
    return h_campaign


@dataclass(frozen=True)
class Decision:
    action: str
    reason: str
    mode: str = ""


def decide(hb, owner, now):
    """Private coordination signal only; the consumer verifies authorization bytes."""
    pointer = hb.get("_active_pointer", {}) if isinstance(hb, dict) else {}
    if pointer.get("status") == "NO_CONFIRMED_CAMPAIGN":
        return Decision("stop", "No confirmed mathematical campaign")
    if not pointer_valid(pointer, hb, owner):
        return Decision("wait", "Missing or mismatched exact active-campaign binding")
    if owner.get("user_stop_requested") is True or pointer.get("stop_requested") is True:
        return Decision("stop", "Explicit stop")
    if pointer.get("status") in ("PAUSED", "CANCELLED", "STOPPED"):
        return Decision("stop", "Explicit pause/cancel/stop")
    campaign = campaign_id(hb, owner)
    if campaign is None:
        return Decision("wait", "Campaign mismatch or unsupported campaign")
    status = hb.get("status")
    if status in ("inactive", "cancelled", "canceled") or hb.get("user_stop_requested") is True:
        return Decision("stop", "Inactive or explicitly cancelled")
    delivered = (hb.get("terminal_delivery_complete") is True
                 and hb.get("dropbox_final_status_verified") is True)
    if status in ("completed", "paused", "expired", "interrupted", "blocked", "terminal") and delivered:
        return Decision("stop", "Verified terminal delivery")
    if status == "paused" and hb.get("resume_authorized") is not True:
        return Decision("stop", "Deliberate pause does not authorize resumption")
    if status not in ("running", "checkpointed", "interrupted", "blocked", "completed", "expired"):
        return Decision("wait", "Unknown status")
    run_id = hb.get("run_id")
    generation, previous_generation = owner.get("generation"), hb.get("lease_generation")
    if (not isinstance(run_id, str) or not run_id
            or type(generation) is not int or type(previous_generation) is not int
            or min(generation, previous_generation) < 1):
        return Decision("wait", "Invalid run or generation")
    if owner.get("status") not in ("active", "inactive", "released"):
        return Decision("wait", "Unknown lease status")
    try:
        lease_end = timestamp(owner.get("lease_expires_utc"))
        last = timestamp(hb.get("last_heartbeat_utc"))
    except (TypeError, ValueError, OverflowError):
        return Decision("wait", "Invalid timestamps")
    if last > now + timedelta(seconds=120):
        return Decision("wait", "Heartbeat is in the future")
    matches = owner.get("owner_run_id") == run_id and generation == previous_generation
    if not matches:
        orphan = (owner.get("status") == "active" and generation == previous_generation + 1
                  and owner.get("owner_run_id") not in (None, "", run_id)
                  and now >= lease_end and (now-last).total_seconds() >= STALE_SECONDS)
        if not orphan:
            return Decision("wait", "Conflicting state or handover in progress")
        return Decision("trigger", "Expired orphaned handover; independently verify",
                        "verify_private_authorization")
    if now < lease_end:
        return Decision("wait", "Unexpired owner")
    if owner.get("status") in ("inactive", "released") and status in ("running", "checkpointed"):
        return Decision("wait", "Released ownership needs reconciliation")
    if status in ("running", "checkpointed") and (now-last).total_seconds() < STALE_SECONDS:
        return Decision("wait", "Heartbeat is fresh")
    mode = ("finalize_only"
            if status in ("completed", "expired") or hb.get("recovery_mode") == "finalize_only"
            else "verify_private_authorization")
    return Decision("trigger", "Expired lease and stale or interrupted execution", mode)



BINDING_FIELDS = ("campaign_id", "statement_version", "statement_sha256", "authorization_id",
                  "authorization_sha256", "checkpoint_id", "checkpoint_sha256", "checkpoint_filename",
                  "authorization_filename", "statement_filename", "next_unfinished_action")

def pointer_valid(pointer, hb, owner):
    if not isinstance(pointer, dict) or pointer.get("status") not in (
            "CONFIRMED", "PAUSED", "CANCELLED", "STOPPED", "TERMINAL"):
        return False
    if not isinstance(owner, dict):
        return False
    for field in BINDING_FIELDS:
        value = pointer.get(field)
        if not isinstance(value, str) or not value or hb.get(field) != value:
            return False
        if field.endswith("sha256") and not re.fullmatch(r"[0-9a-f]{64}", value):
            return False
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", pointer["next_unfinished_action"]):
        return False
    if any(not re.fullmatch(r"[A-Za-z0-9_.-]+", pointer[k]) for k in ("checkpoint_filename", "authorization_filename", "statement_filename")):
        return False
    return (owner.get("campaign_id") == pointer["campaign_id"]
            and owner.get("authorization_id") == pointer["authorization_id"])

def startup_receipt_valid(old_hb, new_hb, new_owner):
    receipt = new_hb.get("_recovery_receipt", {})
    if not isinstance(receipt, dict) or receipt.get("execution_kind") != "WORK_EVENT":
        return False
    if receipt.get("status") != "RESEARCH_STARTED":
        return False
    if any(receipt.get(k) is not True for k in (
            "source_bytes_verified", "authorization_verified", "ownership_readback_verified",
            "bootstrap_readback_verified")):
        return False
    if any(not isinstance(receipt.get(k), str) or not receipt[k] for k in (
            "event_execution_id", "assignment_id", "started_at_utc")):
        return False
    fields = ("campaign_id", "statement_version", "statement_sha256", "authorization_id",
              "authorization_sha256", "hard_deadline_utc", "delivery_reserve_utc")
    for field in fields:
        value = old_hb.get(field)
        if not value or new_hb.get(field) != value or receipt.get(field) != value:
            return False
    if (receipt.get("input_checkpoint_id") != old_hb.get("checkpoint_id")
            or receipt.get("input_checkpoint_sha256") != old_hb.get("checkpoint_sha256")
            or receipt.get("resumed_action") != old_hb.get("next_unfinished_action")):
        return False
    return (receipt.get("owner_run_id") == new_owner.get("owner_run_id")
            and receipt.get("generation") == new_owner.get("generation")
            and receipt.get("generation") == new_hb.get("lease_generation"))

class APIError(RuntimeError):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class GitHubAPI:
    def __init__(self, repo, token):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            raise ValueError("Invalid repository identity")
        if repo != "tpuzz/mckay-watchdog":
            raise ValueError("Only tpuzz/mckay-watchdog is allowed")
        self.repo, self.token = repo, token

    def request(self, method, endpoint, payload=None, missing_ok=False):
        raw = None if payload is None else json.dumps(payload).encode()
        req = Request("https://api.github.com/repos/" + self.repo + endpoint,
                      data=raw, method=method,
                      headers={"Authorization": "Bearer " + self.token,
                               "Accept": "application/vnd.github+json",
                               "Content-Type": "application/json",
                               "X-GitHub-Api-Version": "2022-11-28",
                               "User-Agent": "mckay-fine-workflow-watchdog"})
        try:
            with urlopen(req, timeout=30) as response:
                return json.load(response)
        except HTTPError as error:
            if missing_ok and error.code == 404:
                return None
            raise APIError(error.code, "GitHub HTTP %d on %s %s: %s" %
                           (error.code, method, endpoint,
                            error.read(1200).decode(errors="replace"))) from error

    def file(self, path, ref):
        record = self.request("GET", "/contents/" + path + "?" + urlencode({"ref": ref}))
        return json.loads(base64.b64decode(record["content"]).decode())

    def snapshot(self):
        sha = self.request("GET", "/git/ref/heads/main")["object"]["sha"]
        hb = self.file("watchdog/heartbeat.json", sha)
        hb["_active_pointer"] = self.file("watchdog/active-campaign.json", sha)
        receipt_path = hb.get("recovery_receipt_path")
        if receipt_path:
            if not re.fullmatch(r"watchdog/receipts/[A-Za-z0-9_-]+\.json", receipt_path):
                raise ValueError("Unsafe receipt path")
            hb["_recovery_receipt"] = self.file(receipt_path, sha)
        return sha, hb, self.file("watchdog/owner.json", sha)


def incident_identity(hb, owner):
    campaign = campaign_id(hb, owner)
    if campaign is None:
        raise ValueError("Cannot identify incident for incoherent campaign state")
    value = "%s\0%s\0%s" % (campaign, hb["run_id"], owner["generation"])
    return hashlib.sha256(value.encode()).hexdigest()[:24]


def copy_dict(value):
    return json.loads(json.dumps(value))


def recovery_acknowledged(old_hb, old_owner, new_hb, new_owner, now):
    """A live lease is insufficient: require a bound actual Work start receipt."""
    if not startup_receipt_valid(old_hb, new_hb, new_owner):
        return False
    old_campaign = campaign_id(old_hb, old_owner)
    new_campaign = campaign_id(new_hb, new_owner)
    if old_campaign is None or new_campaign != old_campaign:
        return False
    old_generation = old_owner.get("generation")
    new_generation = new_owner.get("generation")
    if type(old_generation) is not int or type(new_generation) is not int or new_generation <= old_generation:
        return False
    new_run = new_owner.get("owner_run_id")
    if not isinstance(new_run, str) or not new_run or new_run == old_hb.get("run_id"):
        return False
    if new_owner.get("status") != "active":
        return False
    if new_hb.get("run_id") != new_run or new_hb.get("lease_generation") != new_generation:
        return False
    if old_hb.get("authorization_id") and new_hb.get("authorization_id") != old_hb.get("authorization_id"):
        return False
    if old_hb.get("hard_deadline_utc") and new_hb.get("hard_deadline_utc") != old_hb.get("hard_deadline_utc"):
        return False
    if new_hb.get("status") not in ("running", "checkpointed", "interrupted", "blocked"):
        return False
    try:
        lease_end = timestamp(new_owner.get("lease_expires_utc"))
        last = timestamp(new_hb.get("last_heartbeat_utc"))
    except (TypeError, ValueError, OverflowError):
        return False
    if lease_end <= now or last > now + timedelta(seconds=120) or (now-last).total_seconds() >= STALE_SECONDS:
        return False
    return True


def emit_recovery(api, snapshot, decision, attempt=1):
    sha, hb, owner = snapshot
    campaign = campaign_id(hb, owner)
    if campaign is None:
        return "changed"
    incident = incident_identity(hb, owner)
    branch = "watchdog-recovery-" + incident + "-a" + str(attempt)
    query = urlencode({"state": "all",
                       "head": api.repo.split("/")[0] + ":" + branch,
                       "per_page": 100})
    existing = api.request("GET", "/pulls?" + query)
    if existing:
        print("Recovery signal already exists: " + existing[0]["html_url"], flush=True)
        return "done"
    marker_path = "watchdog/events/" + incident + "-a" + str(attempt) + ".json"
    marker = {"campaign_id": campaign, "run_id": hb["run_id"],
              "lease_generation": owner["generation"], "incident_id": incident,
              "recovery_mode": decision.mode, "reason": decision.reason,
              "snapshot_commit": sha, "attempt": attempt}
    ref = api.request("GET", "/git/ref/heads/" + branch, missing_ok=True)
    if ref is None:
        commit = api.request("GET", "/git/commits/" + sha)
        tree = api.request("POST", "/git/trees",
                           {"base_tree": commit["tree"]["sha"],
                            "tree": [{"path": marker_path, "mode": "100644",
                                      "type": "blob",
                                      "content": json.dumps(marker, indent=2) + "\n"}]})
        new_commit = api.request("POST", "/git/commits",
                                 {"message": "Request McKay fine-product recovery " + incident,
                                  "tree": tree["sha"], "parents": [sha]})
        try:
            api.request("POST", "/git/refs",
                        {"ref": "refs/heads/" + branch, "sha": new_commit["sha"]})
        except APIError as error:
            if error.status != 422:
                raise
            api.request("GET", "/git/ref/heads/" + branch)
    saved_marker = api.file(marker_path, branch)
    if any(saved_marker.get(k) != marker[k]
           for k in ("campaign_id", "run_id", "lease_generation", "incident_id")):
        raise ValueError("Existing incident branch has conflicting provenance")
    fresh = api.snapshot()
    current = decide(fresh[1], fresh[2], datetime.now(timezone.utc))
    if current.action != "trigger" or incident_identity(fresh[1], fresh[2]) != incident:
        print("State advanced during preparation; no recovery PR opened", flush=True)
        return "changed"
    title = ((TERMINAL_TITLE_PREFIX if current.mode == "finalize_only" else RECOVERY_TITLE_PREFIX) + " " + current.mode + " "
             + hb["run_id"] + " attempt-" + str(attempt))
    body = ("Recovery request only, not mathematical/editorial authorization.\n\n"
            + "Campaign: " + campaign + "; incident: " + incident
            + "; generation: " + str(owner["generation"])
            + "; attempt: " + str(attempt) + ".\n"
            + "Requested mode: " + current.mode + ".\n"
            + "The consumer must independently verify the latest private durable state, "
            + "including every user-authorized deadline extension, before any work.\n\n"
            + "Do not take over an unexpired or changed owner. Claim and verify the lease "
            + "conditionally before authorized work. At or after the current private delivery "
            + "reserve, perform finalization only; after the current private hard deadline, "
            + "perform no substantive work without a newer explicit authorization. "
            + "Ignore this request if verified terminal delivery has since completed.\n")
    try:
        pr = api.request("POST", "/pulls",
                         {"title": title, "body": body, "head": branch, "base": "main"})
    except APIError as error:
        if error.status != 422:
            raise
        found = api.request("GET", "/pulls?" + query)
        if not found:
            raise
        pr = found[0]
    print("Recovery PR created/verified: " + pr["html_url"], flush=True)
    return "done"


def emit_infrastructure_failure(api, snapshot, attempts):
    """Persist a visible alert if no recovery consumer acknowledges repeated wake-ups."""
    sha, hb, owner = snapshot
    campaign = campaign_id(hb, owner)
    if campaign is None:
        return
    incident = incident_identity(hb, owner)
    branch = "watchdog-recovery-failure-" + incident
    marker_path = "watchdog/events/" + incident + "-launch-failure.json"
    marker = {"campaign_id": campaign, "run_id": hb["run_id"],
              "lease_generation": owner["generation"], "incident_id": incident,
              "attempts": attempts, "reason": "Recovery wake-ups were not acknowledged",
              "snapshot_commit": sha}
    query = urlencode({"state": "all",
                       "head": api.repo.split("/")[0] + ":" + branch,
                       "per_page": 100})
    existing = api.request("GET", "/pulls?" + query)
    if existing:
        print("Infrastructure-failure signal already exists: " + existing[0]["html_url"],
              flush=True)
        return
    ref = api.request("GET", "/git/ref/heads/" + branch, missing_ok=True)
    if ref is None:
        commit = api.request("GET", "/git/commits/" + sha)
        tree = api.request("POST", "/git/trees",
                           {"base_tree": commit["tree"]["sha"],
                            "tree": [{"path": marker_path, "mode": "100644",
                                      "type": "blob",
                                      "content": json.dumps(marker, indent=2) + "\n"}]})
        new_commit = api.request("POST", "/git/commits",
                                 {"message": "Record unacknowledged McKay fine-product recovery " + incident,
                                  "tree": tree["sha"], "parents": [sha]})
        try:
            api.request("POST", "/git/refs",
                        {"ref": "refs/heads/" + branch, "sha": new_commit["sha"]})
        except APIError as error:
            if error.status != 422:
                raise
    title = INFRA_TITLE_PREFIX + " " + hb["run_id"]
    body = ("Automatic recovery was requested " + str(attempts)
            + " times for campaign " + campaign
            + " but no bound Work-start receipt acknowledged it. "
            + "No new authorization is added. Inspect the recovery consumer and preserve "
            + "the private scope and clock.")
    try:
        pr = api.request("POST", "/pulls",
                         {"title": title, "body": body, "head": branch, "base": "main"})
    except APIError as error:
        if error.status != 422:
            raise
        found = api.request("GET", "/pulls?" + query)
        if not found:
            raise
        pr = found[0]
    print("Infrastructure-failure PR created/verified: " + pr["html_url"], flush=True)


def diagnostic_state_valid(snapshot):
    """A transport test is allowed only while production remains unconfirmed."""
    _, hb, owner = snapshot
    return (hb.get('_active_pointer', {}).get('status') == 'NO_CONFIRMED_CAMPAIGN'
            and hb.get('_active_pointer', {}).get('mathematics_authorized') is False
            and hb.get('status') == 'NO_CONFIRMED_CAMPAIGN'
            and hb.get('mathematics_started') is False
            and owner.get('status') in ('inactive', 'released')
            and owner.get('owner_run_id') is None)


def emit_diagnostic(api, diagnostic_id):
    """Emit one fixture signal, never a production stale signal or research start."""
    if not re.fullmatch(r'mckay-supervisor-e2e-[A-Za-z0-9-]{1,80}', diagnostic_id):
        raise ValueError('Invalid diagnostic identity')
    snapshot = api.snapshot()
    if not diagnostic_state_valid(snapshot):
        raise ValueError('Diagnostic requires unconfirmed, inactive production state')
    receipt = api.file('watchdog/receipts/' + TEST_FIXTURE_ID + '.json', snapshot[0])
    if (receipt.get('fixture_id') != TEST_FIXTURE_ID
            or receipt.get('fixture_sha256') != TEST_FIXTURE_SHA256
            or receipt.get('status') != 'EVENT_TEST_PASSED'
            or receipt.get('lease_release_verified') is not True):
        raise ValueError('Previously completed fixture receipt is required')
    branch = 'watchdog-diagnostic-' + diagnostic_id
    marker_path = 'watchdog/events/' + diagnostic_id + '.json'
    title = TEST_TITLE_PREFIX + ' NON-MATHEMATICAL ' + diagnostic_id
    query = urlencode({'state': 'all', 'head': api.repo.split('/')[0] + ':' + branch,
                       'per_page': 100})
    existing = api.request('GET', '/pulls?' + query)
    if existing:
        if existing[0].get('title') != title:
            raise ValueError('Conflicting diagnostic PR')
        print('Diagnostic signal already exists: ' + existing[0]['html_url'], flush=True)
        return existing[0]
    marker = {'diagnostic_id': diagnostic_id, 'fixture_id': TEST_FIXTURE_ID,
              'fixture_sha256': TEST_FIXTURE_SHA256, 'test_only': True,
              'mathematics_authorized': False, 'github_run_id': os.environ.get('GITHUB_RUN_ID')}
    ref = api.request('GET', '/git/ref/heads/' + branch, missing_ok=True)
    if ref is None:
        commit = api.request('GET', '/git/commits/' + snapshot[0])
        tree = api.request('POST', '/git/trees',
                           {'base_tree': commit['tree']['sha'],
                            'tree': [{'path': marker_path, 'mode': '100644', 'type': 'blob',
                                      'content': json.dumps(marker, indent=2) + '\n'}]})
        new_commit = api.request('POST', '/git/commits',
                                {'message': 'McKay non-mathematical supervisor diagnostic',
                                 'tree': tree['sha'], 'parents': [snapshot[0]]})
        api.request('POST', '/git/refs',
                    {'ref': 'refs/heads/' + branch, 'sha': new_commit['sha']})
    saved = api.file(marker_path, branch)
    if any(saved.get(k) != marker[k] for k in marker if k != 'github_run_id'):
        raise ValueError('Conflicting diagnostic branch')
    if not diagnostic_state_valid(api.snapshot()):
        raise ValueError('Production state advanced; diagnostic PR not emitted')
    pr = api.request('POST', '/pulls',
                     {'title': title, 'head': branch, 'base': 'main',
                      'body': ('NON-MATHEMATICAL supervisor transport diagnostic.\n\n'
                               'Fixture ID: ' + TEST_FIXTURE_ID + '\n'
                               'Fixture SHA-256: ' + TEST_FIXTURE_SHA256 + '\n'
                               'Diagnostic ID: ' + diagnostic_id + '\n'
                               'Existing completed fixture; duplicate handling is expected.\n'
                               'No mathematical authorization or production ownership change.\n')})
    print('Diagnostic PR emitted (Work result still unverified): ' + pr['html_url'], flush=True)
    return pr


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="Evaluate once without waiting")
    parser.add_argument("--dry-run", action="store_true", help="Read/evaluate only; never mutate GitHub")
    parser.add_argument('--diagnostic-event', metavar='ID',
                        help='One non-mathematical fixture transport test; no production takeover')
    args = parser.parse_args()
    repo = os.environ["GITHUB_REPOSITORY"]
    if repo != "tpuzz/mckay-watchdog":
        raise ValueError("This supervisor is restricted to the McKay fine-product watchdog repository")
    api = GitHubAPI(repo, os.environ["GH_TOKEN"])
    metadata = api.request("GET", "")
    if metadata.get("full_name") != repo:
        raise ValueError("Repository must be the exact McKay repository")
    if args.diagnostic_event:
        if args.dry_run:
            raise ValueError('Diagnostic emission cannot be combined with dry-run')
        emit_diagnostic(api, args.diagnostic_event)
        return
    failures, previous = 0, None
    stop_at = time.monotonic() + 355 * 60
    pending = None
    while time.monotonic() < stop_at:
        try:
            now = datetime.now(timezone.utc)
            snapshot = api.snapshot()

            if pending is not None:
                if recovery_acknowledged(pending["hb"], pending["owner"],
                                         snapshot[1], snapshot[2], now):
                    print("Bound Work-start receipt verified for successor generation %s run %s" %
                          (snapshot[2]["generation"], snapshot[2]["owner_run_id"]), flush=True)
                    return
                current_incident = incident_identity(snapshot[1], snapshot[2])
                if current_incident != pending["incident"]:
                    print("Incident state changed before acknowledgement; returning to supervision",
                          flush=True)
                    pending = None
                    previous = None
                    continue
                if time.monotonic() >= pending["ack_deadline"]:
                    decision = decide(snapshot[1], snapshot[2], now)
                    if decision.action != "trigger":
                        print("Recovery no longer actionable while awaiting acknowledgement: "
                              + decision.reason, flush=True)
                        pending = None
                        previous = None
                        continue
                    if pending["attempt"] >= MAX_RECOVERY_ATTEMPTS:
                        emit_infrastructure_failure(api, snapshot, pending["attempt"])
                        return
                    pending["attempt"] += 1
                    result = emit_recovery(api, snapshot, decision, pending["attempt"])
                    if result == "changed":
                        pending = None
                        previous = None
                        continue
                    pending["ack_deadline"] = time.monotonic() + ACK_TIMEOUT_SECONDS
                    print("Awaiting recovery acknowledgement after attempt %d"
                          % pending["attempt"], flush=True)
                failures = 0
            else:
                decision = decide(snapshot[1], snapshot[2], now)
                if decision != previous:
                    print(json.dumps(decision.__dict__), flush=True)
                    previous = decision
                if args.dry_run or decision.action == "stop":
                    return
                if decision.action == "trigger":
                    result = emit_recovery(api, snapshot, decision, 1)
                    if result == "done":
                        pending = {"incident": incident_identity(snapshot[1], snapshot[2]),
                                   "hb": copy_dict(snapshot[1]),
                                   "owner": copy_dict(snapshot[2]),
                                   "attempt": 1,
                                   "ack_deadline": time.monotonic() + ACK_TIMEOUT_SECONDS}
                        print("Recovery request emitted; waiting for coherent successor acknowledgement",
                              flush=True)
                    elif result == "changed":
                        previous = None
                failures = 0
        except (APIError, OSError, ValueError, KeyError) as error:
            failures += 1
            print("Supervisor check error (%d/3): %s" % (failures, error),
                  file=sys.stderr, flush=True)
            if isinstance(error, APIError) and error.status in (401, 403):
                raise
            if failures >= 3 or args.once:
                raise
        if args.once:
            return
        time.sleep(POLL_SECONDS)
    raise RuntimeError("Supervisor timebox reached; no further monitoring was scheduled")


if __name__ == "__main__":
    main()

