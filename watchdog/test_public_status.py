import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from watchdog.render_status import render


class PublicStatusTests(unittest.TestCase):
    def base(self):
        hb = {
            "campaign_id": "mckay-fine-cofinal-test",
            "status": "running",
            "phase": "PROOF_BLIND_RECONSTRUCTION_RUNNING",
            "next_unfinished_action": "COMPARE_SECRET_CANDIDATE_V1",
            "checkpoint_id": "checkpoint-0042",
            "lease_generation": 7,
            "last_heartbeat_utc": "2026-10-28T09:00:00Z",
            "active_assignments": [{"assignment_id": "PRIVATE-MATH-NAME"}],
            "recovery_armed": True,
            "work_event_takeover_observed": True,
            "execution_stopped": False,
            "terminal_delivery_complete": False,
        }
        owner = {"status": "active", "generation": 7, "lease_expires_utc": "2026-10-28T09:12:00Z"}
        pointer = {"campaign_id": hb["campaign_id"], "checkpoint_id": hb["checkpoint_id"]}
        return hb, owner, pointer

    def test_generic_status_only(self):
        hb, owner, pointer = self.base()
        text = render(hb, owner, pointer, generated_at="2026-10-28T09:01:00Z")
        self.assertIn("Proof-blind reconstruction", text)
        self.assertIn("Comparison", text)
        self.assertIn("checkpoint-0042", text)
        self.assertIn("Generation | 7", text)
        self.assertNotIn("SECRET_CANDIDATE", text)
        self.assertNotIn("PRIVATE-MATH-NAME", text)
        self.assertNotIn("next_unfinished_action", text)

    def test_hostile_and_leakage_are_generic(self):
        hb, owner, pointer = self.base()
        hb["phase"] = "HOSTILE_AUDIT_RUNNING"
        hb["next_unfinished_action"] = "LEAKAGE_SOMETHING_PRIVATE_V2"
        text = render(hb, owner, pointer, generated_at="2026-10-28T09:01:00Z")
        self.assertIn("Leakage check", text)
        self.assertNotIn("SOMETHING_PRIVATE", text)


if __name__ == "__main__":
    unittest.main()
