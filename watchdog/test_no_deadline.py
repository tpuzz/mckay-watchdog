"""No mathematical content: startup authorization/clock regression tests."""
import copy
import unittest
import json
import base64
from unittest.mock import Mock, patch
from datetime import timedelta
import test_mckay
from supervisor import startup_receipt_valid, recovery_acknowledged, decide, record_supervision_observation, APIError

class ExplicitNoDeadlineTests(unittest.TestCase):
    def setUp(self):
        fixture=test_mckay.McKaySafetyTests()
        fixture.setUp()
        self.old,self.owner,self.now=fixture.h,fixture.o,fixture.now
        self.old.update(hard_deadline_utc=None,delivery_reserve_utc=None,no_deadline_authorized=True)
        self.new=copy.deepcopy(self.old)
        self.new.update(run_id="new-test-run",lease_generation=2,last_heartbeat_utc=self.now.isoformat())
        self.new_owner=copy.deepcopy(self.owner)
        self.new_owner.update(owner_run_id="new-test-run",generation=2,status="active",
                              lease_expires_utc=(self.now+timedelta(minutes=12)).isoformat())
        fields=("campaign_id","statement_version","statement_sha256","authorization_id",
                "authorization_sha256","hard_deadline_utc","delivery_reserve_utc","no_deadline_authorized")
        self.receipt={k:self.old[k] for k in fields}
        self.receipt.update(execution_kind="WORK_EVENT",status="RESEARCH_STARTED",
            source_bytes_verified=True,authorization_verified=True,ownership_readback_verified=True,
            bootstrap_readback_verified=True,event_execution_id="test-event",assignment_id="test-assignment",
            started_at_utc=self.now.isoformat(),input_checkpoint_id=self.old["checkpoint_id"],
            input_checkpoint_sha256=self.old["checkpoint_sha256"],
            resumed_action=self.old["next_unfinished_action"],
            owner_run_id=self.new_owner["owner_run_id"],generation=2)
        self.new["_recovery_receipt"]=self.receipt

    def valid(self):
        return recovery_acknowledged(self.old,self.owner,self.new,self.new_owner,self.now)

    def test_explicit_authorized_nulls_are_acknowledged(self):
        self.assertTrue(self.valid())

    def test_missing_is_not_null(self):
        for record in (self.old,self.new,self.receipt):
            for key in ("hard_deadline_utc","delivery_reserve_utc"):
                with self.subTest(record=id(record),key=key):
                    value=record.pop(key)
                    self.assertFalse(self.valid())
                    record[key]=value

    def test_no_deadline_authorization_required_in_all_bindings(self):
        for record in (self.old,self.new,self.receipt):
            for bad in (False,None,"true",1):
                with self.subTest(record=id(record),bad=bad):
                    record["no_deadline_authorized"]=bad
                    self.assertFalse(self.valid())
            del record["no_deadline_authorized"]
            self.assertFalse(self.valid())
            record["no_deadline_authorized"]=True

    def test_mixed_null_and_timed_clock_rejected(self):
        for record in (self.old,self.new,self.receipt):
            record["delivery_reserve_utc"]=(self.now+timedelta(minutes=50)).isoformat()
        self.assertFalse(self.valid())

    def test_timed_authorization_exact_match(self):
        for record in (self.old,self.new,self.receipt):
            record["hard_deadline_utc"]=(self.now+timedelta(hours=1)).isoformat()
            record["delivery_reserve_utc"]=(self.now+timedelta(minutes=50)).isoformat()
            record.pop("no_deadline_authorized")
        self.assertTrue(self.valid())
        for record in (self.new,self.receipt):
            for key in ("hard_deadline_utc","delivery_reserve_utc"):
                saved=record[key]
                for bad in (None,"",False,"different"):
                    record[key]=bad
                    self.assertFalse(self.valid())
                record[key]=saved

    def test_identity_and_checkpoint_still_required(self):
        for key in ("campaign_id","statement_version","statement_sha256","authorization_id",
                    "authorization_sha256","input_checkpoint_id","input_checkpoint_sha256",
                    "resumed_action","owner_run_id","generation","assignment_id","event_execution_id"):
            with self.subTest(key=key):
                saved=self.receipt[key];self.receipt[key]="wrong" if key not in ("assignment_id","event_execution_id") else ""
                self.assertFalse(self.valid());self.receipt[key]=saved

    def test_actual_start_and_private_verification_still_required(self):
        for key in ("source_bytes_verified","authorization_verified","ownership_readback_verified",
                    "bootstrap_readback_verified"):
            self.receipt[key]=False;self.assertFalse(self.valid());self.receipt[key]=True
        for status in ("BOOTSTRAP_VERIFIED","OWNER_ACQUIRED","",None):
            self.receipt["status"]=status;self.assertFalse(self.valid())
        self.receipt["status"]="RESEARCH_STARTED"
        self.receipt["execution_kind"]="WORK_SESSION"
        self.assertFalse(self.valid())

    def test_supported_campaign_execution_statuses(self):
        for status in ("running","checkpointed","interrupted","blocked"):
            self.new["status"]=status
            self.assertTrue(self.valid())
        self.new["status"]="unknown-phase"
        self.assertFalse(self.valid())
        for status in ("running","checkpointed","interrupted","blocked"):
            self.old["status"]=status
            self.assertNotEqual(decide(self.old,self.owner,self.now).reason,"Unknown status")

    def observation(self):
        pointer=self.new["_active_pointer"]
        pointer.update(mathematics_authorized=True,hard_deadline_utc=None,
                       delivery_reserve_utc=None,no_deadline_authorized=True)
        return ("snapshot-commit",self.new,self.new_owner)

    def test_observation_is_bound_and_is_not_a_research_start(self):
        snapshot=self.observation()
        api=Mock()
        api.request.side_effect=[APIError(404,"not present"),{}]
        with patch.dict("os.environ",{"GITHUB_RUN_ID":"fixture-run","GITHUB_SHA":"fixture-sha"}):
            path=record_supervision_observation(api,snapshot,decide(self.new,self.new_owner,self.now),self.now)
        self.assertTrue(path.endswith("-supervision-g2.json"))
        record=json.loads(base64.b64decode(api.request.call_args.args[2]["content"]))
        self.assertEqual(record["checkpoint_sha256"],self.new["checkpoint_sha256"])
        self.assertEqual(record["status"],"SUPERVISION_BINDING_OBSERVED")
        self.assertFalse(record["research_start_verified"])

    def test_invalid_binding_or_missing_execution_never_writes_observation(self):
        snapshot=self.observation()
        api=Mock()
        self.new["checkpoint_sha256"]="bad"
        with patch.dict("os.environ",{"GITHUB_RUN_ID":"fixture-run","GITHUB_SHA":"fixture-sha"}):
            self.assertIsNone(record_supervision_observation(api,snapshot,decide(self.new,self.new_owner,self.now),self.now))
        api.request.assert_not_called()
        self.new["checkpoint_sha256"]=self.old["checkpoint_sha256"]
        with patch.dict("os.environ",{},clear=True):
            self.assertIsNone(record_supervision_observation(api,snapshot,decide(self.new,self.new_owner,self.now),self.now))
        api.request.assert_not_called()

if __name__=="__main__":
    unittest.main()

