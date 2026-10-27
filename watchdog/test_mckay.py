import copy
from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch
from supervisor import decide, recovery_acknowledged, incident_identity, GitHubAPI, main
from event_policy import classify_event

class McKaySafetyTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
        self.p = dict(status='CONFIRMED', campaign_id='mckay-fine-fixture-only',
            statement_version='DIAGNOSTIC-v1', statement_sha256='1'*64,
            authorization_id='NONMAT-TEST', authorization_sha256='2'*64,
            checkpoint_id='DIAGNOSTIC-CHECKPOINT', checkpoint_sha256='3'*64,
            next_unfinished_action='diagnostic-action-v1',checkpoint_filename='diagnostic-checkpoint.json',
            authorization_filename='diagnostic-authorization.json',statement_filename='diagnostic-statement.txt')
        self.h = dict(self.p, run_id='old-test-run', lease_generation=1, status='running',
            last_heartbeat_utc=(self.now-timedelta(minutes=21)).isoformat(),
            hard_deadline_utc=(self.now+timedelta(hours=1)).isoformat(),
            delivery_reserve_utc=(self.now+timedelta(minutes=50)).isoformat(),
            _active_pointer=self.p)
        self.o = dict(campaign_id=self.p['campaign_id'],authorization_id=self.p['authorization_id'],
            owner_run_id='old-test-run', generation=1, status='active',
            lease_expires_utc=(self.now-timedelta(minutes=1)).isoformat())

    def test_no_confirmed_campaign_always_stops(self):
        self.h['_active_pointer']={'status':'NO_CONFIRMED_CAMPAIGN'}
        self.assertEqual(decide(self.h,self.o,self.now).action,'stop')

    def test_missing_pointer_fails_closed(self):
        del self.h['_active_pointer']
        self.assertEqual(decide(self.h,self.o,self.now).action,'wait')

    def test_every_binding_is_mandatory(self):
        for key in self.p:
            if key=='status': continue
            with self.subTest(key=key):
                h=copy.deepcopy(self.h);h[key]='wrong'
                self.assertEqual(decide(h,self.o,self.now).action,'wait')

    def test_expired_stale_owner_is_only_a_signal(self):
        d=decide(self.h,self.o,self.now)
        self.assertEqual(d.action,'trigger')
        self.assertEqual(d.mode,'verify_private_authorization')

    def test_fresh_owner_blocks(self):
        self.o['lease_expires_utc']=(self.now+timedelta(minutes=12)).isoformat()
        self.assertEqual(decide(self.h,self.o,self.now).action,'wait')

    def test_fresh_heartbeat_blocks(self):
        self.h['last_heartbeat_utc']=self.now.isoformat()
        self.assertEqual(decide(self.h,self.o,self.now).action,'wait')

    def test_successor_blocks(self):
        self.o.update(owner_run_id='successor',generation=2,
            lease_expires_utc=(self.now+timedelta(minutes=12)).isoformat())
        self.assertEqual(decide(self.h,self.o,self.now).action,'wait')

    def test_stop_pause_cancel(self):
        for status in ['PAUSED','CANCELLED','STOPPED']:
            with self.subTest(status=status):
                self.p['status']=status
                self.assertEqual(decide(self.h,self.o,self.now).action,'stop')

    def test_completed_needs_delivery_and_private_verification(self):
        self.h.update(status='completed',terminal_delivery_complete=True)
        self.assertEqual(decide(self.h,self.o,self.now).mode,'finalize_only')
        self.h['dropbox_final_status_verified']=True
        self.assertEqual(decide(self.h,self.o,self.now).action,'stop')

    def test_receipt_not_lease_is_required(self):
        h,o=copy.deepcopy(self.h),copy.deepcopy(self.o)
        h.update(run_id='new-test-run',lease_generation=2,last_heartbeat_utc=self.now.isoformat())
        o.update(owner_run_id='new-test-run',generation=2,
            lease_expires_utc=(self.now+timedelta(minutes=12)).isoformat())
        self.assertFalse(recovery_acknowledged(self.h,self.o,h,o,self.now))
        receipt={key:self.h[key] for key in ['campaign_id','statement_version','statement_sha256',
            'authorization_id','authorization_sha256','hard_deadline_utc','delivery_reserve_utc']}
        receipt.update(execution_kind='WORK_EVENT', status='RESEARCH_STARTED',
            source_bytes_verified=True,authorization_verified=True,ownership_readback_verified=True,
            bootstrap_readback_verified=True,event_execution_id='fixture-event',assignment_id='fixture-assignment',
            started_at_utc=self.now.isoformat(),input_checkpoint_id=self.p['checkpoint_id'],
            input_checkpoint_sha256=self.p['checkpoint_sha256'],resumed_action=self.p['next_unfinished_action'],
            owner_run_id=o['owner_run_id'],generation=o['generation'])
        h['_recovery_receipt']=receipt
        self.assertTrue(recovery_acknowledged(self.h,self.o,h,o,self.now))
        for key in ['input_checkpoint_sha256','authorization_id','hard_deadline_utc','assignment_id']:
            saved=receipt[key];receipt[key]=''
            self.assertFalse(recovery_acknowledged(self.h,self.o,h,o,self.now));receipt[key]=saved

    def test_incident_dedup_changes_only_with_exact_identity(self):
        first=incident_identity(self.h,self.o)
        self.assertEqual(first,incident_identity(copy.deepcopy(self.h),copy.deepcopy(self.o)))
        self.o['generation']+=1
        self.assertNotEqual(first,incident_identity(self.h,self.o))

    def test_api_rejects_other_repositories(self):
        with self.assertRaises(ValueError):GitHubAPI('tpuzz/another-repository','test-token')

    def test_main_rejects_wrong_repository_before_snapshot_or_mutation(self):
        with patch.dict('os.environ',{'GITHUB_REPOSITORY':'tpuzz/mckay-watchdog','GH_TOKEN':'test'}), \
             patch('sys.argv',['supervisor.py','--once']), \
             patch('supervisor.GitHubAPI.request', return_value={'full_name':'tpuzz/unrelated','private':False}) as request, \
             patch('supervisor.GitHubAPI.snapshot') as snapshot:
            with self.assertRaises(ValueError):main()
            request.assert_called_once_with('GET','');snapshot.assert_not_called()

    def test_only_opened_exact_repo_and_four_prefixes(self):
        e={'action':'opened','repository':{'full_name':'tpuzz/mckay-watchdog','private':True},
            'pull_request':{'title':'MCKAY_FINE_RECOVERY_TEST diagnostic',
                'base':{'repo':{'full_name':'tpuzz/mckay-watchdog'}}}}
        for prefix,kind in [('MCKAY_FINE_RECOVERY_TEST','test'),('MCKAY_FINE_WORKFLOW_STALE','recovery'),
                ('MCKAY_FINE_WORKFLOW_TERMINAL','delivery'),('MCKAY_FINE_INFRA_FAILURE','diagnostic')]:
            e['pull_request']['title']=prefix+' diagnostic';self.assertEqual(classify_event(e),kind)
        for action in ['closed','ready_for_review','synchronize','edited','reopened',None]:
            e['action']=action;self.assertEqual(classify_event(e),'ignore')
        e['action']='opened';e['repository']['full_name']='tpuzz/unrelated'
        self.assertEqual(classify_event(e),'ignore')
        e['repository']['full_name']='tpuzz/mckay-watchdog';e['pull_request']['title']='unrelated'
        self.assertEqual(classify_event(e),'ignore')

if __name__=='__main__':unittest.main()
