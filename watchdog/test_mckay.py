import copy
from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch, Mock
from supervisor import decide, recovery_acknowledged, incident_identity, GitHubAPI, main
from event_policy import classify_event
from supervisor import emit_diagnostic, TEST_FIXTURE_ID, TEST_FIXTURE_SHA256


class DiagnosticTransportTests(unittest.TestCase):
    def setUp(self):
        self.identity = 'mckay-supervisor-e2e-unit-test'
        self.snapshot = ('test-commit',
            {'_active_pointer': {'status': 'NO_CONFIRMED_CAMPAIGN', 'mathematics_authorized': False},
             'status': 'NO_CONFIRMED_CAMPAIGN', 'mathematics_started': False},
            {'status': 'inactive', 'owner_run_id': None})
        self.api = Mock(repo='tpuzz/mckay-watchdog')
        self.api.snapshot.return_value = self.snapshot
        self.receipt = {'fixture_id': TEST_FIXTURE_ID, 'fixture_sha256': TEST_FIXTURE_SHA256,
                        'status': 'EVENT_TEST_PASSED', 'lease_release_verified': True}
        self.calls = []
        self.marker = None
        self.api.file.side_effect = lambda path, ref: self.receipt if '/receipts/' in path else self.marker
        self.api.request.side_effect = self.request

    def request(self, method, endpoint, payload=None, **kwargs):
        self.calls.append((method, endpoint, payload))
        if method == 'GET' and endpoint.startswith('/pulls?'): return []
        if method == 'GET' and endpoint.startswith('/git/ref/'): return None
        if method == 'GET' and endpoint.startswith('/git/commits/'): return {'tree': {'sha': 'tree'}}
        if method == 'POST' and endpoint == '/git/trees':
            import json
            self.marker = json.loads(payload['tree'][0]['content'])
            return {'sha': 'new-tree'}
        if method == 'POST' and endpoint == '/git/commits': return {'sha': 'new-commit'}
        if method == 'POST' and endpoint == '/git/refs': return {}
        if method == 'POST' and endpoint == '/pulls': return {'html_url': 'https://github.com/tpuzz/mckay-watchdog/pull/999', **payload}
        raise AssertionError((method, endpoint))

    def test_transport_emits_only_fixture_branch_and_test_pr(self):
        result = emit_diagnostic(self.api, self.identity)
        self.assertTrue(result['title'].startswith('MCKAY_FINE_RECOVERY_TEST NON-MATHEMATICAL '))
        self.assertTrue(self.marker['test_only'])
        self.assertFalse(self.marker['mathematics_authorized'])
        self.assertEqual(self.marker['fixture_id'], TEST_FIXTURE_ID)
        refs = [p for method, endpoint, p in self.calls if endpoint == '/git/refs']
        self.assertEqual(refs[0]['ref'], 'refs/heads/watchdog-diagnostic-' + self.identity)
        self.assertFalse(any('/contents/' in endpoint for _, endpoint, _ in self.calls))

    def test_confirmed_production_blocks_test_before_mutation(self):
        self.snapshot[1]['_active_pointer']['status'] = 'CONFIRMED'
        with self.assertRaises(ValueError): emit_diagnostic(self.api, self.identity)
        self.assertEqual(self.calls, [])

    def test_missing_verified_receipt_blocks_test(self):
        self.receipt['status'] = 'INCOMPLETE'
        with self.assertRaises(ValueError): emit_diagnostic(self.api, self.identity)
        self.assertEqual(self.calls, [])

    def test_production_race_does_not_emit_pr(self):
        changed = copy.deepcopy(self.snapshot)
        changed[2]['owner_run_id'] = 'new-production-owner'
        self.api.snapshot.side_effect = [self.snapshot, changed]
        with self.assertRaises(ValueError): emit_diagnostic(self.api, self.identity)
        self.assertFalse(any(method == 'POST' and endpoint == '/pulls' for method, endpoint, _ in self.calls))

    def test_repeated_diagnostic_is_noop(self):
        self.api.request.side_effect = None
        self.api.request.return_value = [{'title': 'MCKAY_FINE_RECOVERY_TEST NON-MATHEMATICAL ' + self.identity,
                                         'html_url': 'https://github.com/tpuzz/mckay-watchdog/pull/999'}]
        emit_diagnostic(self.api, self.identity)
        self.assertEqual(self.api.request.call_count, 1)
        self.assertEqual(self.api.request.call_args.args[0], 'GET')

    def test_invalid_identity_is_rejected_without_access(self):
        with self.assertRaises(ValueError): emit_diagnostic(self.api, '../unsafe')
        self.api.snapshot.assert_not_called()

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
