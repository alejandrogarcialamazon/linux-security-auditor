import copy
from datetime import datetime, timezone
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import audit_policy as p
import extended_controls as e
import report_analysis as r
import security_auditor as a
from tools.audit_remote import arguments


def report(status='FAIL'):
    return {'host': 'fixture', 'findings': [{'id': 'CIS-LITE-003', 'status': status, 'severity': 'high', 'recommendation': 'review', 'observed': {'permitrootlogin': 'without-password'}}]}


class PolicyTests(unittest.TestCase):
    def test_profiles(self):
        self.assertEqual(p.evaluate(report(), 'laboratorio')['findings'][0]['status'], 'WARN')
        self.assertEqual(p.evaluate(report())['findings'][0]['status'], 'FAIL')
        source = report(); source['findings'][0]['observed']['permitrootlogin'] = 'yes'
        self.assertEqual(p.evaluate(source, 'laboratorio')['findings'][0]['status'], 'FAIL')

    def test_exception_and_expiry(self):
        entry = {'id': 'CIS-LITE-003', 'host': 'fixture', 'reason': 'test', 'responsible': 'operator', 'expires_at': '2030-01-01T00:00:00Z'}
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        original = report(); saved = copy.deepcopy(original)
        data = p.evaluate(original, entries=[entry], now=now)
        self.assertEqual(data['summary']['EXCEPTED'], 1)
        self.assertEqual(data['summary']['PASS'], 0)
        self.assertEqual(original, saved)
        self.assertEqual(p.evaluate(original, entries=[entry], now=p.expiry(entry['expires_at']))['summary']['FAIL'], 1)
        entry['host'] = 'other'
        self.assertEqual(p.evaluate(original, entries=[entry], now=now)['summary']['FAIL'], 1)

    def test_validation(self):
        for value in ({}, {'version': True, 'exceptions': []}, {'version': 1, 'exceptions': {}}):
            with self.assertRaises(ValueError): p.validate_document(value)
        with self.assertRaises(ValueError): p.expiry('2030-01-01')
        with self.assertRaises(ValueError): p.evaluate(report(), entries={})

    def test_no_exception_on_pass(self):
        entry = {'id': 'CIS-LITE-003', 'host': 'fixture', 'reason': 'x', 'responsible': 'x', 'expires_at': '2030-01-01T00:00:00Z'}
        self.assertEqual(p.evaluate(report('PASS'), entries=[entry])['summary']['PASS'], 1)


class ExtendedTests(unittest.TestCase):
    def test_accounts_and_unknowns(self):
        with tempfile.TemporaryDirectory() as directory:
            passwd = Path(directory)/'passwd'; passwd.write_text('root:x:0:0::/:/bin/sh\nextra:x:0:0::/:/bin/sh\n')
            items = e.audit(lambda argv: (1, '', 'denied'), a.Finding, passwd, Path(directory)/'missing')
            self.assertEqual([item.status for item in items], ['FAIL', 'WARN', 'WARN'])
            passwd.write_text('malformed')
            self.assertEqual(e.audit(lambda argv:(0,'no',''), a.Finding, passwd, passwd)[0].status, 'WARN')

    def test_empty_accounts_inconclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'passwd'; path.write_text('')
            self.assertEqual(e.audit(lambda argv:(0,'yes',''), a.Finding, path, path)[0].status, 'WARN')

    def test_boolean_schema_rejected(self):
        data = report(); data['schema_version'] = True
        with self.assertRaises(ValueError): r.validate(data)

    def test_ntp_exact(self):
        for out, expected in [('yes','PASS'),('no','FAIL'),('unknown','WARN')]:
            self.assertEqual(e.audit(lambda argv:(0,out,''), a.Finding, Path('/not-present'), Path('/not-present'))[-1].status, expected)


class ReportingTests(unittest.TestCase):
    def test_compare(self):
        self.assertEqual(r.compare(report(), report('PASS'))['changes'][0]['change'], 'resolved')
        self.assertEqual(r.compare(report(), report('EXCEPTED'))['changes'][0]['change'], 'changed')
        self.assertEqual(r.compare(report(), {'host':'fixture','findings':[]})['changes'][0]['change'], 'removed')

    def test_reject_incompatible_duplicate(self):
        other = report(); other['host'] = 'different'
        with self.assertRaises(ValueError): r.compare(report(), other)
        other = report(); other['findings'] *= 2
        with self.assertRaises(ValueError): r.validate(other)
        other = report(); other['schema_version'] = 99
        with self.assertRaises(ValueError): r.validate(other)

    def test_coverage(self):
        data = r.enrich(report('WARN'), 0.5)
        self.assertEqual(data['coverage']['review'], 1)
        self.assertEqual(data['coverage']['pass'], 0)
        self.assertEqual(data['execution']['duration_seconds'], .5)

    def test_remote_reject_injection(self):
        for host in ['-oProxyCommand=x', 'host;touch /tmp/x', 'host$(id)']:
            with self.assertRaises(SystemExit): arguments([host, '--user', 'user'])
        with self.assertRaises(SystemExit): arguments(['host', '--user', 'root', '--remediate', 'permissions'])
