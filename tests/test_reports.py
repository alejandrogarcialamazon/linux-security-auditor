import json
import unittest
from unittest.mock import patch
import security_auditor as a


class ReportTests(unittest.TestCase):
    def test_pass_never_recommends_a_change(self):
        for identifier in ['CIS-LITE-001', 'CIS-LITE-003', 'CIS-LITE-004', 'CIS-LITE-006']:
            f = a.Finding(identifier, 'title', 'PASS', 'high', 'evidence', 'Change something')
            self.assertEqual(f.recommendation, 'Sin cambios necesarios.')
            self.assertTrue(f.expected)
            self.assertTrue(f.risk)

    def test_service_ids_are_unique_stable_in_every_state(self):
        groups = []
        for state in [True, False, None]:
            with patch.object(a, 'service_is_active', return_value=(state, 'fixture')):
                findings = a.audit_services()
            ids = [f.id for f in findings]
            self.assertEqual(len(set(ids)), 5)
            self.assertTrue(all(i.startswith('CIS-LITE-005-') for i in ids))
            groups.append(ids)
        self.assertEqual(groups[0], groups[1])
        self.assertEqual(groups[0], groups[2])

    def test_structured_fields_and_scope_roundtrip(self):
        with patch.object(a, 'service_is_active', return_value=(False, 'inactive')):
            findings = a.audit_services()
        data = json.loads(json.dumps(a.report_data(findings)))
        self.assertEqual(data['scope'], {'checks': 5, 'control_families': 1})
        self.assertTrue(all(f['expected'] and f['risk'] for f in data['findings']))

    def test_all_markdown_fields_escape_pipe_and_newlines(self):
        f = a.Finding('T', 'A|B', 'FAIL', 'high', 'one\ntwo', 'fix|now', expected='want|this', risk='risk\nline')
        result = a.markdown_report(a.report_data([f]))
        for value in ['A\\|B', 'one two', 'fix\\|now', 'want\\|this', 'risk line']:
            self.assertIn(value, result)
        self.assertIn('Criterio esperado', result)

    def test_previous_json_can_still_be_rendered(self):
        data = a.report_data([a.Finding('T', 'title', 'WARN', 'low', 'unknown', 'Review')])
        del data['scope']
        del data['findings'][0]['expected']
        del data['findings'][0]['risk']
        self.assertIn('No registrado', a.markdown_report(data))


if __name__ == '__main__':
    unittest.main()
