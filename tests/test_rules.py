import json
import tempfile
import unittest
from pathlib import Path

from rules import load_rules, matching_rules
from scan_options import ScanOptions


class RulesTests(unittest.TestCase):
    def test_generic_id_is_not_a_credential(self):
        matches = list(matching_rules(load_rules(), 'records', [{'name': 'id', 'datatype': 'integer'}], True))
        self.assertEqual(matches, [])

    def test_overlapping_categories_yield_one_object_with_all_rules(self):
        matches = list(matching_rules(load_rules(), 'user_passwords', [
            {'name': 'secret_token', 'datatype': 'text'}, {'name': 'id', 'datatype': 'integer'}]))
        self.assertEqual(len(matches), 1)
        self.assertEqual({rule.id for rule in matches[0][1]}, {'identity', 'credentials'})

    def test_literals_and_regexes_are_distinct(self):
        columns = [{'name': 'apiXkey', 'datatype': 'text'}, {'name': 'api.key', 'datatype': 'text'}]
        literal = list(matching_rules(load_rules(keywords='api.key'), 'settings', columns, True))
        regex = list(matching_rules(load_rules(keywords='api.key', mode='regex'), 'settings', columns, True))
        self.assertEqual([item[0] for item in literal], ['api.key'])
        self.assertEqual([item[0] for item in regex], ['apiXkey', 'api.key'])

    def test_combined_signals_exclusions_and_confidence(self):
        path = Path(__file__).resolve().parents[1] / 'examples' / 'rules.json'
        rules = load_rules(path)
        columns = [{'name': 'password', 'datatype': 'text'},
                   {'name': 'password_hint', 'datatype': 'text'},
                   {'name': 'secret_count', 'datatype': 'integer'},
                   {'name': 'api_key', 'datatype': 'varchar'}]
        matches = list(matching_rules(rules, 'accounts', columns, True, 'high'))
        self.assertEqual([name for name, _ in matches], ['password'])
        self.assertEqual(list(matching_rules(rules, 'test_accounts', columns[:1], True)), [])
        self.assertEqual(list(matching_rules(rules, 'inventory', columns[:1], True)), [])

    def test_invalid_regex_duplicate_id_and_unknown_fields_rejected(self):
        with self.assertRaises(ValueError):
            load_rules(keywords='[', mode='regex')
        with self.assertRaises(ValueError):
            load_rules(keywords='password,,token')
        rule = {'id': 'test', 'category': 'test', 'severity': 'low', 'confidence': 'low',
                'description': 'Test', 'match': {'column': 'token'}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'rules.json'
            for definitions in ([rule, rule], [{**rule, 'match': {'typo': 'token'}}],
                                [{**rule, 'severity': 'bogus'}], [{**rule, 'match': {}}]):
                path.write_text(json.dumps({'rules': definitions}))
                with self.assertRaises(ValueError):
                    load_rules(path)

    def test_scope_supports_qualified_names_and_exclusion_wins(self):
        options = ScanOptions(include_database=['app*'], exclude_database=['app_old'],
                              include_table=['public.*'], exclude_table=['*.audit*'])
        self.assertTrue(options.allows('database', 'app_prod'))
        self.assertFalse(options.allows('database', 'app_old'))
        self.assertFalse(options.allows('database', 'other'))
        self.assertTrue(options.allows('table', 'users', 'public.users'))
        self.assertFalse(options.allows('table', 'audit_log', 'public.audit_log'))


if __name__ == '__main__':
    unittest.main()
