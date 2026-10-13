import contextlib
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

from collectors.base import BaseCollector
from reporting import Report
from rules import load_rules
from scan_options import ScanOptions
from scanner import Scanner, bounded_sample, error_status


class FakeCollector(BaseCollector):
    type = 'psql'
    default_database = 'postgres'
    version_query = 'version'
    db_name_query = 'databases'
    table_query = 'tables'
    column_query = 'columns'
    db_privs_query = 'db_privileges'

    def __init__(self, options):
        super().__init__('localhost', 5432, 'analyst', 'not-saved', options=options)
        self.queries = []
        self.connections = []
        self.sample_error = None
        self.metadata_error = None
        self.fail_database = None
        self.closed = False

    def createConnection(self, database=''):
        self.current_database = database or self.default_database
        self.connections.append(self.current_database)
        if database == self.fail_database:
            raise PermissionError('permission denied for database')
        self.connection = True
        self.original_login = 'analyst'
        self.effective_identity = 'analyst_role'

    def execute(self, query):
        self.queries.append((self.current_database, query))
        if query == 'version':
            return [('PostgreSQL 17',)]
        if query == 'databases':
            return [('app',), ('app_archive',), ('other',)]
        if query == 'tables':
            return [('user_passwords', 'public'), ('secret_tokens', 'public'),
                    ('audit_passwords', 'public'), ('secrets', 'private')]
        if query == 'columns':
            if self.metadata_error:
                raise self.metadata_error
            return [('password', 'public', 'user_passwords', 'text'),
                    ('token', 'public', 'secret_tokens', 'varchar'),
                    ('password', 'public', 'audit_passwords', 'text'),
                    ('secret', 'private', 'secrets', 'text')]
        if query == 'db_privileges':
            return [(self.current_database == 'app',)]
        if query.startswith('SELECT'):
            if 'user_passwords' in query and self.sample_error:
                raise self.sample_error
            return [('some,value\nwith "quotes"',)]
        raise AssertionError(f'Unexpected query: {query}')

    def close(self):
        self.closed = True
        self.connection = None


class ScanTests(unittest.TestCase):
    def scan(self, collector, options, directory, database=''):
        scan = Scanner(collector, options, load_rules(), database, directory)
        with contextlib.redirect_stdout(io.StringIO()):
            code = scan.run()
        report = json.loads((Path(directory) / 'report.json').read_text())
        return code, report

    def options(self, **kwargs):
        return ScanOptions(checks=['findings'], include_database=['app*'],
                           exclude_database=['app_archive'], include_schema=['public'],
                           exclude_table=['audit*'], **kwargs)

    def test_scoped_scan_deduplicates_findings_samples_once_and_exports_csv(self):
        options = self.options(sample_rows=2, sample_bytes=100)
        collector = FakeCollector(options)
        with tempfile.TemporaryDirectory() as directory:
            code, report = self.scan(collector, options, directory)
            self.assertEqual(code, 0)
            self.assertEqual(len(report['findings']), 2)
            self.assertEqual(set(report['findings'][0]['rule_ids']), {'credentials', 'identity'})
            self.assertTrue(all(item['effective_identity'] == 'analyst_role' for item in report['findings']))
            self.assertNotIn('not-saved', json.dumps(report))
            samples = [query for _, query in collector.queries if query.startswith('SELECT')]
            self.assertEqual(len(samples), 2)
            self.assertTrue(all('LIMIT 2' in query and 'MAX(' not in query for query in samples))
            self.assertNotIn('app_archive', collector.connections)
            self.assertNotIn('other', collector.connections)
            self.assertEqual(len(report['inventory']['tables']), 2)
            self.assertFalse(any(query == 'db_privileges' for _, query in collector.queries))
            with (Path(directory) / 'findings.csv').open(newline='') as stream:
                records = list(csv.DictReader(stream))
            sample = json.loads(records[0]['evidence'])['sample']['rows'][0][0]
            self.assertEqual(sample, 'some,value\nwith "quotes"')
            self.assertEqual(set(json.loads(records[0]['categories'])), {'credentials', 'identity'})
            markdown = (Path(directory) / 'report.md').read_text()
            self.assertIn('Check coverage', markdown)
            self.assertIn('Original login: analyst', markdown)

    def test_permission_denied_sample_keeps_finding_and_continues(self):
        options = self.options()
        collector = FakeCollector(options)
        collector.sample_error = PermissionError('permission denied for table user_passwords')
        with tempfile.TemporaryDirectory() as directory:
            code, report = self.scan(collector, options, directory)
            self.assertEqual(code, 2)
            self.assertEqual(report['status'], 'partial')
            self.assertEqual(len(report['findings']), 2)
            self.assertEqual(report['findings'][0]['evidence']['sample']['status'], 'permission_denied')
            self.assertEqual(report['findings'][1]['evidence']['sample']['status'], 'completed')

    def test_timeout_is_a_failed_check_not_no_findings(self):
        options = self.options()
        collector = FakeCollector(options)
        collector.sample_error = TimeoutError('query timed out')
        with tempfile.TemporaryDirectory() as directory:
            code, report = self.scan(collector, options, directory)
            self.assertEqual(code, 2)
            self.assertEqual(report['findings'][0]['evidence']['sample']['status'], 'failed')
            self.assertEqual(len(report['findings']), 2)

    def test_interruption_preserves_inventory_and_pending_finding(self):
        options = self.options()
        collector = FakeCollector(options)
        collector.sample_error = KeyboardInterrupt()
        with tempfile.TemporaryDirectory() as directory:
            code, report = self.scan(collector, options, directory)
            self.assertEqual(code, 130)
            self.assertEqual(report['status'], 'interrupted')
            self.assertEqual(report['findings'][0]['evidence']['sample']['status'], 'interrupted')
            self.assertTrue(report['inventory']['columns'])
            self.assertTrue((Path(directory) / 'tables.csv').exists())
            self.assertTrue(collector.closed)

    def test_missing_inventory_skips_detection(self):
        options = self.options()
        collector = FakeCollector(options)
        collector.metadata_error = PermissionError('permission denied for metadata')
        with tempfile.TemporaryDirectory() as directory:
            code, report = self.scan(collector, options, directory)
            self.assertEqual(code, 2)
            self.assertEqual(report['findings'], [])
            self.assertTrue(any(item['name'] == 'findings' and item['status'] == 'skipped'
                                for item in report['checks']))

    def test_skip_data_and_column_mode(self):
        options = self.options(skip_data=True, columns=True)
        collector = FakeCollector(options)
        with tempfile.TemporaryDirectory() as directory:
            code, report = self.scan(collector, options, directory, 'app')
            self.assertEqual(code, 0)
            self.assertFalse(any(query.startswith('SELECT') for _, query in collector.queries))
            self.assertEqual(len(report['findings']), 2)
            self.assertTrue(all(item['evidence']['sample']['status'] == 'skipped' for item in report['findings']))
            self.assertFalse(any(query == 'databases' for _, query in collector.queries))

    def test_database_permissions_switch_to_each_database(self):
        options = ScanOptions(checks=['permissions'])
        collector = FakeCollector(options)
        collector.sys_query = 'db_privileges'
        with tempfile.TemporaryDirectory() as directory:
            code, report = self.scan(collector, options, directory)
            self.assertEqual(code, 0)
            owners = [item['database'] for item in report['findings'] if item['database']]
            self.assertEqual(owners, ['app'])
            self.assertEqual(collector.connections, ['postgres', 'app', 'app_archive', 'other'])

    def test_failed_database_connection_does_not_block_next_database(self):
        options = ScanOptions(checks=['inventory'])
        collector = FakeCollector(options)
        collector.fail_database = 'app'
        with tempfile.TemporaryDirectory() as directory:
            code, report = self.scan(collector, options, directory)
            self.assertEqual(code, 2)
            self.assertTrue(any(item['database'] == 'other' for item in report['inventory']['tables']))
            self.assertEqual(report['inventory']['databases'][0]['status'], 'permission_denied')

    def test_initial_connection_failure_still_writes_reports(self):
        options = self.options()
        collector = FakeCollector(options)
        collector.fail_database = 'app'
        with tempfile.TemporaryDirectory() as directory:
            code, report = self.scan(collector, options, directory, 'app')
            self.assertEqual(code, 1)
            self.assertEqual(report['status'], 'failed')
            self.assertEqual(report['findings'], [])
            self.assertEqual(collector.queries, [])
            self.assertTrue((Path(directory) / 'findings.csv').exists())

    def test_sample_byte_budget_is_applied_to_report_evidence(self):
        options = self.options(sample_bytes=5)
        collector = FakeCollector(options)
        with tempfile.TemporaryDirectory() as directory:
            _, report = self.scan(collector, options, directory)
            for finding in report['findings']:
                sample = finding['evidence']['sample']
                self.assertEqual(sample['value_bytes'], 5)
                self.assertEqual(sample['rows'], [['some,']])
                self.assertTrue(sample['truncated'])

    def test_configuration_privileges_hashes_links_and_emails_share_report(self):
        options = ScanOptions(checks=['permissions', 'configuration', 'hashes', 'connections', 'links', 'emails'])
        collector = FakeCollector(options)
        collector.type = 'mssql'
        collector.impersonation_query = 'impersonation'
        collector.sys_query = 'sysadmin'
        collector.cmd_exec_query = 'configuration'
        collector.hash_query = 'hashes'
        collector.user_query = 'users'
        collector.conn_query = 'connections'
        collector.link_query = 'links'
        collector.email_query = 'emails'
        responses = {
            'impersonation': [('sa',)], 'sysadmin': [(1,)],
            'configuration': [('xp_cmdshell', 1)], 'hashes': [('admin', b'\x01\xff')],
            'users': [('admin', 0)], 'connections': [('client', 'reader')],
            'links': [('linked', 'host')], 'emails': [('a@example.test', 'Subject, with comma', 'line1\nline2')],
            "EXECUTE AS LOGIN = 'sa'": [],
        }
        original_execute = collector.execute

        def execute(query):
            if query in responses:
                collector.queries.append((collector.current_database, query))
                return responses[query]
            return original_execute(query)

        collector.execute = execute
        collector.refresh_identity = lambda: setattr(collector, 'effective_identity', 'sa')
        with tempfile.TemporaryDirectory() as directory:
            code, report = self.scan(collector, options, directory, 'app')
            self.assertEqual(code, 0)
            self.assertEqual({item['category'] for item in report['findings']},
                             {'permissions', 'configuration', 'credentials', 'links', 'sensitive'})
            impersonation = next(item for item in report['findings'] if item['title'] == 'Login impersonation permissions')
            configuration = next(item for item in report['findings'] if item['category'] == 'configuration')
            self.assertEqual(impersonation['effective_identity'], 'analyst_role')
            self.assertEqual(configuration['effective_identity'], 'sa')
            self.assertEqual(configuration['original_login'], 'analyst')
            self.assertEqual((Path(directory) / 'hashcat_mssql.hash').read_text(), '0x01ff\n')
            with (Path(directory) / 'emails_10.csv').open(newline='') as stream:
                row = list(csv.DictReader(stream))[0]
                self.assertEqual(row['Subject'], 'Subject, with comma')
                self.assertEqual(row['Body'], 'line1\nline2')

    def test_sample_budget_handles_multibyte_null_binary_and_multiple_rows(self):
        result = bounded_sample([('ééé', None), (b'\x00\xff', 'extra')], 5)
        self.assertTrue(result['truncated'])
        self.assertLessEqual(result['value_bytes'], 5)
        self.assertEqual(result['rows'][0], ['éé', None])
        self.assertEqual(result['rows'][1], ['0', ''])

    def test_report_checkpoint_and_nonempty_output_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Report(directory, 'localhost', 'psql', 'analyst', {})
            report.check('inventory', 'permission_denied', 'analyst', error='denied')
            report.save()
            saved = json.loads((Path(directory) / 'report.json').read_text())
            self.assertEqual(saved['status'], 'running')
            self.assertEqual(saved['checks'][0]['status'], 'permission_denied')
            with self.assertRaises(ValueError):
                Report(directory, 'localhost', 'psql', 'analyst', {})

    def test_error_classification(self):
        self.assertEqual(error_status(Exception(1142, 'SELECT denied')), 'permission_denied')
        self.assertEqual(error_status(Exception(1146, 'missing table')), 'unsupported')
        self.assertEqual(error_status(NotImplementedError('feature')), 'unsupported')
        self.assertEqual(error_status(RuntimeError('syntax error')), 'failed')


if __name__ == '__main__':
    unittest.main()
