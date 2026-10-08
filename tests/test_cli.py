import contextlib
import io
import unittest
from unittest.mock import patch

from sql_enum import build_parser, main, parse_options


class CLITests(unittest.TestCase):
    base = ['psql', '-t', 'localhost', '-u', 'reader', '-p', 'password']

    def parse(self, arguments):
        parser = build_parser()
        args = parser.parse_args(arguments)
        return parse_options(parser, args)

    def test_default_checks_skip_engine_specific_email_check(self):
        options, _ = self.parse(self.base)
        self.assertNotIn('emails', options.checks)
        options, _ = self.parse(['mssql'] + self.base[1:])
        self.assertIn('emails', options.checks)

    def test_selected_checks_and_repeated_scope_filters(self):
        options, _ = self.parse(self.base + ['--checks', 'inventory,findings,inventory',
                                           '--include-database', 'app*', '--include-database', 'corp',
                                           '--exclude-table', '*.audit', '--sample-rows', '5'])
        self.assertEqual(options.checks, ['inventory', 'findings'])
        self.assertEqual(options.include_database, ['app*', 'corp'])
        self.assertEqual(options.sample_rows, 5)

    def test_invalid_options_fail_before_connecting(self):
        invalid = [
            ['--checks', 'inventroy'], ['--sample-rows', '0'], ['--sample-bytes', '-1'],
            ['--query-timeout', '0'], ['--connect-timeout', '0'], ['--port', '65536'],
            ['--filter', '[', '--filter-mode', 'regex'], ['--filter-mode', 'regex'],
            ['--rules', 'does-not-exist.json'], ['--query', 'SELECT 1'], ['--domain', 'CORP'],
            ['--hash', 'abc'], ['--rules', 'rules.json', '--filter', 'password'],
        ]
        for arguments in invalid:
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()), \
                    patch('sql_enum.make_collector') as make_collector:
                with self.assertRaises(SystemExit) as raised:
                    main(self.base + arguments)
                self.assertEqual(raised.exception.code, 2)
                make_collector.assert_not_called()

    def test_single_query_emits_valid_csv_and_closes_connection(self):
        with patch('sql_enum.make_collector') as make_collector:
            make_collector.return_value.execute.return_value = [('a,b', 'line\nbreak')]
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(self.base + ['-d', 'app', '-q', 'SELECT value'])
            self.assertEqual(code, 0)
            self.assertEqual(output.getvalue(), '"a,b","line\nbreak"\r\n')
            make_collector.return_value.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
