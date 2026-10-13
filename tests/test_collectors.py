import unittest
from unittest.mock import MagicMock, patch

import mssql_python

from collectors.mssql import ImpacketMSSQLCursor, MSSQLCollector
from collectors.mysql import MySQLCollector
from collectors.psql import PostgreSQLCollector
from scan_options import ScanOptions


class CollectorTests(unittest.TestCase):
    def options(self):
        return ScanOptions(connect_timeout=7, query_timeout=13, sample_rows=3, sample_bytes=50)

    def connection(self):
        connection = MagicMock(spec=['cursor', 'close', 'timeout', 'autocommit'])
        connection.cursor.return_value.fetchone.return_value = ('original', 'effective')
        return connection

    def test_mysql_timeouts_and_database_scoping(self):
        collector = MySQLCollector('localhost', 3306, 'reader', 'password', options=self.options())
        with patch('collectors.mysql.pymysql.connect', return_value=self.connection()) as connect:
            collector.createConnection('app')
            self.assertEqual(connect.call_args.kwargs['connect_timeout'], 7)
            self.assertEqual(connect.call_args.kwargs['read_timeout'], 13)
            self.assertEqual(connect.call_args.kwargs['write_timeout'], 13)
            self.assertEqual(connect.call_args.kwargs['database'], 'app')
            for query in (collector.table_query, collector.column_query, collector.db_privs_query):
                self.assertIn('= DATABASE()', query)
            self.assertEqual(collector.effective_identity, 'effective')
            collector.close()

    def test_postgres_statement_timeout_and_reconnect_cleanup(self):
        first, second = self.connection(), self.connection()
        collector = PostgreSQLCollector('localhost', 5432, 'reader', 'password', options=self.options())
        with patch('collectors.psql.psycopg2.connect', side_effect=[first, second]) as connect:
            collector.createConnection('app')
            self.assertEqual(connect.call_args.kwargs['options'], '-c statement_timeout=13000')
            self.assertEqual(connect.call_args.kwargs['connect_timeout'], 7)
            self.assertTrue(first.autocommit)
            collector.use_database('other')
            first.close.assert_called_once()
            first.cursor.return_value.close.assert_called_once()
            self.assertEqual(connect.call_args.kwargs['dbname'], 'other')
            collector.close()

    def test_native_mssql_timeout_and_connection_string_escaping(self):
        connection = self.connection()
        collector = MSSQLCollector('localhost', 1433, 'reader', 'pw;}more', options=self.options())
        with patch('collectors.mssql.mssql_python.connect', return_value=connection) as connect:
            collector.createConnection('db;name')
            self.assertEqual(connect.call_args.kwargs['timeout'], 13)
            self.assertEqual(connect.call_args.kwargs['attrs_before'][mssql_python.SQL_ATTR_LOGIN_TIMEOUT], 7)
            self.assertEqual(connection.timeout, 13)
            self.assertIn('PWD={pw;}}more};', connect.call_args.args[0])
            self.assertIn('DATABASE={db;name};', connect.call_args.args[0])
            collector.close()

    def test_reconnected_mssql_impersonates_before_selecting_database(self):
        connection = self.connection()
        collector = MSSQLCollector('localhost', 1433, 'reader', 'password', options=self.options())
        collector.impersonate = True
        with patch('collectors.mssql.mssql_python.connect', return_value=connection) as connect:
            collector.createConnection('restricted]db')
            self.assertIn('DATABASE={master};', connect.call_args.args[0])
            queries = [call.args[0] for call in connection.cursor.return_value.execute.call_args_list]
            self.assertEqual(queries[:2], ["EXECUTE AS LOGIN = 'sa'", 'USE [restricted]]db]'])
            collector.close()

    def test_impacket_connect_and_query_socket_timeouts(self):
        connection, sock = MagicMock(), MagicMock()
        connection.login.return_value = True
        connection.batch.return_value = [('DOMAIN\\reader', 'DOMAIN\\reader')]
        connection.colMeta = [{'Name': 'original'}, {'Name': 'effective'}]
        collector = MSSQLCollector('localhost', 1433, 'reader', None, domain='DOMAIN',
                                   ntlm_hash='abc', options=self.options())
        with patch('collectors.mssql.MSSQL', return_value=connection), \
                patch('collectors.mssql.socket.create_connection', return_value=sock) as connect:
            collector.createConnection('app')
            connect.assert_called_once_with(('localhost', 1433), timeout=7)
            sock.settimeout.assert_called_once_with(13)
            self.assertEqual(connection.login.call_args.kwargs['hashes'],
                             'aad3b435b51404eeaad3b435b51404ee:abc')
            self.assertEqual(collector.original_login, 'DOMAIN\\reader')
            collector.close()
            connection.disconnect.assert_called_once()

    def test_impacket_errors_are_raised_not_empty_success(self):
        connection = MagicMock()
        connection.batch.return_value = []
        error = RuntimeError('SELECT permission was denied')
        connection.printReplies.side_effect = lambda **kwargs: kwargs['error_logger'](error)
        cursor = ImpacketMSSQLCursor(connection)
        with self.assertRaisesRegex(RuntimeError, 'permission'):
            cursor.execute('SELECT secret')
        self.assertEqual(cursor.fetchall(), [])

    def test_query_error_discards_connection_before_next_check(self):
        first, second = self.connection(), self.connection()
        second.cursor.return_value.fetchall.return_value = [('ok',)]
        collector = PostgreSQLCollector('localhost', 5432, 'reader', 'password', options=self.options())
        with patch('collectors.psql.psycopg2.connect', side_effect=[first, second]):
            collector.createConnection('app')
            first.cursor.return_value.execute.side_effect = TimeoutError('query timed out')
            with self.assertRaises(TimeoutError):
                collector.execute('SELECT slow')
            self.assertIsNone(collector.connection)
            first.close.assert_called_once()
            self.assertEqual(collector.execute('SELECT next'), [('ok',)])
            self.assertEqual(collector.current_database, 'app')
            collector.close()

    def test_sample_queries_escape_identifiers_and_bound_rows_and_cells(self):
        for cls, port, expected in (
            (MSSQLCollector, 1433, '[odd]]schema].[a.b]'),
            (MySQLCollector, 3306, '`odd``schema`.`a.b`'),
            (PostgreSQLCollector, 5432, '"odd""schema"."a.b"'),
        ):
            with self.subTest(engine=cls.type):
                collector = cls('localhost', port, 'reader', 'password', options=self.options())
                delimiter = {'mssql': ']', 'mysql': '`', 'psql': '"'}[cls.type]
                sql = collector.sample_query(f'odd{delimiter}schema', 'a.b', [f'pass{delimiter}word'])
                self.assertIn(expected, sql)
                self.assertIn('LEFT(', sql)
                self.assertIn('50)', sql)
                self.assertIn('TOP 3' if cls.type == 'mssql' else 'LIMIT 3', sql)
                self.assertNotIn('MAX(', sql)
                self.assertNotIn('SELECT *', sql)

    def test_mysql_version_suffixes_do_not_break_hash_query(self):
        collector = MySQLCollector('localhost', 3306, 'reader', 'password')
        self.assertIn('authentication_string', collector.hash_query_for_version('8.0.36-ubuntu'))
        self.assertIn('authentication_string', collector.hash_query_for_version('10.11.6-MariaDB'))
        self.assertIn('password FROM', collector.hash_query_for_version('5.6.51'))
        with self.assertRaises(NotImplementedError):
            collector.hash_query_for_version('unknown')


if __name__ == '__main__':
    unittest.main()
