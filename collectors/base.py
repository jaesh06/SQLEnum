"""Common connection lifecycle and SQL identifier handling."""

import re
import secrets
from pathlib import Path

from scan_options import ScanOptions


class BaseCollector:
    def __init__(self, target, port, user, password, skip_data=False, columns=False,
                 keywords='', options=None):
        self.target = target
        self.port = int(port)
        self.user = user
        self.password = password
        self.options = options or ScanOptions(skip_data=skip_data, columns=columns)
        self.connection = None
        self.cursor = None
        self.current_database = None
        self.original_login = user
        self.effective_identity = None
        self.impersonate = False
        name = re.sub(r'[^a-zA-Z0-9_-]', '-', target)
        self.dir_name = str(Path('results') / f'{name}_{self.type}_{secrets.token_hex(4)}')

    def close(self):
        cursor, connection = self.cursor, self.connection
        self.cursor = self.connection = None
        if cursor is not None:
            try:
                cursor.close()
            except Exception:
                pass
        if connection is not None:
            try:
                if hasattr(connection, 'disconnect'):
                    connection.disconnect()
                else:
                    connection.close()
            except Exception:
                pass

    def createConnection(self, database=''):
        self.close()
        self.current_database = database or self.default_database
        self.effective_identity = None
        try:
            self._connect(self.current_database)
            if self.impersonate:
                self.cursor.execute("EXECUTE AS LOGIN = 'sa'")
                self.cursor.execute(f'USE {self.quote_identifier(self.current_database)}')
            self.refresh_identity()
        except BaseException:
            self.close()
            raise

    def refresh_identity(self):
        self.cursor.execute(self.identity_query)
        row = self.cursor.fetchone()
        if not row:
            raise RuntimeError('Database returned no connection identity.')
        self.original_login, self.effective_identity = row[0], row[1]

    def use_database(self, database):
        database = database or self.default_database
        if self.connection is None or database != self.current_database:
            self.createConnection(database)

    def execute(self, query):
        if self.connection is None:
            self.createConnection(self.current_database)
        try:
            self.cursor.execute(query)
            # Native MSSQL returns Row objects, unlike the other drivers.
            # Normalize these here so report evidence stays structured JSON.
            return [tuple(row) for row in self.cursor.fetchall()] if self.cursor.description else []
        except Exception:
            # A timed-out socket may have unread results. Reconnect for the next
            # check rather than accidentally attributing those rows to it.
            self.close()
            raise

    def quote_identifier(self, identifier):
        if self.type == 'mssql':
            return '[' + identifier.replace(']', ']]') + ']'
        if self.type == 'mysql':
            return '`' + identifier.replace('`', '``') + '`'
        return '"' + identifier.replace('"', '""') + '"'

    def quoted_table(self, schema, table):
        return f'{self.quote_identifier(schema)}.{self.quote_identifier(table)}'

    def sample_query(self, schema, table, columns):
        expressions = []
        for column in columns:
            identifier = self.quote_identifier(column)
            if self.type == 'mssql':
                expression = f'LEFT(CONVERT(nvarchar(max), {identifier}), {self.options.sample_bytes})'
            elif self.type == 'mysql':
                expression = f'LEFT(CAST({identifier} AS CHAR), {self.options.sample_bytes})'
            else:
                expression = f'LEFT(CAST({identifier} AS text), {self.options.sample_bytes})'
            expressions.append(f'{expression} AS {identifier}')
        if not expressions:
            raise ValueError('No visible columns to sample.')
        projection = ', '.join(expressions)
        source = self.quoted_table(schema, table)
        limit = self.options.sample_rows
        if self.type == 'mssql':
            return f'SELECT TOP {limit} {projection} FROM {source}'
        return f'SELECT {projection} FROM {source} LIMIT {limit}'
