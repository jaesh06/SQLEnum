"""Check orchestration, scoped inventory, and incremental finding collection."""

from reporting import Report, write_csv
from rules import CONFIDENCE, SEVERITY, matching_rules
from scan_options import CHECKS


def error_status(error):
    code = getattr(error, 'pgcode', None)
    numbers = {argument for argument in error.args if isinstance(argument, int)}
    message = str(error).lower()
    if (code == '42501' or numbers & {1044, 1045, 1142, 1143, 1227, 229, 916}
            or any(text in message for text in ('permission denied', 'access denied',
                                                'permission was denied', 'does not have permission'))):
        return 'permission_denied'
    if (isinstance(error, NotImplementedError) or code in {'42P01', '42883', '42703'}
            or numbers & {1146, 1054, 1305}
            or 'invalid object name' in message or 'invalid column name' in message):
        return 'unsupported'
    return 'failed'


def bounded_sample(rows, byte_limit):
    """Limit total UTF-8 sample value bytes, preserving row/column positions."""
    remaining, truncated, output = byte_limit, False, []
    for row in rows:
        values = []
        for value in row:
            if value is None:
                values.append(None)
                continue
            text = value.hex() if isinstance(value, bytes) else str(value)
            encoded = text.encode('utf-8')
            shortened = encoded[:remaining].decode('utf-8', errors='ignore')
            remaining -= len(shortened.encode('utf-8'))
            truncated = truncated or len(encoded) > len(shortened.encode('utf-8'))
            values.append(shortened)
        output.append(values)
    return {'rows': output, 'truncated': truncated, 'value_bytes': byte_limit - remaining}


class Scanner:
    def __init__(self, collector, options, rules, database='', directory=None, rule_source='built-in'):
        self.collector = collector
        self.options = options
        self.rules = rules
        self.database = database
        configuration = options.as_dict()
        configuration.update({'database': database or None, 'port': collector.port,
                              'rule_source': rule_source,
                              'rules': [self.describe_rule(rule) for rule in rules]})
        self.report = Report(directory or collector.dir_name, collector.target,
                             collector.type, collector.original_login, configuration)
        self.tables = {}
        self.progress = 0
        self.version = None

    @staticmethod
    def describe_rule(rule):
        return {**{key: getattr(rule, key) for key in ('id', 'category', 'severity', 'confidence', 'description')},
                'match': {key: pattern.pattern for key, pattern in rule.match.items()},
                'exclude': {key: pattern.pattern for key, pattern in rule.exclude.items()}}

    def run_check(self, name, action, database=None, schema=None, object_name=None,
                  evidence=None):
        self.progress += 1
        location = '.'.join(part for part in (database, schema, object_name) if part)
        print(f'[{self.progress}] {name}' + (f' — {location}' if location else ''), flush=True)
        context = {'database': database, 'schema': schema, 'object_name': object_name}
        try:
            result = action()
            self.report.data['original_login'] = self.collector.original_login
            self.report.check(name, 'completed', self.collector.effective_identity,
                              evidence=evidence(result) if evidence else result, **context)
            return result
        except KeyboardInterrupt:
            self.report.check(name, 'interrupted', self.collector.effective_identity, **context)
            raise
        except Exception as error:
            status = error_status(error)
            self.report.check(name, status, self.collector.effective_identity,
                              error=str(error), **context)
            print(f'    {status}: {error}', flush=True)
            return None
        finally:
            self.report.save()

    def query(self, name, sql, database=None, schema=None, object_name=None, evidence=None):
        def execute():
            if database is not None:
                self.collector.use_database(database)
            return self.collector.execute(sql)
        return self.run_check(name, execute, database, schema, object_name, evidence)

    def finding(self, title, category, explanation, evidence, severity='medium',
                confidence='high', **context):
        return self.report.finding(title, category, severity, confidence,
                                   self.collector.effective_identity, explanation,
                                   evidence, **context)

    def export(self, filename, headers, rows):
        write_csv(self.report.directory / filename, headers, rows)

    def run(self):
        status, exit_code = 'completed', 0
        self.report.save()
        try:
            for check in CHECKS:
                if check not in self.options.checks and not (check == 'inventory' and 'findings' in self.options.checks):
                    self.report.check(check, 'skipped', None, evidence='Not selected.')
            connected = self.run_check('connection', self.connect)
            if connected is None:
                status, exit_code = 'failed', 1
            else:
                rows = self.query('version', self.collector.version_query)
                if rows:
                    self.version = str(rows[0][0])
                    print(f'Database version: {self.version}')
                if 'permissions' in self.options.checks:
                    self.server_permissions()
                if 'configuration' in self.options.checks:
                    self.configuration()
                if 'hashes' in self.options.checks:
                    self.hashes()
                if 'connections' in self.options.checks:
                    self.connections()
                if 'links' in self.options.checks and self.collector.type == 'mssql':
                    self.links()
                if 'emails' in self.options.checks:
                    self.emails()
                if (set(self.options.checks) & {'inventory', 'findings', 'permissions'}
                        or ('links' in self.options.checks and self.collector.type != 'mssql')):
                    self.scan_databases()
                if any(check['status'] in {'failed', 'permission_denied', 'unsupported'}
                       for check in self.report.data['checks']):
                    status, exit_code = 'partial', 2
        except KeyboardInterrupt:
            status, exit_code = 'interrupted', 130
        except Exception as error:
            self.report.check('scan', 'failed', self.collector.effective_identity, error=str(error))
            status, exit_code = 'failed', 1
        finally:
            self.collector.close()
            self.export_inventory()
            self.report.finish(status)
            print(self.report.summary())
        return exit_code

    def connect(self):
        self.collector.createConnection(self.database)
        return {'original_login': self.collector.original_login,
                'effective_identity': self.collector.effective_identity}

    def scan_databases(self):
        if self.database:
            databases = [self.database]
        else:
            rows = self.query('databases', self.collector.db_name_query)
            databases = [row[0] for row in rows] if rows is not None else []
        for database in databases:
            allowed = self.options.allows('database', database)
            item = {'name': database, 'status': 'pending' if allowed else 'excluded'}
            self.report.data['inventory']['databases'].append(item)
            if not allowed:
                self.report.check('database', 'skipped', None, database=database,
                                  evidence='Excluded by database scope.')
                continue

            def connect():
                self.collector.use_database(database)
                return True

            if self.run_check('database_connection', connect, database) is None:
                item['status'] = self.report.data['checks'][-1]['status']
                continue
            item['status'] = 'accessible'
            if 'permissions' in self.options.checks:
                self.database_permissions(database)
            if 'links' in self.options.checks and self.collector.type != 'mssql':
                self.links(database)
            if set(self.options.checks) & {'inventory', 'findings'}:
                inventoried = self.inventory(database)
                if 'findings' in self.options.checks:
                    if inventoried:
                        self.detect(database)
                    else:
                        self.report.check('findings', 'skipped', self.collector.effective_identity,
                                          database=database, evidence='Required inventory could not be collected.')
            self.export_inventory()
            self.report.save()

    def inventory(self, database):
        rows = self.query('tables', self.collector.table_query, database,
                          evidence=lambda rows: {'visible_tables': len(rows)})
        if rows is None:
            return False
        for table, schema in rows:
            if (not self.options.allows('schema', schema, f'{database}.{schema}')
                    or not self.options.allows('table', table, f'{schema}.{table}', f'{database}.{schema}.{table}')):
                self.report.check('table', 'skipped', self.collector.effective_identity,
                                  database, schema, table, evidence='Excluded by schema/table scope.')
                continue
            key = (database, schema, table)
            if key not in self.tables:
                self.tables[key] = []
                self.report.data['inventory']['tables'].append(
                    {'database': database, 'schema': schema, 'name': table})
        if not any(key[0] == database for key in self.tables):
            return True
        rows = self.query('columns', self.collector.column_query, database,
                          evidence=lambda rows: {'visible_columns': len(rows)})
        if rows is None:
            return False
        for column, schema, table, datatype in rows:
            key = (database, schema, table)
            if key not in self.tables:
                continue
            self.tables[key].append({'name': column, 'datatype': datatype})
            self.report.data['inventory']['columns'].append(
                {'database': database, 'schema': schema, 'table': table,
                 'name': column, 'datatype': datatype})
        return True

    def export_inventory(self):
        inventory = self.report.data['inventory']
        self.export('dbs.csv', ['Database', 'Status'],
                    ([item['name'], item['status']] for item in inventory['databases']))
        self.export('tables.csv', ['TableName', 'SchemaName', 'Database'],
                    ([item['name'], item['schema'], item['database']] for item in inventory['tables']))
        self.export('columns.csv', ['ColumnName', 'TableName', 'SchemaName', 'Database', 'DataType'],
                    ([item['name'], item['table'], item['schema'], item['database'], item['datatype']]
                     for item in inventory['columns']))

    def detect(self, database):
        for (db, schema, table), columns in self.tables.items():
            if db != database:
                continue
            for name, rules in matching_rules(self.rules, table, columns,
                                               self.options.columns, self.options.min_confidence):
                evidence = {'table': table,
                            'column': name if self.options.columns else None,
                            'sample': {'status': 'pending'}}
                finding = self.finding(
                    f'Interesting {"column" if self.options.columns else "table"}: {name}',
                    rules[0].category, ' '.join(rule.description for rule in rules), evidence,
                    severity=max((rule.severity for rule in rules), key=SEVERITY.get),
                    confidence=max((rule.confidence for rule in rules), key=CONFIDENCE.get),
                    database=db, schema=schema,
                    object_name=f'{table}.{name}' if self.options.columns else table,
                    rule_ids=[rule.id for rule in rules],
                    categories=list(dict.fromkeys(rule.category for rule in rules)),
                )
                context = {'database': db, 'schema': schema, 'object_name': finding['object']}
                if self.options.skip_data:
                    evidence['sample'] = {'status': 'skipped'}
                    self.report.check('sample', 'skipped', self.collector.effective_identity,
                                      evidence='Disabled by --skip-data.', **context)
                    self.report.save()
                    continue
                names = [name] if self.options.columns else [column['name'] for column in columns]

                def sample():
                    self.collector.use_database(db)
                    query = self.collector.sample_query(schema, table, names)
                    rows = self.collector.execute(query)
                    result = bounded_sample(rows, self.options.sample_bytes)
                    # SQL truncates each cell before transfer; a cell at the
                    # character cap may already have been truncated server-side.
                    result['possibly_truncated_at_source'] = any(
                        value is not None and len(value) >= self.options.sample_bytes
                        for row in rows for value in row)
                    result['columns'] = names
                    return result

                result = None
                try:
                    result = self.run_check('sample', sample, **context)
                finally:
                    sample_status = self.report.data['checks'][-1]['status']
                    evidence['sample'] = {'status': sample_status, **(result or {})}
                    self.report.save()
        self.report.check('findings', 'completed', self.collector.effective_identity,
                          database=database, evidence='Evaluated rules against collected, in-scope metadata.')
        self.report.save()

    def server_permissions(self):
        collector = self.collector
        if collector.type == 'mssql':
            rows = self.query('impersonation', collector.impersonation_query)
            if rows:
                self.finding('Login impersonation permissions', 'permissions',
                             'The current identity can impersonate these visible logins.', rows, severity='high')
                if any(row[0] == 'sa' for row in rows):
                    def impersonate():
                        collector.execute("EXECUTE AS LOGIN = 'sa'")
                        collector.refresh_identity()
                        collector.impersonate = True
                        return {'effective_identity': collector.effective_identity}
                    self.run_check('impersonate_sa', impersonate)
        rows = self.query('server_permissions', collector.sys_query)
        if not rows:
            return
        if collector.type == 'mysql':
            for row in rows:
                privileges = [name for name, value in zip(('SUPER', 'FILE', 'GRANT'), row[2:]) if value == 'Y']
                if privileges:
                    self.finding('Administrative privileges', 'permissions',
                                 ', '.join(privileges), row, severity='high')
        elif rows[0][0] in (True, 1):
            self.finding('Administrative database identity', 'permissions',
                         'The current identity is a sysadmin or superuser.', rows, severity='high')

    def database_permissions(self, database):
        rows = self.query('database_permissions', self.collector.db_privs_query, database)
        if not rows:
            return
        if self.collector.type == 'mysql':
            self.finding('Database-level grants', 'permissions',
                         'Explicit schema grants for the current account; these do not imply ownership.',
                         rows, severity='info', database=database)
        elif rows[0][0] in (True, 1):
            self.finding('Database ownership privileges', 'permissions',
                         'The current identity owns the database or belongs to db_owner.',
                         rows, severity='high', database=database)

    def configuration(self):
        rows = self.query('command_execution_configuration', self.collector.cmd_exec_query)
        if not rows:
            return
        if self.collector.type == 'mysql':
            self.finding('Server file access configuration', 'configuration',
                         'secure_file_priv constrains file import/export; FILE and operating-system permissions also apply.',
                         rows, severity='info')
        elif self.collector.type == 'mssql' and rows[0][1] == 1:
            self.finding('xp_cmdshell is enabled', 'configuration',
                         'The server enables xp_cmdshell. Execution permission for this identity '
                         'is not established by this configuration check.', rows, severity='high')
        elif self.collector.type == 'psql' and rows[0][0] in (True, 1):
            self.finding('Server-program execution privileges', 'configuration',
                         'The PostgreSQL identity has superuser or server-program role privileges. '
                         'This check does not execute a host command.', rows, severity='high')

    def hashes(self):
        collector = self.collector

        def query_hashes():
            if collector.type == 'mysql':
                if self.version is None:
                    raise NotImplementedError('Hash query requires a detected MySQL version.')
                sql = collector.hash_query_for_version(self.version)
            else:
                sql = collector.hash_query
            return collector.execute(sql)

        rows = self.run_check('hashes', query_hashes)
        if rows is not None:
            hashes = [(row[0], '0x' + row[1].hex() if isinstance(row[1], bytes) else row[1]) for row in rows]
            self.export(f'{collector.type}_hashes.csv', ['UserName', 'Hash'], hashes)
            with (self.report.directory / f'hashcat_{collector.type}.hash').open('w', encoding='utf-8') as stream:
                for _, value in hashes:
                    if value:
                        stream.write(str(value) + '\n')
            if any(value for _, value in hashes):
                self.finding('Readable database authentication hashes', 'credentials',
                             'The current identity can read stored authentication material.',
                             {'accounts': [name for name, value in hashes if value]}, severity='high')
            elif rows:
                self.report.check('hash_visibility', 'completed', collector.effective_identity,
                                  evidence='Accounts are visible, but no authentication hashes were returned; '
                                  'this alone does not establish whether access was denied.')
        rows = self.query('users', collector.user_query)
        if rows is not None:
            self.export('users.csv', ['Username', 'Status'], rows)

    def connections(self):
        rows = self.query('connections', self.collector.conn_query)
        if rows is not None:
            self.export('connections.csv', self.column_headers(rows), rows)

    def column_headers(self, rows):
        description = getattr(self.collector.cursor, 'description', None)
        if description:
            return [column[0] for column in description]
        return [f'Column{index + 1}' for index in range(len(rows[0]) if rows else 0)]

    def links(self, database=None):
        rows = self.query('linked_servers', self.collector.link_query, database)
        if rows is not None:
            # One cross-database export, preserving the source database.
            existing = getattr(self, '_links', [])
            existing.extend((database, list(row)) for row in rows)
            self._links = existing
            self.export('linked_servers.csv', ['Database', 'Details'], existing)
        if rows:
            self.finding('Linked database endpoints', 'links',
                         'Configured linked servers, foreign servers, or FEDERATED tables were found.',
                         rows, severity='info', database=database)

    def emails(self):
        if self.collector.type != 'mssql':
            self.report.check('emails', 'unsupported', self.collector.effective_identity,
                              evidence='Database Mail enumeration is MSSQL-only.')
            return
        rows = self.query('emails', self.collector.email_query)
        if rows is not None:
            self.export('emails_10.csv', ['Recipients', 'Subject', 'Body'], rows)
        if rows:
            self.finding('Readable Database Mail messages', 'sensitive',
                         'Up to ten stored sent messages are readable.',
                         {'message_count': len(rows)}, severity='medium')
