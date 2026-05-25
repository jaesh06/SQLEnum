import psycopg2
import secrets
import os
from collectors.base import BaseCollector

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

class PostgreSQLCollector(BaseCollector):
    def __init__(self, target, port, user, password, skip_data, columns, keywords):
        self.target = target
        self.port = int(port)
        self.user = user
        self.password = password
        self.skip_data = skip_data
        self.columns = columns
        self.keywords = keywords.replace(',','|')

        self.type = 'psql'

        self.dir_name = f'{self.target.replace('.', '-')}_{self.type}_{secrets.token_hex(2)}'

        self.version_query = 'SELECT version();'
        self.hash_query = 'SELECT usename AS name, passwd AS password_hash FROM pg_shadow;'
        self.user_query = 'SELECT rolname AS username, CASE WHEN rolvaliduntil < CURRENT_TIMESTAMP THEN \'EXPIRED\' WHEN rolcanlogin = \'f\' THEN \'DISABLED\' ELSE \'ACTIVE\' END AS status FROM pg_roles WHERE rolname NOT LIKE \'pg_%\';'
        self.db_name_query = 'SELECT datname FROM pg_database WHERE datistemplate = false;'
        # To run something like xp_cmdshell, you just need a superuser account or have pg_execute_server_program
        self.cmd_exec_query = 'SELECT ((SELECT usesuper FROM pg_user WHERE usename = CURRENT_USER) OR pg_has_role(current_user, \'pg_execute_server_program\', \'member\')) AS has_rce_privs;'
        self.sys_query = 'SELECT usesuper FROM pg_user WHERE usename = CURRENT_USER;'
        self.db_privs_query = 'SELECT (r.rolname = current_user) as is_owner FROM pg_database d JOIN pg_roles r ON d.datdba = r.oid WHERE d.datname = current_database();'
        self.conn_query = 'SELECT pid, usename AS user, datname AS database, client_addr AS ip_address, backend_start AS login_time, state, query AS current_query FROM pg_stat_activity ORDER BY backend_start DESC;'
        self.link_query = 'SELECT * FROM pg_foreign_server;'

        self.dbs = {}
        self.findings = {"columns": []}
        self.matches = []
    
    def createConnection(self, database):
        if database == '':
            database = f'postgres'

        conn = psycopg2.connect(
            host=self.target,
            port=self.port,
            user=self.user,
            password=self.password,
            dbname=database
            )
        # Necessary for psql so that failed queries don't require a reconnect
        conn.autocommit = True
        self.cursor = conn.cursor()
    
    def getAllTables(self):
        with open(f'{self.dir_name}/tables.csv', 'w') as f:
            f.write("TableName,SchemaName,Database\n")
        for db in self.dbs:
            self.createConnection(db)
            table_query = f'SELECT table_name, table_schema FROM INFORMATION_SCHEMA.TABLES WHERE table_schema NOT IN (\'information_schema\', \'pg_catalog\');'
            self.getTables(table_query, db)
    
    def getAllColumns(self):
        with open(f'{self.dir_name}/columns.csv', 'w') as f:
            f.write('ColumnName,TableName,Database\n')
        for db in self.dbs:
            self.createConnection(db)
            column_query = f'SELECT COLUMN_NAME, TABLE_SCHEMA, TABLE_NAME, TABLE_CATALOG FROM INFORMATION_SCHEMA.COLUMNS WHERE table_schema NOT IN (\'information_schema\', \'pg_catalog\');'
            self.getColumns(column_query, db)
    
    def getAllDBPrivs(self):
        for db in self.dbs:
            self.checkDBPrivs(db)
    
    def getAllLoot(self):
        for db in self.dbs:
            self.createConnection(db)
            self.findLoot(db, self.keywords)
        if self.columns:
            self.findings['columns'] = self.matches
        else:
            self.findings['tables'] = self.matches

        with open(f'{self.dir_name}/findings.csv', 'a') as f:
            if self.columns:
                f.write('ColumnName,TableName,Database,SampleData\n')
                for item in self.findings['columns']:
                    f.write(f'{item['ColumnName']},{item['TableName']},{item['Database']},{item['SampleData']}\n')
            else:
                f.write('TableName,Database,SampleRow\n')
                for item in self.findings['tables']:
                    f.write(f'{item['TableName']},{item['Database']},')
                    for record in item['SampleRow']:
                        f.write(f'|{record}')
                    f.write(f'\n')