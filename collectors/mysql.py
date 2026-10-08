import re

import pymysql

from collectors.base import BaseCollector


class MySQLCollector(BaseCollector):
    type = 'mysql'
    default_database = ''
    identity_query = 'SELECT USER(), CURRENT_USER()'
    version_query = 'SELECT @@version'
    user_query = 'SELECT CONCAT(user, "@", host), account_locked FROM mysql.user'
    db_name_query = """SELECT schema_name FROM information_schema.schemata
        WHERE schema_name NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys')"""
    table_query = '''SELECT table_name, table_schema FROM information_schema.tables
        WHERE table_schema = DATABASE()'''
    column_query = '''SELECT column_name, table_schema, table_name, data_type
        FROM information_schema.columns WHERE table_schema = DATABASE() ORDER BY ordinal_position'''
    sys_query = """SELECT User, Host, Super_priv, File_priv, Grant_priv FROM mysql.user
        WHERE CONCAT(User, '@', Host) = CURRENT_USER()"""
    db_privs_query = """SELECT GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE
        FROM information_schema.SCHEMA_PRIVILEGES
        WHERE GRANTEE = CONCAT(CHAR(39), REPLACE(CURRENT_USER(), '@', CONCAT(CHAR(39), '@', CHAR(39))), CHAR(39))
        AND TABLE_SCHEMA = DATABASE()"""
    conn_query = 'SHOW FULL PROCESSLIST'
    link_query = """SELECT table_schema, table_name, engine, create_options
        FROM information_schema.tables WHERE engine = 'FEDERATED' AND table_schema = DATABASE()"""
    cmd_exec_query = "SHOW VARIABLES LIKE 'secure_file_priv'"

    def _connect(self, database):
        self.connection = pymysql.connect(
            host=self.target, port=self.port, user=self.user, password=self.password,
            database=database or None, autocommit=True,
            connect_timeout=self.options.connect_timeout,
            read_timeout=self.options.query_timeout,
            write_timeout=self.options.query_timeout,
        )
        self.cursor = self.connection.cursor()

    def hash_query_for_version(self, version):
        match = re.match(r'(\d+)\.(\d+)', str(version))
        if not match:
            raise NotImplementedError(f'Unknown MySQL version format: {version}')
        if 'mariadb' in version.lower():
            column = 'authentication_string'
        else:
            column = 'authentication_string' if tuple(map(int, match.groups())) >= (5, 7) else 'password'
        return f'SELECT CONCAT(user, "@", host), {column} FROM mysql.user'
