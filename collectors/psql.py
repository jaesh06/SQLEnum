import psycopg2

from collectors.base import BaseCollector


class PostgreSQLCollector(BaseCollector):
    type = 'psql'
    default_database = 'postgres'
    identity_query = 'SELECT session_user, current_user'
    version_query = 'SELECT version()'
    hash_query = 'SELECT usename, passwd FROM pg_shadow'
    user_query = """SELECT rolname, CASE WHEN rolvaliduntil < CURRENT_TIMESTAMP THEN 'EXPIRED'
        WHEN NOT rolcanlogin THEN 'DISABLED' ELSE 'ACTIVE' END
        FROM pg_roles WHERE rolname NOT LIKE 'pg_%'"""
    db_name_query = 'SELECT datname FROM pg_database WHERE NOT datistemplate'
    table_query = """SELECT table_name, table_schema FROM information_schema.tables
        WHERE table_schema NOT IN ('information_schema', 'pg_catalog')"""
    column_query = """SELECT column_name, table_schema, table_name, data_type
        FROM information_schema.columns WHERE table_schema NOT IN ('information_schema', 'pg_catalog')
        ORDER BY ordinal_position"""
    cmd_exec_query = """SELECT ((SELECT usesuper FROM pg_user WHERE usename = CURRENT_USER)
        OR pg_has_role(current_user, 'pg_execute_server_program', 'member'))"""
    sys_query = 'SELECT usesuper FROM pg_user WHERE usename = CURRENT_USER'
    db_privs_query = '''SELECT r.rolname = current_user FROM pg_database d
        JOIN pg_roles r ON d.datdba = r.oid WHERE d.datname = current_database()'''
    conn_query = '''SELECT pid, usename, datname, client_addr, backend_start, state, query
        FROM pg_stat_activity ORDER BY backend_start DESC'''
    link_query = 'SELECT srvname, srvtype, srvversion, srvoptions FROM pg_foreign_server'

    def _connect(self, database):
        self.connection = psycopg2.connect(
            host=self.target, port=self.port, user=self.user, password=self.password,
            dbname=database, connect_timeout=self.options.connect_timeout,
            options=f'-c statement_timeout={self.options.query_timeout * 1000}',
        )
        self.connection.autocommit = True
        self.cursor = self.connection.cursor()
