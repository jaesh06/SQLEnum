import pymysql
import secrets
from packaging import version
from collectors.base import BaseCollector

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

class MySQLCollector(BaseCollector):
    def __init__(self, target, port, user, password, skip_data, columns, keywords):
        self.target = target
        self.port = int(port)
        self.user = user
        self.password = password
        self.skip_data = skip_data
        self.columns = columns
        self.keywords = keywords.replace(',','|')

        self.type = 'mysql'

        self.dir_name = f'{self.target.replace('.', '-')}_{self.type}_{secrets.token_hex(2)}'

        self.version_query = 'SELECT @@version;'
        # self.hash_query defined below in getVersion()
        self.db_name_query = 'SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN (\'information_schema\', \'mysql\', \'performance_schema\', \'sys\');'
        self.user_query = 'SELECT CONCAT( user, "@", host) AS query, account_locked FROM mysql.user;'
        self.sys_query = 'SELECT User, Host, Super_priv, File_priv, Grant_priv FROM mysql.user WHERE user = SUBSTRING_INDEX(CURRENT_USER(), \'@\', 1) AND (Super_priv = \'Y\' OR File_priv = \'Y\' OR Grant_priv = \'Y\');'
        self.db_privs_query = """
        SELECT 
            GRANTEE, 
            TABLE_SCHEMA, 
            PRIVILEGE_TYPE 
        FROM information_schema.SCHEMA_PRIVILEGES 
        WHERE GRANTEE = CONCAT('\\'', REPLACE(CURRENT_USER(), '@', '\\'@\\''), '\\'');
        """
        self.conn_query = "SHOW FULL PROCESSLIST;"
        self.link_query = """
        SELECT 
            table_schema AS local_db, 
            table_name AS local_table, 
            engine, 
            create_options AS connection_string
        FROM information_schema.tables 
        WHERE engine = 'FEDERATED';
        """

        self.dbs = {}
        self.findings = {"columns": []}
        self.matches = []
    
    def createConnection(self, database):
        conn = pymysql.connect(
            host=self.target,
            port=self.port,
            user=self.user,
            password=self.password,
            database=database
        )
        
        self.cursor = conn.cursor()
    
    # Overwrite default getVersion() to set custom query strings according to version
    def getVersion(self):
        try:
            self.cursor.execute(self.version_query)
            rows = self.cursor.fetchall()

            self.version = rows[0][0]
            print(f'Database Version: {self.version}')
        except Exception as e:
            print(f'{RED}SQL Error: {e}')
        if version.parse(self.version) >= version.parse('8.0') or version.parse(self.version) >= version.parse('5.7'):
            self.hash_query = 'SELECT user AS name, authentication_string AS password_hash FROM mysql.user;'
        else:
            self.hash_query = 'SELECT user AS name, password AS password_hash FROM mysql.user;'
    
    def getAllTables(self):
        with open(f'{self.dir_name}/tables.csv', 'w') as f:
            f.write("TableName,SchemaName,Database\n")
        for db in self.dbs:
            self.createConnection(db)
            table_query = 'SELECT table_name, table_schema FROM information_schema.tables WHERE table_schema NOT IN (\'information_schema\', \'mysql\', \'performance_schema\', \'sys\');'
            self.getTables(table_query, db)
    
    def getAllColumns(self):
        with open(f'{self.dir_name}/columns.csv', 'w') as f:
            f.write('ColumnName,TableName,Database\n')
        for db in self.dbs:
            self.createConnection(db)
            column_query = f'SELECT COLUMN_NAME, TABLE_SCHEMA, TABLE_NAME, TABLE_CATALOG FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA NOT IN (\'information_schema\', \'mysql\', \'performance_schema\', \'sys\');'
            self.getColumns(column_query, db)

    def checkCmdExec(self):
        try:
            self.cursor.execute('SELECT CONCAT(user, \"@\", host) as User, file_priv FROM mysql.user WHERE user = SUBSTRING_INDEX(CURRENT_USER(), \'@\', 1);')
            file_perms = self.cursor.fetchall()
            print('User needs FILE permission and an empty sfp variable to perform RCE...What do we have?')
            for perm in file_perms:
                if perm[1] == 'Y':
                    print(f'{YELLOW}User has FILE permission!{RESET}\n')
                else:
                    print(f'{GREEN}User does not have FILE permission :({RESET}\n')
        except Exception as e:
            print(f'{RED}SQL Error: {e}{RESET}')

        self.cursor.execute("SHOW VARIABLES LIKE 'secure_file_priv'")
        sfp = self.cursor.fetchall()
                
        if sfp[0][1] == "":
            print(f'{YELLOW}secure_file_priv is empty! Try OUTFILE to upload file anywhere!{RESET}')
        elif sfp[0][1] is None:
            print(f'{GREEN}secure_file_priv is NULL. OUTFILE is disabled :({RESET}')
        else:
            print(f'secure_file_priv limited to: {sfp[0][1]}')
    
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
    
