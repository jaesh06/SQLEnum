import re
from impacket import smbserver

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

class BaseCollector:
    def getVersion(self):
        try:
            self.cursor.execute(self.version_query)
            rows = self.cursor.fetchall()

            self.version = rows[0][0]
            print(f'Database Version: {self.version}')
        except Exception as e:
            print(f'{RED}SQL Error: {e}')
    def getHashes(self):
        try:
            self.cursor.execute(self.hash_query)

            rows = self.cursor.fetchall()
            if not rows or rows[0][1] == None:
                print(f'{RED}User either does not have permissions to view hashes or hash table is empty...\n{RESET}')
            
            else:
                # Write results to mssql.hash for cracking, and mssql_hashes.txt for correlation
                with open(f'{self.dir_name}/hashcat_{self.type}.hash', 'w') as f1, open(f'{self.dir_name}/{self.type}_hashes.csv', 'w') as f2:
                    f2.write("UserName,Hash\n")
                    for row in rows:
                        if isinstance(row[1], bytes):
                            hash = row[1].hex()
                        else:
                            hash = row[1]
                        username = row[0]
                        if self.type == "mssql":
                            f1.write(f'0x{hash}\n')
                        else:
                            f1.write(f'{hash}\n')
                        f2.write(f'{username},{hash}\n')
                print(f'Usernames and Hashes written to {self.type}_hashes.csv')
                # TODO: Use hash identification to get actual hash mode
                match self.type:
                    case 'mssql':
                        hashcat_mode = '1731'
                    case 'psql':
                        hashcat_mode = '28600'
                    case 'mysql':
                        hashcat_mode = '11200'
                print(f'Hashcat Command:\n\nhashcat -a 0 -m {hashcat_mode} hashcat_{self.type}.hash wordlist.txt [rules.txt]\n')

        except Exception as e:
            print(f'{RED}SQL Error: {e}{RESET}')

        # Query all database users
        try:
            self.cursor.execute(self.user_query)
        except Exception as e:
            print(f'{RED}SQL Error: {e}{RESET}')
            return

        rows = self.cursor.fetchall()

        with open(f'{self.dir_name}/users.csv', 'a') as f:
            f.write('Username,is_disabled\n')
            print('Database Users | is_disabled:')
            for row in rows:
                username = row[0]
                is_disabled = row[1]
                f.write(f'{username},{is_disabled}\n')
                print(f'{username} | {is_disabled}')
    def getDBs(self):
        try:
            self.cursor.execute(self.db_name_query)
        except Exception as e:
            print(f'{RED}SQL Error: {e}{RESET}')
            exit(1)

        rows = self.cursor.fetchall()

        # Write dbs to dbs.txt
        with open(f'{self.dir_name}/dbs.csv', 'w') as f:
            f.write("Database\n")
            for row in rows:
                try:
                    # Test for user access to database
                    #self.createConnection(row[0])
                    self.cursor.execute(f'USE {row[0]}')

                    self.dbs[row[0]] = {}
                    print(f'{row[0]}')
                    f.write(f'{row[0]}\n')
                except Exception as e:
                    #print(e)
                    print(f'{row[0]} {RED}(Cannot access){RESET}')
                    f.write(f'{row[0]} (Cannot access)\n')
                    pass
    def getTables(self, table_query, database):
        try:
            self.cursor.execute(table_query)
        except Exception as e:
            print(f'{RED}SQL Error: {e}{RESET}')
            exit(1)
        rows = self.cursor.fetchall()

        with open(f'{self.dir_name}/tables.csv', 'a') as f:
            for row in rows:
                f.write(f'{row[0]},{row[1]},{database}\n')
                table_name = f'{row[1]}.{row[0]}'
                self.dbs[database][table_name] = []

        print(f'{database}: {len(rows)}\n')
    
    def getColumns(self, column_query, database):
        try:
            self.cursor.execute(column_query)
        except Exception as e:
            print(f'{RED}SQL Error: {e}{RESET}')
            exit(1)
        rows = self.cursor.fetchall()

        with open(f'{self.dir_name}/columns.csv', 'a') as f:
            for row in rows:
                f.write(f'{row[0]},{row[2]},{row[3]}\n')
                table_name = f'{row[1]}.{row[2]}'
                self.dbs[database][table_name].append(row[0])
        
        print(f'{database}: {len(rows)}\n')
    
    def checkCmdExec(self):
        try:
            self.cursor.execute(self.cmd_exec_query)
        except Exception as e:
            print(f'{RED}SQL Error: {e}{RESET}')
            return
        rows = self.cursor.fetchall()

        match self.type:
            case 'mssql':
                if rows[0][1] == 1:
                    print(f'{YELLOW}xp_cmdshell enabled!{RESET}')
                else:
                    print(f'{GREEN}xp_cmdshell disabled :({RESET}')
            case 'psql':
                # Result is either True or False
                if rows[0][0] == True:
                    print(f'{YELLOW}User can execute host commands!!{RESET}')
                else:
                    print(f'{GREEN}User cannot execute host commands :({RESET}')
    
    def checkSysPrivs(self):
        try:
            self.cursor.execute(self.sys_query)
        except Exception as e:
            print(f'{RED}SQL Error: {e}{RESET}')
            return
        rows = self.cursor.fetchall()

        match self.type:
            case 'mssql':
                if rows[0][0] == 1:
                    print(f'{YELLOW}User has sysadmin privs!!{RESET}')
                else:
                    print(f'{GREEN}User is not sysadmin :({RESET}')
            case 'psql':
                if rows[0][0] == True:
                    print(f'{YELLOW}User is superuser!!{RESET}')
                else:
                    print(f'{GREEN}User is not a superuser :({RESET}')
            case 'mysql':
                for row in rows:
                    if 'Y' in row[2:]:
                        for n in range(2,5):
                            if row[n] == 'Y':
                                match n:
                                    case 2:
                                        priv = 'SUPER'
                                    case 3:
                                        priv = 'FILE'
                                    case 4:
                                        priv = 'GRANT'
                                print(f'{YELLOW}User {row[0]}@{row[1]} has {priv} privileges!{RESET}')
                    else:
                        print(f'{GREEN}User does not have any admin privileges :({RESET}')
                    
    
    def checkDBPrivs(self, database):
        try:
            match self.type:
                case 'mssql':
                    self.cursor.execute(f'USE {database}')
                    self.cursor.execute('SELECT IS_ROLEMEMBER(\'db_owner\');')
                case 'psql':
                    self.cursor.execute(self.db_privs_query)
                case 'mysql':
                    self.cursor.execute(self.db_privs_query)
                    rows = self.cursor.fetchall()
                    for row in rows:
                        if (row[2] == 'CREATE') or (row[2] == 'ALL PRIVILEGES'):
                            print(f'{database}: {YELLOW}User is db_owner!{RESET}')
                            return
                    print(f'{database}: {GREEN}User is not db_owner{RESET}')
                    return
        except Exception as e:
            print(f'{RED}SQL Error: {e}{RESET}')
            return

        rows = self.cursor.fetchall()

        if (rows[0][0] == 1) or (rows[0][0] == True):
            print(f'{database}: {YELLOW}User is db_owner!{RESET}')
        else:
            print(f'{database}: {GREEN}User is not db_owner{RESET}')

    def checkDBConns(self):
        try:
            self.cursor.execute(self.conn_query)
            rows = self.cursor.fetchall()

            print('Host: User')
            with open(f'{self.dir_name}/connections.csv', 'a') as f:    
                for row in rows:
                    match self.type:
                        case 'mssql':
                            if row[3] != '  .':
                                print(f'{row[3]}: {row[2]}')
                        case 'psql':
                            if (row[6] != '<insufficient privilege>') and (row[1] != None):
                                print(f'{row[3]}: {row[1]}')
                        case 'mysql':
                            print(f'{row[2]}: {row[1]}')
                    for item in row:
                        f.write(f'{str(item)},')
                    f.write('\n')
        except Exception as e:
            print(f'{RED}SQL Error: {e}{RESET}')
    
    def checkLinkedServers(self):
        try:
            self.cursor.execute(self.link_query)
            rows = self.cursor.fetchall()

            if rows:
                print('IP Address: ServerName')
                with open(f'{self.dir_name}/linked_servers.csv', 'a') as f:
                    for row in rows:
                        match self.type:
                            case 'mssql':
                                print(f'{YELLOW}{row[3]}: {row[0]}{RESET}')
                            case 'psql':
                                print(f'{YELLOW}{row[7]}: {row[1]}{RESET}')
                            case 'mysql':
                                print(f'{YELLOW}{row[3]}{RESET}')
                        for item in row:
                            f.write(f'{str(item)},')
                        f.write('\n')
            
            else:
                print(f'{GREEN}No linked servers found{RESET}')
        except Exception as e:
            print(f'{RED}SQL Error: {e}{RESET}')

    def findLoot(self, database, keywords):
        if keywords == "":
            patterns = {
                "credentials": r"pass|pwd|hash|salt|shadow|secret|token|cred|psw|id|session|vault",
                "identity": r"user|admin|login|member|account|ssn|social.*security",
                "financial": r"card|credit|cc_|bank|acc_|iban|routing|wallet|payment",
                "sensitive": r"email|phone|addr|dob|birth|private|key|config"
            }
        else:
            patterns = {
                "custom": keywords
            }
        if self.columns:
            for table in self.dbs[database]:
                for column in self.dbs[database][table]:
                    for label, pattern in patterns.items():
                        if re.search(pattern, column, re.IGNORECASE):
                            if not self.skip_data:
                                # Query to get data type, this is needed for the MAX() SQL function to work on 'bit' data types
                                if self.type == 'mysql':
                                    data_type_query = f'SELECT DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = \'{database}\' AND COLUMN_NAME = \'{column}\' AND TABLE_NAME = \'{table.split('.')[1]}\''
                                else:
                                    data_type_query = f'SELECT DATA_TYPE FROM {database}.INFORMATION_SCHEMA.COLUMNS WHERE COLUMN_NAME = \'{column}\' AND TABLE_NAME = \'{table.split('.')[1]}\''
                                self.cursor.execute(data_type_query)
                                rows = self.cursor.fetchone()
                                if rows[0] in ['bit', 'boolean']:
                                    query = f'SELECT MAX(CAST({column} AS INT)) FROM {table}'
                                else:
                                    query = f'SELECT MAX({column}) FROM {table}'
                                try:
                                    self.cursor.execute(query)
                                except:
                                    continue
                                rows = self.cursor.fetchall()
                                if not rows:
                                    sample = 'Null'
                                else:
                                    sample = str(rows[0][0])
                            else:
                                sample = 'Skipped'
                            print(f'{YELLOW}Interesting column name found:{RESET} {column} in {database}.{table}')
                            self.matches.append({"ColumnName": column, "TableName": table, "Database": database, "SampleData": sample})
        else:
            for table in self.dbs[database]:
                for label, pattern in patterns.items():
                    if re.search(pattern, table, re.IGNORECASE):
                        if not self.skip_data:
                            # Query to get data type, this is needed for the MAX() SQL function to work on 'bit' data types
                            column_list = ''
                            for column in self.dbs[database][table]:
                                column_list += f'{column}, '
                            if self.type == 'mssql':
                                data_sample = f"SELECT TOP 1 * FROM {table}"
                                # data_sample = f"""
                                # SELECT TOP 1 * FROM {table} 
                                # WHERE COALESCE({column_list[:-2]}) IS NOT NULL OR COALESCE({column_list[:-2]}) != ''
                                # """
                            else:
                                data_sample = f'SELECT * FROM {table} LIMIT 1'
                            self.cursor.execute(data_sample)
                            row = self.cursor.fetchone()
                            if not row:
                                sample = 'Null'
                            else:
                                sample = row[0:]
                        else:
                            sample = 'Skipped'
                        print(f'{YELLOW}Interesting table name found:{RESET} {table} in {database}')
                        self.matches.append({"TableName": table, "Database": database, "SampleRow": sample})

    def performQuery(self, query):
        try:
            self.cursor.execute(query)
            rows = self.cursor.fetchall()

            for row in rows:
                print(*row, sep=',')
        except Exception as e:
            print(f'{RED}SQL Error: {e}{RESET}')