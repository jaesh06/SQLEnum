import argparse
import os
from impacket import smbserver
from collectors.base import BaseCollector
from collectors.mssql import MSSQLCollector
from collectors.psql import PostgreSQLCollector
from collectors.mysql import MySQLCollector

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

description = "Perform quick enumeration of MSSQL, MySQL, or PostgreSQL"

parser = argparse.ArgumentParser(
    prog='sql_enum',
    description=description,
    formatter_class=argparse.RawTextHelpFormatter
)
parser.add_argument(
    "type", 
    choices=["mssql", "psql", "mysql"], 
    default="mssql", 
    help="Database type (default: mssql)"
)
parser.add_argument('-t', '--target', required=True, help='Target IP or hostname of SQL server.')
parser.add_argument('-u', '--user', required=True, help='Database username to connect with.')
parser.add_argument('-p', '--password', required=True, help='Database password to connect with.')
parser.add_argument('-d', '--database', default='', help='Database to connect to.')
#parser.add_argument("-c", "--coerce", action="store_true", help="Attempt NTLM coercion via xp_dirtree")
#parser.add_argument("-L", "--local-ip", help="Your host IP (required for -r)")
parser.add_argument('--skip-data', action="store_true", help="Skips the query for one row of data per interesting column found (recommended for large databases)")
parser.add_argument('--columns', action="store_true", help="Searches columns for interesting names instead of tables.")
parser.add_argument('-q', '--query', help='Single SQL query to run against specified database (-d <database> required!)')
parser.add_argument('-P', '--port', help='Destination port. If not specified, default server ports are used (e.g. 1433 for MSSQL)')
parser.add_argument('-f', '--filter', default='', help='Filter table/column names for comma-separated (no whitespace) keywords.')
args = parser.parse_args()

def main():
    match args.type:
        case "mssql":
            if args.port:
                port = args.port
            else:
                port = '1433'
            conn_obj = MSSQLCollector(args.target, port, args.user, args.password, args.skip_data, args.columns, args.filter)
        case "psql":
            if args.port:
                port = args.port
            else:
                port = '5432'
            conn_obj = PostgreSQLCollector(args.target, port, args.user, args.password, args.skip_data, args.columns, args.filter)
        case "mysql":
            if args.port:
                port = args.port
            else:
                port = '3306'
            conn_obj = MySQLCollector(args.target, port, args.user, args.password, args.skip_data, args.columns, args.filter)
        case _:
            print(f'{RED}{args.type} is not a valid database type.{RESET}')
            exit(1)
    if args.query:
        if args.database == '':
            print('ERROR: \'-d <database>\' is required when using \'-q\'!')
            raise SystemExit
        else:
            dbQuery(conn_obj)
    else:
        dbEnum(conn_obj)

    #  if args.coerce:
    #     if args.local_ip:
    #         conn_obj.startSMBServer()
    #         time.sleep(10)
    #     else:
    #         print('Error: -L [local_ip] option is required when using -c')
    #         exit(1)
    
def dbQuery(conn_obj):
    conn_obj.createConnection(args.database)
    conn_obj.performQuery(args.query)

def dbEnum(conn_obj):
    if ' ' in args.filter:
        print('ERROR: \'--filter\' argument cannot contain whitespace!')
        raise SystemExit
    conn_obj.createConnection(args.database)
    os.mkdir(conn_obj.dir_name)
    print("======== Getting Database Version... ========\n")
    conn_obj.getVersion()

    if args.type == 'mssql':
        # If user can impersonate 'sa', remaining queries are run as 'sa'
        print("\n======== (MSSQL) Checking for impersonation rights... ========\n")
        conn_obj.getImpersonation()
    
    print("\n======== Gathering User Hashes... ========\n")
    conn_obj.getHashes()

    if args.database == '':
        print("\n======== Getting Databases... ========\n")
        # Structure for dbs is as follows:
        # {'db1': {
        #   'table1': [
        #       'col1',
        #       'col2'
        #       ]
        #   }
        # }
        # Write CSV header
        conn_obj.getDBs()
        # This is to refresh the cursor back to original location
        conn_obj.createConnection(args.database)
    else:
        conn_obj.dbs[args.database] = {}

    print("\n======== Getting Tables... ========\n")
    conn_obj.getAllTables()

    print("======== Getting Columns... ========\n")
    conn_obj.getAllColumns()

    print("======== Checking for host cmd exec... ========\n")
    conn_obj.checkCmdExec()

    print("\n======== Checking if user is sysadmin... ========\n")
    conn_obj.checkSysPrivs()

    print("\n======== Checking if user is dbo... ========\n")
    conn_obj.getAllDBPrivs()

    if args.type == 'mssql':
        print("\n======== (MSSQL) Checking sysmail for sent emails... ========\n")
        conn_obj.checkSysmail()
    
    print("\n======== Checking for database connections... ========\n")
    conn_obj.checkDBConns()

    print("\n======== Checking for linked servers... ========\n")
    conn_obj.checkLinkedServers()

    print("\n======== Finding interesting columns... ========\n")
    conn_obj.getAllLoot()
    
if __name__ == "__main__":
    main()

