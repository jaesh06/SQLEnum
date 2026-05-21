import argparse
from impacket import smbserver
from collectors.base import BaseCollector
from collectors.mssql import MSSQLCollector
from collectors.psql import PostgreSQLCollector
from collectors.mysql import MySQLCollector

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

description = "Perform quick enum of MSSQL with valid creds"

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
parser.add_argument("-c", "--coerce", action="store_true", help="Attempt NTLM coercion via xp_dirtree")
parser.add_argument("-L", "--local-ip", help="Your host IP (required for -r)")
parser.add_argument('--skip-data', action="store_true", help="Skips the query for one row of data per interesting column found (recommended for large databases)")
parser.add_argument('--columns', action="store_true", help="Searches columns for interesting names instead of tables.")

args = parser.parse_args()

def main():
    match args.type:
        case "mssql":
            conn_obj = MSSQLCollector(args.target, args.user, args.password, args.skip_data, args.columns)
        case "psql":
            conn_obj = PostgreSQLCollector(args.target, args.user, args.password, args.skip_data, args.columns)
        case "mysql":
            conn_obj = MySQLCollector(args.target, args.user, args.password, args.skip_data, args.columns)
        case _:
            print(f'{RED}{args.type} is not a valid database type.{RESET}')
            exit(1)
    conn_obj.createConnection(args.database)

    #  if args.coerce:
    #     if args.local_ip:
    #         conn_obj.startSMBServer()
    #         time.sleep(10)
    #     else:
    #         print('Error: -L [local_ip] option is required when using -c')
    #         exit(1)
    print("======== Getting Database Version... ========")
    conn_obj.getVersion()
    
    print("======== Gathering User Hashes... ========\n")
    conn_obj.getHashes()

    if args.database == '':
        print("======== Getting Databases... ========\n")
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

    print("======== Getting Tables... ========\n")
    conn_obj.getAllTables()

    print("======== Getting Columns... ========\n")
    conn_obj.getAllColumns()

    print("======== Checking for host cmd exec... ========\n")
    conn_obj.checkCmdExec()

    print("======== Checking if user is sysadmin... ========\n")
    conn_obj.checkSysPrivs()

    print("======== Checking if user is dbo... ========\n")
    conn_obj.getAllDBPrivs()

    if args.type == 'mssql':
        print("======== (MSSQL) Checking sysmail for sent emails... ========\n")
        conn_obj.checkSysmail()
    
    print("======== Checking for database connections... ========")
    conn_obj.checkDBConns()

    print("======== Checking for linked servers... ========")
    conn_obj.checkLinkedServers()

    print("======== Finding interesting columns... ========\n")
    conn_obj.getAllLoot()
    
if __name__ == "__main__":
    main()

