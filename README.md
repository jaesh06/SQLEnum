# SQLEnum
Have you ever been on a pentest, found valid SQL creds, and spent hours looking through hundreds of tables looking for juicy information or pivot/priv esc opportunities? Or had to refresh your memory for the 50th time on how to query user hashes from the database? I know I have...

Enter SQLEnum: a script that automatically pulls database data and configurations that can help YOU decide where to pivot next.
## Script Functions
SQLEnum performs the following:
- Attempts to dump SQL user hashes
- Pulls all database, table, and column names
- Checks for interesting column names ('password', 'ssn', 'secret', etc.)
- Checks for sensitive stored procedures (xp_cmdshell, xp_dirtree, host RCE, etc.)
- Checks current user privileges (sysadmin, database_owner)
- Checks for saved sent emails (MSSQL)
- Lists all current database connections
- Lists any linked servers
- (TODO) Performs xp_dirtree coercion and prints out NTLMv2 hash (MSSQL)
Go to [queries.sql](./queries.sql) to view all queries used in `sql_enum.py`.
## Installation
Activate virtual environment:
```bash
python3 -m venv sql_enum
source sql_enum/bin/activate
```
Install required modules:
```bash
python3 -m pip install -r requirements.txt
```
## Usage
```bash
python3 sql_enum.py [mssql, mysql, psql] -t <ip|hostname> -u <user> -p <password>
```
Output files for enumeration include:
- columns.csv (Contains column names, and which database/table contains the column)
- connections.csv (Contains details of current DB connections)
- dbs.csv (Contains list of database names)
- findings.csv (Contains interesting columns and one row of sample data)
- linked_servers.csv (Contains linked MSSQL server information)
- <server_type>_hashes.csv (Contains MSSQL usernames and hashes)
- <server_type>.hash (Contains MSSQL hashes in hashcat format)
- tables.csv (Contains table names, schema, and associated database)
- users.csv (Contains all MSSQL users and their status)
These files are stored within a unique directory name from where the script is run. The directory name includes the target IP, the database type, and 4 random hex characters to prevent duplicates:
For example: `127-0-0-1_mssql_af14`
## Examples
To perform basic enumeration of a MSSQL server:
```bash
python3 sql_enum.py mssql -t 127.0.0.1 -u sa -p 'Password123!'
```
To perform basic enumeration of a MySQL, and of a specific database, but filter for interesting column names instead of table names:
```bash
python3 sql_enum.py mysql -t 127.0.0.1 -u root -p 'Password123!' --columns -d web_store
```
To only run a single query and perform no other enumeration ('-d' is required!):
```bash
python3 sql_enum.py psql -t 127.0.0.1 -u pentester -p 'Password123!' -d corp_data -q 'SELECT * FROM internal_vault.api_tokens LIMIT 10'
```
*Note: this outputs the results to STDOUT, not a file!*
## Dev Setup
The below section details how to setup small SQL containers for testing.
(Tested on ARM Mac)
### Requirements
- Docker
- docker-compose (if on Linux)
```bash
sudo apt install docker-compose
```
- sqlcmd
```bash
brew install microsoft/mssql-release/mssql-tools18
```
OR

[sqlcmd Github](https://github.com/microsoft/go-sqlcmd/releases/latest)
- psql
```bash
brew install libpq
echo 'export PATH="/opt/homebrew/opt/libpq/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```
OR
```bash
sudo apt install postgresql-client
```
- mysql
```bash
brew install mysql
```
OR
```bash
sudo apt install mysql-client
```
### Setup Steps
1. Choose or customize correct docker-compose file based on running CPU architecture:
- [docker-compose-x86.yml](docker-compose-x86.yml)
- [docker-compose-arm.yml](docker-compose-arm.yml)
2. Run `docker compose` with chosen file:
```bash
docker compose -f [x86.yml|arm.yml] up -d
```
OR
```bash
docker-compose -f [x86.yml|arm.yml] up -d
```
3. Run following commands to populate database with fake DBs, tables, and data:
```bash
sqlcmd -S 127.0.0.1,1433 -U sa -P 'Password123!' -i data_populate_ms.sql -C
psql -h 127.0.0.1 -U pentester -d corp_data < data_populate_postgre.sql
mysql -h 127.0.0.1 -u root -p'Password123!' web_store < data_populate_my.sql
```
4. Test with the following command:
```bash
sqlcmd -S 127.0.0.1,1433 -U sa -P 'Password123!' -C -Q "SELECT * FROM CorporateDB.dbo.Users"
```
```bash
psql -h 127.0.0.1 -U pentester -d corp_data -c 'SELECT * FROM internal_vault.api_tokens;'
```
```bash
mysql -h 127.0.0.1 -u root web_store -p'Password123!' -e 'SELECT * FROM site_sessions;'
```
You should see dummy credentials returned from this

5. SQLEnum can now be used against any of the SQL containers:
```bash
python3 sql_enum.py mssql -t 127.0.0.1 -u sa -p 'Password123!'
```
## TODO
- [ ] Perform more testing in live environments to discover edge cases/bugs
- [x] Test x86 dev setup
- [ ] Test xp_dirtree coercion
    - Currently doesn't seem to work with a container, need a VM of MSSQL to test
- [x] Add option to filter only for custom word[s]
- [x] Add option to skip sample data queries in findLoot() 
- [x] Add option to filter on table names instead of columns (good for larger databases)
- [ ] Look into sqlmap integration