# SQLEnum
Have you ever been on a pentest, found valid SQL creds, and spent hours looking through hundreds of tables looking for juicy information or pivot/priv esc opportunities? Or had to refresh your memory for the 50th time on how to query user hashes from the database? I know I have...

Enter SQLEnum: a script that automatically pulls database data and configurations that can help YOU decide where to pivot next.
## Script Functions
SQLEnum performs the following:
- Checks for impersonation rights of current user (MSSQL)
- Attempts to dump SQL user hashes
- Pulls all database, table, and column names
- Checks for interesting column names ('password', 'ssn', 'secret', etc.)
- Checks for sensitive stored procedures (xp_cmdshell, xp_dirtree, host RCE, etc.)
- Checks current user privileges (sysadmin, database_owner)
- Checks for saved sent emails (MSSQL)
- Lists all current database connections
- Lists any linked servers
- Writes unified JSON, Markdown, and CSV findings with evidence and check coverage
- Supports custom JSON detection rules, confidence filtering, and scoped scans
- Bounds sample rows and sample size, with configurable connection/query timeouts
- (TODO) Performs xp_dirtree coercion and prints out NTLMv2 hash (MSSQL)
Go to [queries.sql](./queries.sql) for reference queries. Runtime queries live in `collectors/`.
## Installation
Requires Python 3.10 or newer.

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
python3 sql_enum.py [mssql, mysql, psql] -t <ip|hostname> -u <user> [-p <password>] [--domain <domain>] [-H <ntlm_hash>]
```
Output files for enumeration include:
- report.json (Versioned scan results, options, findings, inventory, and check outcomes)
- report.md (Severity-prioritized findings and check coverage for assessment notes)
- columns.csv (Column names, datatypes, schema, table, and database)
- connections.csv (Contains details of current DB connections)
- dbs.csv (Contains list of database names)
- findings.csv (All findings, including privileges/configuration; evidence is a JSON field)
- linked_servers.csv (Contains linked MSSQL server information)
- <server_type>_hashes.csv (Database usernames and available hashes)
- hashcat_<server_type>.hash (Exported hash strings; choose the mode appropriate to their format)
- tables.csv (Contains table names, schema, and associated database)
- users.csv (Visible database users and engine-specific account status)
- emails_10.csv (Up to ten MSSQL Database Mail messages, when accessible)
These files are stored within a unique directory nested under `results/` from where the script is run. The directory name includes the target, the database type, and 8 random hex characters:
For example: `results/127-0-0-1_mssql_af14e890`. Use `--output-dir PATH` to choose an empty output directory. Raw check exports are created only when their queries succeed; inventory and finding CSVs always have headers.

**CSV format change:** `findings.csv` now contains every finding type rather than only table/column matches. Its `evidence` field includes sample columns, rows, status, and truncation indicators. `columns.csv` now includes schema and datatype. CSV values containing commas, quotes, or newlines are escaped correctly.

### Reports and scan status

Each finding records its category/categories, severity, confidence, target, database, schema, object, original login, effective identity, explanation, rule IDs, and evidence. JSON includes `schema_version: 1`, timestamps, and the selected options/rule definitions, but does not serialize connection passwords or supplied NTLM hashes. The terminal prints check progress and a final summary by severity and check outcome.

Check outcomes are `completed`, `permission_denied`, `unsupported`, `failed`, `skipped`, or `interrupted`. A successful query with no rows is distinct from a failed query. A name-based detection remains a finding even when sampling fails; its evidence records the sampling outcome.

Reports are atomically replaced after each check and sampling result. Ctrl+C closes the connection and finalizes the partial reports. After a hard process termination, the latest `report.json`/`report.md` checkpoint remains available with `status: running`; resuming a scan is not implemented.

Exit codes:
- `0`: all attempted checks completed (deliberately skipped checks are allowed).
- `1`: initial connection or fatal scan/output failure.
- `2`: partial coverage due to failed, permission-denied, or unsupported checks; also used for invalid CLI arguments.
- `130`: interrupted with Ctrl+C.

MSSQL's existing automatic `sa` impersonation behavior runs only when `permissions` is selected and the connected login can impersonate `sa`. Reports record the original login, transition, and effective identity for subsequent checks. Reconnected sessions restore that identity.

### Select checks and scope

Use `--checks` with a comma-separated list:

| Check | Collects |
| --- | --- |
| `inventory` | Databases, schemas/tables, columns, and datatypes |
| `permissions` | Server/database privilege checks and MSSQL impersonation |
| `configuration` | Command execution or server-file configuration |
| `hashes` | Database users and available authentication hashes |
| `connections` | Current database connections |
| `links` | MSSQL linked servers, PostgreSQL foreign servers, MySQL FEDERATED tables |
| `emails` | MSSQL Database Mail messages |
| `findings` | Rule-based table/column detection and optional bounded samples |

The default runs all applicable checks; `emails` is omitted for MySQL/PostgreSQL. Explicit `--checks all` attempts every check and records unsupported engine-specific checks. `findings` automatically collects the inventory it needs. Connection identity and version checks always run. Other selected checks can also produce findings; `--min-confidence` filters detection rules, not privilege/configuration evidence.

Scope options accept **case-sensitive shell globs** and can be repeated. Quote globs to prevent shell expansion. Includes are ORed; exclusions always win.
- `--include-database GLOB`, `--exclude-database GLOB`: database names.
- `--include-schema GLOB`, `--exclude-schema GLOB`: schema names or `database.schema`.
- `--include-table GLOB`, `--exclude-table GLOB`: table names, `schema.table`, or `database.schema.table`.
- `-d NAME`: an exact database, still subject to database scope filters.

Database scope controls database-local checks. Schema/table scope controls inventory and detection/sampling. Server-wide checks remain server-wide. Metadata may be read to evaluate scope, but excluded objects are not sampled. Without `-d`, the initial connection uses the engine's default database; `--include-database` does not change that initial connection.

```bash
python3 sql_enum.py psql -t 127.0.0.1 -u pentester -p 'Password123!' \
  --checks inventory,findings --include-database 'corp*' \
  --include-schema 'public' --exclude-table '*audit*' --skip-data
```

### Detection rules

Built-in rules cover credentials, identity, financial, and other potentially sensitive names. Generic `id` is no longer treated as a credential indicator. `--columns` evaluates individual columns; the default reports tables. Matching multiple rules produces one finding and one sample per object, retaining all matching rule IDs and categories. The finding uses the highest matched confidence and severity. Confidence describes the naming signals, not confirmation that a value is a real secret.

`--filter 'password,api.key'` replaces the built-in rules with literal, case-insensitive keywords. Whitespace around keywords is trimmed. Use `--filter-mode regex` to explicitly interpret the comma-separated entries as regular expressions. Custom filters have medium confidence. `--filter` and `--rules` are mutually exclusive.

For combined table/column/datatype conditions, use `--rules examples/rules.json`. JSON format:

```json
{
  "rules": [
    {
      "id": "account-passwords",
      "category": "credentials",
      "severity": "high",
      "confidence": "high",
      "description": "Credential-like text column in an account table.",
      "match": {
        "table": "user|account",
        "column": "password|secret",
        "datatype": "char|text"
      },
      "exclude": {"column": "hint|policy"}
    }
  ]
}
```

All `match` conditions must match the same table/column combination; **any** `exclude` match rejects that combination. Patterns use Python's case-insensitive regex syntax. Fields are `table` (unqualified table name), `column`, `datatype`, and `name` (table name by default, column name with `--columns`). In table mode, a combined rule matches if any column meets its conditions. All fields except `exclude` are required; IDs must be unique. Severities: `info`, `low`, `medium`, `high`, `critical`. Confidence levels: `low`, `medium`, `high`. Invalid files or regexes are rejected before connecting.

```bash
python3 sql_enum.py mysql -t 127.0.0.1 -u root -p 'Password123!' -d web_store \
  --checks findings --columns --rules examples/rules.json --min-confidence high
```

### Sampling and timeouts

- `--sample-rows N`: maximum rows per detected object, default `1`.
- `--sample-bytes N`: total UTF-8 sample **value** bytes retained per finding, default `4096`; excludes field names/JSON overhead.
- `--skip-data`: skip table/column samples (does not disable separately selected hash/email checks).
- `--connect-timeout SECONDS`: default `10`.
- `--query-timeout SECONDS`: default `30`.

Sampling uses `TOP`/`LIMIT`, never `MAX()`, and truncates each selected cell server-side to at most `sample-bytes` characters before applying the aggregate byte budget locally. Sample values are display text, with SQL NULL preserved. Row/column positions are retained when values are truncated. Rows are not randomly selected or guaranteed representative. Unsupported casts are recorded as sampling failures and do not stop other objects from being checked.

PostgreSQL uses server-side `statement_timeout`; native MSSQL uses the driver's query timeout. MySQL uses socket read/write timeouts, and MSSQL Windows authentication uses a socket read/write timeout through Impacket. Socket timeouts bound individual network waits, not total execution time for a continuously streaming query. Failed queries discard their connection and the next check reconnects. Connection timeout behavior, including DNS resolution, follows the selected driver.

```bash
python3 sql_enum.py mssql -t 127.0.0.1 -u sa -p 'Password123!' \
  --checks inventory,findings --sample-rows 3 --sample-bytes 2048 \
  --connect-timeout 5 --query-timeout 15 --output-dir results/assessment-01
```
## Examples
To perform basic enumeration of a MSSQL server:
```bash
python3 sql_enum.py mssql -t 127.0.0.1 -u sa -p 'Password123!'
```
To use Active Directory credentials for MSSQL Windows authentication:
```bash
python3 sql_enum.py mssql -t sql01.corp.local -u pentester -p 'Password123!' --domain CORP
```
To use an NTLM hash for MSSQL Windows authentication:
```bash
python3 sql_enum.py mssql -t sql01.corp.local -u pentester --domain CORP -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
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

### Automated tests

After installing `requirements.txt`, run:

```bash
python3 -m unittest discover -s tests -v
```

Tests cover rule matching/validation, scope precedence, report/CSV round trips, failure isolation, interrupted scans, driver configuration, identity restoration, and real driver connection timeouts against a stalled loopback TCP peer. They do not require running database servers. The Docker fixtures below support live database verification.
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
- [ ] Implement Kerberos authentication
- [x] Implement MSSQL Windows authentication using passwords/NTLM hashes (Kerberos remains pending)
- [ ] Implement TLS/SSL authentication
- [ ] Perform more testing in live environments to discover edge cases/bugs
- [x] Test x86 dev setup
- [ ] Test xp_dirtree coercion
    - The experimental helper is not exposed through the CLI; needs a MSSQL VM for validation
- [x] Add option to filter only for custom word[s]
- [x] Add option to skip sample data queries
- [x] Add option to filter on table names instead of columns (good for larger databases)
- [x] Add unified findings, JSON/Markdown reports, and check coverage
- [x] Add configurable JSON rules, confidence filtering, and deduplication
- [x] Add scoped checks, timeouts, bounded sampling, and partial reports
- [ ] Look into sqlmap integration
