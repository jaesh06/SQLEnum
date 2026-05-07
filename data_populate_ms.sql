-- DATABASE 1: Sensitive DB
CREATE DATABASE CorporateDB;
GO

USE CorporateDB;
GO

-- 1. Users (Identity)
CREATE TABLE Users (
    id INT PRIMARY KEY,
    username VARCHAR(50),
    password_hash VARCHAR(100),
    email VARCHAR(100)
);

-- DATABASE 2: ERP_Production (Standard Corporate Structure)
CREATE DATABASE ERP_Production;
GO
USE ERP_Production;
GO

-- 1. Employees (Identity)
CREATE TABLE dbo.Employees (id INT PRIMARY KEY, login_name VARCHAR(50), password_hash CHAR(64), ssn_last4 INT, hire_date DATE);
-- 2. Payroll (Financial)
CREATE TABLE dbo.Payroll (emp_id INT, salary INT, iban_code VARCHAR(34), tax_id VARCHAR(20));
-- 3. API_Configs (Sensitive)
CREATE TABLE dbo.API_Configs (service_name VARCHAR(50), api_key VARCHAR(100), secret_token VARCHAR(100));
-- 4. Audit_Logs
CREATE TABLE dbo.Audit_Logs (log_id INT, event_desc TEXT, ip_address VARCHAR(15));
-- 5. Customers
CREATE TABLE dbo.Customers (cust_id INT, full_name VARCHAR(100), email_addr VARCHAR(100));
-- 6. Credit_Cards (Loot)
CREATE TABLE dbo.Credit_Cards (cc_id INT, cust_id INT, card_number_enc VARBINARY(MAX), expiry VARCHAR(5));
-- 7. Warehousing
CREATE TABLE dbo.Warehousing (item_id INT, stock_count INT, location_code VARCHAR(10));
-- 8. Vendors
CREATE TABLE dbo.Vendors (v_id INT, v_name VARCHAR(100), contact_phone VARCHAR(20));
-- 9. App_Settings
CREATE TABLE dbo.App_Settings (setting_name VARCHAR(50), setting_value VARCHAR(MAX));
-- 10. Legacy_Users
CREATE TABLE dbo.Legacy_Users (uid INT, old_pass VARCHAR(50), salt VARCHAR(20));
GO

-- DATABASE 3: Web_Storefront (Public-facing style)
CREATE DATABASE Web_Storefront;
GO
USE Web_Storefront;
GO

CREATE SCHEMA site;
GO

-- 1. Web_Logins
CREATE TABLE site.Web_Logins (id INT, username VARCHAR(50), pwd VARCHAR(50), last_login DATETIME);
-- 2. User_Profiles
CREATE TABLE site.User_Profiles (id INT, bio TEXT, avatar_url VARCHAR(255), dob DATE);
-- 3. Orders
CREATE TABLE site.Orders (order_id INT, total_amt DECIMAL(10,2), payment_status VARCHAR(20));
-- 4. Product_Catalog
CREATE TABLE site.Product_Catalog (sku VARCHAR(20), price MONEY, description TEXT);
-- 5. Support_Tickets
CREATE TABLE site.Support_Tickets (ticket_id INT, user_email VARCHAR(100), issue_text VARCHAR(MAX));
-- 6. Sessions (Sensitive)
CREATE TABLE site.Sessions (session_id VARCHAR(100), user_id INT, cookie_data TEXT);
-- 7. Discounts
CREATE TABLE site.Discounts (code VARCHAR(20), percent_off INT);
-- 8. Newsletter_Subs
CREATE TABLE site.Newsletter_Subs (email VARCHAR(100), active BIT);
-- 9. Site_Admin_Notes
CREATE TABLE site.Site_Admin_Notes (note_id INT, admin_comment VARCHAR(MAX), private_flag BIT);
-- 10. Password_Resets
CREATE TABLE site.Password_Resets (reset_token VARCHAR(100), expires_at DATETIME);
GO

-- Create Pentest User
CREATE LOGIN test WITH PASSWORD = 'PentestPassword123!', CHECK_POLICY = OFF;
CREATE USER test FOR LOGIN test;
EXEC sp_addrolemember 'db_datareader', 'test';
GO

-- Grant access to your test user (should not have access to CorporateDB)
USE ERP_Production;
CREATE USER test FOR LOGIN test;
EXEC sp_addrolemember 'db_datareader', 'test';
GO
USE Web_Storefront;
CREATE USER test FOR LOGIN test;
EXEC sp_addrolemember 'db_datareader', 'test';
GO

-- This section puts fake data into databases
-- DATABASE 1: CorporateDB
USE CorporateDB;
GO

-- Populate Users with fake users
INSERT INTO Users VALUES 
(1, 'admin', '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918', 'admin@corp.local'),
(2, 'jdoe', '5f4dcc3b5aa765d61d8327deb882cf99', 'j.doe@corp.local');

-- DATABASE 2: ERP_Production
USE ERP_Production;
GO

-- Populate API_Configs with sparse data (10 NULLs, 1 Valid Key)
INSERT INTO dbo.API_Configs (service_name, api_key, secret_token) VALUES 
(NULL, NULL, NULL), (NULL, NULL, NULL), (NULL, NULL, NULL), (NULL, NULL, NULL), (NULL, NULL, NULL),
(NULL, NULL, NULL), (NULL, NULL, NULL), (NULL, NULL, NULL), (NULL, NULL, NULL), (NULL, NULL, NULL),
('AWS_PROD', 'AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');

-- Populate Credit_Cards with sparse data (10 NULLs, 1 Valid Card)
INSERT INTO dbo.Credit_Cards (cc_id, cust_id, card_number_enc) VALUES 
(101, NULL, NULL), (102, NULL, NULL), (103, NULL, NULL), (104, NULL, NULL), (105, NULL, NULL),
(106, NULL, NULL), (107, NULL, NULL), (108, NULL, NULL), (109, NULL, NULL), (110, NULL, NULL),
(111, 5001, 0x414243443132333435363738); -- Dummy hex for 'ABCD12345678'
GO

-- DATABASE 3: Web_Storefront
USE Web_Storefront;
GO

-- Populate Sessions with sparse data
INSERT INTO site.Sessions (session_id, user_id, cookie_data) VALUES 
(NULL, NULL, NULL), (NULL, NULL, NULL), (NULL, NULL, NULL), (NULL, NULL, NULL), (NULL, NULL, NULL),
(NULL, NULL, NULL), (NULL, NULL, NULL), (NULL, NULL, NULL), (NULL, NULL, NULL), (NULL, NULL, NULL),
('sess_99999', 1, 'session_token=h4ck3r_p2w_acc3ss_99; user=admin');

-- Populate Site_Admin_Notes with sparse data
INSERT INTO site.Site_Admin_Notes (note_id, admin_comment, private_flag) VALUES 
(201, NULL, 0), (202, NULL, 0), (203, NULL, 0), (204, NULL, 0), (205, NULL, 0),
(206, NULL, 0), (207, NULL, 0), (208, NULL, 0), (209, NULL, 0), (210, NULL, 0),
(211, 'Migration complete. Default password for new devs is: DevPass2026!', 1);
GO
