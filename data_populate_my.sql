USE web_store;

-- Create a table for session hijacking tests
CREATE TABLE site_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_data TEXT,
    is_active TINYINT(1)
);

-- Sparse data: 10 empty sessions, 1 admin session
INSERT INTO site_sessions (session_data, is_active) VALUES 
(NULL, 0), (NULL, 0), (NULL, 0), (NULL, 0), (NULL, 0),
(NULL, 0), (NULL, 0), (NULL, 0), (NULL, 0), (NULL, 0),
('user_id=1; role=admin; hash=884350bd67c062b55365511073906212', 1);

-- Testing binary/blob data storage
CREATE TABLE legacy_vault (
    vault_id INT,
    enc_payload VARBINARY(255)
);

INSERT INTO legacy_vault (vault_id, enc_payload)
VALUES (999, 0xDEADC0DEBEEF1337);

-- 1. Create the user restricted to a specific host (e.g., localhost)
CREATE USER 'guest_user' IDENTIFIED BY 'GuestPassword123!';

-- 2. Grant READ-ONLY access to only ONE specific database
GRANT SELECT ON web_store.* TO 'guest_user';

-- 3. (Optional) Explicitly restrict them from seeing the 'mysql' system DB
REVOKE ALL PRIVILEGES ON mysql.* FROM 'guest_user';

-- 4. Apply the changes
FLUSH PRIVILEGES;