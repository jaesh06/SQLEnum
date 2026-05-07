-- Create a 'secret' schema to test discovery
CREATE SCHEMA IF NOT EXISTS internal_vault;

CREATE TABLE internal_vault.api_tokens (
    id SERIAL PRIMARY KEY,
    service_name TEXT,
    token_val TEXT
);

-- Sparse data: 10 rows of junk, 1 row of gold
INSERT INTO internal_vault.api_tokens (service_name, token_val)
SELECT NULL, NULL FROM generate_series(1, 10);

INSERT INTO internal_vault.api_tokens (service_name, token_val)
VALUES ('Stripe_Live_Key', 'sk_live_51MzS24Lkd7QW9abcdefg');

-- A table with BIT-like boolean data (Postgres supports BOOLEAN natively)
CREATE TABLE public.user_flags (
    user_id INT,
    is_admin BOOLEAN
);

INSERT INTO public.user_flags (user_id, is_admin)
VALUES (101, NULL), (102, NULL), (103, TRUE);

-- 1. Create the user with 'NOLOGIN' style properties (no superuser, no create db)
CREATE USER guest_user WITH PASSWORD 'GuestPassword123!';

-- 2. Revoke their ability to create objects in the 'public' schema
REVOKE CREATE ON SCHEMA public FROM guest_user;

-- 3. Grant them ONLY 'CONNECT' to your specific database
GRANT CONNECT ON DATABASE corp_data TO guest_user;

-- 4. Grant SELECT (read-only) on existing tables in a specific schema
GRANT USAGE ON SCHEMA public TO guest_user;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO guest_user;