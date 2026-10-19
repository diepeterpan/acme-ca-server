-- Migration 006: Support OIDC Users and Email Address
CREATE TYPE user_type AS ENUM ('local', 'oidc');

ALTER TABLE users ADD COLUMN user_type user_type NOT NULL DEFAULT 'local';

ALTER TABLE users ADD COLUMN email mail_addr UNIQUE;

ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;

-- Database constraints:
-- 1. OIDC users must have an email address
ALTER TABLE users ADD CONSTRAINT chk_oidc_user_email 
    CHECK (user_type = 'local' OR (user_type = 'oidc' AND email IS NOT NULL));

-- 2. Local users must have a password hash
ALTER TABLE users ADD CONSTRAINT chk_local_user_password 
    CHECK (user_type = 'oidc' OR (user_type = 'local' AND password_hash IS NOT NULL));

CREATE INDEX users_email_idx ON users (email);
