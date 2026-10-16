-- Migration 005: Support DNS-01 Challenge
CREATE TYPE challenge_type AS ENUM ('http-01', 'dns-01');

ALTER TABLE challenges ADD COLUMN type challenge_type NOT NULL DEFAULT 'http-01';

ALTER TABLE challenges DROP CONSTRAINT IF EXISTS challenges_authz_id_key;

ALTER TABLE challenges ADD CONSTRAINT challenges_authz_id_type_key UNIQUE (authz_id, type);
