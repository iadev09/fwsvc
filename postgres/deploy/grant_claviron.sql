-- Deploy fwsvc:grant_claviron to pg

BEGIN;

SET LOCAL ROLE roman;

-- Allow schema visibility
GRANT USAGE ON SCHEMA firewall TO claviron;

-- Existing tables
GRANT SELECT, INSERT, UPDATE, DELETE
ON ALL TABLES IN SCHEMA firewall
TO claviron;

-- Existing sequences
GRANT USAGE, SELECT, UPDATE
ON ALL SEQUENCES IN SCHEMA firewall
TO claviron;

-- Future tables
ALTER DEFAULT PRIVILEGES
FOR ROLE roman IN SCHEMA firewall
GRANT SELECT, INSERT, UPDATE, DELETE
ON TABLES TO claviron;

-- Future sequences
ALTER DEFAULT PRIVILEGES
FOR ROLE roman IN SCHEMA firewall
GRANT USAGE, SELECT, UPDATE
ON SEQUENCES TO claviron;

COMMIT;
