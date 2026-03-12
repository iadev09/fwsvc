-- Revert fwsvc:init_schema from pg

BEGIN;

-- Run DDL as the owner role, scoped to this transaction.
SET LOCAL ROLE roman;

-- Drop everything created in init_schema.
DROP SCHEMA IF EXISTS firewall CASCADE;

COMMIT;