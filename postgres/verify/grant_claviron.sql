-- Verify fwsvc:grant_claviron on pg

BEGIN;

SET LOCAL ROLE developer;

-- Schema usage check
SELECT 1
FROM pg_namespace n
JOIN pg_roles r ON r.rolname = 'claviron'
WHERE n.nspname = 'firewall'
  AND has_schema_privilege('claviron', n.oid, 'USAGE');

-- Table privilege check (örnek: services)
SELECT 1
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'firewall'
  AND c.relname = 'services'
  AND has_table_privilege('claviron', c.oid, 'SELECT');

ROLLBACK;