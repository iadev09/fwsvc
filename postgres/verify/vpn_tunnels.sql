-- Verify fwsvc:vpn_tunnels on pg

BEGIN;

-- Enum exists
SELECT 1
FROM pg_type t
JOIN pg_namespace n ON n.oid = t.typnamespace
WHERE n.nspname = 'firewall'
  AND t.typname = 'vpn_nat_mode'
  AND t.typtype = 'e';

-- Table exists
SELECT 1
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'firewall'
  AND c.relname = 'vpn_tunnels'
  AND c.relkind = 'r';

-- Required columns exist
WITH cols AS (
  SELECT column_name
  FROM information_schema.columns
  WHERE table_schema = 'firewall'
    AND table_name = 'vpn_tunnels'
)
SELECT 1
WHERE (
  SELECT COUNT(*)
  FROM cols
  WHERE column_name IN (
    'id',
    'name',
    'enabled',
    'transport_protocol',
    'port',
    'address',
    'network',
    'nat_mode',
    'snat_to',
    'egress_interface',
    'created_at',
    'updated_at'
  )
) = 12;

-- Trigger exists (updated_at maintenance)
SELECT 1
FROM pg_trigger tg
JOIN pg_class c ON c.oid = tg.tgrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'firewall'
  AND c.relname = 'vpn_tunnels'
  AND tg.tgname = 'trg_vpn_tunnels_updated_at'
  AND tg.tgenabled <> 'D'
  AND NOT tg.tgisinternal;

-- Indexes exist
SELECT 1
FROM pg_class idx
JOIN pg_index i ON i.indexrelid = idx.oid
JOIN pg_class tbl ON tbl.oid = i.indrelid
JOIN pg_namespace n ON n.oid = tbl.relnamespace
WHERE n.nspname = 'firewall'
  AND tbl.relname = 'vpn_tunnels'
  AND idx.relname = 'idx_vpn_tunnels_enabled_name';

SELECT 1
FROM pg_class idx
JOIN pg_index i ON i.indexrelid = idx.oid
JOIN pg_class tbl ON tbl.oid = i.indrelid
JOIN pg_namespace n ON n.oid = tbl.relnamespace
WHERE n.nspname = 'firewall'
  AND tbl.relname = 'vpn_tunnels'
  AND idx.relname = 'idx_vpn_tunnels_nat_mode';

ROLLBACK;
