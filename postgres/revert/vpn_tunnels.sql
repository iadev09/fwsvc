-- Revert fwsvc:vpn_tunnels from pg

BEGIN;

SET LOCAL ROLE roman;

-- Drop trigger first (table drop would cascade it too, but be explicit)
DROP TRIGGER IF EXISTS trg_vpn_tunnels_updated_at ON firewall.vpn_tunnels;

-- Drop table
DROP TABLE IF EXISTS firewall.vpn_tunnels;

-- Drop enum (will fail if still referenced elsewhere, which is fine for revert)
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_type t
    JOIN pg_namespace n ON n.oid = t.typnamespace
    WHERE n.nspname = 'firewall' AND t.typname = 'vpn_nat_mode'
  ) THEN
    DROP TYPE firewall.vpn_nat_mode;
  END IF;
END
$$;

COMMIT;
