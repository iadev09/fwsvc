-- Deploy fwsvc:vpn_tunnels to pg

BEGIN;

SET LOCAL ROLE roman;

-- VPN NAT mode enum
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_type t
    JOIN pg_namespace n ON n.oid = t.typnamespace
    WHERE n.nspname = 'firewall' AND t.typname = 'vpn_nat_mode'
  ) THEN
    CREATE TYPE firewall.vpn_nat_mode AS ENUM ('none', 'masquerade', 'snat');
  END IF;
END
$$;

-- VPN tunnels
CREATE TABLE IF NOT EXISTS firewall.vpn_tunnels (
  id SERIAL PRIMARY KEY,
  name VARCHAR(32) NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9_]+$'),
  enabled BOOLEAN NOT NULL DEFAULT true,

  -- Public/listen side
  transport_protocol firewall.transport_protocol NOT NULL,
  port SMALLINT NOT NULL CHECK (port BETWEEN 1 AND 65535),
  address CIDR NOT NULL,

  -- Tunnel network
  network CIDR NOT NULL,

  -- NAT behavior for outbound traffic originating from `network`
  nat_mode firewall.vpn_nat_mode NOT NULL DEFAULT 'none',
  snat_to CIDR,

  -- Optional: egress interface name for NAT (if NULL, fwsvc decides)
  egress_interface VARCHAR(32),

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- If nat_mode is not snat, snat_to must be NULL.
  CHECK ((nat_mode = 'snat') OR (snat_to IS NULL))
);

-- Keep updated_at fresh
DROP TRIGGER IF EXISTS trg_vpn_tunnels_updated_at ON firewall.vpn_tunnels;
CREATE TRIGGER trg_vpn_tunnels_updated_at
BEFORE UPDATE ON firewall.vpn_tunnels
FOR EACH ROW
EXECUTE FUNCTION firewall.set_updated_at();

-- Indexes for common reads
CREATE INDEX IF NOT EXISTS idx_vpn_tunnels_enabled_name
ON firewall.vpn_tunnels(name)
WHERE enabled = true;

CREATE INDEX IF NOT EXISTS idx_vpn_tunnels_nat_mode
ON firewall.vpn_tunnels(nat_mode);

COMMIT;
