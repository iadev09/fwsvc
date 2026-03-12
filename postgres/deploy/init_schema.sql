-- Deploy fwsvc:init_schema to pg

BEGIN;

-- Run all DDL as the owner role, scoped to this transaction.
SET LOCAL ROLE roman;

CREATE SCHEMA IF NOT EXISTS firewall AUTHORIZATION roman;

-- =====================================================
-- Firewall services
-- =====================================================

-- Service scope enum
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_type t
    JOIN pg_namespace n ON n.oid = t.typnamespace
    WHERE n.nspname = 'firewall' AND t.typname = 'service_scope'
  ) THEN
    CREATE TYPE firewall.service_scope AS ENUM ('public', 'private');
  END IF;
END
$$;

-- Transport protocol enum
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_type t
    JOIN pg_namespace n ON n.oid = t.typnamespace
    WHERE n.nspname = 'firewall' AND t.typname = 'transport_protocol'
  ) THEN
    CREATE TYPE firewall.transport_protocol AS ENUM ('tcp', 'udp');
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS firewall.services (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9_]+$'),
  scope firewall.service_scope NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT true,
  logging BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Automatically maintain updated_at
CREATE OR REPLACE FUNCTION firewall.set_updated_at()
RETURNS trigger AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_services_updated_at ON firewall.services;
CREATE TRIGGER trg_services_updated_at
BEFORE UPDATE ON firewall.services
FOR EACH ROW
EXECUTE FUNCTION firewall.set_updated_at();

-- Fast reads for fwsvc: enabled services ordered by scope then name
CREATE INDEX IF NOT EXISTS idx_services_enabled_scope_name
ON firewall.services(scope, name)
WHERE enabled = true;

CREATE TABLE IF NOT EXISTS firewall.service_ports (
  id SERIAL PRIMARY KEY,
  service_id INTEGER NOT NULL
    REFERENCES firewall.services(id)
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  transport_protocol firewall.transport_protocol NOT NULL,
  port SMALLINT NOT NULL CHECK (port BETWEEN 1 AND 65535),
  UNIQUE(service_id, transport_protocol, port)
);

CREATE INDEX IF NOT EXISTS idx_service_ports_service_id
ON firewall.service_ports(service_id);

-- Destination addresses for a service (public or private)
CREATE TABLE IF NOT EXISTS firewall.service_ips (
  id SERIAL PRIMARY KEY,
  service_id INTEGER NOT NULL
    REFERENCES firewall.services(id)
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  address CIDR NOT NULL,
  UNIQUE(service_id, address)
);

CREATE INDEX IF NOT EXISTS idx_service_ips_service_id
ON firewall.service_ips(service_id);

-- Allowed source addresses (ACL) for PRIVATE services
CREATE TABLE IF NOT EXISTS firewall.service_allowed (
  id SERIAL PRIMARY KEY,
  service_id INTEGER NOT NULL
    REFERENCES firewall.services(id)
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  source CIDR NOT NULL,
  comment TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ,
  UNIQUE(service_id, source)
);

CREATE INDEX IF NOT EXISTS idx_service_allowed_service_id
ON firewall.service_allowed(service_id);

CREATE INDEX IF NOT EXISTS idx_service_allowed_expires_at
ON firewall.service_allowed(expires_at);

-- =====================================================
-- Global whitelist / blacklist (CIDR entries)
-- =====================================================

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_type t
    JOIN pg_namespace n ON n.oid = t.typnamespace
    WHERE n.nspname = 'firewall' AND t.typname = 'global_list_kind'
  ) THEN
    CREATE TYPE firewall.global_list_kind AS ENUM ('whitelist', 'blacklist');
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS firewall.global_list_entries (
  id SERIAL PRIMARY KEY,
  kind firewall.global_list_kind NOT NULL,
  source CIDR NOT NULL,
  comment TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ,
  UNIQUE(kind, source)
);

CREATE INDEX IF NOT EXISTS idx_global_list_entries_expires_at
ON firewall.global_list_entries(expires_at);

CREATE OR REPLACE FUNCTION firewall.enforce_private_service_allowed()
RETURNS trigger AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM firewall.services s
    WHERE s.id = NEW.service_id
      AND s.scope = 'private'
  ) THEN
    RAISE EXCEPTION
      'service_allowed can only reference services with scope=private (service_id=%)',
      NEW.service_id;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_service_allowed_private_only ON firewall.service_allowed;
CREATE TRIGGER trg_service_allowed_private_only
BEFORE INSERT OR UPDATE ON firewall.service_allowed
FOR EACH ROW
EXECUTE FUNCTION firewall.enforce_private_service_allowed();


-- =====================================================
-- Derived chain names
-- =====================================================

-- Deterministic chain name derived from service scope + name.
-- Example: private + fundist -> Private_Fundist
CREATE OR REPLACE VIEW firewall.service_chains AS
SELECT
  s.id AS service_id,
  s.name AS service_name,
  s.scope AS service_scope,
  (
    CASE
      WHEN s.scope = 'private' THEN 'Private_'
      ELSE 'Public_'
    END
    || regexp_replace(initcap(replace(s.name, '_', ' ')), ' ', '_', 'g')
  ) AS chain_name
FROM firewall.services s
WHERE s.enabled = true;

COMMIT;
