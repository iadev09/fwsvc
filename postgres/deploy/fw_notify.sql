-- Deploy fwsvc:fw_notify to pg

BEGIN;

SET LOCAL ROLE roman;

CREATE OR REPLACE FUNCTION firewall.reject_fwsvc_event_updates()
RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION
    'Firewall event rows are immutable on %.%; use DELETE + INSERT instead',
    TG_TABLE_SCHEMA,
    TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION firewall.notify_fwsvc_global_blacklist()
RETURNS trigger AS $$
BEGIN
  IF (CASE WHEN TG_OP = 'DELETE' THEN OLD.kind ELSE NEW.kind END) <> 'blacklist' THEN
    RETURN NULL;
  END IF;

  PERFORM pg_notify(
    'fwsvc_events',
    jsonb_build_object(
      'entity', 'global_blacklist',
      'op', lower(TG_OP),
      'source',
      CASE
        WHEN TG_OP = 'DELETE' THEN host(OLD.source) || '/' || masklen(OLD.source)
        ELSE host(NEW.source) || '/' || masklen(NEW.source)
      END
    )::text
  );
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION firewall.notify_fwsvc_service_allowed()
RETURNS trigger AS $$
BEGIN
  PERFORM pg_notify(
    'fwsvc_events',
    jsonb_build_object(
      'entity', 'service_allowed',
      'op', lower(TG_OP),
      'service_id', CASE WHEN TG_OP = 'DELETE' THEN OLD.service_id ELSE NEW.service_id END,
      'source',
      CASE
        WHEN TG_OP = 'DELETE' THEN host(OLD.source) || '/' || masklen(OLD.source)
        ELSE host(NEW.source) || '/' || masklen(NEW.source)
      END
    )::text
  );
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_fwsvc_no_update_service_allowed ON firewall.service_allowed;
CREATE TRIGGER trg_fwsvc_no_update_service_allowed
BEFORE UPDATE ON firewall.service_allowed
FOR EACH ROW
EXECUTE FUNCTION firewall.reject_fwsvc_event_updates();

DROP TRIGGER IF EXISTS trg_fwsvc_notify_service_allowed ON firewall.service_allowed;
CREATE TRIGGER trg_fwsvc_notify_service_allowed
AFTER INSERT OR DELETE ON firewall.service_allowed
FOR EACH ROW
EXECUTE FUNCTION firewall.notify_fwsvc_service_allowed();

DROP TRIGGER IF EXISTS trg_fwsvc_no_update_global_list_entries ON firewall.global_list_entries;
CREATE TRIGGER trg_fwsvc_no_update_global_list_entries
BEFORE UPDATE ON firewall.global_list_entries
FOR EACH ROW
EXECUTE FUNCTION firewall.reject_fwsvc_event_updates();

DROP TRIGGER IF EXISTS trg_fwsvc_notify_global_list_entries ON firewall.global_list_entries;
CREATE TRIGGER trg_fwsvc_notify_global_list_entries
AFTER INSERT OR DELETE ON firewall.global_list_entries
FOR EACH ROW
EXECUTE FUNCTION firewall.notify_fwsvc_global_blacklist();

COMMIT;
