-- Revert fwsvc:fw_notify from pg

BEGIN;

SET LOCAL ROLE roman;

DROP TRIGGER IF EXISTS trg_fwsvc_no_update_global_list_entries ON firewall.global_list_entries;
DROP TRIGGER IF EXISTS trg_fwsvc_notify_global_list_entries ON firewall.global_list_entries;
DROP TRIGGER IF EXISTS trg_fwsvc_no_update_service_allowed ON firewall.service_allowed;
DROP TRIGGER IF EXISTS trg_fwsvc_notify_service_allowed ON firewall.service_allowed;
DROP FUNCTION IF EXISTS firewall.reject_fwsvc_event_updates();
DROP FUNCTION IF EXISTS firewall.notify_fwsvc_service_allowed();
DROP FUNCTION IF EXISTS firewall.notify_fwsvc_global_blacklist();

COMMIT;
