-- Verify fwsvc:fw_notify on pg

BEGIN;

SELECT pg_get_functiondef('firewall.notify_fwsvc_service_allowed()'::regprocedure);
SELECT pg_get_functiondef('firewall.notify_fwsvc_global_blacklist()'::regprocedure);
SELECT pg_get_functiondef('firewall.reject_fwsvc_event_updates()'::regprocedure);
SELECT 1
FROM pg_trigger
WHERE tgname = 'trg_fwsvc_notify_service_allowed';
SELECT 1
FROM pg_trigger
WHERE tgname = 'trg_fwsvc_notify_global_list_entries';
SELECT 1
FROM pg_trigger
WHERE tgname = 'trg_fwsvc_no_update_service_allowed';
SELECT 1
FROM pg_trigger
WHERE tgname = 'trg_fwsvc_no_update_global_list_entries';

ROLLBACK;
