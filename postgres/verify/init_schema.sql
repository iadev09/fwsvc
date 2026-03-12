-- Verify fwsvc:init_schema on pg

BEGIN;

-- XXX Add verifications here.


SELECT 1 FROM firewall.services LIMIT 1;
SELECT 1 FROM firewall.service_ports LIMIT 1;
SELECT 1 FROM firewall.service_ips LIMIT 1;
SELECT 1 FROM firewall.service_allowed LIMIT 1;

ROLLBACK;
