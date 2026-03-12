# fwsvc

`fwsvc` is a DB-backed firewall service for Linux hosts.

It reads firewall state from PostgreSQL and applies it to `iptables`.
The service owns the firewall state it manages and rebuilds that state on reload.

## What It Does

- Loads public services from the database and opens their IP/port rules.
- Loads private services and applies source-based allow rules.
- Applies global whitelist and blacklist entries.
- Applies VPN access rules and VPN NAT rules.
- Resets and rebuilds `filter` and `nat` state during reload.
- Saves the resulting IPv4 ruleset to the distro-specific persistent path.

## Runtime Model

- Startup does not automatically rebuild firewall state.
- `SIGHUP` triggers a full reload from PostgreSQL.
- The service listens on PostgreSQL `LISTEN/NOTIFY` channel `fwsvc_events`.
- Listener events are runtime signals; they are not the same thing as a full reload.
- Only one `fwsvc` instance is allowed at a time.

## Rule Order

Current reload order is:

1. Reset `filter` and `nat`
2. Accept loopback traffic
3. Accept `ESTABLISHED,RELATED`
4. Apply global whitelist
5. Apply global blacklist
6. Apply private service rules
7. Apply public service rules
8. Apply VPN access rules
9. Apply VPN NAT rules
10. Drop everything else on `INPUT`

This favors connection stability and predictable rebuilds over aggressive immediate blocking.

## Database

`fwsvc` expects PostgreSQL schema and migrations from this repository.

Relevant changes currently include:

- `init_schema`
- `grant_claviron`
- `vpn_tunnels`
- `fw_notify`

Apply them with Sqitch before running the service.

## Configuration

Database connection info is read from:

1. `FW_DATABASE_URL`
2. `DATABASE_URL`

If neither is set, `fwsvc` exits.

Examples:

```bash
export FW_DATABASE_URL='dbname=roma user=claviron host=/var/run/postgresql'
```

or

```bash
export FW_DATABASE_URL='postgres://claviron@/roma?host=/var/run/postgresql'
```

`FW_DEBUG=1` enables extra runtime debug logs.

## Build

```bash
cmake -S . -B build-debug -G Ninja -DCMAKE_C_COMPILER=/usr/bin/clang -DCMAKE_BUILD_TYPE=Debug
cmake --build build-debug
```

## Run

Normal development run:

```bash
FW_DATABASE_URL='dbname=roma user=claviron host=/var/run/postgresql' ./build-debug/fwsvc
```

Real firewall reload testing requires root:

```bash
FW_DATABASE_URL='dbname=roma user=claviron host=/var/run/postgresql' ./runner.sh
```

## Reload

Manual reload:

```bash
kill -HUP <pid>
```

Successful reload prints:

```text
fwsvc: firewall reload completed
```

If reload fails after mutation begins, `fwsvc` restores the previous iptables snapshot.

## Persistence

On successful reload, `fwsvc` saves IPv4 rules to a distro-specific path:

- Debian/Ubuntu: `/etc/iptables/rules.v4`
- RHEL/Fedora family: `/etc/sysconfig/iptables`

On Debian, reboot-time restore typically requires:

- `netfilter-persistent`
- `iptables-persistent`

## Current Scope

Included:

- Public services
- Private services
- Global whitelist
- Global blacklist
- VPN access
- VPN NAT (`masquerade`, `snat`)

Not implemented yet:

- Service logging behavior
- Reserved/private drop behavior from older workflows
- Incremental per-event iptables reconciliation
- `mangle` table handling
