# OpenBSDDDOSShield

`ddosshield` is an OpenBSD daemon that monitors the pf(4) state table
for suspected DDoS attacks and reports them to a remote syslog server
over UDP using the RFC 3164 syslog protocol.

## How it works

1. Every *interval* seconds `ddosshield` runs `pfctl -s state` and
   counts the number of active connections per source IP address.
2. If any source IP exceeds the configured *threshold* during that
   interval, a **warning** syslog message is sent via UDP to the
   remote syslog server.
3. Counters are reset at the end of each interval and monitoring
   continues.

On OpenBSD, `pledge(2)` is used to restrict the process to only the
privileges it actually needs (`stdio proc exec inet`).

## Prerequisites

* OpenBSD with pf(4) enabled and `pfctl` at `/sbin/pfctl`
* GNUstep Base and libobjc2 — install with the package manager:

```sh
pkg_add gnustep-make gnustep-base libobjc2
```

* The process must have permission to run `pfctl -s state`
  (typically requires root)

## Building

```sh
make
```

The program is written in Objective-C and compiled with `cc` against
GNUstep Base and `libobjc2`.

## Installation

```sh
doas make install   # installs to /usr/local/sbin/ddosshield
```

## Configuration

Copy the example configuration file and edit it:

```sh
doas cp ddosshield.conf.example /etc/ddosshield.conf
doas vi /etc/ddosshield.conf
```

| Key           | Default | Description                                         |
|---------------|---------|-----------------------------------------------------|
| `remote_host` | —       | Hostname or IP of the remote syslog server (required) |
| `remote_port` | `514`   | UDP port on the remote syslog server                |
| `threshold`   | `100`   | Connections from one IP per interval to trigger alert |
| `interval`    | `10`    | Sampling interval in seconds                        |

## Usage

```
ddosshield [-v] [-c config] [-H host] [-p port] [-t threshold] [-i interval]

  -v            Verbose mode: print alerts to stderr as well
  -c config     Path to configuration file (default: /etc/ddosshield.conf)
  -H host       Remote syslog server hostname or IP
  -p port       Remote syslog server UDP port (default: 514)
  -t threshold  Connection threshold per interval (default: 100)
  -i interval   Sampling interval in seconds (default: 10)
```

### Quick start (no config file)

```sh
doas ddosshield -v -H 192.0.2.1 -t 50 -i 5
```

### Running as a daemon via rc(8)

Add the following to `/etc/rc.conf.local`:

```
ddosshield_flags="-c /etc/ddosshield.conf"
```

And create `/etc/rc.d/ddosshield`:

```sh
#!/bin/ksh
daemon="/usr/local/sbin/ddosshield"
. /etc/rc.d/rc.subr
rc_cmd $1
```

Then enable and start it:

```sh
doas rcctl enable ddosshield
doas rcctl start ddosshield
```

## Remote syslog server setup

Configure the remote syslog server to accept UDP traffic on port 514
from the OpenBSD host.  For example, with `syslogd(8)` on another
OpenBSD machine add `-u` to accept remote UDP messages and add a rule
in `/etc/syslog.conf` to capture `local0.warning` messages.
A ready-to-deploy DDoS and brute-force protection stack for OpenBSD web
servers, built entirely from OpenBSD's native tools:

| Component | Role |
|-----------|------|
| **pf** (Packet Filter) | SYN-proxy, per-IP connection/rate limits, auto-ban table |
| **relayd** | Reverse proxy, health checks, HTTP header filtering, idle timeouts |
| **sysctl** | TCP/IP stack hardening (SYN cookies, cache sizes, broadcast ICMP) |
| **cron** | Periodic expiry of auto-banned IPs |

No third-party software is required.

---

## Architecture

```
Internet
   │
   ▼
[pf — Packet Filter]
   • Scrub / normalise packets
   • SYN-proxy (defeats SYN floods before the connection reaches relayd)
   • Per-source-IP connection count & rate limits
   • Auto-populate <ddos_block> table → all connections from offender dropped
   │
   ▼
[relayd — Relay Daemon]
   • Short idle timeouts (defeats Slowloris / slow-read attacks)
   • Forces "Connection: close" (limits keep-alive abuse)
   • Injects X-Forwarded-For / X-Real-IP headers
   • Strips Server / X-Powered-By response headers
   • HTTP health checks → stops forwarding to a downed backend
   │
   ▼
[Backend web server — httpd / nginx / apache / etc.]
   Listens on 127.0.0.1:8080 (not exposed directly to the internet)
```

---

## Files

```
etc/
  pf.conf       OpenBSD Packet Filter rules
  relayd.conf   relayd relay daemon configuration
scripts/
  setup.sh      One-shot installer (copies configs, applies sysctl, starts services)
```

---

## Quick start

### 1. Adjust variables

**`etc/pf.conf`** — set your external interface and tune the limits:

```sh
ext_if      = "em0"   # Change to your NIC (ifconfig to find it)

max_http_conn      = "200"  # Simultaneous HTTP connections per source IP
max_http_conn_rate = "50/5" # New connections per 5-second window per source IP
max_ssh_conn       = "5"
max_ssh_rate       = "5/60"
max_icmp_rate      = "5/10"
```

**`etc/relayd.conf`** — set your backend address:

```sh
relay_http_addr    = "0.0.0.0"
relay_http_port    = 80        # relayd listens here (internet-facing)

backend_ip         = "127.0.0.1"
backend_http_port  = 8080      # Your actual web server port
```

### 2. Configure your backend web server

Make your web server listen on `127.0.0.1:8080` instead of `0.0.0.0:80` so
it is only reachable through relayd.

**httpd** (`/etc/httpd.conf`):
```
server "example.com" {
    listen on 127.0.0.1 port 8080
    ...
}
```

**nginx** (`/etc/nginx/nginx.conf`):
```
listen 127.0.0.1:8080;
```

### 3. Run the installer

```sh
doas sh scripts/setup.sh
```

The installer:
1. Backs up existing `/etc/pf.conf` and `/etc/relayd.conf`
2. Installs the new configs and validates their syntax before loading
3. Applies `sysctl` hardening values and persists them in `/etc/sysctl.conf`
4. Enables and starts `relayd` via `rcctl`
5. Adds a cron job that expires auto-banned IPs after one hour

---

## HTTPS / TLS termination

To have relayd terminate TLS, place your certificate and key under
`/etc/ssl/relayd/` and uncomment the `https_relay` block in `etc/relayd.conf`:

```
/etc/ssl/relayd/example.com.crt
/etc/ssl/relayd/private/example.com.key
```

Then in `etc/relayd.conf`:

```
relay "https_relay" {
    listen on $relay_https_addr port $relay_https_port tls
    ...
}
```

See `relayd.conf(5)` for the full TLS configuration reference.

---

## Manual IP management

```sh
# View all currently blocked IPs
pfctl -t ddos_block -T show

# Manually block an IP
pfctl -t ddos_block -T add 203.0.113.42

# Unblock an IP
pfctl -t ddos_block -T delete 203.0.113.42

# Flush the entire block table
pfctl -t ddos_block -T expire 0

# Permanently whitelist a trusted IP (survives reloads/reboots)
echo "203.0.113.1" >> /etc/pf.whitelist
pfctl -t whitelist -T add 203.0.113.1
```

---

## Monitoring

```sh
# relayd overview
relayctl show summary

# Backend health
relayctl show hosts

# Active sessions
relayctl show sessions

# PF connection stats
pfctl -s info

# Top blocked hosts
pfctl -t ddos_block -T show | sort
```

---

## Tuning guide

| Scenario | Adjustment |
|----------|-----------|
| Shared hosting / many legit users behind a NAT | Raise `max_http_conn` and `max_http_conn_rate`; consider whitelisting the NAT's IP |
| API server with low expected volume | Lower `max_http_conn` (e.g. `20`) and `max_http_conn_rate` (e.g. `10/5`) for tighter control |
| Bots causing high 404 / scan traffic | Lower `client_timeout` in `relayd.conf` to reclaim resources faster |
| Multi-server load balancing | Add extra backend IPs to `<webhosts_http>` in `relayd.conf` |
| Persistent blocklist | Add IPs to `/etc/pf.whitelist` or `/etc/pf.ddos_block`; they are reloaded on every `pfctl -f` |

---

## How pf's rate-limiting works

`max-src-conn N` — a source IP that has more than *N* simultaneous open
connections is added to `<ddos_block>` and all its existing connections are
flushed (`flush global`).

`max-src-conn-rate R/T` — a source IP that opens more than *R* new
connections in *T* seconds is added to `<ddos_block>` and flushed.

`synproxy state` — pf completes the TCP three-way handshake with the client
*before* forwarding the connection to relayd.  SYN flood packets (which never
complete the handshake) are absorbed by pf and never reach the application.

---

## License

MIT
An Objective-C command-line program for OpenBSD that detects DDoS attacks by
inspecting the live pf state table and, depending on whether
[OBJC-HomemadeBlockProgram (HBP)](https://github.com/gladiola/OBJC-HomemadeBlockProgram)
is installed, either defers blocking to HBP or handles it directly.

---

## How it works

Every run, `ddos-shield`:

1. Counts active pf state entries per source IP (`pfctl -s state`).
2. Flags any source IP whose count meets or exceeds `connectionThreshold`.
3. Checks whether HBP (`/usr/local/sbin/pf-blocker`) is installed.

**HBP present** — detection-only mode:

- Logs each flagged IP to local syslog at `daemon.warning` priority with the
  tag `DDOSShield`:
  ```
  DDOSShield[pid]: detected from 198.51.100.42
  ```
- Does **not** call `pfctl` directly.
- HBP's `--monitor-ddos` cron job reads `/var/log/daemon`, finds the log
  line, and manages all blocking, ledger tracking, and expiry.

**HBP absent** — self-contained mode:

- Logs the same syslog line (for auditability).
- Also adds the IP directly to the pf block table:
  ```
  pfctl -t arbitraryblocks -T add 198.51.100.42
  ```

---

## Source files

| File | Purpose |
|------|---------|
| `main.m` | Entry point — detects HBP presence, orchestrates detection and blocking |
| `DDOSShieldConfiguration.h/m` | All tunable settings (threshold, pf table name, whitelist IP, …) |
| `DDOSShieldDetector.h/m` | Runs `pfctl -s state`, counts connections per source IP, returns attackers |
| `DDOSShieldBlocker.h/m` | Logs via `logger(1)`; adds IPs to pf table when HBP is absent |
| `Makefile` | Build, test, and install targets |

---

## Prerequisites

OpenBSD with GNUstep (one-time setup):

```sh
pkg_add gnustep-base
```

---

## Configuration

Open `DDOSShieldConfiguration.m` and edit `+defaultConfiguration` before
building:

```objc
config.connectionThreshold = 100;   // active pf states per IP before flagging
config.pfTableName         = @"arbitraryblocks";  // must match /etc/pf.conf
config.whitelistIP         = @"192.0.2.1";        // YOUR management IP
```

> **⚠ Important — set `whitelistIP` before deploying.**  Replace the
> placeholder `www.xxx.yyy.zzz` with your actual management IP address.
> Any source IP matching that address is skipped entirely, so you cannot
> accidentally block yourself.

---

## pf.conf

`/etc/pf.conf` must already contain the block table used by HBP (or by
`ddos-shield` itself in standalone mode):

```
table <arbitraryblocks> persist file "/etc/pf/blocks/arbitraryBlocks.txt"
block in quick from <arbitraryblocks>
```

---

## Building

```sh
make          # build ddos-shield
make test     # run the test suite (no root required)
sudo make install   # install to /usr/local/sbin/ddos-shield
```

---

## Crontab integration

### When HBP is present

`ddos-shield` only needs its own detection entry.  HBP's `--monitor-ddos`
entry (already in root's crontab) handles blocking:

```
*/5 * * * * /usr/local/sbin/ddos-shield
*/5 * * * * /usr/local/sbin/pf-blocker --monitor-ddos
0   * * * * /usr/local/sbin/pf-blocker --expire-blocks
```

### When HBP is absent

`ddos-shield` detects and blocks on its own:

```
*/5 * * * * /usr/local/sbin/ddos-shield
```

---

## Hazards

Tune `connectionThreshold` carefully.  A value that is too low will block
legitimate users during traffic spikes (e.g. a flash crowd on a web server).
Start high and lower it only after reviewing logs.

Replace `www.xxx.yyy.zzz` in `DDOSShieldConfiguration.m` with a trusted IP
you never want blocked (e.g. your own management address) before deploying.
The program will emit a warning each run if the placeholder is still in place.
