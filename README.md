# OpenBSDDDOSShield

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