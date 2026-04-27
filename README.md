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