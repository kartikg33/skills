<!--
Copyright 2026 Kartik Gohil
SPDX-License-Identifier: Apache-2.0
-->

# Filesystem dependencies

Files are the most common hidden IPC in RDK-B. Treat each path as an interface.

## What to capture

| Field | Example |
|---|---|
| path (or template) | `/tmp/.ipt`, `/tmp/filter_%x`, `/var/run/dnsmasq.pid` |
| op | read / write / append / create / delete / exists-check / exec / source |
| format | iptables-restore, KEY=VALUE, JSON, XML, INI, plain list, pid, flag (presence only) |
| peer | who else reads/writes it |
| persistence | volatile (`/tmp`, `/var`, `/run`) vs persistent (`/nvram`, `/nvram2`, `/opt/secure`, `/data`) vs read-only image (`/etc`, `/usr`, `/lib`) |

## Root filesystem view

Every path is a `FilePath` node: `kind` (`file`, `dir`, `symlink`, `device`, `fifo`,
`socket`) and `storage` (`rootfs-ro`, `tmpfs`, `nvram`, `secure`, `logs`, `proc`, `sys`).
Record the parent chain: `/usr/bin/firewall` -> `/usr/bin` -> `/usr` -> `/`.
An executable name resolves to a path on the rootfs; a script may come from another
recipe. Do not claim an owner from the path alone: check `do_install`, `FILES:${PN}`,
packagegroups and `IMAGE_INSTALL` in the Yocto layers.

## How to detect

C:
- `fopen(path, "w"|"a"|"r+")` write; `"r"` read. `open(path, O_WRONLY|O_CREAT)`.
- `access(path, F_OK)`, `stat()`, `opendir()`: existence/flag files (e.g. `/tmp/.lxcIptablesLock`, `/nvram/.reboot_*`).
- `unlink`, `remove`, `rename`, `mkdir`, `truncate`, `chmod`, `symlink`.
- `#define LOG_FILE "/rdklogs/logs/FirewallDebug.txt"` style macros: resolve.
- Paths inside command strings: `v_secure_system("cat %s > /tmp/x", ...)`.

Shell:
- `> file`, `>> file`, `< file`, `tee`, `cat file`, `[ -f file ]`, `[ -e ]`, `[ -d ]`, `touch`, `rm`, `mv`, `cp`, `ln`.
- `source /etc/x.sh` / `. /etc/x.sh`: library dependency on another package's script.

## Common RDK-B locations

- `/tmp/*` flags and handoff files: `/tmp/.ipt`, `/tmp/RFC/*`, `/tmp/lanhosts`, `/tmp/conn_mac`, `/tmp/ccsp_msg.cfg`, `/tmp/*_initialized`.
- `/var/run/*.pid`, `/var/dnsmasq.conf`, `/var/log/*`.
- `/nvram/syscfg.db`, `/nvram/bbhm_cur_cfg.xml`, `/nvram/partners_defaults.json`, `/nvram/*.log`.
- `/opt/secure/*` (encrypted/protected: RFC store, bootstrap.json, certificates).
- `/etc/device.properties`, `/etc/utopia/system_defaults`, `/etc/utopia/service.d/*.sh`, `/etc/debug.ini`, `/etc/dropbear/*`.
- `/rdklogs/logs/*.txt.0`.
- `/proc/*`, `/sys/*`: kernel (see external-processes.md).

## Flag-file protocol

Many components coordinate by presence: A `touch /tmp/foo_ready`, B `while [ ! -f /tmp/foo_ready ]`. Record both
sides; this is an ordering dependency. systemd `.path` units with `PathExists=` are the same pattern.
