# External process and kernel-interface dependencies

## Spawn APIs

| API | Notes |
|---|---|
| `v_secure_system("fmt", ...)` | `libsecure_wrapper`. printf-style; runs via `/bin/sh -c`. Most common in RDK-B. |
| `v_secure_popen("r", "fmt", ...)` | **mode is the FIRST argument**. Close with `v_secure_pclose`. |
| `system(cmd)`, `popen(cmd, "r")` | legacy; often flagged by security scans. |
| `execl/execv/execvp("/bin/sh", ...)`, `fork`, `vfork`, `daemon`, `posix_spawn` | record the program path. |
| shell: any command at line start or after `;`, `&&`, `\|\|`, `\|`, `` ` ``, `$(`, `then`, `do`, `else` | |

For each command string:
1. Split on `;`, `&&`, `||`, `|`, `` ` ``, `$(`; each segment's first word is a dependency.
2. Note redirections: `> /tmp/x` (write), `< file` (read), `2>/dev/null`.
3. Note arguments that are themselves interfaces: `iptables -t nat -A <chain>`, `ip route add table <n>`,
   `sysevent set <key>`, `systemctl restart <unit>`, `killall -HUP <proc>`.
4. Classify the binary: coreutils/busybox, network tool, RDK/CCSP CLI, vendor CLI, in-repo script, other component's script.

Common families seen in utopia:
- networking: `ip`, `ifconfig`, `route`, `brctl`, `vconfig`, `bridge`, `arping`, `conntrack`, `ipset`
- netfilter: `iptables`, `ip6tables`, `iptables-restore`, `ip6tables-restore`, `ebtables`, `nft`
- daemons: `dnsmasq`, `udhcpc`, `dibbler-server`, `zebra`, `ripd`, `chronyd`/`ntpd`, `dropbear`, `hostapd`, `igmpproxy`
- RDK CLIs: `sysevent`, `syscfg`, `psmcli`, `dmcli`, `rbuscli`, `t2ValNotify`, `rpcclient`
- vendor: `mocacfg`, `mocactl`, `wlancfg`, `switchcfg`, `swctl`, `ivictl`, `et`, `wl`, `latticecli`, `ncpu_exec`, `arris_rpc_client`
- process control: `killall`, `kill`, `pidof`, `ps`, `systemctl`, `reboot`, `modprobe`
- text tools: `echo`, `cat`, `tail`, `head`, `grep`, `sed`, `awk`, `cut`, `ls`, `rm`, `cp`, `touch`

`echo x > /proc/...` or `cat /tmp/file` are both a process dependency (busybox) and a file dependency.

## systemd / init

- `systemctl start|stop|restart|is-active <unit>` from C or shell: dependency on that unit
  (e.g. utopia restarts `xupnp`, `xcal-device`, `CcspLMLite.service`, `dnsmasq.service`, `dns-failover-manager.service`).
- `.service` files: `After=`, `Requires=`, `Wants=`, `ExecStart=`, `EnvironmentFile=`, `ConditionPathExists=`.
- `.path` units watching files = file-triggered activation.
- `sd_notify` = Type=notify unit.

## ioctl

`ioctl(fd, REQ, &arg)`. Record `REQ` and the device or socket:
- `SIOCGIFADDR`, `SIOCGIFHWADDR`, `SIOCGIFINDEX`, `SIOCSIFHWADDR`, `SIOCGIFCONF`, `SIOCSARP` on an `AF_INET` socket: kernel netdev.
- `SIOCETHTOOL`, `SIOCDEVPRIVATE`, `TUNSETIFF`: driver-specific.
- Custom vendor ioctls on `/dev/xxx`: hardware driver dependency.

## netlink

`socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)`, `RTM_NEWROUTE/RTM_GETROUTE/RTM_NEWADDR/RTM_NEWLINK`,
`NLM_F_*`, libnl `nl_*`/`rtnl_*`/`genl_*`, libmnl `mnl_*`. Record protocol and message types.
Also `NETLINK_KOBJECT_UEVENT` (hotplug), `NETLINK_NETFILTER`.

## Netfilter libraries and generated rules

- `nfq_*` (libnetfilter_queue: utopia `trigger`, `nfq_handler`), `nfct_*`, `iptc_*`, `nftnl_*`, `ipset_*`, `libnet_*`.
- Generated ruleset: `fprintf(nat_fp, "-A POSTROUTING -o %s -j %s\n", ...)` into `/tmp/.ipt`, `/tmp/.ipt_v6`,
  then `iptables-restore`. Chains, `-j` targets, `-m set --match-set <ipset>`, `-m mark`, `NFQUEUE --queue-num N`
  are contracts with other components that add rules to the same chains, or with kernel modules.
  utopia `firewall.c` generates hundreds of chains (`lan2wan`, `wan2lan`, `general_input`, ...).

## Raw sockets

`AF_PACKET`, `SOCK_RAW`, `ETH_P_*`: direct L2 I/O (utopia `firewall/raw_socket_send.c`, `dhcpproxy`).

## procfs / sysfs / kernel tunables

- `/proc/sys/net/...` (sysctl), `/proc/net/...`, `/proc/<pid>/...`, `/proc/uptime`, `/proc/meminfo`.
- `/sys/class/net/<if>/...`, `/sys/devices/virtual/net/<br>/brif`.
- `sysctl -w key=val`, `echo 1 > /proc/sys/...`.
Record path and R/W.

## Kernel modules

`modprobe`, `insmod`, `rmmod`; `-m <match>` in iptables implies `xt_<match>` module;
`nf_conntrack_helper` writes. Record module names.

## Environment and runtime plugins

- `getenv("X")`: dependency on whoever exports `X` (systemd `EnvironmentFile`, init script).
- `dlopen("libfoo.so")`/`dlsym`: runtime library dependency not visible in link flags.

## Cron

`crontab`, `/etc/cron/cron.everyminute/`, utopia `addCron`/`removeCron` (from `service_crond.sh`), sysevent `cron_every_minute`.
