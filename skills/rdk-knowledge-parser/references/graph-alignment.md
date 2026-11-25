<!--
Copyright 2026 Kartik Gohil
SPDX-License-Identifier: Apache-2.0
-->

# Interface model and knowledge-graph alignment

This skill's report is written so it can feed an RDK knowledge graph without a second translation pass. 

## One vocabulary for dependencies

Every dependency is one statement: `artifact --[relation]--> interface`.
There are no direct component-to-component dependency edges; those are derived from a
shared interface. One relationship per (artifact, relation, interface), with all
`file:line` evidence collected on it.

| Relation | Use for | Evidence in this skill |
|---|---|---|
| `READS` | value/file read | `sysevent_get`, `syscfg_get`, `PSM_Get*`, `rbus_get`, `fopen(..., "r")`, shell `cat` |
| `WRITES` | value/file written | `sysevent_set`, `syscfg_set`, `rbus_set`, `> /tmp/x` |
| `DELETES` | removal | `unlink`, `syscfg_unset`, `rm` |
| `SEEDS` | ships a default | `system_defaults*`, `bbhm_def_cfg.xml`, `partners_defaults.json` |
| `SUBSCRIBES` | notified on change | `sysevent_setnotification`, `sysevent async`, `rbusEvent_Subscribe`, MQTT subscribe |
| `PUBLISHES` | event/message sent | `rbusEvent_Publish`, MQTT publish, telemetry marker (report only) |
| `TRIGGERED_BY` | runs when it fires | `SERVICE_CUSTOM_EVENTS` tuples, systemd `.path` units |
| `PROVIDES` | implements/serves | COSA DML, `rbus_regDataElements`, WebConfig handler, HTTP route |
| `REGISTERS` | bus identity | `CCSP_Message_Bus_Init`, `rbus_open`, `sysevent_open` |
| `CALLS` | function/method call | HAL function, `ioctl`, netlink, D-Bus method, HTTP request |
| `EXECUTES` | process or shell function | `v_secure_system`, `popen`, `system`, shell command, `addCron` |
| `SOURCES` | shell library | `source /etc/utopia/service.d/ut_plat.sh` |
| `SCHEDULES` | cron/timer | `addCron`, `crontab`, systemd `.timer` |
| `INVOKED_BY` | started by | `ExecStart`, handler script |
| `LOADS` | kernel module | `modprobe`, `insmod` |
| `DEFINES` | chain/rule created | `-N chain`, `fprintf(fp, "-A ...")` |
| `USES` | shm/sem/queue | `shm_open`, `semget`, `mq_open` |
| `CHECKS` | feature switch | RFC lookup, `device.properties`, `isFeatureSupportedInCurrentMode` |

`c_extract.py` emits `direction` values that map onto these relations:
`read -> READS`, `write -> WRITES`, `subscribe -> SUBSCRIBES`, `publish -> PUBLISHES`,
`exec/exec-read -> EXECUTES`, `call -> CALLS`, `register -> REGISTERS`,
`define -> DEFINES`, `load -> LOADS`, `check -> CHECKS`, `discover -> CALLS`.

## Interface kinds

The interface node is named by its natural key. Keep these exact forms in the report:

| Interface | Example key |
|---|---|
| sysevent key | `sysevent:firewall-restart` |
| syscfg key | `syscfg:firewall_enabled`, `syscfg:ns::key` |
| PSM record | `psm:dmsb.truestaticip.Enable` |
| TR-181 / TR-104 node | `Device.WiFi.Radio.{i}.Enable` (instances as `{i}`) |
| bus endpoint / method | `eRT.com.cisco.spvtg.ccsp.wifi`, `busmethod:dbus-system:org.freedesktop.systemd1:StartUnit` |
| HAL function | `halfn:wifi:wifi_getRadioEnable` (module + header) |
| file path | `/tmp/.ipt`, `/usr/bin`, `/nvram/syscfg.db` |
| executable | `iptables-restore`, `/lib/rdk/iptables_container.sh` |
| shell function | `/etc/utopia/service.d/ut_plat.sh:addCron` |
| systemd unit | `CcspPandMSsp.service` |
| kernel interface | `ioctl:SIOCGIFADDR`, `netlink:NETLINK_ROUTE`, `sysctl:net.ipv4.ip_forward`, `proc:/proc/net/arp` |
| netfilter chain/rule | `chain:ipv4:filter:wan2lan`, one rule per `fprintf` template |
| shared memory | `shm:FirewallMutex` |
| API endpoint | `api:mqtt:x/fr/webconfig/#`, `api:unix:/tmp/syseventd.sock` |
| WebConfig subdoc | `webconfig:portforwarding` |
| RFC feature | `rfc:RadiusGreyList` (also a TR-181 node; link with `MAPS_TO`) |
| device property | `devprop:BUILD_TYPE` |

## Evidence fields to carry

Every observed dependency in the report needs:

- `evidence`: `repo/path:line`. `c_extract.py --repo utopia` writes this directly.
- `resolution`: `literal`, `macro`, `templated`, `namespaced`, `wrapper`, `manual`.
- `unconditional`: `true` if at least one use is outside all gates.
- `gates`: list of `#if`/automake/Yocto conditions as written; `devices`: device profiles they select.
- `functions`: enclosing functions (`c_extract.py` supplies one per record).
- `values`: literal values written; `mechanism`: `ccsp`/`rbus`/`dbus`/`dmcli`/`cli` when ambiguous.
- `commit`, `scope` (profile/release/manifest) and `parse run` when writing to a graph.

## Templated keys and injected values

`ipv4_%s-status` and `ipv4_1-status` are **different** interfaces, linked by a pattern.
Keep both, mark the template `templated: true`, and derive a regex that matches the
concrete keys. Producer and consumer connect through that match, not by guessing.

For a generated firewall rule, keep the whole `fprintf` template with placeholders.
Each placeholder is linked to its source (`FILLED_FROM`): a sysevent key, syscfg key,
PSM record, TR-181 node, device property, or a code symbol (variable, struct field, macro)
when the value is computed. `c_extract.py` emits `filled_from` with the placeholder,
position and the argument expression; trace the expression back one level.
Example from utopia `firewall.c:995`:
`-I POSTROUTING -o %s -j SNAT --to-source %s` with `XLAT_IF` and `XLAT_IP`.

## Files and the root filesystem

A `FilePath` is a node with `kind` (`file`, `dir`, `symlink`, `device`, `fifo`, `socket`) and
`storage` (`rootfs-ro`, `tmpfs`, `nvram`, `secure`, `logs`, `proc`, `sys`). Record parent
directories with `CHILD_OF`: `/usr/bin/firewall` -> `/usr/bin` -> `/usr` -> `/`.
Do not claim which recipe installs a file until `do_install`, `FILES:${PN}`, packagegroups
and the image recipe have been checked. A command name resolves to its installed path
through `RESOLVES_TO`; the path hints in `c_extract.py` are hints only.

## Peers, providers and scope

- A key read but never written in this component has a **provider unknown**. Do not invent one.
- A peer seen only in another component's evidence is a stub until parsed.
- Everything below one manifest (release + build) belongs to that scope. The same component
  in two releases is two sets of nodes; compare by local id, do not share interfaces across scopes.
- Software and hardware are separate. The only link is a device gate
  (`_HUB4_PRODUCT_REQ_`, `MACHINE_FEATURES`, `.bbappend:<machine>`) selecting a device profile.

## Static only

Use source, manifests and recipes. Do not infer dependencies from a built rootfs, bitbake
logs or `buildhistory`. If a value cannot be resolved statically, put it in open questions.
Log messages/files written purely for logging and telemetry markers are reported but are
not component dependencies in the graph.
