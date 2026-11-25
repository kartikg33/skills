---
name: rdk-knowledge-parser
description: Map every dependency of an RDK / RDK-B component (C/C++, shell, autotools/cmake, Yocto). Use when asked what a component depends on, what it talks to, what would break if X changes, or to build a dependency/interface inventory. Covers IPC (sysevent, syscfg, PSM, CCSP message bus/COSA, D-Bus, rbus, MQTT, msgpack, JSON/YAML/INI/TOML, nvram, /tmp and other file IPC), external processes (v_secure_system, system(), popen, systemctl, iptables/ip, ioctl, netlink, procfs/sysfs), data model and cloud interfaces (TR-181, RFC, Telemetry T2 markers, logs, syslog, WebConfig blobs, WebPA, TR-369 USP, TR-069, HAL), and build dependencies (Yocto DEPENDS/RDEPENDS, .bb/.bbappend, make, automake, cmake, autoconf, CFLAGS, -l/-L libraries, compile-time feature flags). Reports direction, gates, key resolution and rootfs owners for graph ingestion.
license: Apache-2.0
compatibility: opencode, claude-code, openai-codex
metadata:
  domain: rdk-b
  validated-against: rdkcentral/utopia@develop
---
<!--
Copyright 2026 Kartik Gohil
SPDX-License-Identifier: Apache-2.0
-->

# RDK knowledge parser: dependency mapping

Goal: produce a **complete, evidence-backed** list of everything an RDK component
depends on, and everything that depends on it. Every claim needs `file:line`.
Never infer a dependency from a name alone; open the code.

## Workflow

1. **Inventory the tree.** List source kinds: `*.c/*.h/*.cpp`, `*.sh` (and
   extension-less files with a `#!/bin/sh` shebang), `Makefile.am`, `configure.ac`,
   `CMakeLists.txt`, `*.bb/*.bbappend/*.inc`, `*.service`, `*.json/*.xml/*.conf`,
   `system_defaults*`.
2. **Run the scanner** for a first pass:
   ```bash
   python3 <skill_dir>/scripts/rdk_dep_scan.py <component_dir> > deps.md
   python3 <skill_dir>/scripts/rdk_dep_scan.py <component_dir> --format json > deps.json
   python3 <skill_dir>/scripts/rdk_dep_scan.py <dir> --category ipc --max-evidence 5
   ```
   Categories: `ipc`, `filesystem`, `external_process`, `data_model_cloud`,
   `build`, `runtime_orchestration`.
3. **Extract call-level detail from C.** The inventory has no direction, gate or function.
   Run the call extractor on each interesting `.c` file (or every one in a small component):
   ```bash
   python3 <skill_dir>/scripts/c_extract.py --root <repo_root> --file <rel/path.c> --repo <repo> > calls.json
   ```
   It records `direction` (`read`/`write`/`subscribe`/`publish`/`exec`/`call`/...),
   the `#if` gate stack, enclosing function, key resolution (`literal`/`macro`/
   `templated`/`unresolved`), HAL module, MQTT topic, netfilter rule template with
   injected argument names, and executable path hints. Pass header files with
   string `#define`s via `--macros <rel/path.h>` when the component defines keys there.
4. **Work the UNCLASSIFIED section.** It lists commands, libraries and scripts
   that match no catalog entry. Each one is either a real dependency (classify
   it) or a false positive (dismiss it). Never drop it silently.
5. **Do the manual passes** the scanner cannot do (see "Blind spots").
6. **Read each category reference** before writing conclusions:
   - [references/ipc.md](references/ipc.md): sysevent, syscfg, utctx/utapi, PSM, CCSP bus, COSA, rbus, D-Bus, MQTT, msgpack, file formats, nvram, shm, signals, srvmgr
   - [references/external-processes.md](references/external-processes.md): system/v_secure_system/popen, shell commands, systemctl, ioctl, netlink, netfilter, procfs/sysfs, kernel modules
   - [references/data-model-cloud.md](references/data-model-cloud.md): TR-181, RFC, T2 markers, logging, WebConfig, WebPA, USP, TR-069, HAL, device.properties, partner defaults
   - [references/build.md](references/build.md): Yocto, autotools, cmake, make, flags, libraries, `#ifdef` features
   - [references/filesystem.md](references/filesystem.md): paths, file IPC, persistence locations
   - [references/runtime-orchestration.md](references/runtime-orchestration.md): systemd units, utopia service registration, event handlers, cron, process monitoring
   - [references/graph-alignment.md](references/graph-alignment.md): interface model, direction vocabulary, evidence fields, peer/rootfs questions, alignment with the RDK knowledge graph
7. **Write the report** using [references/report-template.md](references/report-template.md).

## Core rules

- **Interfaces, not direct component edges.** Two components are linked only through a shared
  interface: a sysevent key, a syscfg key, a TR-181 node, a HAL function, a file, a command,
  a package. Never write "X depends on component Y" without naming the interface and evidence.
  Attach every dependency to the **artifact** (binary, library, script) whose source has the
  evidence, not just to the directory. Peers seen only in evidence stay `provider unknown`
  until another component is parsed.
- **Direction matters.** Use one vocabulary everywhere: `read`, `write`, `delete`, `seeds`,
  `subscribe`, `publish`, `provides`, `registers`, `calls`, `executes`, `sources`, `schedules`,
  `triggers`, `loads`, `defines`, `uses`, `checks`. `sysevent_set` = write,
  `sysevent_get`/`setnotification`/`async` = read/subscribe/triggered-by;
  `syscfg_set`+commit = write, `syscfg_get` = read. Unpaired keys point to another component.
- **Key-level, not API-level.** "Uses sysevent" is useless. List every key
  (`wan-status`, `firewall-restart`, ...) with direction. Same for syscfg, PSM, TR-181, RFC, T2.
- **Resolve indirection.** Keys hidden behind `#define`, `snprintf` templates
  (`"ipv6_%s-prefix"`), arrays, or helper wrappers must be resolved to their
  literal form or marked `templated:` with the format string. For templated keys also
  derive a pattern (`ipv4_%s-status` -> `ipv4_.+-status`) and find the concrete keys it matches:
  a producer may write `ipv4_1-status` while the consumer reads the template.
- **Follow wrappers one level.** `Utopia_Get*` hits syscfg. `Utopia_SetEvent` hits sysevent.
  `PSM_VALUE_GET_STRING` is a macro over `PSM_Get_Record_Value2` over the CCSP bus.
  `v_secure_system` is `libsecure_wrapper` over `fork/exec` of `/bin/sh -c`.
- **Shell is code.** A command string inside `v_secure_system("iptables -t nat ...")`
  is an external process dependency *and* may contain more (`| grep`, `> /tmp/x`, `sysevent set`).
  Parse every pipeline segment.
- **Files are interfaces.** Any path under `/tmp`, `/var`, `/nvram`, `/etc`,
  `/opt/secure`, `/rdklogs`, `/proc`, `/sys` is a contract with whoever else
  reads/writes it. Record path, R/W, format, and the likely peer.
- **Compile-time gates are dependencies.** `#ifdef _HUB4_PRODUCT_REQ_`,
  `AM_CONDITIONAL`, `DISTRO_FEATURES` decide which deps exist on which platform.
  Report the gate next to the dependency, with the enclosing function and the exact
  `file:line`. `c_extract.py` supplies the gate stack for C. Mark a dependency
  `unconditional: true` only when at least one use is outside all gates.
  A gate that selects a device profile (`_HUB4_PRODUCT_REQ_`, `:append:<machine>`)
  also tells you which hardware the dependency exists on.
- **Platform split.** Many RDK-B devices run two CPUs (ARM + ATOM / Puma). `rpcclient`,
  `arris_rpc_client`, `ncpu_exec`, `ATOM_INTERFACE_IP` mean cross-CPU dependencies.
- **HAL functions are interfaces.** Not just "uses WiFi HAL": list
  `wifi_getRadioEnable`, module `wifi`, header, and the library that implements it.
  `-lhal_wifi` plus the call is the full dependency.
- **Utilities need an owner.** `iptables`, `psmcli`, `cat`, `awk` are interfaces too.
  Say where the binary is expected on the rootfs (`/usr/sbin`, `/bin`, busybox applet,
  `/lib/rdk/...`) and find the recipe/package that installs it. A bare command name is
  not enough if the rootfs layout changes.
- **Rule templates carry injected values.** For `-A ... -d %s -j DNAT --to-destination %s`,
  trace each placeholder to the key, device property or computed variable that fills it.
- **Test code is separate.** Mark gtest/gmock/mocks as test-only; do not mix
  into runtime deps. Logs written for logging only and telemetry markers are exports,
  not component dependencies: report them separately.

## Blind spots (always check by hand)

- Keys/commands built at runtime: `snprintf(buf, ..., "%s_%d", ...)` then `sysevent_get(.., buf, ..)`.
  Grep for the format string and list as `templated`.
- Commands assembled in variables then executed (`v_secure_system(cmd)` with `cmd` a variable,
  `eval $CMD` in shell). Trace the variable.
- Generated files: rules written with `fprintf` to `/tmp/.ipt` then loaded by
  `iptables-restore`. The file content (chains, targets, ports, ipsets) is the real dependency.
- Shell functions called but not defined in the tree (e.g. `addCron`, `onboarding_log`,
  `rdkb_feature_check`) come from **sourced external libraries** like
  `/etc/utopia/service.d/*.sh`, `/lib/rdk/utils.sh`, `/etc/log_timestamp.sh`. Name the source.
- Script names referenced but not in the tree (`apply_partner_customization.sh`,
  `utopia_ip_route.sh`) belong to another component. Find the owner.
- Event names passed through tables (`SERVICE_CUSTOM_EVENTS` strings like
  `"lan-status|/etc/utopia/service.d/x.sh"`) are sysevent subscriptions.
- `dlopen` / function pointers to HAL vendor libs.
- The value written to a key or into a rule: `sysevent_set(fd, tok, key, value, 0)` records the
  key but the value may come from another interface.
- Rootfs provenance: a path seen in code is not proof of which recipe installs it. Check
  `do_install`, `FILES:${PN}`, packagegroups and the image recipe before claiming an owner.
- Data in config defaults (`system_defaults*`, `partners_defaults.json`, `bbhm_def_cfg.xml`)
  seeds syscfg/PSM keys: the owner of the default is not the user of the key.

## Output contract

Produce, per component:
1. Summary table: category, count, top peers.
2. One section per category with `dependency | direction | key/target | resolution | evidence (file:line) | function | gate`.
3. Peer component list (who is on the other side of each interface; mark unknown owners).
4. Rootfs/package view: binary, script and installed file -> install path -> recipe.
5. Open questions: everything unresolved, unclassified or templated.

State the scanner version/run and which manual passes were done, so a reviewer can trust coverage.
