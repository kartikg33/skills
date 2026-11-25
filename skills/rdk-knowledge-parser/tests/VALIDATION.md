# Validation record

Target: [rdkcentral/utopia](https://github.com/rdkcentral/utopia) `develop` @ `8183e64`
(189 `.c`, 92 `.h`, 146 `.sh`, 73 `Makefile.am`, `configure.ac`).
Start point: `source/firewall/firewall.c` (16k lines), then the whole tree.

Reproduce:

```sh
git clone --depth 1 -b develop https://github.com/rdkcentral/utopia /tmp/utopia
python3 scripts/rdk_dep_scan.py /tmp/utopia > /tmp/utopia-deps.md
python3 tests/validate_coverage.py /tmp/utopia                    # utopia
python3 tests/validate_coverage.py tests/fixtures/sample_component # rbus, msgpack, D-Bus, MQTT, netlink, Yocto, cmake, systemd
```

## How coverage is proven

`validate_coverage.py` does not reuse the scanner's rules. For each mechanism it uses a
deliberately broad grep for call sites (e.g. any `sysevent_get*(`/`sysevent_set*(`, any
`fopen(`, any `-l<lib>`), then checks that every call site appears as `file:line` evidence
in a scanner finding of the right category or in UNCLASSIFIED. Missed sites are listed.

Result on utopia: **100% on all 29 checks**.

| Check | Call sites |
|---|---|
| sysevent C calls | 1664 |
| syscfg C calls | 1296 |
| PSM calls | 331 |
| CCSP bus calls | 36 |
| v_secure_system / system / popen | 469 |
| exec* / fork | 21 |
| ioctl | 18 |
| T2 markers | 66 |
| RDK_LOG / CcspTrace | 294 |
| cJSON | 476 |
| fopen | 328 |
| getenv | 64 |
| #include | 2129 |
| sh: sysevent CLI | 1898 |
| sh: syscfg CLI | 734 |
| sh: psmcli / dmcli | 214 |
| sh: systemctl | 28 |
| sh: source | 253 |
| build: -l libs | 147 |

## What the scanner extracts from utopia (selection)

| Finding | Distinct |
|---|---|
| sysevent keys (literal / via `#define` / via variable) | 515 / 34 / 59 |
| syscfg keys | 382 |
| PSM keys | 64 |
| srvmgr `event\|handler` subscriptions | 284 |
| TR-181 parameters | 105 |
| RFC references | 12 |
| T2 markers | 44 |
| commands spawned from C | 57 (+14 in-repo scripts) |
| shell commands (external) | 121 (+29 in-repo) |
| systemd units controlled | 13 |
| generated iptables chains / jump targets | 133 / 154 |
| netlink symbols | 22 |
| link libraries | 36 |
| filesystem paths | 922 |

## Gaps found during validation, and fixes

| Gap | Fix |
|---|---|
| `v_secure_popen("r", "cmd")` takes mode first; `popen` regex captured `"r"` as a command | dedicated pattern; documented in references/external-processes.md |
| sysevent/syscfg/PSM keys behind `#define` (33 of 138 sysevent calls in firewall.c) | collect `#define NAME "literal"` across tree, resolve `KEY => "value"` |
| keys in variables (`snprintf` templates) | separate "via variable: trace by hand" finding |
| `SERVICE_CUSTOM_EVENTS[]` tuples `"lan-status\|/usr/bin/service_dhcp"` | srvmgr subscription rule |
| iptables rules written with `fprintf` into `/tmp/.ipt`, then `iptables-restore` | chain and `-j` target rules |
| `psmcli get -e`, `eval \`eval psmcli\``, `CCSP_CLI="dmcli"` | looser CLI patterns |
| `ioctl(fd, req, ...)` with variable request; `fopen(path, mode_var)` | accept identifiers |
| shell tokenizer: `x=\`cmd\``, `case` labels, `$(( ))`, single-quoted strings | assignment/label/arith filtering |
| shell functions from sourced libs (`addCron`, `onboarding_log`, `rdkb_feature_check`) | reported UNCLASSIFIED by design: external shell-library deps |
| scripts owned by other components (`apply_partner_customization.sh`, `utopia_ip_route.sh`) | reported UNCLASSIFIED by design |
| ~60 real tools missing from catalog (`chronyc`, `arping`, `hostapd`, `ncpu_exec`, `latticecli`, ...) | added to `KNOWN_COMMANDS` |

## Known limits

- Static only: no macro expansion beyond string `#define`s, no data-flow for variables.
- MQTT topics, D-Bus object paths and msgpack schema keys are listed by API call, not decoded.
- Owners of peer interfaces (which component sets a sysevent key you only read) need a scan of the peer repos.
