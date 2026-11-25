<!--
Copyright 2026 Kartik Gohil
SPDX-License-Identifier: Apache-2.0
-->

# Dependency report template

```markdown
# <component> dependency map
Source: <repo>@<commit>  Scanner: rdk_dep_scan.py (<date>)  Manual passes: <list>

## Summary
| Category | Distinct deps | Main peers |
|---|---|---|
| IPC: sysevent | 53 keys (20 produced, 33 consumed) | service_wan, service_dhcp, WAN manager |
| IPC: syscfg | ... | ... |
| IPC: PSM / CCSP bus / rbus | ... | ... |
| Filesystem | ... | ... |
| External processes | ... | ... |
| Kernel (ioctl/netlink/procfs) | ... | ... |
| Data model (TR-181/RFC) | ... | ... |
| Telemetry / logs | ... | ... |
| Cloud (WebConfig/WebPA/USP) | ... | ... |
| Build (libs/recipes) | ... | ... |
| Runtime orchestration | ... | ... |

## IPC
### sysevent
| Key | Relation | Resolution | Evidence | Function | Gate | Provider |
|---|---|---|---|---|---|---|
| `current_wan_ifname` | READS | literal | utopia/firewall.c:2610 | `firewall_main` | - | WAN manager |
| `ipv4_%s-status` | READS | templated (`ipv4_.+-status`) | utopia/firewall.c:123 | `get_firewall_settings` | `_HUB4_PRODUCT_REQ_` | unknown |

`c_extract.py` fills relation/resolution/function/gate for C call sites. Mark
`unconditional: true` only when a use is outside all gates. Keep templated and
concrete keys as separate rows linked by the pattern.

(... one table per mechanism / category ...)

## HAL functions and utility owners
| Interface | Module / path hint | Evidence | Recipe / package |
|---|---|---|---|

## Root filesystem
| Artifact | Installed path | Recipe | Package |
|---|---|---|---|

## Peer components
| Peer | Interfaces | Status |
|---|---|---|
| ... | ... | provider unknown / stub / parsed |

## Open questions
- Unresolved macros, templated keys, unclassified commands, unknown owners.
```
