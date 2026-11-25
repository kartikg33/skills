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
| Key | Dir | Evidence | Gate | Peer |
|---|---|---|---|---|
| `current_wan_ifname` | get | firewall.c:2610 | - | WAN manager |
| `ipv6_%s-prefix` (templated) | get | firewall_ipv6.c:123 | `_HUB4_PRODUCT_REQ_` | service_ipv6 |

(... one table per mechanism / category ...)

## Peer components
| Peer | Interfaces |
|---|---|

## Open questions
- Unresolved macros, templated keys, unclassified commands, unknown owners.
```
