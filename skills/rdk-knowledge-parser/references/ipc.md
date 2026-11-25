<!--
Copyright 2026 Kartik Gohil
SPDX-License-Identifier: Apache-2.0
-->

# IPC and configuration-store dependencies

For each mechanism: how to spot it, how to extract the key, which direction it
is, and who is usually on the other side. Examples cite `rdkcentral/utopia`.

## sysevent (volatile key/value + event bus, `syseventd`)

| Form | Direction |
|---|---|
| `sysevent_set(fd, tok, "key", val, 0)`, `sysevent_set_unique` | producer |
| `sysevent_get(fd, tok, "key", buf, len)`, `sysevent_get_unique` | consumer (poll) |
| `sysevent_setnotification(fd, tok, "key", &async_id)` + `sysevent_getnotification` loop | consumer (subscribe) |
| `sysevent_setcallback(...)`, `sysevent_rmcallback` | consumer (handler) |
| `sysevent_set_options(.., "key", TUPLE_FLAG_EVENT)` | defines key as edge-triggered event |
| shell: `sysevent set key val`, `sysevent get key`, `sysevent setunique`, `sysevent async key /path/handler` | same |
| `sysevent setoptions key 0x00000002` (`TUPLE_FLAG_EVENT`) | event definition |
| srvmgr tuples `"lan-status\|/usr/bin/service_dhcp"` in `SERVICE_CUSTOM_EVENTS[]` | subscription: handler runs on event |
| `Utopia_SetEvent`, `Utopia_EventSet`, `sysevent_syscfg_init` | wrappers |

Open: `sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "name", &tok)` or
`sysevent_open_local`/`sysevent_local_open(UDS_PATH, ...)`. The client name string identifies the component.

Key conventions: `<service>-status` (`started|stopped|starting|error`), `<service>-start|stop|restart`,
`current_wan_ifname`, `wan-status`, `lan-status`, `ipv6_prefix`, `firewall-restart`.
A `*-restart` set by component A and handled in B = **A triggers B**.

Pitfalls:
- Keys via macros (`SYSEVENT_MAPT_CONFIG_FLAG` => `"mapt_config_flag"`). Scanner resolves `#define`s in tree.
- Keys via `snprintf(evt, "ipv6_%s-prefix", ifname)`. List as templated.
- `sysevent` CLI inside `v_secure_system("sysevent set ...")` strings: parse the string.
- syseventd may be proxied cross-CPU (`syseventd_proxy`, `-i <ip>` option on CLI).

## syscfg (persistent key/value, `/nvram/syscfg.db`, shared-memory backed)

| Form | Direction |
|---|---|
| `syscfg_get(NULL\|ns, "key", buf, len)`, `syscfg_getall` | reader |
| `syscfg_set*`, `syscfg_unset`, `syscfg_commit`, `syscfg_set_commit`, `syscfg_set_u_commit`, `syscfg_set_nns_commit` | writer (commit = flush to flash) |
| shell `syscfg get/set/unset/commit` | same |
| shell `$SYSCFG_<key>` after `eval \`utctx_cmd get key1 key2\`` | reader |
| `Utopia_Get*/Utopia_Set*/Utopia_RawGet/RawSet` with `UtopiaValue` enums | reader/writer via utctx: map enum to key in `utctx/lib/utctx.c` table |
| `syscfg_create`, `syscfg_format`, `apply_system_defaults` with `system_defaults*` files | default seeding |

Namespaced keys: `syscfg_get("ns", "key")` stored as `syscfg:ns::key`; record the
`namespace` property. Indexed keys like `PortRangeForward_%d` are templated: derive a
pattern and find the concrete keys it matches. `c_extract.py` records the namespace
argument and marks the resolution. It also records literal values written by
`sysevent_set`, useful for proving the writer of a key.

## PSM (CCSP Persistent Storage Manager, `PsmSsp`, `/nvram/bbhm_cur_cfg.xml`)

- `PSM_Get_Record_Value2(bus, CCSP_SUBSYS, "dmsb.x.y", NULL, &val)`, `PSM_Set_Record_Value2`,
  `PSM_Del_Record`, `PsmGetNextLevelInstances`. Local macros `PSM_VALUE_GET_STRING`, `PSM_VALUE_GET_INS`.
- shell `psmcli get|set|getallinst|getinstcnt dmsb.l3net.`.
- Keys start `dmsb.`, `eRT.com.cisco.spvtg.ccsp.`, or occasionally a TR-181 path.
- Needs a CCSP bus handle: PSM implies the CCSP message bus dependency.
- Defaults: `bbhm_def_cfg.xml` (owned by the platform/PSM component).

## CCSP message bus (D-Bus based, `libccsp_common`)

- Init: `CCSP_Message_Bus_Init(name, CCSP_MSG_BUS_CFG, &bus_handle, ...)` or `_Init_Synced`.
  `CCSP_MSG_BUS_CFG` = `/tmp/ccsp_msg.cfg`.
- Discover: `CcspBaseIf_discComponentSupportingNamespace(bus, CR_NAME, "Device.X.", "", &comps, &n)`
  (talks to `CcspCr`, component registry, `eRT.com.cisco.spvtg.ccsp.CR`).
- Access: `CcspBaseIf_getParameterValues` / `setParameterValues` / `setCommit` /
  `getParameterNames` / `AddTblRow` / `DeleteTblRow`. Extract each TR-181 path passed.
- Events: `CcspBaseIf_Register_Event`, `CcspBaseIf_SendSignal`, `parameterValueChangeSignal`.
- CLI: `dmcli eRT getv|setv|addtable|deltable Device.X`.
- Peer = owner of the TR-181 namespace (CcspPandM, CcspWifiAgent, CcspLMLite...).

## COSA / CCSP data-model plugin (provider side)

Signals that the component *exposes* a data model: `COSA_*`, `Cosa*` DML functions
(`*_GetParamStringValue`, `*_SetParamBoolValue`, `*_Validate`, `*_Commit`, `*_Rollback`),
`ANSC_HANDLE`, `SLAP_*`, `DSLH_*`, and an XML like `TR181-*.xml`/`*_dm.xml` with
`<object>` / `<parameter>` / `<functions>`. Record each exposed TR-181 path as *provided*.

## rbus

- `rbus_open(&h, "name")`, `rbus_get/rbus_set/rbus_getExt`, `rbusValue_*`, `rbusObject_*`.
- Provider: `rbus_regDataElements(h, n, rbusDataElement_t[])` with `{"Device.X.Y", RBUS_ELEMENT_TYPE_PROPERTY, {getH, setH, ...}}`.
- Events: `rbusEvent_Subscribe(h, "Device.X.Y!", ...)`, `rbusEvent_Publish`. Methods: `rbusMethod_Invoke(h, "Device.X.Method()", ...)`.
- CLI `rbuscli get|set|sub|method_noargs`. Legacy: `rtMessage_*`, `rbus_openBrokerConnection`.
- Many components support both CCSP and rbus via `rbus_checkStatus()` / `RBUS_ENABLED` — record both.

## D-Bus (direct), systemd bus

`dbus_connection_*`, `dbus_message_*`, `g_dbus_*`, `sd_bus_*`, `dbus-send`, `busctl`.
Record bus name, object path, interface, member.

## MQTT / messagepack / protobuf / JSON / YAML / INI / TOML / XML

- MQTT: `mosquitto_*`, `MQTTClient_*`, `MQTTAsync_*`. Record broker URL source, topics. RDK: `mqttcm` (MQTT connection
  manager), `MQTT_INIT_URL`/`MQTT_INIT_PORT`/`MQTT_INIT_LOCATIONID` defaults in utopia `apply_system_defaults_helper.c`.
- msgpack: `msgpack_pack_*`, `msgpack_unpack*`, `msgpack_object_*` (WebConfig blobs, Parodus/WRP payloads).
- protobuf: `*__pack`, `*__unpack`, `protobuf_c_*`, `.proto` files (USP records).
- JSON: `cJSON_*` (most RDK-B), `json_object_*` (json-c), `json_file_parse` (utopia `util`), jansson.
  Record file path and keys read via `cJSON_GetObjectItem(obj, "key")`.
- YAML/INI/TOML: `yaml_parser_*`, `iniparser_*`, `g_key_file_*`, `toml_*`. Also hand-rolled
  `KEY=VALUE` parsing of `/etc/device.properties`, `rfcVariable.ini`, `tr181store.ini` with `fgets`+`strstr`.
- XML: `ixml*` (libupnp), libxml2 `xml*`, mxml. PSM defaults and UPnP SCPD files.

## nvram (vendor)

Broadcom-style `nvram get|set|commit`, `nvram_get()`; distinct from `/nvram` filesystem.

## Other OS IPC

- shm: `shm_open`, `shmget`, `mmap` (syscfg uses shared memory).
- queues/semaphores: `mq_*`, `msgget`, `sem_open` (named semaphore names are cross-process contracts).
- FIFO: `mkfifo`. UNIX socket: `AF_UNIX` + `sun_path` (record path).
- nanomsg/nng/zmq: `nn_socket(AF_SP, NN_PUSH)` + `nn_connect(s, "ipc:///tmp/...")`. utopia `service_udhcpc` talks to WAN manager this way.
- Sun RPC / custom RPC: `clnt_create`, `xdr_*`, utopia `util/rpc` (`rpcclient`/`rpcserver` across ARM/ATOM).
- signals: `kill(pid, SIGUSR1)`, `killall -HUP dnsmasq`. Record target process + signal.
- pid files: `/var/run/*.pid`, `/tmp/*.pid` read to find a peer process.

## Utopia service manager (srvmgr)

- C registration: `sm_register(SERVICE_NAME, SERVICE_DEFAULT_HANDLER, SERVICE_CUSTOM_EVENTS)`
  in `scripts/init/c_registration/*.c`. Each tuple `"event|handler[|flags|params]"` = subscription.
- shell: `service_start`, `service_stop`, `service_init`, `wait_till_end_state <svc>`,
  `sysevent async <event> <handler>`.
- The handler script/binary is a runtime dependency; the event is an IPC dependency.
