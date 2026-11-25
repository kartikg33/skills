<!--
Copyright 2026 Kartik Gohil
SPDX-License-Identifier: Apache-2.0
-->

# Data model, cloud, telemetry and logging dependencies

## TR-181 data model

- Literals `"Device.X.Y.Z"`, also templated `"Device.WiFi.SSID.%d.Enable"`, `{i}` in XML.
- Consumer if passed to `CcspBaseIf_getParameterValues`, `rbus_get`, `dmcli getv`, `PSM_Get_*`.
- Writer if passed to `setParameterValues`, `rbus_set`, `dmcli setv`.
- Provider if registered (`rbus_regDataElements`, COSA DML XML, `*_GetParamXxxValue` handlers).
- Vendor extensions: `X_RDKCENTRAL-COM_*`, `X_CISCO_COM_*`, `X_COMCAST-COM_*`, `X_RDK_*`.
- Record the owner component of each namespace (via `CcspBaseIf_discComponentSupportingNamespace` or known mapping).

## RFC (Remote Feature Control)

- TR-181 `Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.<Name>.Enable` (and `.Control`, `.Identity`).
- Files: `/tmp/RFC/*`, `/opt/secure/RFC/tr181store.ini`, `/opt/secure/RFC/rfcVariable.ini`, `bootstrap.json`.
- APIs: `getRFCParameter`, `setRFCParameter`, `isRFCEnabled`, shell `tr181 -g`, `RFC_ENABLE_*` variables.
- RFC values are often cached in syscfg (e.g. `syscfg get <Feature>_Enable`) or PSM. Record both.

## Telemetry

- T2 (Telemetry 2.0): `t2_init("component")`, `t2_event_d("MARKER", int)`, `t2_event_s("MARKER", str)`,
  `t2_event_f`. Shell: `t2ValNotify "MARKER" val`, `t2CountNotify "MARKER" [n]`. Link: `-ltelemetry_msgsender`.
  Every marker name is a contract with the cloud telemetry profile. List all.
- T1 (log-grep): marker strings echoed to `/rdklogs/logs/*.txt.0` and matched by DCA/`dcm` profiles,
  e.g. `echo_t "RDKB_FIREWALL_RESTART ..."`. Record the exact string and log file.

## Logging

- RDK logger: `RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.FIREWALL", ...)`, `rdk_logger_init("/etc/debug.ini")`. The module
  string ties to `/etc/debug.ini`. CCSP: `CcspTraceInfo/Error/Warning`, `AnscTrace*`.
- ulog (utopia): `ulog`, `ulogf`, `ulog_error`, `ulog_debugf(ULOG_FIREWALL, UL_INFO, ...)`; shell `ulog <comp> <sub> msg`.
- syslog: `openlog/syslog/vsyslog`; shell `logger`. Peer: `syslogd`/`klogd`/`rsyslog`, config `syslog.conf`.
- Log files: `/rdklogs/logs/<Name>.txt.0`, `/var/log/*`, `/nvram/*log*`, `/tmp/*.log`. Consumers: log upload
  (`uploadRDKBLogs.sh`, `backupLogs.sh`), T1 telemetry, `logrotate`. Record file and R/W.

## WebConfig (blob delivery)

- Framework: `register_sub_docs`, `webconfig_framework`, `execData`, `PushBlobRequest`, `rollback_*`, `getBlobVersion`,
  `setBlobVersion`, `blob->subdoc_name`. Link `-lwebconfig_framework`, `-lmsgpackc`, `-ltrower-base64`.
- Subdoc name (`"portforwarding"`, `"lan"`, `"hotspot"`, `"wan"`, ...) is the cloud contract; msgpack schema = keys unpacked.
- TR-181 entry point `Device.X_RDK_WebConfig.*` or component-specific `...Data` parameter.

## WebPA / Parodus

`libparodus_*`, `wrp_*`/`WRP_MSG_*`, `parodus` service; `cimplog` logging. Record service name and event destinations.

## TR-369 USP / MTP

`obuspa`, `Device.LocalAgent.*`, `Usp__Msg`/`Usp__Record` (protobuf-c), MTP over STOMP, MQTT or WebSocket.
Record agent endpoint id, controller, MTP type, topics.

## TR-069 / CWMP

`CcspTr069Pa`, `cwmp*`, `Device.ManagementServer.*`, `X_CISCO_COM_*` notifications.

## UPnP / IGD

libupnp (`Upnp*`, `ixml*`), SCPD XML, `Device.UPnP.*`. utopia `igd` exposes IGD services.

## HAL

`platform_hal_*`, `wifi_hal`/`wifi_get*`, `moca_hal_*`, `cm_hal_*`, `ethsw_hal`/`CcspHalEthSw*`, `dhcpv4c_*`, `mta_hal_*`.
Link `-lhal_platform`, `-lhal_wifi`, etc. HAL = vendor implementation dependency.

## Device identity and gating

- `/etc/device.properties` keys (`BOX_TYPE`, `MODEL_NUM`, `BUILD_TYPE`, `WAN_INTERFACE`, `ARM_INTERFACE_IP`,
  `ATOM_INTERFACE_IP`, `MESH_*`). Read by shell `source /etc/device.properties` or C property readers.
- `/etc/waninfo.sh`, `/etc/utopia/service.d/*.sh`, `/lib/rdk/*.sh` shared shell libraries.
- Device mode / OneStack gates: `isFeatureSupportedInCurrentMode(FEATURE_X)`, `-lrdkb_feature_mode_gate`, `-ldevicemode`.
- Partner defaults: `/etc/partners_defaults.json`, `/nvram/partners_defaults.json`, `/opt/secure/bootstrap.json`,
  `PartnerID`, `apply_system_defaults`, `system_defaults*`.

## Security / crypto

`/opt/secure/*`, `rdkssa`, `mtlsUtil`, `GetConfigFile` (encrypted config), OpenSSL/mbedTLS APIs, `-lssl -lcrypto`.

## HTTP

`curl_easy_*`, shell `curl`/`wget`: record URLs or the TR-181/RFC parameter that supplies them.
