#!/usr/bin/env python3
"""
rdk_dep_scan.py - static dependency inventory for RDK / RDK-B components.

Walks a component source tree and emits every dependency signal it can find,
grouped by category (IPC, external process, data model / cloud, build, ...).
Each finding carries file:line evidence so an agent (or human) can verify it.

It also reports *unclassified* candidates: commands, libraries, headers and
paths that look like dependencies but match no known catalog entry. A clean
run means the catalog covers the component; anything left over must be
classified by hand (and, ideally, added to the catalog).

Pure stdlib, Python 3.8+.

Usage:
  rdk_dep_scan.py <path> [--format md|json] [--category NAME ...]
                         [--max-evidence N] [--no-unclassified]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field

# --------------------------------------------------------------------------
# File classification
# --------------------------------------------------------------------------

C_EXT = {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"}
SH_EXT = {".sh", ".bash", ".ksh"}
PY_EXT = {".py"}
BUILD_NAMES = {"makefile", "makefile.am", "makefile.in", "configure.ac",
               "configure.in", "cmakelists.txt", "meson.build", "kconfig"}
BUILD_EXT = {".am", ".mk", ".cmake", ".ac", ".m4"}
YOCTO_EXT = {".bb", ".bbappend", ".bbclass", ".inc", ".conf"}
DATA_EXT = {".json", ".yaml", ".yml", ".ini", ".toml", ".xml", ".proto",
            ".cfg", ".properties", ".service", ".path", ".timer",
            ".socket", ".target", ".schema"}
SKIP_DIRS = {".git", ".svn", "node_modules", "__pycache__", ".repo",
             "build", "_build", "autom4te.cache"}


def file_kind(path: str) -> str | None:
    base = os.path.basename(path).lower()
    ext = os.path.splitext(base)[1]
    if base in BUILD_NAMES or ext in BUILD_EXT:
        return "build"
    if ext in YOCTO_EXT:
        return "yocto"
    if ext in C_EXT:
        return "c"
    if ext in SH_EXT:
        return "sh"
    if ext in PY_EXT:
        return "py"
    if ext in DATA_EXT:
        return "data"
    if ext == "" or base.startswith("system_defaults") or base.endswith(".sample"):
        # extension-less: sniff for a shebang
        try:
            with open(path, "rb") as fh:
                head = fh.read(64)
            if head.startswith(b"#!") and (b"sh" in head.split(b"\n")[0]):
                return "sh"
            if base.startswith("system_defaults"):
                return "data"
        except OSError:
            return None
    return None


# --------------------------------------------------------------------------
# Rule catalog
# --------------------------------------------------------------------------

@dataclass
class Rule:
    category: str          # top-level bucket
    name: str              # dependency name (what it depends on)
    pattern: str           # regex
    kinds: tuple = ("c",)  # file kinds the rule applies to
    capture: int = 0       # group to record as the "key" (0 = whole match)
    flags: int = 0
    rx: re.Pattern = field(init=False, repr=False)

    def __post_init__(self):
        self.rx = re.compile(self.pattern, self.flags)


C = ("c",)
SH = ("sh",)
CSH = ("c", "sh", "py")
ALLSRC = ("c", "sh", "py", "data")
BLD = ("build",)
YOC = ("yocto",)

R: list[Rule] = []


def rule(cat, name, pat, kinds=C, capture=0, flags=0):
    R.append(Rule(cat, name, pat, kinds, capture, flags))


# ---- 1. IPC / configuration stores ---------------------------------------
IPC = "ipc"
rule(IPC, "sysevent", r"\bsysevent_(open|local_open|close|get|set|get_unique|set_unique|"
     r"setnotification|setcallback|rmcallback|set_options|getnotification|del_unique|"
     r"get_binmsg_maxsize|set_binmsg)\b")
rule(IPC, "sysevent (other API)", r"\b(sysevent_(?:get|set)\w+)\s*\(", C, 1)
rule(IPC, "sysevent", r"\bsysevent\s+(get|set|setunique|getunique|async|async_with_flags|"
     r"rm_async|setoptions|delunique)\b", SH)
rule(IPC, "sysevent", r"#\s*include\s*[<\"]sysevent/sysevent\.h[>\"]")
rule(IPC, "sysevent (key)", r"\bsysevent_(?:get|set)\w*\s*\([^,]+,[^,]+,\s*\"([A-Za-z0-9_\-%.]+)\"",
     C, 1)
rule(IPC, "sysevent (key)", r"\bsysevent\s+(?:get|set|setunique|async|setoptions)\s+(?:-i\s+\S+\s+)?([A-Za-z0-9_\-${}]+)",
     SH, 1)
rule(IPC, "sysevent (key via macro)", r"\bsysevent_(?:get|set)\w*\s*\([^,]+,[^,]+,\s*([A-Z][A-Z0-9_]+)\s*,", C, 1)
rule(IPC, "sysevent (key via variable: trace by hand)", r"\bsysevent_(?:get|set)\w*\s*\([^,]+,[^,]+,\s*([a-z_][A-Za-z0-9_\[\]\.>\-]*)\s*,", C, 1)
rule(IPC, "syscfg", r"\bsyscfg_(init|get|set|set_commit|set_u|set_ns|set_ns_commit|set_nns|"
     r"set_nns_commit|set_u_commit|unset|commit|getall|getall2|create|destroy|is_match)\w*\b")
rule(IPC, "syscfg", r"\bsyscfg\s+(get|set|unset|commit|show|destroy)\b", SH)
rule(IPC, "syscfg (key)", r"\bsyscfg_(?:get|set)\w*\s*\(\s*(?:NULL|[A-Za-z_]+)\s*,\s*\"([A-Za-z0-9_\-%.]+)\"",
     C, 1)
rule(IPC, "syscfg (key via macro)", r"\bsyscfg_(?:get|set)\w*\s*\(\s*(?:NULL|[a-z_]+)\s*,\s*([A-Z][A-Z0-9_]+)\s*,", C, 1)
rule(IPC, "syscfg (key via variable: trace by hand)", r"\bsyscfg_(?:get|set)\w*\s*\(\s*(?:NULL|[a-z_]+)\s*,\s*([a-z_][A-Za-z0-9_\[\]\.>\-]*)\s*,", C, 1)
rule(IPC, "PSM (key via macro)", r"\bPSM_VALUE_(?:GET|SET)_\w+\s*\(\s*([A-Z][A-Z0-9_]+)\s*,", C, 1)
rule(IPC, "syscfg (key)", r"\bsyscfg_(?:get|set)\w*\s*\(\s*\"([A-Za-z0-9_\-%.]+)\"", C, 1)
rule(IPC, "syscfg (key)", r"\bsyscfg\s+(?:get|set|unset)\s+([A-Za-z0-9_\-${}]+)", SH, 1)
rule(IPC, "syscfg (key, shell var import)", r"\$SYSCFG_([A-Za-z0-9_]+)", SH, 1)
rule(IPC, "utctx/utapi (syscfg+sysevent wrapper)",
     r"\b(Utopia_(Init|Free|Get\w*|Set\w*|Unset\w*|Raw\w+|EventSet|IsEvent)|UTCTX_|UtopiaContext)\b")
rule(IPC, "PSM (CCSP persistent storage)",
     r"\b(PSM_(Get|Set|Del)_Record_Value2|PSM_VALUE_(GET|SET)_\w+|PsmGetNextLevelInstances|"
     r"PSM_Get_Record_Status|PsmHal\w*)\b")
rule(IPC, "PSM (CCSP persistent storage)", r"\bpsmcli\b(?:\s+-\w+)*(?:\s+(get|set|del|getdetail|getallinst|getinstcnt|nosubsys))?", CSH)
rule(IPC, "PSM (key)", r"\"(dmsb\.[A-Za-z0-9_.%]+|eRT\.com\.cisco\.[A-Za-z0-9_.%]+)\"", ALLSRC, 1)
rule(IPC, "CCSP message bus (D-Bus based)",
     r"\b(CCSP_Message_Bus_\w+|CcspBaseIf_\w+|CCSP_Msg_\w+|ccsp_\w*bus\w*|"
     r"CCSP_DBUS_\w+|COMPONENT_NAME_\w+|CCSP_DBUS_PATH_\w+|CCSP_COMPONENT_\w+|eRT\.com\.cisco\.spvtg\.ccsp\.\w+)\b")
rule(IPC, "CCSP message bus (D-Bus based)", r"\bdmcli\b(?:\s+\w+\s+(getv|setv|getvalues|setvalues|addtable|deltable|getnames|getattributes))?", CSH)
rule(IPC, "COSA / CCSP data-model plugin",
     r"\b(Cosa\w+|COSA_\w+|ANSC_HANDLE|AnscAllocateMemory|AnscFreeMemory|SLAP_\w+|"
     r"g_pDslhDmlAgent|DSLH_\w+|PLUGIN_\w+|COSAGetParamValue\w*|COSASetParamValue\w*)\b")
rule(IPC, "rbus", r"\b(rbus_\w+|rbusValue_\w+|rbusObject_\w+|rbusProperty_\w+|rbusEvent_\w+|"
     r"rbusMethod_\w+|rbusHandle_t|rbusTable_\w+|rbusElementInfo_t)\b")
rule(IPC, "rbus", r"\brbuscli\s+\w+", CSH)
rule(IPC, "rbus (legacy rtMessage/rbus-core)", r"\b(rtMessage_\w+|rtConnection_\w+|rbus_register\w*|rbus_openBrokerConnection)\b")
rule(IPC, "D-Bus (direct)", r"\b(dbus_\w+|DBusConnection|DBusMessage|g_dbus_\w+|GDBus\w+|sd_bus_\w+)\b")
rule(IPC, "D-Bus (direct)", r"\b(dbus-send|gdbus|busctl)\b", SH)
rule(IPC, "MQTT (client API)", r"\b(mosquitto_\w+|MQTTClient_\w+|MQTTAsync_\w+|mqtt_(?:connect|publish|subscribe)\w*)\b")
rule(IPC, "MQTT (config/reference)", r"\b(MQTT_[A-Z0-9_]+|mqttcm\w*|[A-Za-z_]*[Mm]qtt[A-Za-z_]*)\b", ALLSRC, 1)
rule(IPC, "MessagePack", r"\b(msgpack_\w+|mpack_\w+)\b")
rule(IPC, "cJSON / JSON", r"\b(cJSON_\w+|json_object_\w+|json_tokener_\w+|json_file_parse|"
     r"jansson|json_(loads|load_file|dumps|dump_file|object_get|array_get)\w*|yajl_\w+)\b")
rule(IPC, "YAML", r"\b(yaml_parser_\w+|yaml_emitter_\w+|YAML::\w+)\b")
rule(IPC, "INI", r"\b(iniparser_\w+|ini_parse\w*|g_key_file_\w+)\b")
rule(IPC, "TOML", r"\b(toml_\w+)\b")
rule(IPC, "XML", r"\b(xmlRead\w+|xmlParse\w+|xmlDoc\w+|ixml\w+|XML_Parser\w*|mxml\w+)\b")
rule(IPC, "protobuf", r"\b(protobuf_c_\w+|\w+__pack|\w+__unpack|google::protobuf::\w+)\b")
rule(IPC, "nanomsg / nng / zeromq", r"\b(nn_(socket|bind|connect|send|recv|close)|nng_\w+|zmq_\w+)\b")
rule(IPC, "Sun RPC / custom RPC", r"\b(clnt_create|clnt_call|svc_register|svc_run|svcudp_create|"
     r"svctcp_create|xdr_\w+|rpc_\w+)\b")
rule(IPC, "POSIX shared memory / mmap", r"\b(shm_open|shm_unlink|shmget|shmat|mmap|munmap)\s*\(")
rule(IPC, "POSIX/SysV message queue", r"\b(mq_open|mq_send|mq_receive|msgget|msgsnd|msgrcv)\s*\(")
rule(IPC, "semaphore", r"\b(sem_open|sem_init|sem_wait|sem_post|semget|semop)\s*\(")
rule(IPC, "named pipe (FIFO)", r"\b(mkfifo|mknod)\s*\(")
rule(IPC, "named pipe (FIFO)", r"\bmkfifo\b", SH)
rule(IPC, "UNIX domain socket", r"\bAF_UNIX\b|\bAF_LOCAL\b|\bsockaddr_un\b")
rule(IPC, "signals (inter-process)", r"\b(kill|killpg|sigqueue|raise)\s*\(")
rule(IPC, "signals (inter-process)", r"\b(kill|killall|pkill)\s+-(\w+)", SH)
rule(IPC, "pid files", r"\"([^\"]*\.pid)\"", CSH, 1)
rule(IPC, "inotify / file watch", r"\b(inotify_\w+|fanotify_\w+)\b")
rule(IPC, "libevent / epoll loop", r"\b(event_base_\w+|evhttp_\w+|epoll_\w+)\b")
rule(IPC, "systemd notify / sd-bus", r"\b(sd_notify\w*|sd_journal_\w+|sd_bus_\w+)\b")
rule(IPC, "nvram (Broadcom / CLI)", r"\b(nvram_(get|set|unset|commit|getall)\w*)\s*\(")
rule(IPC, "nvram (Broadcom / CLI)", r"\bnvram\s+(get|set|unset|commit|show|getall)\b", SH)
rule(IPC, "RDK config / device props", r"\b(rdkconfig_\w+|getDevicePropertyData|"
     r"get_device_property|GetValueFromPropertiesFile)\b")
rule(IPC, "service manager (utopia srvmgr)", r"\b(sm_register|sm_unregister|srvmgr_\w+)\b")
rule(IPC, "srvmgr event subscription (event|handler)", r"\"([A-Za-z0-9_\-]+\|/[^|\"]+)", C, 1)
rule(IPC, "service manager (utopia srvmgr)", r"\b(service_start|service_stop|service_init|"
     r"wait_till_end_state|sm_register|sm_unregister)\b", SH)

# ---- 1b. Filesystem paths -------------------------------------------------
FS = "filesystem"
PATH_RX = r"[\"'\s=(>](/(?:tmp|var|nvram|nvram2|etc|proc|sys|dev|run|opt|data|rdklogs|minidumps|" \
          r"mnt|usr|lib|bin|sbin|fss|home|media|secure|jffs)(?:/[A-Za-z0-9_.%${}\-*@:]+)*/?)"
rule(FS, "path", PATH_RX, ALLSRC + BLD + YOC, 1)
rule(FS, "file open (C: target, mode)", r"\b(fopen\s*\(\s*[^,]+,\s*[^)]+)\)", C, 1)
rule(FS, "file write (C)", r"\bfopen\s*\([^,]+,\s*\"(w|a|r\+|w\+|a\+)[be]?\"", C, 1)
rule(FS, "file mutate (C)", r"\b(unlink|remove|rename|mkdir|rmdir|truncate|ftruncate|chmod|chown|"
     r"symlink|link|creat)\s*\(", C, 1)
rule(FS, "file probe (C)", r"\b(access|stat|lstat|opendir|realpath)\s*\(", C, 1)
rule(FS, "file write (sh)", r"(?<![0-9&<])>>?\s*(\"?\$?[A-Za-z0-9_/{}.\-]+)", SH, 1)
rule(FS, "file mutate (sh)", r"\b(rm|touch|mkdir|mv|cp|ln|chmod|chown)\s+-?\w*\s*(\S+)", SH, 1)
rule(FS, "sourced shell library", r"^\s*(?:source|\.)\s+(\S+)", SH, 1, re.M)
rule(FS, "config file format", r"[\"'/]([A-Za-z0-9_.\-]+\.(json|ya?ml|ini|toml|conf|cfg|xml|"
     r"properties|db|list|txt|log|proto|msgpack|bin))\b", ALLSRC, 1)

# ---- 2. External processes / kernel interfaces ---------------------------
EXT = "external_process"
rule(EXT, "process spawn API", r"\b(v_secure_system|v_secure_popen|v_secure_pclose|system|popen|pclose|"
     r"execl|execlp|execle|execv|execvp|execve|posix_spawn\w*|fork|vfork|daemon)\s*\(", C, 1)
rule(EXT, "systemctl / systemd unit", r"\bsystemctl\s+(?:start|stop|restart|reload|enable|disable|"
     r"is-active|is-enabled|status|kill|daemon-reload|show|try-restart|mask|unmask)\s+(?:--?[a-z\-]+\s+)*"
     r"([A-Za-z0-9_@.${}\-]+)", CSH, 1)
rule(EXT, "ioctl", r"\bioctl\s*\(\s*[^,]+,\s*([A-Za-z_0-9>.\-]+)", C, 1)
rule(EXT, "ioctl request", r"\b(SIOC[A-Z0-9_]+|ETHTOOL_\w+|TUN\w+|BRCTL\w+|SIOCDEVPRIVATE)\b", C, 1)
rule(EXT, "netlink", r"\b(AF_NETLINK|NETLINK_\w+|RTM_\w+|NLM_F_\w+|nl_\w+|rtnl_\w+|"
     r"genl_\w+|nla_\w+|mnl_\w+|nlmsg\w*)\b", C, 1)
rule(EXT, "raw/packet sockets", r"\b(AF_PACKET|SOCK_RAW|PF_PACKET|ETH_P_\w+)\b", C, 1)
rule(EXT, "netfilter (lib)", r"\b(nfq_\w+|nfct_\w+|iptc_\w+|ip6tc_\w+|nftnl_\w+|nft_ctx_\w+|"
     r"ipset_\w+|libnet_\w+)\b", C, 1)
rule(EXT, "generated netfilter rule (chain)", r"\bfprintf\s*\([^,]+,\s*\"-[AIN]\s+([A-Za-z0-9_%\-]+)", C, 1)
rule(EXT, "generated netfilter rule (jump target)", r"\bfprintf\s*\([^,]+,\s*\"[^\"]*-j\s+([A-Za-z0-9_%\-]+)", C, 1)
rule(EXT, "procfs / sysfs", r"\"(/proc/[^\"]+|/sys/[^\"]+)\"", CSH, 1)
rule(EXT, "kernel module", r"\b(modprobe|insmod|rmmod)\b\s+(\S+)", CSH)
rule(EXT, "sysctl", r"\bsysctl\s+(-w\s+)?(\S+)", CSH)
rule(EXT, "dlopen (runtime plugin)", r"\b(dlopen|dlsym)\s*\(", C, 1)
rule(EXT, "environment variable", r"\b(getenv|setenv|putenv|secure_getenv)\s*\(\s*\"([^\"]+)\"", C, 2)
rule(EXT, "cron", r"\b(crontab|/etc/cron[^\"\s]*|cron_every_\w+)\b", CSH)

# ---- 3. Data model / cloud / telemetry / logging -------------------------
DM = "data_model_cloud"
rule(DM, "TR-181 parameter", r"(Device\.[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-{}%]+)*\.?)", ALLSRC + YOC, 1)
rule(DM, "RFC (Remote Feature Control)", r"(X_RDKCENTRAL-COM_RFC\.[A-Za-z0-9_.]+|RFC_[A-Za-z0-9_]+|"
     r"/tmp/RFC/[^\"\s]+|rfcVariable\.ini|tr181store\.ini|getRFCParameter|setRFCParameter|"
     r"isRFCEnabled|bootstrap\.json)", ALLSRC, 1)
rule(DM, "Telemetry 2.0 marker", r"\bt2_event_[sdf]\s*\(\s*\"([^\"]+)\"", C, 1)
rule(DM, "Telemetry 2.0 marker", r"\bt2(?:ValNotify|CountNotify)\s+\"?([A-Za-z0-9_]+)", SH, 1)
rule(DM, "Telemetry 2.0 API", r"\b(t2_init|t2_uninit|t2_event_\w+|telemetry_busmessage_sender)\b")
rule(DM, "Telemetry 1.0 log grep marker", r"\becho(?:_t)?\s+\"?([A-Z][A-Za-z0-9_]*(?:_(?:ERROR|SPLIT|INFO|"
     r"WARN|split))[A-Za-z0-9_]*)", SH, 1)
rule(DM, "RDK logger", r"\b(RDK_LOG|rdk_logger_init|rdk_dbg_\w+|CcspTrace\w+|AnscTrace\w+|"
     r"LOG_\w+_MOD|\"LOG\.RDK\.[A-Z0-9_]+\")")
rule(DM, "ulog (utopia logging)", r"\b(ulog\w*)\s*\(", C, 1)
rule(DM, "ulog (utopia logging)", r"^\s*(ulog|ulog_\w+)\b", SH, 1, re.M)
rule(DM, "syslog", r"\b(syslog|openlog|closelog|vsyslog|setlogmask)\s*\(", C, 1)
rule(DM, "syslog", r"\blogger\s+", SH)
rule(DM, "log file", r"(/rdklogs/logs/[A-Za-z0-9_.\-]+|/var/log/[A-Za-z0-9_.\-/]+|"
     r"/nvram/[A-Za-z0-9_\-]*log[A-Za-z0-9_.\-]*|[A-Za-z0-9_]+(?:Log|log)\.txt\.\d+)", ALLSRC, 1)
rule(DM, "WebConfig blob", r"\b(webconfig_\w+|wbStatus|blob_\w+|register_sub_docs|execData|"
     r"PushBlobRequest|rollback_\w+|getBlob\w*|subdoc\w*|WebConfig\w*|"
     r"ExecuteBlob|webcfg_\w+|wcf_\w+)\b", C, 1)
rule(DM, "WebPA / Parodus", r"\b(libparodus_\w+|parodus\w*|wrp_\w+|WRP_\w+|webpa\w*|cimplog\w*)\b", CSH, 1)
rule(DM, "TR-369 USP / MTP", r"\b(USP_\w+|usp_\w+|MTP_\w+|Usp__\w+|obuspa|STOMP\w*|"
     r"Device\.LocalAgent\.[A-Za-z0-9_.{}]+)\b", ALLSRC, 1)
rule(DM, "TR-069 / CWMP", r"\b(cwmp\w*|CWMP\w*|Tr069\w*|tr69\w*|TR069\w*)\b", ALLSRC, 1)
rule(DM, "UPnP / IGD", r"\b(Upnp\w+|UPNP_\w+|upnp_\w+|IGD\w+|SCPD\w*)\b", C, 1)
rule(DM, "HAL API", r"\b((?:platform|wifi|moca|cm|ethsw|dhcpv4c|mta|fan|thermal|vlan|bt|"
     r"cellular|xdsl|epon|ppp|tad|mso_mgmt|ccsp_hal|sfp|led)_hal_\w+|"
     r"wifi_(get|set|init|push|create)\w*|mocaHal\w*|CcspHalEthSw\w+|wifi_hal\w*)\b", C, 1)
rule(DM, "feature / device-mode gating", r"\b(isFeatureSupportedInCurrentMode|FEATURE_[A-Z0-9_]+|"
     r"getDeviceMode|DEVICE_MODE_\w+|isExtender\w*|onestack\w*)\b", C, 1)
rule(DM, "device.properties key", r"\b(BOX_TYPE|MODEL_NUM|PARTNER_ID|BUILD_TYPE|"
     r"MANUFACTURE|MODEL_NAME|DEVICE_TYPE|CMDINTERFACE|WAN_INTERFACE|ARM_INTERFACE|"
     r"ATOM_INTERFACE_IP|ARM_INTERFACE_IP|LOG_PATH|PERSISTENT_PATH|MESH_\w+|"
     r"RDK_PROFILE|FIRMWARE_\w+)\b", CSH, 1)
rule(DM, "partner defaults / bootstrap", r"\b(partners_defaults\.json|bootstrap\.json|"
     r"system_defaults\w*|PartnerID|syscfg_create|apply_system_defaults)\b", ALLSRC, 1)
rule(DM, "secure storage / crypto", r"\b(SSL_\w+|EVP_\w+|X509_\w+|mbedtls_\w+|rdkssa\w*|"
     r"mtlsUtil\w*|/opt/secure/\S*|GetConfigFile|SecureStorage\w*)\b", ALLSRC, 1)
rule(DM, "HTTP client", r"\b(curl_\w+|CURL\w*)\b", C, 1)
rule(DM, "HTTP client", r"\b(curl|wget)\s", SH)

# ---- 4. Build ------------------------------------------------------------
BUILD = "build"
rule(BUILD, "header include", r"^\s*#\s*include\s*[<\"]([^>\"]+)[>\"]", C, 1, re.M)
rule(BUILD, "link library (-l)", r"(?<![A-Za-z0-9_])-l([A-Za-z0-9_+.\-]+)", BLD + YOC, 1)
rule(BUILD, "library search path (-L)", r"(?<![A-Za-z0-9_])-L(\S+)", BLD + YOC, 1)
rule(BUILD, "include path (-I)", r"(?<![A-Za-z0-9_])-I(\S+)", BLD + YOC, 1)
rule(BUILD, "compile-time define (-D)", r"(?<![A-Za-z0-9_])-D([A-Za-z_][A-Za-z0-9_]*)", BLD + YOC, 1)
rule(BUILD, "pkg-config module", r"PKG_CHECK_MODULES\s*\(\s*\[?(\w+)\]?\s*,\s*\[?([^\])]+)", BLD, 2)
rule(BUILD, "pkg-config module", r"pkg_check_modules\s*\(\s*\w+\s+(?:REQUIRED\s+)?([^)]+)\)", BLD, 1, re.I)
rule(BUILD, "autoconf check", r"\b(AC_CHECK_LIB|AC_CHECK_HEADERS?|AC_SEARCH_LIBS|AC_CHECK_FUNCS?)\s*\(\s*\[?([^\],)]+)",
     BLD, 2)
rule(BUILD, "autoconf feature flag", r"\bAC_ARG_(ENABLE|WITH)\s*\(\s*\[?([A-Za-z0-9_\-]+)", BLD, 2)
rule(BUILD, "automake conditional", r"\bAM_CONDITIONAL\s*\(\s*\[?([A-Za-z0-9_]+)", BLD, 1)
rule(BUILD, "automake conditional", r"^\s*if\s+([A-Z][A-Z0-9_]+)\s*$", BLD, 1, re.M)
rule(BUILD, "automake target", r"^\s*(?:bin|sbin|lib|noinst|libexec|check)_(PROGRAMS|LTLIBRARIES|"
     r"LIBRARIES|SCRIPTS|HEADERS)\s*\+?=\s*(.+)$", BLD, 2, re.M)
rule(BUILD, "internal libtool lib (.la)", r"([A-Za-z0-9_\-./$()]+\.la)\b", BLD, 1)
rule(BUILD, "automake subdir", r"^\s*SUBDIRS\s*\+?=\s*(.+)$", BLD, 1, re.M)
rule(BUILD, "cmake dependency", r"\b(find_package|find_library|target_link_libraries|"
     r"add_subdirectory|include_directories|pkg_search_module)\s*\(([^)]*)\)", BLD, 2, re.I)
rule(BUILD, "Yocto DEPENDS", r"^\s*DEPENDS(?::\w+|_\w+)?\s*[+?:.]?=+\s*\"([^\"]*)\"", YOC, 1, re.M)
rule(BUILD, "Yocto RDEPENDS", r"^\s*RDEPENDS[:_]\$\{PN\}[^=]*=+\s*\"([^\"]*)\"", YOC, 1, re.M)
rule(BUILD, "Yocto RRECOMMENDS / PROVIDES", r"^\s*(RRECOMMENDS|RPROVIDES|PROVIDES|RCONFLICTS)\S*\s*[+?:.]?=+\s*\"([^\"]*)\"",
     YOC, 2, re.M)
rule(BUILD, "Yocto DISTRO/MACHINE feature", r"bb\.utils\.contains\(\s*'(DISTRO_FEATURES|MACHINE_FEATURES)'\s*,\s*'([^']+)'",
     YOC, 2)
rule(BUILD, "Yocto EXTRA_OECONF / CFLAGS", r"^\s*(EXTRA_OECONF|EXTRA_OECMAKE|EXTRA_OEMAKE|CFLAGS|LDFLAGS|"
     r"CXXFLAGS)\S*\s*[+?:.]?=+\s*\"([^\"]*)\"", YOC, 2, re.M)
rule(BUILD, "Yocto inherit", r"^\s*inherit\s+(.+)$", YOC, 1, re.M)
rule(BUILD, "Yocto SRC_URI", r"^\s*SRC_URI\S*\s*[+?:.]?=+\s*\"([^\"]*)\"", YOC, 1, re.M)
rule(BUILD, "Yocto systemd unit", r"SYSTEMD_SERVICE\S*\s*[+?:.]?=+\s*\"([^\"]*)\"", YOC, 1)
rule(BUILD, "Yocto installed file", r"\$\{D\}(\$\{[a-z_]+\}|/)[^\s\"]*", YOC)
rule(BUILD, "Makefile raw flags", r"^\s*(\w*(?:CFLAGS|CPPFLAGS|LDFLAGS|LIBADD|LDADD|LIBS))\s*\+?=", BLD, 1, re.M)
rule(BUILD, "compile-time #if feature", r"^\s*#\s*(?:if|ifdef|ifndef|elif)\b\s*(?:defined\s*\(?)?\s*([A-Z_][A-Z0-9_]+)",
     C, 1, re.M)
rule(BUILD, "test framework", r"\b(gtest|gmock|GTEST|TEST_F|TEST\(|cmocka|CUnit)\b", C + BLD, 1)

# systemd unit file contents
rule("runtime_orchestration", "systemd unit relation", r"^\s*(After|Before|Requires|Wants|BindsTo|"
     r"PartOf|Conflicts|ExecStart|ExecStartPre|ExecStartPost|ExecStop|EnvironmentFile|"
     r"ConditionPathExists|PathExists|PathChanged)\s*=\s*(.+)$", ("data",), 0, re.M)


# --------------------------------------------------------------------------
# External command catalog (for shell + system()/popen() payloads)
# --------------------------------------------------------------------------

KNOWN_COMMANDS = {
    # rdk / ccsp / utopia CLIs
    "sysevent": "IPC: sysevent CLI", "syscfg": "IPC: syscfg CLI",
    "syscfg_create": "IPC: syscfg DB create", "syscfg_format": "IPC: syscfg format",
    "psmcli": "IPC: PSM CLI", "dmcli": "IPC: CCSP data-model CLI",
    "rbuscli": "IPC: rbus CLI", "nvram": "IPC: nvram CLI", "t2ValNotify": "Telemetry",
    "t2CountNotify": "Telemetry", "rpcclient": "RPC to peer CPU (ARM<->ATOM)",
    "ulog": "logging", "echo_t": "logging", "logger": "syslog",
    "firewall": "utopia firewall binary", "gw_lan_refresh": "utopia binary",
    "pmon.sh": "utopia process monitor", "service_wan": "utopia service",
    "service_dhcp": "utopia service", "service_dslite": "utopia service",
    "service_routed": "utopia service", "service_ipv6": "utopia service",
    "service_dhcpv6_client": "utopia service", "service_udhcpc": "utopia service",
    "execute_dir": "utopia helper", "trigger": "utopia binary", "newhost": "utopia binary",
    "apply_system_defaults": "utopia binary", "pal_log_router_transmitter": "utopia binary",
    "bridgeUtils": "RDK bridge utility", "handle_sw.sh": "switch helper",
    "backupLogs.sh": "RDK log backup", "uploadRDKBLogs.sh": "RDK log upload",
    "image_writer": "firmware writer", "wan-status": "utopia helper", "lan-status": "utopia helper",
    "nfq_handler": "utopia netfilter-queue handler",
    # vendor / platform tools
    "mocacfg": "MoCA vendor CLI", "mocactl": "MoCA vendor CLI", "wlancfg": "WiFi vendor CLI",
    "wlancfg_tr": "WiFi vendor CLI", "switchcfg": "switch vendor CLI", "swctl": "switch vendor CLI",
    "ivictl": "IVI (MAP-T/E) CLI", "et": "Broadcom ethernet CLI", "wl": "Broadcom WiFi CLI",
    "ti_udhcpc": "TI DHCP client", "ti_dhcp6c": "TI DHCPv6 client",
    # networking
    "ip": "iproute2", "ip6tables": "netfilter", "iptables": "netfilter",
    "iptables-restore": "netfilter", "ip6tables-restore": "netfilter", "iptables-save": "netfilter",
    "ebtables": "netfilter bridge", "nft": "nftables", "ipset": "netfilter ipset",
    "conntrack": "netfilter conntrack", "ifconfig": "net-tools", "route": "net-tools",
    "arp": "net-tools", "brctl": "bridge-utils", "vconfig": "vlan", "bridge": "iproute2",
    "udhcpc": "busybox DHCP client", "udhcpd": "busybox DHCP server", "dnsmasq": "DNS/DHCP",
    "dibbler-server": "DHCPv6", "dibbler-client": "DHCPv6", "dhcp6c": "DHCPv6", "zebra": "quagga",
    "ripd": "quagga", "resolvconf": "resolver", "ping": "net", "ping6": "net",
    "nslookup": "net", "dig": "net", "traceroute": "net", "tcpdump": "net",
    "ethtool": "net", "ndisc6": "net", "rdisc6": "net", "sysctl": "kernel tunables",
    "dropbear": "ssh", "lighttpd": "web server", "igmpproxy": "mcast", "mcproxy": "mcast",
    "pppd": "ppp", "ntpd": "time", "ntpclient": "time", "chronyd": "time",
    # process / service control
    "systemctl": "systemd", "service": "init", "start-stop-daemon": "init",
    "killall": "procps", "kill": "procps", "pkill": "procps", "pidof": "procps",
    "ps": "procps", "top": "procps", "nice": "procps", "nohup": "coreutils",
    "modprobe": "kmod", "insmod": "kmod", "rmmod": "kmod", "reboot": "system",
    "crond": "cron", "crontab": "cron", "strace": "debug", "sh": "shell", "bash": "shell",
    "eval": "shell", "flock": "util-linux", "mount": "util-linux", "umount": "util-linux",
    "deluser": "busybox", "adduser": "busybox", "passwd": "shadow", "hostname": "system",
    "date": "coreutils", "uptime": "coreutils", "free": "procps", "df": "coreutils",
    "du": "coreutils", "sync": "coreutils",
    # text / file utils
    "echo": "shell builtin", "printf": "shell builtin", "cat": "coreutils", "tail": "coreutils",
    "head": "coreutils", "grep": "grep", "egrep": "grep", "sed": "sed", "awk": "awk",
    "cut": "coreutils", "tr": "coreutils", "sort": "coreutils", "uniq": "coreutils",
    "wc": "coreutils", "ls": "coreutils", "rm": "coreutils", "cp": "coreutils",
    "mv": "coreutils", "touch": "coreutils", "mkdir": "coreutils", "ln": "coreutils",
    "chmod": "coreutils", "chown": "coreutils", "find": "findutils", "xargs": "findutils",
    "basename": "coreutils", "dirname": "coreutils", "readlink": "coreutils",
    "md5sum": "coreutils", "sha256sum": "coreutils", "tar": "archive", "gzip": "archive",
    "gunzip": "archive", "uncompress": "archive", "tee": "coreutils", "sleep": "coreutils",
    "test": "shell builtin", "expr": "coreutils", "seq": "coreutils", "stat": "coreutils",
    "curl": "http", "wget": "http", "openssl": "crypto", "jq": "json",
    # added after validating against rdkcentral/utopia
    "chronyc": "time (chrony)", "ntpq": "time (ntp)", "arping": "net", "dmesg": "kernel log",
    "hostapd": "WiFi AP daemon", "eapd": "Broadcom WiFi daemon", "nas": "Broadcom WiFi auth",
    "wps_monitor": "Broadcom WPS", "ssh-keygen": "ssh", "scp": "ssh", "chattr": "e2fsprogs",
    "lsattr": "e2fsprogs", "chgrp": "coreutils", "cmp": "diffutils", "uname": "coreutils",
    "which": "debianutils", "hexdump": "util-linux", "fuser": "psmisc", "klogd": "busybox",
    "syslogd": "busybox", "ti_syslogd": "TI syslog", "lxc-ls": "LXC containers",
    "latticecli": "Lattice FPGA vendor CLI", "arris_rpc_client": "ARM<->ATOM RPC (vendor)",
    "rpcserver": "ARM<->ATOM RPC server", "ncpu_exec": "Puma7 cross-CPU exec",
    "configparammod": "vendor config tool", "cryptpw": "busybox password hash",
    "chpasswd": "shadow", "ez-ipupdate": "DDNS client", "igmp_snooper": "mcast vendor",
    "tinyftp": "ftp server", "wecb_master": "WECB (MoCA extender) daemon", "xhs": "xfinity home security",
    "syseventd": "sysevent daemon", "syseventd_proxy": "sysevent proxy", "pptp": "ppp",
    "conntrack_flush": "vendor conntrack helper", "expect_flush": "vendor conntrack helper",
    "cosa_start.sh": "CCSP stack launcher", "deviceinfo.sh": "RDK device info helper",
    "git": "dev tool", "lcov": "dev tool", "autoreconf": "dev tool", "wmon": "ppp monitor",
}

SHELL_KEYWORDS = {
    "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case",
    "esac", "in", "function", "return", "exit", "break", "continue", "local", "export",
    "readonly", "set", "unset", "shift", "source", ".", "true", "false", "let", "read",
    "wait", "trap", "exec", "cd", "pwd", "type", "command", "alias", "declare", "typeset",
    "getopts", "umask", "ulimit", "[", "[[", "test", "echo", "printf", "eval", "local",
    "time", "times", "hash", "builtin", "select", "{", "}", "(", ")", ";;", "!",
}

CMD_SPAWN_RX = re.compile(
    # NB: v_secure_popen() takes the MODE FIRST: v_secure_popen("r", "cmd %s", arg)
    r"\b(?:(?:v_secure_system|system|popen)\s*\(|v_secure_popen\s*\(\s*\"[rw]\"\s*,)\s*\"((?:\\.|[^\"\\])*)\"")
DEFINE_STR_RX = re.compile(r'^\s*#\s*define\s+([A-Z][A-Z0-9_]+)\s+"([^"]*)"', re.M)
EXEC_RX = re.compile(r"\bexec[lv]p?e?\s*\(\s*\"([^\"]+)\"")
SH_CMD_RX = re.compile(r"(?:^|;|&&|\|\||\||`|\$\((?!\()|\bthen\b|\bdo\b|\belse\b|!)\s*"
                       r"([A-Za-z0-9_./\-]+)(?![A-Za-z0-9_./\-]*[=)])")
SH_FUNC_DEF_RX = re.compile(r"^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_\-]*)\s*\(\s*\)", re.M)
SH_VAR_RX = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def first_command_tokens(cmd: str) -> list[str]:
    """Return the program names in a shell command string (handles ; && || | ())."""
    out = []
    cmd = re.sub(r"'[^']*'", "''", cmd)
    for seg in re.split(r"\|\||&&|[;|&`]|\$\(|\(|\)", cmd):
        seg = seg.strip()
        if not seg:
            continue
        toks = seg.split()
        while toks and SH_VAR_RX.match(toks[0]):
            toks.pop(0)
        if not toks:
            continue
        t = toks[0].strip("\"'")
        if not t or t.startswith(("%", "$", "-", ">", "<", "\\", "/dev/null")) or t.isdigit():
            continue
        out.append(os.path.basename(t))
    return out


# --------------------------------------------------------------------------
# Scan
# --------------------------------------------------------------------------

def strip_c_comments(text: str) -> str:
    def repl(m):
        s = m.group(0)
        return s if s.startswith(('"', "'")) else re.sub(r"[^\n]", " ", s)
    return re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                  repl, text, flags=re.S)


def strip_sh_comments(text: str) -> str:
    return re.sub(r"(?m)^\s*#(?!!).*$", "", text)


def line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def scan(root: str, wanted_cats: set[str] | None):
    findings = defaultdict(lambda: defaultdict(list))   # cat -> key -> [loc]
    unclassified = defaultdict(lambda: defaultdict(list))
    stats = defaultdict(int)
    defined_funcs: set[str] = set()
    sh_files = []
    c_defines: dict[str, str] = {}
    local_names = set()
    for dp, dn, fns in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP_DIRS]
        local_names.update(fns)
        local_names.update(os.path.splitext(f)[0] for f in fns)
        local_names.update(dn)

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            kind = file_kind(path)
            if not kind:
                continue
            stats[kind] += 1
            try:
                with open(path, "r", errors="replace") as fh:
                    raw = fh.read()
            except OSError:
                continue
            rel = os.path.relpath(path, root)
            text = strip_c_comments(raw) if kind == "c" else \
                strip_sh_comments(raw) if kind in ("sh", "build", "yocto") else raw

            for r in R:
                if kind not in r.kinds:
                    continue
                if wanted_cats and r.category not in wanted_cats:
                    continue
                for m in r.rx.finditer(text):
                    key = m.group(r.capture) if r.capture else m.group(0)
                    key = (key or "").strip()
                    if not key:
                        continue
                    findings[(r.category, r.name)][key].append(f"{rel}:{line_of(text, m.start())}")

            # command extraction: C spawns
            if kind == "c":
                for m in DEFINE_STR_RX.finditer(raw):
                    c_defines.setdefault(m.group(1), m.group(2))
                for m in CMD_SPAWN_RX.finditer(text):
                    for tok in first_command_tokens(m.group(1)):
                        loc = f"{rel}:{line_of(text, m.start())}"
                        if tok in local_names:
                            findings[(EXT, "spawned command (in-repo script/binary)")][tok].append(loc)
                            continue
                        bucket = findings[(EXT, "spawned command")] if tok in KNOWN_COMMANDS \
                            else unclassified["spawned command"]
                        bucket[tok].append(loc)
                for m in EXEC_RX.finditer(text):
                    findings[(EXT, "exec'd program")][m.group(1)].append(
                        f"{rel}:{line_of(text, m.start())}")
            if kind == "sh":
                sh_files.append((rel, text))
                defined_funcs.update(SH_FUNC_DEF_RX.findall(text))

    # resolve "key via macro" findings against #define NAME "literal" in the tree
    for (cat, name), keys in list(findings.items()):
        if "via macro" not in name:
            continue
        resolved = {}
        for k, locs in keys.items():
            v = c_defines.get(k)
            resolved[f'{k} => "{v}"' if v is not None else f"{k} (unresolved: defined outside tree?)"] = locs
        findings[(cat, name)] = resolved

    # shell commands need the global function table to filter local helpers
    for rel, text in sh_files:
        for ln_no, line in enumerate(text.split("\n"), 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            line = re.sub(r"'[^']*'", "''", line)
            line = re.sub(r"\$\(\([^)]*\)\)", "", line)
            for m in SH_CMD_RX.finditer(line):
                tok = os.path.basename(m.group(1))
                if (tok in SHELL_KEYWORDS or tok in defined_funcs or tok.isdigit()
                        or SH_VAR_RX.match(tok + "=") and tok.isupper() and tok not in KNOWN_COMMANDS):
                    continue
                if not re.match(r"^[a-z][A-Za-z0-9_.\-]*$", tok):
                    continue
                loc = f"{rel}:{ln_no}"
                if tok in local_names:
                    findings[(EXT, "shell command (in-repo script/binary)")][tok].append(loc)
                elif tok in KNOWN_COMMANDS:
                    findings[(EXT, "shell command")][tok].append(loc)
                else:
                    unclassified["shell command"][tok].append(loc)

    # unclassified: libraries / headers that no domain rule explains
    known_libs = {"pthread", "rt", "m", "dl", "c", "z", "gcov", "gtest", "gmock", "stdc++"}
    lib_hits = findings.get((BUILD, "link library (-l)"), {})
    for lib, locs in lib_hits.items():
        if lib not in known_libs and lib not in LIB_CATALOG:
            unclassified["link library"][lib] = locs
    return findings, unclassified, stats


LIB_CATALOG = {
    "sysevent": "sysevent client", "syscfg": "syscfg", "ulog": "utopia log",
    "utctx": "utopia context (syscfg+sysevent)", "utapi": "utopia API",
    "srvmgr": "utopia service manager", "secure_wrapper": "v_secure_system/popen",
    "telemetry_msgsender": "Telemetry 2.0", "ccsp_common": "CCSP base / message bus / PSM",
    "rbus": "rbus", "rbuscore": "rbus core", "rtMessage": "rbus legacy",
    "dbus-1": "D-Bus", "cjson": "cJSON", "msgpackc": "msgpack", "msgpack": "msgpack",
    "trower-base64": "base64 (webconfig)", "webconfig_framework": "WebConfig",
    "rdkloggers": "RDK logger", "log4c": "RDK logger backend", "rdkconfig": "RDK config",
    "hal_platform": "platform HAL", "hal_wifi": "WiFi HAL", "hal_moca": "MoCA HAL",
    "hal_ethsw": "ethernet switch HAL", "hal_cm": "cable modem HAL",
    "nfnetlink": "netfilter netlink", "netfilter_queue": "NFQUEUE", "mnl": "libmnl",
    "nl-3": "libnl", "nl-route-3": "libnl", "nl-genl-3": "libnl", "ip4tc": "iptables lib",
    "ip6tc": "iptables lib", "nftnl": "nftables lib", "net": "libnet (packet crafting)",
    "upnp": "libupnp", "ixml": "libupnp XML", "threadutil": "libupnp threads",
    "nanomsg": "nanomsg IPC", "event": "libevent", "event_core": "libevent",
    "event_extra": "libevent", "curl": "libcurl", "ssl": "OpenSSL", "crypto": "OpenSSL",
    "safec": "safe C lib", "safec-3.5.1": "safe C lib", "rdkb_feature_mode_gate": "device-mode gate",
    "devicemode": "device-mode", "onestack_init": "OneStack init", "parodus": "WebPA",
    "libparodus": "WebPA", "wrp-c": "WebPA", "cimplog": "WebPA logging",
    "breakpadwrapper": "crash dumps", "systemd": "systemd", "protobuf-c": "protobuf",
    "mosquitto": "MQTT", "tirpc": "Sun RPC (libtirpc)", "paho-mqtt3as": "MQTT", "yaml": "YAML", "jansson": "JSON",
    "json-c": "JSON", "xml2": "libxml2", "uuid": "libuuid", "glib-2.0": "GLib",
}


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def render_md(findings, unclassified, stats, max_ev, show_uncl):
    out = ["# RDK dependency scan", ""]
    out.append("Files scanned: " + ", ".join(f"{k}={v}" for k, v in sorted(stats.items())))
    out.append("")
    by_cat = defaultdict(list)
    for (cat, name), keys in findings.items():
        by_cat[cat].append((name, keys))
    for cat in sorted(by_cat):
        out.append(f"## {cat}")
        for name, keys in sorted(by_cat[cat]):
            total = sum(len(v) for v in keys.values())
            out.append(f"### {name}  ({len(keys)} distinct, {total} hits)")
            for key, locs in sorted(keys.items(), key=lambda kv: (-len(kv[1]), kv[0])):
                ev = ", ".join(locs[:max_ev]) + (" ..." if len(locs) > max_ev else "")
                note = KNOWN_COMMANDS.get(key) or LIB_CATALOG.get(key) if name in (
                    "spawned command", "shell command", "link library (-l)") else None
                out.append(f"- `{key}` x{len(locs)}" + (f" [{note}]" if note else "") + f" — {ev}")
            out.append("")
    if show_uncl:
        out.append("## UNCLASSIFIED (review and classify by hand)")
        if not any(unclassified.values()):
            out.append("_none_")
        for name, keys in sorted(unclassified.items()):
            out.append(f"### {name}  ({len(keys)} distinct)")
            for key, locs in sorted(keys.items(), key=lambda kv: (-len(kv[1]), kv[0])):
                out.append(f"- `{key}` x{len(locs)} — {', '.join(locs[:max_ev])}")
            out.append("")
    return "\n".join(out)


def render_json(findings, unclassified, stats):
    res = {"stats": stats, "findings": {}, "unclassified": unclassified}
    for (cat, name), keys in findings.items():
        res["findings"].setdefault(cat, {})[name] = keys
    return json.dumps(res, indent=1, default=dict)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path")
    ap.add_argument("--format", choices=("md", "json"), default="md")
    ap.add_argument("--category", action="append",
                    help="limit to category: ipc, filesystem, external_process, "
                         "data_model_cloud, build, runtime_orchestration")
    ap.add_argument("--max-evidence", type=int, default=3)
    ap.add_argument("--no-unclassified", action="store_true")
    a = ap.parse_args(argv)
    if not os.path.isdir(a.path):
        ap.error(f"not a directory: {a.path}")
    findings, uncl, stats = scan(a.path, set(a.category) if a.category else None)
    if a.format == "json":
        print(render_json(findings, uncl, stats))
    else:
        print(render_md(findings, uncl, stats, a.max_evidence, not a.no_unclassified))


if __name__ == "__main__":
    sys.exit(main())
