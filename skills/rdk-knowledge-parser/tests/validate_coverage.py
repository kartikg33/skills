#!/usr/bin/env python3
"""
validate_coverage.py - prove rdk_dep_scan.py captures every dependency signal
in a source tree.

Independently of the scanner's rule catalog, this script uses broad, dumb
greps to find every *call site* of each dependency mechanism. It then checks
that every call site appears as evidence in at least one scanner finding (or
in the UNCLASSIFIED section, which counts as "surfaced for review").

Any call site the scanner missed is printed. Exit code 1 when coverage of
any check is below --threshold (default 100%).

Usage: validate_coverage.py <src_dir> [--threshold 100] [--verbose]
"""

import argparse
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER = os.path.join(HERE, "..", "scripts", "rdk_dep_scan.py")

# (check name, file kinds, broad call-site regex, scanner finding-name prefixes that may cover it)
CHECKS = [
    ("sysevent C calls", "c", r"\bsysevent_(get|set)\w*\s*\(", ["sysevent"]),
    ("syscfg C calls", "c", r"\bsyscfg_(get|set)\w*\s*\(", ["syscfg"]),
    ("PSM calls", "c", r"\bPSM_(VALUE_|Get_|Set_|Del_)\w*\s*\(|\bPsmGetNextLevelInstances\s*\(", ["PSM"]),
    ("CCSP bus calls", "c", r"\b(CCSP_Message_Bus_\w+|CcspBaseIf_\w+)\s*\(", ["CCSP message bus"]),
    ("v_secure_system/system/popen", "c",
     r"\b(v_secure_system|v_secure_popen|system|popen)\s*\(\s*\"", ["spawned command", "process spawn API"]),
    ("exec*/fork", "c", r"\b(exec[lv]p?e?|fork|vfork)\s*\(", ["process spawn API", "exec'd program"]),
    ("ioctl", "c", r"\bioctl\s*\(", ["ioctl"]),
    ("netlink", "c", r"\bAF_NETLINK\b|\bNETLINK_\w+", ["netlink"]),
    ("telemetry T2", "c", r"\bt2_event_[sdf]\s*\(", ["Telemetry"]),
    ("RDK_LOG / CcspTrace", "c", r"\b(RDK_LOG|CcspTrace\w+)\s*\(", ["RDK logger"]),
    ("syslog", "c", r"\b(syslog|openlog)\s*\(", ["syslog"]),
    ("cJSON", "c", r"\bcJSON_\w+\s*\(", ["cJSON"]),
    ("msgpack", "c", r"\bmsgpack_\w+\s*\(", ["MessagePack"]),
    ("rbus", "c", r"\brbus\w*_\w+\s*\(", ["rbus"]),
    ("dbus", "c", r"\bdbus_\w+\s*\(", ["D-Bus"]),
    ("fopen", "c", r"\bfopen\s*\(", ["file ", "path", "config file", "log file", "procfs"]),
    ("getenv", "c", r"\bgetenv\s*\(\s*\"", ["environment variable"]),
    ("dlopen", "c", r"\bdlopen\s*\(", ["dlopen"]),
    ("#include", "c", r"^\s*#\s*include\b", ["header include"]),
    ("sh: sysevent CLI", "sh", r"\bsysevent\s+(get|set|setunique|async|setoptions)\b", ["sysevent", "shell command"]),
    ("sh: syscfg CLI", "sh", r"\bsyscfg\s+(get|set|unset|commit)\b", ["syscfg", "shell command"]),
    ("sh: psmcli/dmcli", "sh", r"\b(psmcli|dmcli)\b", ["PSM", "CCSP", "shell command"]),
    ("sh: systemctl", "sh", r"\bsystemctl\s+\w", ["systemctl", "shell command"]),
    ("sh: source", "sh", r"^\s*(source|\.)\s+/", ["sourced shell library"]),
    ("build: -l libs", "build", r"(?<![\w])-l[A-Za-z0-9_]", ["link library"]),
    ("build: PKG_CHECK_MODULES", "build", r"PKG_CHECK_MODULES", ["pkg-config"]),
    ("build: AC_ARG_ENABLE/WITH", "build", r"\bAC_ARG_(ENABLE|WITH)\b", ["autoconf feature"]),
    ("build: AM_CONDITIONAL", "build", r"\bAM_CONDITIONAL\b", ["automake conditional"]),
    ("yocto: DEPENDS/RDEPENDS", "yocto", r"^\s*R?DEPENDS", ["Yocto"]),
]

sys.path.insert(0, os.path.join(HERE, "..", "scripts"))
from rdk_dep_scan import file_kind, strip_c_comments, strip_sh_comments  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--threshold", type=float, default=100.0)
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()

    out = subprocess.run([sys.executable, SCANNER, a.path, "--format", "json", "--max-evidence", "100000"],
                         check=True, capture_output=True, text=True).stdout
    data = json.loads(out)

    # location -> set of finding names
    covered = {}
    for cat, names in data["findings"].items():
        for name, keys in names.items():
            for locs in keys.values():
                for loc in locs:
                    covered.setdefault(loc, set()).add(name)
    for name, keys in data["unclassified"].items():
        for locs in keys.values():
            for loc in locs:
                covered.setdefault(loc, set()).add("UNCLASSIFIED " + name)

    results, failed = [], False
    for check, kind, pat, prefixes in CHECKS:
        rx = re.compile(pat, re.M)
        sites, missed = 0, []
        for dp, dn, fns in os.walk(a.path):
            dn[:] = [d for d in dn if d not in {".git"}]
            for fn in fns:
                p = os.path.join(dp, fn)
                if file_kind(p) != kind:
                    continue
                raw = open(p, errors="replace").read()
                text = strip_c_comments(raw) if kind == "c" else strip_sh_comments(raw)
                if kind == "c":  # call sites inside string literals (log messages) are not calls
                    text = re.sub(r'"(?:\\.|[^"\\\n])*"', lambda m: '"' + " " * (len(m.group(0)) - 2) + '"', text)
                rel = os.path.relpath(p, a.path)
                for m in rx.finditer(text):
                    ln = text.count("\n", 0, m.start()) + 1
                    sites += 1
                    names = covered.get(f"{rel}:{ln}", set())
                    if not any(n.startswith(px) or px in n for n in names for px in prefixes):
                        missed.append(f"{rel}:{ln}")
        pct = 100.0 if sites == 0 else 100.0 * (sites - len(missed)) / sites
        failed |= pct < a.threshold
        results.append((check, sites, len(missed), pct, missed))

    w = max(len(r[0]) for r in results)
    print(f"{'check'.ljust(w)}  sites  missed  coverage")
    for check, sites, nmiss, pct, missed in results:
        print(f"{check.ljust(w)}  {sites:5d}  {nmiss:6d}  {pct:7.1f}%")
        if missed and (a.verbose or pct < a.threshold):
            for m in missed[:10]:
                print(f"    missed: {m}")
            if len(missed) > 10:
                print(f"    ... {len(missed) - 10} more")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
