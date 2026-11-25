#!/usr/bin/env python3
# Copyright 2026 Kartik Gohil
# SPDX-License-Identifier: Apache-2.0
"""Evidence-level dependency extractor for RDK C sources.

Complements rdk_dep_scan.py (full-tree inventory) with call-level detail:
  * direction per call (read/write/subscribe/publish/exec/call/...)
  * the compile-time gate (#if stack) and enclosing function at each call
  * key resolution: literal, macro, templated, variable or unresolved
  * HAL module/function, API endpoint, netfilter rule template and injected values
  * evidence in the form <repo>/<path>:<line> (add --repo for the prefix)

Output: JSON list of evidence records on stdout.

Usage:
  c_extract.py --root <repo_root> --file <rel/path.c> [--macros <rel/hdr.h> ...] [--repo <name>]
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

# --------------------------------------------------------------------------- #
# Source preprocessing
# --------------------------------------------------------------------------- #


def strip_comments(text):
    """Blank out comments, keep strings and newlines so line numbers survive."""
    out = []
    i, n = 0, len(text)
    state = None  # None | 'str' | 'chr' | 'line' | 'block'
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state is None:
            if c == "/" and nxt == "/":
                state = "line"
                out.append("  ")
                i += 2
                continue
            if c == "/" and nxt == "*":
                state = "block"
                out.append("  ")
                i += 2
                continue
            if c == '"':
                state = "str"
            elif c == "'":
                state = "chr"
            out.append(c)
        elif state in ("str", "chr"):
            out.append(c)
            if c == "\\":
                out.append(nxt)
                i += 2
                continue
            if (state == "str" and c == '"') or (state == "chr" and c == "'") or c == "\n":
                state = None
        elif state == "line":
            if c == "\n":
                state = None
                out.append(c)
            else:
                out.append(" ")
        elif state == "block":
            if c == "*" and nxt == "/":
                state = None
                out.append("  ")
                i += 2
                continue
            out.append("\n" if c == "\n" else " ")
        i += 1
    return "".join(out)


DEFINE_RE = re.compile(r'^\s*#\s*define\s+(\w+)\s+((?:\w+|"(?:[^"\\]|\\.)*")(?:\s*(?:\w+|"(?:[^"\\]|\\.)*"))*)\s*$')


def load_macros(paths):
    """Collect `#define NAME "literal"` (and literal/macro concatenations)."""
    raw = {}
    for p in paths:
        for line in strip_comments(Path(p).read_text(errors="replace")).splitlines():
            m = DEFINE_RE.match(line)
            if m and '"' in m.group(2):
                raw.setdefault(m.group(1), m.group(2))
    resolved = {}
    for name in raw:
        val = concat_tokens(raw[name], raw, depth=0)
        if val is not None:
            resolved[name] = val
    return resolved


TOKEN_RE = re.compile(r'"((?:[^"\\]|\\.)*)"|(\w+)')


def concat_tokens(expr, macros, depth):
    """Resolve `A "lit" B` where A/B are macros (raw or resolved)."""
    if depth > 5:
        return None
    parts = []
    pos = 0
    expr = expr.strip()
    while pos < len(expr):
        m = TOKEN_RE.match(expr, pos)
        if not m:
            if expr[pos].isspace():
                pos += 1
                continue
            return None
        if m.group(1) is not None:
            parts.append(m.group(1))
        else:
            v = macros.get(m.group(2))
            if v is None:
                return None
            if v.startswith('"') or " " in v or '"' in v:
                v = concat_tokens(v, macros, depth + 1)
                if v is None:
                    return None
            parts.append(v)
        pos = m.end()
    return "".join(parts) if parts else None


# --------------------------------------------------------------------------- #
# Call extraction helpers
# --------------------------------------------------------------------------- #


def split_args(s):
    """Split a C argument list on top-level commas."""
    args, depth, cur, q = [], 0, [], None
    i = 0
    while i < len(s):
        c = s[i]
        if q:
            cur.append(c)
            if c == "\\" and i + 1 < len(s):
                cur.append(s[i + 1])
                i += 2
                continue
            if c == q:
                q = None
        elif c in "\"'":
            q = c
            cur.append(c)
        elif c in "([{":
            depth += 1
            cur.append(c)
        elif c in ")]}":
            depth -= 1
            cur.append(c)
        elif c == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    if cur or args:
        args.append("".join(cur).strip())
    return args


def call_args(lines, idx, start_col):
    """Return argument string of the call whose '(' is at/after start_col."""
    buf = lines[idx][start_col:]
    j = idx
    while buf.count("(") > buf.count(")") and j < idx + 8 and j + 1 < len(lines):
        j += 1
        buf += " " + lines[j].strip()
    o = buf.find("(")
    if o < 0:
        return None
    depth, q = 0, None
    for k in range(o, len(buf)):
        c = buf[k]
        if q:
            if c == "\\":
                continue
            if c == q and buf[k - 1] != "\\":
                q = None
            continue
        if c in "\"'":
            q = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return buf[o + 1:k]
    return buf[o + 1:]


CAST_RE = re.compile(r"^\(\s*(?:const\s+)?(?:unsigned\s+)?char\s*\*\s*\)\s*")


def resolve(arg, macros, lines, idx):
    """Resolve an argument to (value, resolution, via)."""
    if arg is None:
        return None, "missing", None
    a = CAST_RE.sub("", arg.strip())
    if a in ("NULL", "0"):
        return None, "null", None
    lit = concat_tokens(a, macros, 0)
    if lit is not None:
        if re.fullmatch(r'(?:\s*"(?:[^"\\]|\\.)*")+\s*', a):
            return lit, "literal", None
        return lit, "macro", a
    if re.fullmatch(r"\w+", a):
        tpl = trace_variable(a, macros, lines, idx)
        if tpl:
            return tpl[0], tpl[1], a
        return None, "unresolved", a
    return None, "expression", a


SPEC_RE = re.compile(r"%[-+ #0]*\d*(?:\.\d+)?(?:hh|h|ll|l|z)?[sdiuxXcp]")


def substitute_args(fmt, args, macros):
    """Replace %s specifiers whose argument is a known literal/macro."""
    out, pos, ai = [], 0, 0
    for m in SPEC_RE.finditer(fmt):
        out.append(fmt[pos:m.start()])
        spec = m.group(0)
        lit = concat_tokens(args[ai], macros, 0) if ai < len(args) and spec.endswith("s") else None
        out.append(lit if lit is not None else spec)
        pos = m.end()
        ai += 1
    out.append(fmt[pos:])
    return "".join(out)


def trace_variable(var, macros, lines, idx, window=120):
    """Look back for snprintf/sprintf/strcpy into `var`; return (value, kind)."""
    pat = re.compile(r"\b(snprintf_s|snprintf|sprintf_s|sprintf|strcpy_s|strncpy|strcpy|strcat)\s*\(\s*\(?\s*(?:char\s*\*\s*\))?\s*" + re.escape(var) + r"\b")
    decl = re.compile(r"(?:\bchar\s*\*\s*|\bchar\s+|^\s*)" + re.escape(var) + r"\s*(?:\[\w*\])?\s*=\s*([^=].*?);")
    for j in range(idx, max(-1, idx - window), -1):
        line = lines[j]
        m = pat.search(line)
        if m:
            args = split_args(call_args(lines, j, m.start()) or "")
            fn = m.group(1)
            if fn in ("snprintf", "snprintf_s", "sprintf_s") and len(args) >= 3:
                fmt = concat_tokens(args[2], macros, 0)
            elif fn == "sprintf" and len(args) >= 2:
                fmt = concat_tokens(args[1], macros, 0)
            elif fn in ("strcpy", "strncpy", "strcpy_s") and len(args) >= 2:
                fmt = concat_tokens(args[-1] if fn == "strcpy_s" else args[1], macros, 0)
            else:
                fmt = None
            if fmt is not None:
                if "%" in fmt and fn in ("snprintf", "snprintf_s", "sprintf_s", "sprintf"):
                    fmt = substitute_args(fmt, args[3:] if fn != "sprintf" else args[2:], macros)
                return fmt, ("templated" if "%" in fmt else "variable-literal")
            return None
        d = decl.search(line)
        if d:
            v = concat_tokens(d.group(1), macros, 0)
            if v is not None:
                return v, "variable-literal"
            return None
        if re.match(r"^\S.*\)\s*$", line) and j < idx and re.match(r"^\{", lines[j + 1] if j + 1 < len(lines) else ""):
            break  # reached function header
    return None


# --------------------------------------------------------------------------- #
# Rules: (regex on call name, kind, direction, index of key argument)
# --------------------------------------------------------------------------- #

# Hints only: the real owner/install path is proven from the recipe's do_install
# and FILES:<PN>. Never treat a hint as evidence.
UTILITY_PATHS = {
    "sysevent": ("/sbin/sysevent", "utopia"), "syscfg": ("/sbin/syscfg", "utopia"),
    "psmcli": ("/usr/bin/psmcli", "ccsp"), "dmcli": ("/usr/bin/dmcli", "ccsp"),
    "rbuscli": ("/usr/bin/rbuscli", "rbus"), "iptables": ("/usr/sbin/iptables", "iptables"),
    "iptables-restore": ("/usr/sbin/iptables-restore", "iptables"),
    "ip6tables": ("/usr/sbin/ip6tables", "iptables"), "nft": ("/usr/sbin/nft", "nftables"),
    "ip": ("/sbin/ip", "iproute2"), "ifconfig": ("/sbin/ifconfig", "net-tools"),
    "systemctl": ("/bin/systemctl", "systemd"), "cat": ("/bin/cat", "busybox"),
    "grep": ("/bin/grep", "busybox"), "sh": ("/bin/sh", "busybox"),
}
HAL_MODULES = {
    "wifi_": "wifi", "platform_hal_": "platform", "moca_hal_": "moca",
    "cm_hal_": "cm", "ethsw_hal_": "ethsw", "dhcpv4c_": "dhcpv4c",
    "mta_hal_": "mta", "CcspHal": "ethsw", "wifiHal": "wifi", "mocaHal": "moca",
    "PAL_": "platform", "pal_": "platform",
}
HAL_PREFIXES = tuple(HAL_MODULES)

CALL_RULES = [
    (r"sysevent_get_unique", "sysevent", "read", 2),
    (r"sysevent_get", "sysevent", "read", 2),
    (r"sysevent_set_options", "sysevent", "write-options", 2),
    (r"sysevent_setnotification", "sysevent", "subscribe", 2),
    (r"sysevent_setcallback", "sysevent", "subscribe", 2),
    (r"sysevent_unset", "sysevent", "write", 2),
    (r"sysevent_set", "sysevent", "write", 2),
    (r"syscfg_get", "syscfg", "read", 1),
    (r"syscfg_set_u_commit|syscfg_set_commit|syscfg_set_u|syscfg_set", "syscfg", "write", 1),
    (r"syscfg_unset", "syscfg", "write", 1),
    (r"PSM_VALUE_GET_STRING", "psm", "read", 0),
    (r"PSM_VALUE_GET_INS", "psm", "read-instances", 0),
    (r"PSM_VALUE_SET_STRING", "psm", "write", 0),
    (r"PSM_Get_Record_Value2", "psm", "read", 2),
    (r"PSM_Set_Record_Value2", "psm", "write", 2),
    (r"PsmGetNextLevelInstances", "psm", "read-instances", 2),
    (r"psmGet", "psm", "read", 1),
    (r"RdkBus_GetParamValues", "tr181", "read", 2),
    (r"v_secure_system", "exec", "exec", 0),
    (r"v_secure_popen", "exec", "exec-read", 1),
    (r"popen", "exec", "exec-read", 0),
    (r"system", "exec", "exec", 0),
    (r"fopen", "file", "open", 0),
    (r"unlink|remove", "file", "delete", 0),
    (r"access", "file", "probe", 0),
    (r"opendir", "file", "read-dir", 0),
    (r"mkdir", "file", "create-dir", 0),
    (r"shm_open", "shm", "open", 0),
    (r"t2_event_s|t2_event_d|t2_event_f", "t2", "emit", 0),
    (r"t2_init", "t2-init", "init", 0),
    (r"ioctl", "ioctl", "call", 1),
    (r"isFeatureSupportedInCurrentMode", "feature-mode", "check", 0),
    (r"CCSP_Message_Bus_Init_Synced|CCSP_Message_Bus_Init", "ccsp-register", "register", 0),
    (r"sysevent_open", "sysevent-register", "register", 3),
    (r"CcspBaseIf_getParameterValues", "tr181", "read", 2),
    (r"CcspBaseIf_setParameterValues", "tr181", "write", 2),
    (r"CcspBaseIf_discComponentSupportingNamespace", "tr181", "discover", 2),
    (r"rbus_get", "rbus", "read", 1),
    (r"rbus_set", "rbus", "write", 1),
    (r"rbusEvent_Subscribe", "api", "subscribe", 1),
    (r"rbusEvent_Publish", "api", "publish", 1),
    (r"rbusMethod_Invoke", "api", "call", 1),
    (r"mosquitto_publish", "api", "publish", 2),
    (r"mosquitto_subscribe", "api", "subscribe", 2),
    (r"dlopen", "link", "load", 0),
    (r"kill", "signal", "send", 1),
    (r"insmod|modprobe", "kmod", "load", 0),
]

CALL_RE = re.compile(r"(?<![\w.>])(" + "|".join(r[0] for r in CALL_RULES)
                     + r"|(?:" + "|".join(re.escape(p) for p in HAL_MODULES) + r")\w+"
                     + r")\s*\(")
RULE_BY_NAME = []
for pat, kind, direction, ai in CALL_RULES:
    RULE_BY_NAME.append((re.compile(r"^(?:" + pat + r")$"), kind, direction, ai))

NF_RULE_RE = re.compile(r'fprintf\s*\(\s*(\w+)\s*,\s*"(-[A-Z][^"]*)"')
CHAIN_DECL_RE = re.compile(r'fprintf\s*\(\s*(\w+)\s*,\s*"(?::(\w[\w%-]*) - \[0:0\]|:%s - \[0:0\][^"]*"\s*,\s*"(\w[\w%-]*)"|-N (\w[\w%-]*))')
FUNC_RE = re.compile(r"^(?:static\s+|inline\s+|extern\s+)*[A-Za-z_][\w\s\*]*?\b([A-Za-z_]\w*)\s*\([^;]*$")
COND_RE = re.compile(r"^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)$")


def gate_expr(directive, rest):
    rest = rest.strip()
    if directive == "ifdef":
        return f"defined({rest})"
    if directive == "ifndef":
        return f"!defined({rest})"
    return re.sub(r"\s+", " ", rest)


def table_for(fp):
    for t in ("filter", "nat", "mangle", "raw"):
        if t in fp:
            return t
    return "unknown"


def extract(root, rel, macro_files):
    path = Path(root) / rel
    text = strip_comments(path.read_text(errors="replace"))
    lines = text.splitlines()
    macros = load_macros([Path(root) / m for m in macro_files] + [path])

    stack = []  # list of [expr_for_branch, all_prior_exprs, dead]
    func = None
    out = []

    def current_gate():
        return [s[0] for s in stack if s[0]]

    def dead():
        return any(s[2] for s in stack)

    for idx, line in enumerate(lines):
        m = COND_RE.match(line)
        if m:
            d, rest = m.group(1), m.group(2)
            if d in ("if", "ifdef", "ifndef"):
                e = gate_expr(d, rest)
                stack.append([e, [e], e.strip() == "0"])
            elif d == "elif" and stack:
                e = gate_expr("if", rest)
                prior = stack[-1][1]
                neg = " && ".join(f"!({p})" for p in prior)
                stack[-1] = [f"{neg} && ({e})" if neg else e, prior + [e], e.strip() == "0"]
            elif d == "else" and stack:
                prior = stack[-1][1]
                was_dead = stack[-1][2]
                expr = " && ".join(f"!({p})" for p in prior)
                stack[-1] = [expr, prior, False if was_dead else (prior == ["1"])]
            elif d == "endif" and stack:
                stack.pop()
            continue
        if dead():
            continue

        fm = FUNC_RE.match(line)
        is_def = bool(fm and not line.startswith((" ", "\t", "#")) and fm.group(1) not in ("if", "while", "for", "switch", "return"))
        if is_def:
            func = fm.group(1)

        gate = current_gate()
        loc = {"file": rel, "line": idx + 1, "function": func, "gate": gate}
        if line.lstrip().startswith("#"):
            continue

        for cm in CALL_RE.finditer(line):
            name = cm.group(1)
            if is_def and name == func:
                continue  # function definition, not a call
            rule = next((r for r in RULE_BY_NAME if r[0].match(name)), None)
            if rule is None:
                if not name.startswith(HAL_PREFIXES):
                    continue
                kind, direction, ai = "hal", "call", None
            else:
                _, kind, direction, ai = rule
            argstr = call_args(lines, idx, cm.start())
            args = split_args(argstr or "")
            key_arg = args[ai] if ai is not None and len(args) > ai else (name if kind == "hal" else None)
            if kind in ("ioctl", "feature-mode"):
                value, res, via = (key_arg, "literal", None) if key_arg and re.fullmatch(r"[A-Z_][A-Z0-9_]+", key_arg) else (None, "unresolved", key_arg)
            else:
                value, res, via = resolve(key_arg, macros, lines, idx)
            rec = dict(loc, kind=kind, api=name, direction=direction, key=value, resolution=res, via=via)
            if kind == "syscfg" and args:
                ns, nres, nvia = resolve(args[0], macros, lines, idx)
                if nres != "null":
                    rec["namespace"] = ns if ns else f"<{nvia or args[0]}>"
                    rec["namespace_var"] = CAST_RE.sub("", args[0].strip())
                if direction == "read" and len(args) > 2:
                    rec["out_var"] = CAST_RE.sub("", args[2].strip())
            if kind == "file" and name == "fopen" and len(args) > 1:
                rec["mode"] = concat_tokens(args[1], macros, 0)
            if kind == "tr181" and len(args) > 1:
                rec["bus_component"] = resolve(args[0], macros, lines, idx)[0]
                rec["bus_path"] = resolve(args[1], macros, lines, idx)[0]
            if kind == "hal":
                rec["module"] = next((m for p, m in HAL_MODULES.items() if name.startswith(p)), "unknown")
                rec["key"] = name
                rec["resolution"] = "literal"
            if kind in ("exec", "exec-read"):
                exe = first_token(key_arg or "")
                rec["executable"] = exe
                if exe in UTILITY_PATHS:
                    rec["path_hint"], rec["provider_hint"] = UTILITY_PATHS[exe]
            if kind == "sysevent" and direction == "write" and len(args) > 3:
                v, vres, _ = resolve(args[3], macros, lines, idx)
                rec["value"] = v if vres in ("literal", "macro") else None
            rec["unconditional"] = not gate
            out.append(rec)

        for rm in NF_RULE_RE.finditer(line):
            fp, template = rm.group(1), rm.group(2)
            args = split_args(call_args(lines, idx, rm.start()) or "")
            filled = [{"placeholder": ph, "position": i, "argument": args[i + 2].strip() if len(args) > i + 2 else None}
                      for i, ph in enumerate(SPEC_RE.findall(template))]
            out.append(dict(loc, kind="netfilter-rule", api="fprintf", direction="define",
                            key=template, resolution="templated" if filled else "literal",
                            via=fp, family="ipv6" if "_v6" in fp or "_ipv6" in fp else "ipv4",
                            table=next((t for t in ("filter", "nat", "mangle", "raw", "security")
                                        if t in fp), "unknown"), filled_from=filled,
                            unconditional=not gate))

        ch = CHAIN_DECL_RE.search(line)
        if ch:
            chain = ch.group(2) or ch.group(3) or ch.group(4)
            out.append(dict(loc, kind="netfilter-chain", api="fprintf", direction="define",
                            key=chain, table=table_for(ch.group(1)),
                            resolution="templated" if "%" in chain else "literal", via=ch.group(1),
                            unconditional=not gate))
    return out


def first_token(cmd):
    if not cmd:
        return None
    m = re.search(r'"((?:\\.|[^"\\])*)"', cmd)
    if not m:
        return None
    parts = re.split(r"[;&|`\s]+", m.group(1).strip())
    return os.path.basename(parts[0]) if parts else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--file", required=True)
    ap.add_argument("--macros", nargs="*", default=[])
    ap.add_argument("--repo", default="", help="repository prefix for evidence strings")
    a = ap.parse_args()
    records = extract(a.root, a.file, a.macros)
    if a.repo:
        for rec in records:
            rec["evidence"] = f"{a.repo}/{rec['file']}:{rec['line']}"
    json.dump(records, sys.stdout, indent=1)


if __name__ == "__main__":
    main()
