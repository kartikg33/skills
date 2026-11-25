#!/usr/bin/env python3
# Copyright 2026 Kartik Gohil
# SPDX-License-Identifier: Apache-2.0
"""Validate c_extract.py: call-level direction, gates, functions and resolution."""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EXTRACT = os.path.join(HERE, "..", "scripts", "c_extract.py")
FIXTURE = os.path.join(HERE, "fixtures", "sample_component")


def run(root, rel, repo=None):
    cmd = [sys.executable, EXTRACT, "--root", root, "--file", rel]
    if repo:
        cmd += ["--repo", repo]
    return json.loads(subprocess.run(cmd, check=True, capture_output=True, text=True).stdout)


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--utopia", help="optional path to a utopia checkout")
    a = ap.parse_args()

    records = run(FIXTURE, "src/agent.c", "sample")
    check(len(records) >= 8, "fixture extraction returned too few records")
    for r in records:
        for field in ("file", "line", "function", "gate", "unconditional",
                      "kind", "api", "direction", "key", "resolution", "evidence"):
            check(field in r, f"missing {field} in {r}")
        check(r["evidence"] == f"sample/{r['file']}:{r['line']}", "bad evidence")
        check(r["function"] == "main", "bad enclosing function")
    kinds = {r["kind"] for r in records}
    check({"rbus", "api", "hal", "exec", "link"} <= kinds, f"missing kinds: {kinds}")
    check(any(r.get("module") == "wifi" and r["key"] == "wifi_getRadioEnable" for r in records), "HAL wifi not found")
    check(any(r.get("module") == "platform" and r["key"] == "platform_hal_getFactoryPartnerId"
              for r in records), "HAL platform not found")
    check(any(r["api"] == "mosquitto_publish" and r["key"] == "x/usp/controller"
              for r in records), "MQTT topic not found")
    check(any(r["api"] == "rbus_get" and r["direction"] == "read"
              and r["key"].startswith("Device.") for r in records), "rbus read not found")
    check(any(r["api"] == "v_secure_popen" and r.get("path_hint") == "/bin/cat"
              for r in records), "utility path hint not found")
    print(f"fixture: {len(records)} records, fields/evidence/direction OK")

    if a.utopia:
        fw = run(a.utopia, "source/firewall/firewall.c", "utopia")
        check(len(fw) > 1000, "firewall extraction returned too few records")
        dirs = {(r["api"], r["direction"]) for r in fw}
        check(("syscfg_get", "read") in dirs and ("syscfg_set", "write") in dirs, "syscfg direction")
        check(("sysevent_get", "read") in dirs and ("sysevent_set", "write") in dirs, "sysevent direction")
        check(any(r["resolution"] == "templated" and "%d" in (r["key"] or "")
                  and r["kind"] == "psm" for r in fw), "templated PSM key not found")
        check(any("FEATURE_464XLAT" in " ".join(r["gate"]) for r in fw), "compile gate not found")
        check(any(r["kind"] == "netfilter-rule" and r["filled_from"]
                  and r["family"] == "ipv4" and r["table"] == "nat" for r in fw),
              "netfilter rule with injected values not found")
        check(any(r["kind"] == "exec" and r.get("path_hint") for r in fw), "executable path hint not found")
        check(any(r["unconditional"] for r in fw) and any(not r["unconditional"] for r in fw),
              "unconditional flag not varied")
        print(f"utopia firewall.c: {len(fw)} records, gates/directions/templates/rules OK")
    else:
        print("utopia: skipped (pass --utopia)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as e:
        print(f"FAIL: {e}", file=sys.stderr)
        sys.exit(1)
