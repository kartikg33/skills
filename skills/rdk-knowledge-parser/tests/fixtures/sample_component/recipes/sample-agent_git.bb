# Copyright 2026 Kartik Gohil
# SPDX-License-Identifier: Apache-2.0

SUMMARY = "sample agent"
LICENSE = "Apache-2.0"
DEPENDS = "rbus msgpack-c dbus mosquitto webconfig-framework utopia telemetry"
DEPENDS:append = " ${@bb.utils.contains('DISTRO_FEATURES', 'usppa', 'obuspa', '', d)}"
RDEPENDS:${PN} += "bash rbus"
inherit cmake pkgconfig systemd
SYSTEMD_SERVICE:${PN} = "sample-agent.service"
CFLAGS:append = " -DFEATURE_SAMPLE -lrt"
