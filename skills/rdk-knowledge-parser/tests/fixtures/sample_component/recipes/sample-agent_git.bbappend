# Copyright 2026 Kartik Gohil
# SPDX-License-Identifier: Apache-2.0

EXTRA_OECMAKE:append = " -DENABLE_MQTT=ON"
RDEPENDS_${PN}_append = " mosquitto"
