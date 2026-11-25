/*
 * Copyright 2026 Kartik Gohil
 * SPDX-License-Identifier: Apache-2.0
 */
#include <rbus/rbus.h>
#include <msgpack.h>
#include <dbus/dbus.h>
#include <mosquitto.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <dlfcn.h>
#include "webconfig_framework.h"
#include "secure_wrapper.h"
#include "wifi_hal.h"
#include "platform_hal.h"
#include <telemetry_busmessage_sender.h>

#define BLOB_SUBDOC "portforwarding"

static rbusHandle_t h;

static void on_blob(void *data, size_t len)
{
    msgpack_unpacked u;
    msgpack_unpacked_init(&u);
    msgpack_unpack_next(&u, data, len, NULL);
    register_sub_docs(NULL, 1, NULL, NULL);
}

int main(void)
{
    rbus_open(&h, "sample-agent");
    rbusValue_t v;
    int enabled = 0;
    char partner[64] = {0};
    rbus_get(h, "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.Sample.Enable", &v);
    rbusEvent_Subscribe(h, "Device.WiFi.SSID.1.Status", NULL, NULL, 0);

    DBusConnection *c = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
    (void)c;

    struct mosquitto *m = mosquitto_new("agent", true, NULL);
    mosquitto_connect(m, "broker", 1883, 60);
    mosquitto_publish(m, NULL, "x/usp/controller", 0, "", 0, false);

    (void)wifi_getRadioEnable(0, &enabled);
    (void)platform_hal_getFactoryPartnerId(partner, sizeof(partner));

    int s = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    (void)s; (void)RTM_GETLINK;

    void *hal = dlopen("libhal_vendor.so", RTLD_NOW);
    (void)hal;

    FILE *fp = v_secure_popen("r", "cat /proc/net/arp | grep br0");
    v_secure_pclose(fp);
    v_secure_system("systemctl restart CcspLMLite.service");
    t2_event_d("SYS_INFO_SampleStarted", 1);
    return 0;
}
