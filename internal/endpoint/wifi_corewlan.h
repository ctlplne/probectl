// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

#ifndef PROBECTL_WIFI_COREWLAN_H
#define PROBECTL_WIFI_COREWLAN_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    bool present;
    bool associated;
    uint8_t band;
    uint64_t channel;
    int64_t rssi;
    int64_t noise;
    double rate;
    char ssid[129];
    char bssid[18];
} probectl_wifi_link;

void probectl_read_wifi_link(bool collect_ssid, bool collect_bssid, probectl_wifi_link *link);

#endif
