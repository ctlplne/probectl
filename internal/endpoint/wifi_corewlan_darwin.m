// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build darwin && cgo

#import <CoreWLAN/CoreWLAN.h>
#import <Foundation/Foundation.h>
#include "wifi_corewlan.h"

void probectl_read_wifi_link(bool collect_ssid, bool collect_bssid, probectl_wifi_link *link) {
    @autoreleasepool {
        *link = (probectl_wifi_link){0};
        CWInterface *interface = [[CWWiFiClient sharedWiFiClient] interface];
        if (interface == nil) {
            return;
        }
        link->present = true;
        CWInterfaceMode mode = [interface interfaceMode];
        if (mode != kCWInterfaceModeStation && mode != kCWInterfaceModeIBSS) {
            return;
        }
        link->associated = true;
        link->rssi = [interface rssiValue];
        link->noise = [interface noiseMeasurement];
        link->rate = [interface transmitRate];
        CWChannel *channel = [interface wlanChannel];
        link->channel = [channel channelNumber];
        switch ([channel channelBand]) {
        case kCWChannelBand2GHz:
            link->band = 2;
            break;
        case kCWChannelBand5GHz:
            link->band = 5;
            break;
        case kCWChannelBand6GHz:
            link->band = 6;
            break;
        default:
            break;
        }
        if (collect_ssid && ![[interface ssid] getCString:link->ssid
                                                  maxLength:sizeof(link->ssid)
                                                   encoding:NSUTF8StringEncoding]) {
            link->ssid[0] = '\0';
        }
        if (collect_bssid && ![[interface bssid] getCString:link->bssid
                                                    maxLength:sizeof(link->bssid)
                                                     encoding:NSUTF8StringEncoding]) {
            link->bssid[0] = '\0';
        }
    }
}
