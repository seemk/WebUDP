#pragma once
#include <stdint.h>

struct Wu;
struct WuConf;
struct WuEvent;
struct WuClient;
struct WuHost;

WuHost* WuHostCreate(const WuConf* conf);
void WuHostSetNonblocking(WuHost* host, int32_t nonblocking);
int32_t WuHostServe(WuHost* host, WuEvent* evt);
void WuHostRemoveClient(WuHost* wu, WuClient* client);
int32_t WuHostSendText(WuHost* host, WuClient* client, const char* text,
                       int32_t length);
int32_t WuHostSendBinary(WuHost* host, WuClient* client, const uint8_t* data,
                         int32_t length);
