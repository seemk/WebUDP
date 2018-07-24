#pragma once
#include <stdint.h>
#include "Wu.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct WuHost WuHost;

int32_t WuHostCreate(const char* hostAddr, const char* port, int32_t maxClients,
                     WuHost** host);
void WuHostDestroy(WuHost* host);
int32_t WuHostServe(WuHost* host, WuEvent* evt);
void WuHostRemoveClient(WuHost* wu, WuClient* client);
int32_t WuHostSendText(WuHost* host, WuClient* client, const char* text,
                       int32_t length);
int32_t WuHostSendBinary(WuHost* host, WuClient* client, const uint8_t* data,
                         int32_t length);
void WuHostSetErrorCallback(WuHost* host, WuErrorFn callback);
#ifdef __cplusplus
}
#endif
