#pragma once

#include <stddef.h>
#include <stdint.h>

struct WuClient;
struct WuPool;
struct WuCert;
struct WuArena;
struct WuQueue;
struct ssl_ctx_st;

enum WuEventType {
  WuEvent_BinaryData,
  WuEvent_ClientJoin,
  WuEvent_ClientLeave,
  WuEvent_TextData
};

struct WuEvent {
  WuEventType type;
  WuClient* client;
  const uint8_t* data;
  int32_t length;
};

enum WuSDPStatus {
  WuSDPStatus_Success,
  WuSDPStatus_InvalidSDP,
  WuSDPStatus_MaxClients
};

struct SDPResult {
  WuSDPStatus status;
  WuClient* client;
};

typedef void (*WuErrorFn)(const char* err, void* userData);
typedef void (*WuWriteFn)(const uint8_t* data, size_t length,
                          const WuClient* client, void* userData);

struct WuConf {
  const char* host;
  const char* port;
  int blocking;
  int maxClients;
  WuErrorFn errorHandler;
};

struct WuHost {
  WuArena* arena;
  double time;
  double dt;
  uint16_t port;
  WuQueue* pendingEvents;
  int32_t maxClients;
  int32_t numClients;

  WuPool* clientPool;
  WuClient** clients;
  WuCert* cert;

  ssl_ctx_st* sslCtx;

  const WuConf* conf;

  char errBuf[512];
  void* userData;
  WuErrorFn errorHandler;
  WuWriteFn writeUdpData;
  WuWriteFn writeSignallingData;
};

int32_t WuInit(WuHost* wu, const WuConf* conf);
int32_t WuServe(WuHost* wu, WuEvent* evt);
int32_t WuSendText(WuHost* wu, WuClient* client, const char* text,
                   int32_t length);
int32_t WuSendBinary(WuHost* wu, WuClient* client, const uint8_t* data,
                     int32_t length);
void WuRemoveClient(WuHost* wu, WuClient* client);
void WuClientSetUserData(WuClient* client, void* user);
void* WuClientGetUserData(const WuClient* client);
SDPResult WuHandleSDP(WuHost* wu, const char* sdp, int32_t length);
void WuHandleUDP(WuHost* wu, const uint8_t* data, int32_t length);
void WuHostSetUserData(WuHost* wu, void* userData);
