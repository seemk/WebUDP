#pragma once

#include <stddef.h>
#include <stdint.h>

struct WuClient;
struct WuPool;
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
  const char* sdp;
  int32_t sdpLength;
};

typedef void (*WuErrorFn)(const char* err, void* userData);
typedef void (*WuWriteFn)(const uint8_t* data, size_t length,
                          const WuClient* client, void* userData);

struct WuAddress {
  uint32_t host;
  uint16_t port;
};

struct WuConf {
  const char* host = "127.0.0.1";
  const char* port = "9555";
  int maxClients = 256;
};

struct Wu {
  WuArena* arena;
  double time;
  double dt;
  char host[256];
  uint16_t port;
  WuQueue* pendingEvents;
  int32_t maxClients;
  int32_t numClients;

  WuPool* clientPool;
  WuClient** clients;
  ssl_ctx_st* sslCtx;

  char certFingerprint[96];

  char errBuf[512];
  void* userData;
  WuErrorFn errorCallback;
  WuWriteFn writeUdpData;
};

int32_t WuInit(Wu* wu, const WuConf* conf);
int32_t WuUpdate(Wu* wu, WuEvent* evt);
void WuReportError(Wu* wu, const char* error);
int32_t WuSendText(Wu* wu, WuClient* client, const char* text, int32_t length);
int32_t WuSendBinary(Wu* wu, WuClient* client, const uint8_t* data,
                     int32_t length);
void WuRemoveClient(Wu* wu, WuClient* client);
void WuClientSetUserData(WuClient* client, void* user);
void* WuClientGetUserData(const WuClient* client);
SDPResult WuExchangeSDP(Wu* wu, const char* sdp, int32_t length);
void WuHandleUDP(Wu* wu, const WuAddress* remote, const uint8_t* data,
                 int32_t length);
void WuSetUDPWriteFunction(Wu* wu, WuWriteFn write);
void WuSetUserData(Wu* wu, void* userData);
void WuSetErrorCallback(Wu* wu, WuErrorFn callback);
WuAddress WuClientGetAddress(const WuClient* client);
