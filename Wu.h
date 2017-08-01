#pragma once

#include <stddef.h>
#include <stdint.h>

struct WuClient;
struct WuConnectionBufferPool;
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
  union {
    struct {
      const uint8_t* buf;
      int32_t length;
    } data;
  } as;
};

typedef void (*WuErrorFn)(const char* err, void* userData);

struct WuConf {
  const char* host;
  const char* port;
  int blocking;
  WuErrorFn errorHandler;
  void* errorHandlerData;
};

struct WuHost {
  WuArena* arena;
  double time;
  double dt;
  uint16_t port;
  int pollTimeout;
  int tcpfd;
  int udpfd;
  int epfd;
  WuQueue* pendingEvents;
  WuConnectionBufferPool* bufferPool;
  int32_t maxEvents;
  struct epoll_event* events;
  int32_t maxClients;
  int32_t numClients;

  WuPool* clientPool;
  WuClient** clients;
  WuCert* cert;

  ssl_ctx_st* sslCtx;

  const WuConf* conf;

  char errBuf[512];
  void* errorHandlerData;
  WuErrorFn errorHandler;
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
