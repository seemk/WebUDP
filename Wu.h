#pragma once

#include <openssl/ssl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <string>
#include <vector>
#include "WuArena.h"
#include "WuCert.h"
#include "WuHttp.h"
#include "WuPool.h"
#include "WuQueue.h"

struct WuClient;

struct WuConf {
  const char* host;
  const char* port;
};

const size_t kCertFingerprintLength = 95;

struct WuConnectionBuffer {
  size_t size = 0;
  int fd = -1;
  uint8_t requestBuffer[kMaxHttpRequestLength];
};

struct WuConnectionBufferPool {
  WuConnectionBufferPool(size_t n) : buffers(n) {
    for (size_t i = 0; i < n; i++) {
      freeBuffers.push_back(&buffers[i]);
    }
  }

  WuConnectionBuffer* GetBuffer() {
    if (freeBuffers.size() > 0) {
      WuConnectionBuffer* buf = freeBuffers.back();
      freeBuffers.pop_back();
      return buf;
    }

    return nullptr;
  }

  void Reclaim(WuConnectionBuffer* buf) {
    buf->fd = -1;
    buf->size = 0;
    freeBuffers.push_back(buf);
  }

  std::vector<WuConnectionBuffer> buffers;
  std::vector<WuConnectionBuffer*> freeBuffers;
};

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

struct WuHost {
  WuArena arena;
  double time;
  double dt;
  uint16_t port;
  int tcpfd;
  int udpfd;
  int epfd;
  WuQueue pendingEvents;
  WuConnectionBufferPool* bufferPool;
  int32_t maxEvents;
  struct epoll_event* events;
  int32_t maxClients;
  int32_t numClients;

  WuPool* clientPool;
  WuClient** clients;
  WuCert* cert;

  SSL_CTX* sslCtx;

  const WuConf* conf;
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
