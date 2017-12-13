#pragma once
#include <stdint.h>

struct WuConnectionBufferPool;
struct WuHost;
struct WuConf;
struct WuEvent;
struct WuClient;

struct WuEpoll {
  char errBuf[512];
  WuConnectionBufferPool* bufferPool;
  uint16_t port;
  int pollTimeout;
  int tcpfd;
  int udpfd;
  int epfd;
  int32_t maxEvents;
  struct epoll_event* events;
  WuHost* host;
};

int32_t WuEpollInit(WuEpoll* ctx, const WuConf* conf);
void WuEpollSetNonblocking(WuEpoll* ctx, int32_t nonblocking);
int32_t WuServe(WuEpoll* ctx, WuEvent* evt);
void WuHostRemoveClient(WuEpoll* wu, WuClient* client);
int32_t WuHostSendText(WuEpoll* host, WuClient* client, const char* text,
                   int32_t length);
int32_t WuHostSendBinary(WuEpoll* host, WuClient* client, const uint8_t* data,
                     int32_t length);
