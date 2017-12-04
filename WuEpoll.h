#pragma once

struct WuConnectionBufferPool;
struct WuHost;

struct WuEpoll {
  WuConnectionBufferPool* bufferPool;
  struct epoll_event* events;
  uint16_t port;
  int pollTimeout;
  int tcpfd;
  int udpfd;
  int epfd;
  int32_t maxEvents;
  WuHost* host;
};

void WuEpollInit(WuEpoll* ctx);
