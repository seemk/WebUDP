#include "WuEpoll.h"
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "Wu.h"
#include "WuArena.h"
#include "WuCert.h"
#include "WuClock.h"
#include "WuHttp.h"
#include "WuMath.h"
#include "WuNetwork.h"
#include "WuPool.h"
#include "WuQueue.h"
#include "WuRng.h"
#include "WuSctp.h"
#include "WuSdp.h"
#include "WuStun.h"
#include "picohttpparser.h"

static void HandleErrno(WuEpoll* ctx, const char* description) {
  snprintf(ctx->errBuf, sizeof(ctx->errBuf), "%s: %s", description,
           strerror(errno));
  WuHostError(ctx->host, ctx->errBuf);
}

static void WriteUDPData(const uint8_t* data, size_t length,
                         const WuClient* client, void* userData) {
  WuEpoll* ctx = (WuEpoll*)userData;

  // TODO: Get client address
  struct sockaddr_in address;

  int ret = sendto(ctx->udpfd, data, length, 0, (struct sockaddr*)&address,
                   sizeof(address));
  (void)ret;
}

struct WuConnectionBuffer {
  size_t size = 0;
  int fd = -1;
  uint8_t requestBuffer[kMaxHttpRequestLength];
};

struct WuConnectionBufferPool {
  WuConnectionBufferPool(size_t n)
      : pool(WuPoolCreate(sizeof(WuConnectionBuffer), n)) {}

  WuConnectionBuffer* GetBuffer() {
    WuConnectionBuffer* buffer = (WuConnectionBuffer*)WuPoolAcquire(pool);
    return buffer;
  }

  void Reclaim(WuConnectionBuffer* buf) {
    buf->fd = -1;
    buf->size = 0;
    WuPoolRelease(pool, buf);
  }

  WuPool* pool;
};

static void HandleHttpRequest(WuEpoll* ctx, WuConnectionBuffer* conn) {
  for (;;) {
    ssize_t count = read(conn->fd, conn->requestBuffer + conn->size,
                         kMaxHttpRequestLength - conn->size);
    if (count == -1) {
      if (errno != EAGAIN) {
        HandleErrno(ctx, "failed to read from TCP socket");
        close(conn->fd);
        ctx->bufferPool->Reclaim(conn);
      }
      return;
    } else if (count == 0) {
      close(conn->fd);
      ctx->bufferPool->Reclaim(conn);
      return;
    }

    size_t prevSize = conn->size;
    conn->size += count;

    const char* method;
    const char* path;
    size_t methodLength, pathLength;
    int minorVersion;
    struct phr_header headers[16];
    size_t numHeaders = 16;
    int parseStatus = phr_parse_request(
        (const char*)conn->requestBuffer, conn->size, &method, &methodLength,
        &path, &pathLength, &minorVersion, headers, &numHeaders, prevSize);

    if (parseStatus > 0) {
      size_t contentLength = 0;
      for (size_t i = 0; i < numHeaders; i++) {
        if (CompareCaseInsensitive(headers[i].name, headers[i].name_len,
                                   STRLIT("content-length"))) {
          contentLength = StringToUint(headers[i].value, headers[i].value_len);
          break;
        }
      }

      if (contentLength > 0) {
        if (conn->size == parseStatus + contentLength) {
          const SDPResult sdp = WuExchangeSDP(
              ctx->host, (const char*)conn->requestBuffer + parseStatus,
              contentLength);

          if (sdp.status == WuSDPStatus_MaxClients) {
            SocketWrite(conn->fd, STRLIT(HTTP_UNAVAILABLE));
          } else if (sdp.status == WuSDPStatus_InvalidSDP) {
            SocketWrite(conn->fd, STRLIT(HTTP_BAD_REQUEST));
          }

          char response[4096];
          int responseLength = snprintf(response, 4096,
                                        "HTTP/1.1 200 OK\r\n"
                                        "Content-Type: application/json\r\n"
                                        "Content-Length: %d\r\n"
                                        "Connection: close\r\n"
                                        "Access-Control-Allow-Origin: *\r\n"
                                        "\r\n%s",
                                        sdp.sdpLength, sdp.sdp);
          SocketWrite(conn->fd, response, responseLength);
          close(conn->fd);
          ctx->bufferPool->Reclaim(conn);
        }
      }

      return;
    } else if (parseStatus == -1) {
      close(conn->fd);
      ctx->bufferPool->Reclaim(conn);
      return;
    } else {
      if (conn->size == kMaxHttpRequestLength) {
        SocketWrite(conn->fd, STRLIT(HTTP_BAD_REQUEST));
        close(conn->fd);
        ctx->bufferPool->Reclaim(conn);
        return;
      }
    }
  }
}

int32_t WuServe(WuEpoll* ctx, WuEvent* evt) {
  int32_t hres = WuHostUpdate(ctx->host, evt);

  if (hres) {
    return hres;
  }

  int n = epoll_wait(ctx->epfd, ctx->events, ctx->maxEvents, ctx->pollTimeout);

  WuConnectionBufferPool* pool = ctx->bufferPool;
  for (int i = 0; i < n; i++) {
    struct epoll_event* e = &ctx->events[i];
    WuConnectionBuffer* c = (WuConnectionBuffer*)e->data.ptr;

    if ((e->events & EPOLLERR) || (e->events & EPOLLHUP) ||
        (!(e->events & EPOLLIN))) {
      close(c->fd);
      pool->Reclaim(c);
      continue;
    }

    if (ctx->tcpfd == c->fd) {
      for (;;) {
        struct sockaddr_in inAddress;
        socklen_t inLength = sizeof(inAddress);

        int infd = accept(ctx->tcpfd, (struct sockaddr*)&inAddress, &inLength);
        if (infd == -1) {
          if (errno != EAGAIN && errno != EWOULDBLOCK) {
            HandleErrno(ctx, "TCP accept");
          }
          break;
        }

        if (MakeNonBlocking(infd) == -1) {
          close(infd);
          continue;
        }

        WuConnectionBuffer* conn = pool->GetBuffer();

        if (conn) {
          conn->fd = infd;
          struct epoll_event event;
          event.events = EPOLLIN | EPOLLET;
          event.data.ptr = conn;
          if (epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, infd, &event) == -1) {
            close(infd);
            HandleErrno(ctx, "EPOLL_CTL_ADD infd");
          }
        } else {
          close(infd);
        }
      }
    } else if (ctx->udpfd == c->fd) {
      struct sockaddr_in remote;
      socklen_t remoteLen = sizeof(remote);
      uint8_t buf[4096];

      ssize_t r = 0;
      while ((r = recvfrom(ctx->udpfd, buf, sizeof(buf), 0,
                           (struct sockaddr*)&remote, &remoteLen)) > 0) {
        WuAddress address;
        address.host = ntohl(remote.sin_addr.s_addr);
        address.port = ntohs(remote.sin_port);
        WuHandleUDP(ctx->host, &address, buf, r);
      }

    } else {
      HandleHttpRequest(ctx, c);
    }
  }

  return 0;
}

int32_t WuEpollInit(WuEpoll* ctx, const WuConf* conf) {
  memset(ctx, 0, sizeof(WuEpoll));

  ctx->tcpfd = CreateSocket(conf->port, ST_TCP);

  if (ctx->tcpfd == -1) {
    return 0;
  }

  int s = MakeNonBlocking(ctx->tcpfd);
  if (s == -1) {
    return 0;
  }

  s = listen(ctx->tcpfd, SOMAXCONN);
  if (s == -1) {
    HandleErrno(ctx, "tcp listen failed");
    return 0;
  }

  ctx->udpfd = CreateSocket(conf->port, ST_UDP);

  if (ctx->udpfd == -1) {
    return 0;
  }

  s = MakeNonBlocking(ctx->udpfd);
  if (s == -1) {
    return 0;
  }

  ctx->epfd = epoll_create1(0);
  if (ctx->epfd == -1) {
    HandleErrno(ctx, "epoll_create");
    return 0;
  }

  const int32_t maxEvents = 128;

  ctx->bufferPool = new WuConnectionBufferPool(maxEvents + 2);

  WuConnectionBuffer* udpBuf = ctx->bufferPool->GetBuffer();
  udpBuf->fd = ctx->udpfd;

  WuConnectionBuffer* tcpBuf = ctx->bufferPool->GetBuffer();
  tcpBuf->fd = ctx->tcpfd;

  struct epoll_event event;
  event.data.ptr = tcpBuf;
  event.events = EPOLLIN | EPOLLET;

  s = epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, ctx->tcpfd, &event);
  if (s == -1) {
    HandleErrno(ctx, "EPOLL_CTL_ADD tcpfd");
    return 0;
  }

  event.data.ptr = udpBuf;
  s = epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, ctx->udpfd, &event);
  if (s == -1) {
    HandleErrno(ctx, "EPOLL_CTL_ADD udpfd");
    return 0;
  }

  ctx->maxEvents = maxEvents;
  ctx->events = (struct epoll_event*)calloc(ctx->maxEvents, sizeof(event));
  ctx->host = (WuHost*)calloc(1, sizeof(WuHost));

  if (!WuHostInit(ctx->host, conf)) {
    return 0;
  }

  WuHostSetUDPWrite(ctx->host, WriteUDPData);

  return 1;
}

void WuEpollSetNonblocking(WuEpoll* ctx, int32_t nonblocking) {
  (void)ctx;
  (void)nonblocking;
}

void WuHostRemoveClient(WuEpoll* wu, WuClient* client) {
  WuRemoveClient(wu->host, client);
}

int32_t WuHostSendText(WuEpoll* host, WuClient* client, const char* text,
                   int32_t length) {
  return WuSendText(host->host, client, text, length);
}

int32_t WuHostSendBinary(WuEpoll* host, WuClient* client, const uint8_t* data,
                     int32_t length) {
  return WuSendBinary(host->host, client, data, length);
}
