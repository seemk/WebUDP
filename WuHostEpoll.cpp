#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "WuHost.h"
#include "WuHttp.h"
#include "WuMath.h"
#include "WuNetwork.h"
#include "WuPool.h"
#include "WuRng.h"
#include "WuString.h"
#include "picohttpparser.h"

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

struct WuHost {
  char errBuf[512];
  WuConnectionBufferPool* bufferPool;
  uint16_t port;
  int pollTimeout;
  int tcpfd;
  int udpfd;
  int epfd;
  int32_t maxEvents;
  struct epoll_event* events;
  Wu* wu;
};

static void HandleErrno(WuHost* host, const char* description) {
  snprintf(host->errBuf, sizeof(host->errBuf), "%s: %s", description,
           strerror(errno));
  WuReportError(host->wu, host->errBuf);
}

static void WriteUDPData(const uint8_t* data, size_t length,
                         const WuClient* client, void* userData) {
  WuHost* host = (WuHost*)userData;

  WuAddress address = WuClientGetAddress(client);
  struct sockaddr_in netaddr;
  netaddr.sin_family = AF_INET;
  netaddr.sin_port = htons(address.port);
  netaddr.sin_addr.s_addr = htonl(address.host);

  sendto(host->udpfd, data, length, 0, (struct sockaddr*)&netaddr,
         sizeof(netaddr));
}

static void HandleHttpRequest(WuHost* host, WuConnectionBuffer* conn) {
  for (;;) {
    ssize_t count = read(conn->fd, conn->requestBuffer + conn->size,
                         kMaxHttpRequestLength - conn->size);
    if (count == -1) {
      if (errno != EAGAIN) {
        HandleErrno(host, "failed to read from TCP socket");
        close(conn->fd);
        host->bufferPool->Reclaim(conn);
      }
      return;
    } else if (count == 0) {
      close(conn->fd);
      host->bufferPool->Reclaim(conn);
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
              host->wu, (const char*)conn->requestBuffer + parseStatus,
              contentLength);

          if (sdp.status == WuSDPStatus_Success) {
            char response[4096];
            int responseLength =
                snprintf(response, sizeof(response),
                         "HTTP/1.1 200 OK\r\n"
                         "Content-Type: application/json\r\n"
                         "Content-Length: %d\r\n"
                         "Connection: close\r\n"
                         "Access-Control-Allow-Origin: *\r\n"
                         "\r\n%.*s",
                         sdp.sdpLength, sdp.sdpLength, sdp.sdp);
            SocketWrite(conn->fd, response, responseLength);
          } else if (sdp.status == WuSDPStatus_MaxClients) {
            SocketWrite(conn->fd, STRLIT(HTTP_UNAVAILABLE));
          } else if (sdp.status == WuSDPStatus_InvalidSDP) {
            SocketWrite(conn->fd, STRLIT(HTTP_BAD_REQUEST));
          } else {
            SocketWrite(conn->fd, STRLIT(HTTP_SERVER_ERROR));
          }

          close(conn->fd);
          host->bufferPool->Reclaim(conn);
        }
      }

      return;
    } else if (parseStatus == -1) {
      close(conn->fd);
      host->bufferPool->Reclaim(conn);
      return;
    } else {
      if (conn->size == kMaxHttpRequestLength) {
        SocketWrite(conn->fd, STRLIT(HTTP_BAD_REQUEST));
        close(conn->fd);
        host->bufferPool->Reclaim(conn);
        return;
      }
    }
  }
}

int32_t WuHostServe(WuHost* host, WuEvent* evt) {
  int32_t hres = WuUpdate(host->wu, evt);

  if (hres) {
    return hres;
  }

  int n =
      epoll_wait(host->epfd, host->events, host->maxEvents, host->pollTimeout);

  WuConnectionBufferPool* pool = host->bufferPool;
  for (int i = 0; i < n; i++) {
    struct epoll_event* e = &host->events[i];
    WuConnectionBuffer* c = (WuConnectionBuffer*)e->data.ptr;

    if ((e->events & EPOLLERR) || (e->events & EPOLLHUP) ||
        (!(e->events & EPOLLIN))) {
      close(c->fd);
      pool->Reclaim(c);
      continue;
    }

    if (host->tcpfd == c->fd) {
      for (;;) {
        struct sockaddr_in inAddress;
        socklen_t inLength = sizeof(inAddress);

        int infd = accept(host->tcpfd, (struct sockaddr*)&inAddress, &inLength);
        if (infd == -1) {
          if (errno != EAGAIN && errno != EWOULDBLOCK) {
            HandleErrno(host, "TCP accept");
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
          if (epoll_ctl(host->epfd, EPOLL_CTL_ADD, infd, &event) == -1) {
            close(infd);
            HandleErrno(host, "EPOLL_CTL_ADD infd");
          }
        } else {
          close(infd);
        }
      }
    } else if (host->udpfd == c->fd) {
      struct sockaddr_in remote;
      socklen_t remoteLen = sizeof(remote);
      uint8_t buf[4096];

      ssize_t r = 0;
      while ((r = recvfrom(host->udpfd, buf, sizeof(buf), 0,
                           (struct sockaddr*)&remote, &remoteLen)) > 0) {
        WuAddress address;
        address.host = ntohl(remote.sin_addr.s_addr);
        address.port = ntohs(remote.sin_port);
        WuHandleUDP(host->wu, &address, buf, r);
      }

    } else {
      HandleHttpRequest(host, c);
    }
  }

  return 0;
}

int32_t WuHostInit(WuHost* host, const WuConf* conf) {
  memset(host, 0, sizeof(WuHost));

  host->tcpfd = CreateSocket(conf->port, ST_TCP);

  if (host->tcpfd == -1) {
    return 0;
  }

  int s = MakeNonBlocking(host->tcpfd);
  if (s == -1) {
    return 0;
  }

  s = listen(host->tcpfd, SOMAXCONN);
  if (s == -1) {
    HandleErrno(host, "tcp listen failed");
    return 0;
  }

  host->udpfd = CreateSocket(conf->port, ST_UDP);

  if (host->udpfd == -1) {
    return 0;
  }

  s = MakeNonBlocking(host->udpfd);
  if (s == -1) {
    return 0;
  }

  host->epfd = epoll_create1(0);
  if (host->epfd == -1) {
    HandleErrno(host, "epoll_create");
    return 0;
  }

  const int32_t maxEvents = 128;

  host->bufferPool = new WuConnectionBufferPool(maxEvents + 2);

  WuConnectionBuffer* udpBuf = host->bufferPool->GetBuffer();
  udpBuf->fd = host->udpfd;

  WuConnectionBuffer* tcpBuf = host->bufferPool->GetBuffer();
  tcpBuf->fd = host->tcpfd;

  struct epoll_event event;
  event.data.ptr = tcpBuf;
  event.events = EPOLLIN | EPOLLET;

  s = epoll_ctl(host->epfd, EPOLL_CTL_ADD, host->tcpfd, &event);
  if (s == -1) {
    HandleErrno(host, "EPOLL_CTL_ADD tcpfd");
    return 0;
  }

  event.data.ptr = udpBuf;
  s = epoll_ctl(host->epfd, EPOLL_CTL_ADD, host->udpfd, &event);
  if (s == -1) {
    HandleErrno(host, "EPOLL_CTL_ADD udpfd");
    return 0;
  }

  host->maxEvents = maxEvents;
  host->events = (struct epoll_event*)calloc(host->maxEvents, sizeof(event));
  host->wu = (Wu*)calloc(1, sizeof(Wu));

  if (!WuInit(host->wu, conf)) {
    return 0;
  }

  WuSetUserData(host->wu, host);
  WuSetUDPWriteFunction(host->wu, WriteUDPData);

  return 1;
}

void WuHostRemoveClient(WuHost* host, WuClient* client) {
  WuRemoveClient(host->wu, client);
}

int32_t WuHostSendText(WuHost* host, WuClient* client, const char* text,
                       int32_t length) {
  return WuSendText(host->wu, client, text, length);
}

int32_t WuHostSendBinary(WuHost* host, WuClient* client, const uint8_t* data,
                         int32_t length) {
  return WuSendBinary(host->wu, client, data, length);
}

WuHost* WuHostCreate(const WuConf* conf) {
  WuHost* host = (WuHost*)calloc(1, sizeof(WuHost));

  if (!WuHostInit(host, conf)) {
    free(host);
    return NULL;
  }

  return host;
}

void WuHostSetErrorCallback(WuHost* host, WuErrorFn callback) {
  WuSetErrorCallback(host->wu, callback);
}
