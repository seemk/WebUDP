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

struct WuHost {
  Wu* wu;
  int tcpfd;
  int udpfd;
  int epfd;
  int pollTimeout;
  WuPool* bufferPool;
  struct epoll_event* events;
  int32_t maxEvents;
  uint16_t port;
  char errBuf[512];
};

static void HostReclaimBuffer(WuHost* host, WuConnectionBuffer* buffer) {
  buffer->fd = -1;
  buffer->size = 0;
  WuPoolRelease(host->bufferPool, buffer);
}

static WuConnectionBuffer* HostGetBuffer(WuHost* host) {
  WuConnectionBuffer* buffer = (WuConnectionBuffer*)WuPoolAcquire(host->bufferPool);
  return buffer;
}

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
        HostReclaimBuffer(host, conn);
      }
      return;
    } else if (count == 0) {
      close(conn->fd);
      HostReclaimBuffer(host, conn);
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
          HostReclaimBuffer(host, conn);
        }
      }

      return;
    } else if (parseStatus == -1) {
      close(conn->fd);
      HostReclaimBuffer(host, conn);
      return;
    } else {
      if (conn->size == kMaxHttpRequestLength) {
        SocketWrite(conn->fd, STRLIT(HTTP_BAD_REQUEST));
        close(conn->fd);
        HostReclaimBuffer(host, conn);
        return;
      }
    }
  }
}

int32_t WuHostServe(WuHost* host, WuEvent* evt, int timeout) {
  int32_t hres = WuUpdate(host->wu, evt);

  if (hres) {
    return hres;
  }

  int n =
      epoll_wait(host->epfd, host->events, host->maxEvents, timeout);

  for (int i = 0; i < n; i++) {
    struct epoll_event* e = &host->events[i];
    WuConnectionBuffer* c = (WuConnectionBuffer*)e->data.ptr;

    if ((e->events & EPOLLERR) || (e->events & EPOLLHUP) ||
        (!(e->events & EPOLLIN))) {
      close(c->fd);
      HostReclaimBuffer(host, c);
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

        WuConnectionBuffer* conn = HostGetBuffer(host);;

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

int32_t WuHostCreate(const char* hostAddr, const char* port, int32_t maxClients, WuHost** host) {
  *host = NULL;

  WuHost* ctx = (WuHost*)calloc(1, sizeof(WuHost));


  if (!ctx) {
    return WU_OUT_OF_MEMORY;
  }

  int32_t status = WuCreate(hostAddr, port, maxClients, &ctx->wu);

  if (status != WU_OK) {
    free(ctx);
    return status;
  }

  ctx->tcpfd = CreateSocket(port, ST_TCP);

  if (ctx->tcpfd == -1) {
    WuHostDestroy(ctx);
    return WU_ERROR;
  }

  status = MakeNonBlocking(ctx->tcpfd);
  if (status == -1) {
    WuHostDestroy(ctx);
    return WU_ERROR;
  }

  status = listen(ctx->tcpfd, SOMAXCONN);
  if (status == -1) {
    WuHostDestroy(ctx);
    return WU_ERROR;
  }

  ctx->udpfd = CreateSocket(port, ST_UDP);

  if (ctx->udpfd == -1) {
    WuHostDestroy(ctx);
    return WU_ERROR;
  }

  status = MakeNonBlocking(ctx->udpfd);
  if (status == -1) {
    WuHostDestroy(ctx);
    return WU_ERROR;
  }

  ctx->epfd = epoll_create1(0);
  if (ctx->epfd == -1) {
    WuHostDestroy(ctx);
    return WU_ERROR;
  }

  const int32_t maxEvents = 128;
  ctx->bufferPool = WuPoolCreate(sizeof(WuConnectionBuffer), maxEvents + 2);

  if (!ctx->bufferPool) {
    WuHostDestroy(ctx);
    return WU_OUT_OF_MEMORY;
  }

  WuConnectionBuffer* udpBuf = HostGetBuffer(ctx);
  udpBuf->fd = ctx->udpfd;

  WuConnectionBuffer* tcpBuf = HostGetBuffer(ctx);
  tcpBuf->fd = ctx->tcpfd;

  struct epoll_event event;
  event.data.ptr = tcpBuf;
  event.events = EPOLLIN | EPOLLET;

  status = epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, ctx->tcpfd, &event);
  if (status == -1) {
    WuHostDestroy(ctx);
    return WU_ERROR;
  }

  event.data.ptr = udpBuf;
  status = epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, ctx->udpfd, &event);
  if (status == -1) {
    WuHostDestroy(ctx);
    return WU_ERROR;
  }

  ctx->maxEvents = maxEvents;
  ctx->events = (struct epoll_event*)calloc(ctx->maxEvents, sizeof(event));

  if (!ctx->events) {
    WuHostDestroy(ctx);
    return WU_OUT_OF_MEMORY;
  }

  WuSetUserData(ctx->wu, ctx);
  WuSetUDPWriteFunction(ctx->wu, WriteUDPData);

  *host = ctx;

  return WU_OK;
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

void WuHostSetErrorCallback(WuHost* host, WuErrorFn callback) {
  WuSetErrorCallback(host->wu, callback);
}

void WuHostDestroy(WuHost* host) {
  if (!host) {
    return;
  }

  WuDestroy(host->wu);

  if (host->tcpfd != -1) {
    close(host->tcpfd);
  }

  if (host->udpfd != -1) {
    close(host->udpfd);
  }

  if (host->epfd != -1) {
    close(host->epfd);
  }

  if (host->bufferPool) {
    free(host->bufferPool);
  }

  if (host->events) {
    free(host->events);
  }
}

WuClient* WuHostFindClient(const WuHost* host, WuAddress address) {
  return WuFindClient(host->wu, address);
}
