#include <stdlib.h>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include "WuHost.h"
#include "WuPool.h"
#include "WuNetwork.h"
#include "WuHttp.h"
#include "WuString.h"
#include "wepoll.h"
#include "picohttpparser.h"

struct WuHost {
    Wu* wu;
    int tcpfd;
    int udpfd;
    HANDLE epfd;
    int pollTimeout;
    WuPool* bufferPool;
    struct epoll_event* events;
    int32_t maxEvents;
    uint16_t port;
    char errBuf[512];
};

struct WuConnectionBuffer {
    size_t size = 0;
    int fd = -1;
    uint8_t requestBuffer[kMaxHttpRequestLength];
};

static WuConnectionBuffer* HostGetBuffer(WuHost* host) {
    WuConnectionBuffer* buffer = (WuConnectionBuffer*)WuPoolAcquire(host->bufferPool);
    return buffer;
}

static void WriteUDPData(const uint8_t* data, size_t length,
    const WuClient* client, void* userData) {
    WuHost* host = (WuHost*)userData;

    WuAddress address = WuClientGetAddress(client);
    struct sockaddr_in netaddr;
    netaddr.sin_family = AF_INET;
    netaddr.sin_port = htons(address.port);
    netaddr.sin_addr.s_addr = htonl(address.host);

    sendto(host->udpfd, (const char*)data, length, 0, (struct sockaddr*)&netaddr,
        sizeof(netaddr));
}
int CreateSocket(const char* port, SocketType type) {
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = type == ST_TCP ? SOCK_STREAM : SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo* result = NULL;
    int s = getaddrinfo(NULL, port, &hints, &result);

    if (s != 0) {
        return -1;
    }

    int sfd = -1;

    struct addrinfo* rp = result;
    for (; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1) {
            continue;
        }

        int enable = 1;
        setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&enable, sizeof(int));

        s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            break;
        }

        closesocket(sfd);
    }

    freeaddrinfo(result);

    if (rp == NULL) {
        return -1;
    }

    return sfd;
}

int MakeNonBlocking(int sfd) {
    /*
    int flags = fcntl(sfd, F_GETFL, 0);
    if (flags == -1) {
        return -1;
    }

    flags |= O_NONBLOCK;

    int s = fcntl(sfd, F_SETFL, flags);
    if (s == -1) {
        return -1;
    }
    */
    u_long enable = 1;
    if (SOCKET_ERROR == ioctlsocket(sfd, FIONBIO, &enable)) {
        return -1; // WSAGetLastError();
    }
    return 0;
}


void WuHostDestroy(WuHost* host) {
    if (!host) {
        return;
    }

    WuDestroy(host->wu);

    if (host->tcpfd != -1) {
        closesocket(host->tcpfd);
    }

    if (host->udpfd != -1) {
        closesocket(host->udpfd);
    }

    if (host->epfd != (HANDLE)-1) {
        CloseHandle(host->epfd);
    }

    if (host->bufferPool) {
        free(host->bufferPool);
    }

    if (host->events) {
        free(host->events);
    }
}

void SocketsStartup() {
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    /* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
    wVersionRequested = MAKEWORD(2, 2);

    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        /* Tell the user that we could not find a usable */
        /* Winsock DLL.                                  */
        //printf("WSAStartup failed with error: %d\n", err);
    }
}


int32_t WuHostCreate(const char* hostAddr, const char* port, int32_t maxClients, WuHost** host) {

    SocketsStartup();

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
    if (ctx->epfd == (HANDLE)-1) {
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
    event.events = EPOLLIN; // | EPOLLET;

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
static void HostReclaimBuffer(WuHost* host, WuConnectionBuffer* buffer) {
    buffer->fd = -1;
    buffer->size = 0;
    WuPoolRelease(host->bufferPool, buffer);
}

static void HandleErrno(WuHost* host, const char* description) {
    snprintf(host->errBuf, sizeof(host->errBuf), "%s: %s", description,
        strerror(errno));
    WuReportError(host->wu, host->errBuf);
}
ssize_t SocketWrite(int fd, const uint8_t* buf, size_t len) {
    const ssize_t towrite = (ssize_t)len;
    ssize_t written = 0;
    while (written != towrite) {
        //ssize_t r = write(fd, buf + written, towrite - written);
        ssize_t r = send(fd, (const char*)(buf + written), towrite - written, 0);
        if (r == 0) return written;
        if (r == -1) {
            return -1;
        }

        written += r;
    }

    return written;
}

ssize_t SocketWrite(int fd, const char* buf, size_t len) {
    return SocketWrite(fd, (const uint8_t*)buf, len);
}


static void HandleHttpRequest(WuHost* host, WuConnectionBuffer* conn) {
    for (;;) {
        //ssize_t count = read(conn->fd, conn->requestBuffer + conn->size,
        //    kMaxHttpRequestLength - conn->size);
        ssize_t count = recv(conn->fd, (char*)(conn->requestBuffer + conn->size),
            kMaxHttpRequestLength - conn->size, 0);
        if (count == -1) {
            if (errno != EAGAIN) {
                HandleErrno(host, "failed to read from TCP socket");
                closesocket(conn->fd);
                HostReclaimBuffer(host, conn);
            }
            return;
        }
        else if (count == 0) {
            closesocket(conn->fd);
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
                    }
                    else if (sdp.status == WuSDPStatus_MaxClients) {
                        SocketWrite(conn->fd, STRLIT(HTTP_UNAVAILABLE));
                    }
                    else if (sdp.status == WuSDPStatus_InvalidSDP) {
                        SocketWrite(conn->fd, STRLIT(HTTP_BAD_REQUEST));
                    }
                    else {
                        SocketWrite(conn->fd, STRLIT(HTTP_SERVER_ERROR));
                    }

                    closesocket(conn->fd);
                    HostReclaimBuffer(host, conn);
                }
            }

            return;
        }
        else if (parseStatus == -1) {
            closesocket(conn->fd);
            HostReclaimBuffer(host, conn);
            return;
        }
        else {
            if (conn->size == kMaxHttpRequestLength) {
                SocketWrite(conn->fd, STRLIT(HTTP_BAD_REQUEST));
                closesocket(conn->fd);
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
            closesocket(c->fd);
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
                    closesocket(infd);
                    continue;
                }

                WuConnectionBuffer* conn = HostGetBuffer(host);;

                if (conn) {
                    conn->fd = infd;
                    struct epoll_event event;
                    event.events = EPOLLIN; // | EPOLLET;
                    event.data.ptr = conn;
                    if (epoll_ctl(host->epfd, EPOLL_CTL_ADD, infd, &event) == -1) {
                        closesocket(infd);
                        HandleErrno(host, "EPOLL_CTL_ADD infd");
                    }
                }
                else {
                    closesocket(infd);
                }
            }
        }
        else if (host->udpfd == c->fd) {
            struct sockaddr_in remote;
            socklen_t remoteLen = sizeof(remote);
            uint8_t buf[4096];

            ssize_t r = 0;
            while ((r = recvfrom(host->udpfd, (char*)buf, sizeof(buf), 0,
                (struct sockaddr*)&remote, &remoteLen)) > 0) {
                WuAddress address;
                address.host = ntohl(remote.sin_addr.s_addr);
                address.port = ntohs(remote.sin_port);
                WuHandleUDP(host->wu, &address, buf, r);
            }

        }
        else {
            HandleHttpRequest(host, c);
        }
    }

    return 0;
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
