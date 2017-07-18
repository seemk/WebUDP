#include "Wu.h"
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
#include <algorithm>
#include <vector>
#include "WuCert.h"
#include "WuCert.h"
#include "WuClock.h"
#include "WuDataChannel.h"
#include "WuHttp.h"
#include "WuNetwork.h"
#include "WuPool.h"
#include "WuRng.h"
#include "WuSctp.h"
#include "WuSdp.h"
#include "WuStun.h"
#include "picohttpparser.h"

enum WuClientState {
  WuClient_Dead,
  WuClient_WaitingRemoval,
  WuClient_DTLSHandshake,
  WuClient_SCTPEstablished,
  WuClient_DataChannelOpen
};

const char* WuClientStateString(WuClientState state) {
  switch (state) {
    case WuClient_Dead:
      return "client-state-dead";
    case WuClient_WaitingRemoval:
      return "client-state-waitremove";
    case WuClient_DTLSHandshake:
      return "client-state-dtls-handshake";
    case WuClient_SCTPEstablished:
      return "client-state-sctp-established";
    case WuClient_DataChannelOpen:
      return "client-state-datachannel-open";
    default:
      return "client-state-invalid";
  }
}

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

const double kMaxClientTtl = 8.0;
const double heartbeatInterval = 4.0;

struct WuClient {
  StunUserIdentifier serverUser;
  StunUserIdentifier serverPassword;
  StunUserIdentifier remoteUser;
  StunUserIdentifier remoteUserPassword;
  struct sockaddr_in address;
  WuClientState state = WuClient_Dead;
  uint16_t localSctpPort = 0;
  uint16_t remoteSctpPort = 0;
  uint32_t sctpVerificationTag = 0;
  uint32_t remoteTsn = 0;
  uint32_t tsn = 1;
  double ttl = kMaxClientTtl;
  double nextHeartbeat = heartbeatInterval;

  SSL* ssl;
  BIO* inBio;
  BIO* outBio;

  void* user;
};

void WuClientSetUserData(WuClient* client, void* user) { client->user = user; }

void* WuClientGetUserData(const WuClient* client) { return client->user; }

void SslInfoCallback(const SSL* ssl, int where, int ret) {
  (void)where;
  (void)ret;
  (void)ssl;
}

void WuClientFinish(WuClient* client) {
  SSL_free(client->ssl);
  client->ssl = NULL;
  client->inBio = NULL;
  client->outBio = NULL;
  client->state = WuClient_Dead;
}

void WuClientStart(const WuHost* wu, WuClient* client) {
  client->state = WuClient_DTLSHandshake;
  client->remoteSctpPort = 0;
  client->sctpVerificationTag = 0;
  client->remoteTsn = 0;
  client->tsn = 1;
  client->ttl = kMaxClientTtl;
  client->nextHeartbeat = heartbeatInterval;
  client->user = NULL;

  client->ssl = SSL_new(wu->sslCtx);
  SSL_set_info_callback(client->ssl, SslInfoCallback);

  client->inBio = BIO_new(BIO_s_mem());
  BIO_set_mem_eof_return(client->inBio, -1);
  client->outBio = BIO_new(BIO_s_mem());
  BIO_set_mem_eof_return(client->outBio, -1);
  SSL_set_bio(client->ssl, client->inBio, client->outBio);
  SSL_set_options(client->ssl, SSL_OP_SINGLE_ECDH_USE);
  SSL_set_options(client->ssl, SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
  SSL_set_tmp_ecdh(client->ssl, EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  SSL_set_accept_state(client->ssl);
}

void WuSendSctp(const WuHost* wu, WuClient* client, const SctpPacket* packet,
                const SctpChunk* chunks, int32_t numChunks);

WuClient* WuHostNewClient(WuHost* wu) {
  WuClient* client = (WuClient*)WuPoolAcquire(wu->clientPool);
  memset(client, 0, sizeof(WuClient));

  if (client) {
    WuClientStart(wu, client);
    wu->clients[wu->numClients++] = client;
    return client;
  }

  return NULL;
}

void WuHostPushEvent(WuHost* wu, WuEvent evt) {
  WuQueuePush(&wu->pendingEvents, &evt);
}

void WuSendSctpShutdown(WuHost* wu, WuClient* client) {
  SctpPacket response;
  response.sourcePort = client->localSctpPort;
  response.destionationPort = client->remoteSctpPort;
  response.verificationTag = client->sctpVerificationTag;

  SctpChunk rc;
  rc.type = Sctp_Shutdown;
  rc.flags = 0;
  rc.length = SctpChunkLength(sizeof(rc.as.shutdown.cumulativeTsnAck));
  rc.as.shutdown.cumulativeTsnAck = client->remoteTsn;

  WuSendSctp(wu, client, &response, &rc, 1);
}

void WuRemoveClient(WuHost* wu, WuClient* client) {
  for (int32_t i = 0; i < wu->numClients; i++) {
    if (wu->clients[i] == client) {
      WuSendSctpShutdown(wu, client);
      WuClientFinish(client);
      WuPoolRelease(wu->clientPool, client);
      wu->clients[i] = wu->clients[wu->numClients - 1];
      wu->numClients--;
      return;
    }
  }
}

bool SockAddrEqual(const sockaddr_in* a, const sockaddr_in* b) {
  return a->sin_family == b->sin_family &&
         a->sin_addr.s_addr == b->sin_addr.s_addr && a->sin_port == b->sin_port;
}

void WuHandleHttpRequest(WuHost* wu, WuConnectionBuffer* conn) {
  for (;;) {
    ssize_t count = read(conn->fd, conn->requestBuffer + conn->size,
                         kMaxHttpRequestLength - conn->size);
    if (count == -1) {
      if (errno != EAGAIN) {
        perror("read");
        close(conn->fd);
        wu->bufferPool->Reclaim(conn);
      }
      return;
    } else if (count == 0) {
      close(conn->fd);
      wu->bufferPool->Reclaim(conn);
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
          ICESdpFields iceFields;
          if (ParseSdp((const char*)conn->requestBuffer + parseStatus,
                       contentLength, &iceFields)) {
            WuClient* client = WuHostNewClient(wu);

            if (client) {
              client->serverUser.length = 4;
              WuRandomString((char*)client->serverUser.identifier,
                             client->serverUser.length);
              client->serverPassword.length = 24;
              WuRandomString((char*)client->serverPassword.identifier,
                             client->serverPassword.length);
              memcpy(
                  client->remoteUser.identifier, iceFields.ufrag.value,
                  std::min(iceFields.ufrag.length, kMaxStunIdentifierLength));
              client->remoteUser.length = iceFields.ufrag.length;
              memcpy(client->remoteUserPassword.identifier,
                     iceFields.password.value,
                     std::min(iceFields.password.length,
                              kMaxStunIdentifierLength));

              int bodyLength = 0;
              const char* body = GenerateSDP(
                  &wu->arena, wu->cert->fingerprint, wu->conf->host,
                  wu->conf->port, (char*)client->serverUser.identifier,
                  client->serverUser.length,
                  (char*)client->serverPassword.identifier,
                  client->serverPassword.length, &iceFields, &bodyLength);

              char response[4096];
              int responseLength = snprintf(response, 4096,
                                            "HTTP/1.1 200 OK\r\n"
                                            "Content-Type: application/json\r\n"
                                            "Content-Length: %d\r\n"
                                            "Connection: close\r\n"
                                            "Access-Control-Allow-Origin: *\r\n"
                                            "\r\n%s",
                                            bodyLength, body);
              SocketWrite(conn->fd, response, responseLength);
            } else {
              SocketWrite(conn->fd, STRLIT(HTTP_UNAVAILABLE));
            }

          } else {
            SocketWrite(conn->fd, STRLIT(HTTP_BAD_REQUEST));
          }

          close(conn->fd);
          wu->bufferPool->Reclaim(conn);
        }
      }

      return;
    } else if (parseStatus == -1) {
      close(conn->fd);
      wu->bufferPool->Reclaim(conn);
      return;
    } else {
      if (conn->size == kMaxHttpRequestLength) {
        SocketWrite(conn->fd, STRLIT(HTTP_BAD_REQUEST));
        close(conn->fd);
        wu->bufferPool->Reclaim(conn);
        return;
      }
    }
  }
}

WuClient* WuHostFindClient(WuHost* wu, const sockaddr_in* address) {
  for (int32_t i = 0; i < wu->numClients; i++) {
    WuClient* client = wu->clients[i];
    if (SockAddrEqual(&client->address, address)) {
      return client;
    }
  }

  return NULL;
}

WuClient* WuHostFindClientByCreds(WuHost* wu, const StunUserIdentifier* svUser,
                                  const StunUserIdentifier* clUser) {
  for (int32_t i = 0; i < wu->numClients; i++) {
    WuClient* client = wu->clients[i];
    if (StunUserIdentifierEqual(&client->serverUser, svUser) &&
        StunUserIdentifierEqual(&client->remoteUser, clUser)) {
      return client;
    }
  }

  return NULL;
}

ssize_t UDPSend(const WuHost* wu, const WuClient* client, const void* data,
                size_t size) {
  int ret = sendto(wu->udpfd, data, size, 0, (struct sockaddr*)&client->address,
                   sizeof(client->address));
  return ret;
}

void WuClientSendPendingDTLS(const WuHost* wu, WuClient* client) {
  uint8_t sendBuffer[4096];

  while (BIO_ctrl_pending(client->outBio) > 0) {
    int bytes = BIO_read(client->outBio, sendBuffer, sizeof(sendBuffer));
    if (bytes > 0) {
      UDPSend(wu, client, sendBuffer, bytes);
    }
  }
}

void TLSSend(const WuHost* wu, WuClient* client, const void* data,
             int32_t length) {
  if (client->state < WuClient_DTLSHandshake ||
      !SSL_is_init_finished(client->ssl)) {
    return;
  }

  SSL_write(client->ssl, data, length);
  WuClientSendPendingDTLS(wu, client);
}

void WuSendSctp(const WuHost* wu, WuClient* client, const SctpPacket* packet,
                const SctpChunk* chunks, int32_t numChunks) {
  uint8_t outBuffer[4096];
  memset(outBuffer, 0, sizeof(outBuffer));
  size_t bytesWritten = SerializeSctpPacket(packet, chunks, numChunks,
                                            outBuffer, sizeof(outBuffer));
  TLSSend(wu, client, outBuffer, bytesWritten);
}

void WuHostHandleSctp(WuHost* wu, WuClient* client, const uint8_t* buf,
                      int32_t len) {
  const size_t maxChunks = 8;
  SctpChunk chunks[maxChunks];
  SctpPacket sctpPacket;
  size_t nChunk = 0;

  if (!ParseSctpPacket(buf, len, &sctpPacket, chunks, maxChunks, &nChunk)) {
    return;
  }

  for (size_t n = 0; n < nChunk; n++) {
    SctpChunk* chunk = &chunks[n];
    if (chunk->type == Sctp_Data) {
      auto* dataChunk = &chunk->as.data;
      const uint8_t* userDataBegin = dataChunk->userData;
      const int32_t userDataLength = dataChunk->userDataLength;

      client->remoteTsn = std::max(chunk->as.data.tsn, client->remoteTsn);
      client->ttl = kMaxClientTtl;

      if (dataChunk->protoId == DCProto_Control) {
        DataChannelPacket packet;
        ParseDataChannelControlPacket(userDataBegin, userDataLength, &packet);
        if (packet.messageType == DCMessage_Open) {
          client->remoteSctpPort = sctpPacket.sourcePort;
          uint8_t outType = DCMessage_Ack;
          SctpPacket response;
          response.sourcePort = sctpPacket.destionationPort;
          response.destionationPort = sctpPacket.sourcePort;
          response.verificationTag = client->sctpVerificationTag;

          SctpChunk rc;
          rc.type = Sctp_Data;
          rc.flags = kSctpFlagCompleteUnreliable;
          rc.length = SctpDataChunkLength(1);

          auto* dc = &rc.as.data;
          dc->tsn = client->tsn++;
          dc->streamId = chunk->as.data.streamId;
          dc->streamSeq = 0;
          dc->protoId = DCProto_Control;
          dc->userData = &outType;
          dc->userDataLength = 1;

          if (client->state != WuClient_DataChannelOpen) {
            client->state = WuClient_DataChannelOpen;
            WuEvent event;
            event.type = WuEvent_ClientJoin;
            event.client = client;
            WuHostPushEvent(wu, event);
          }

          WuSendSctp(wu, client, &response, &rc, 1);
        }
      } else if (dataChunk->protoId == DCProto_String) {
        WuEvent evt;
        evt.type = WuEvent_TextData;
        evt.client = client;
        evt.as.data.buf = dataChunk->userData;
        evt.as.data.length = dataChunk->userDataLength;
        WuHostPushEvent(wu, evt);
      } else if (dataChunk->protoId == DCProto_Binary) {
        WuEvent evt;
        evt.type = WuEvent_BinaryData;
        evt.client = client;
        evt.as.data.buf = dataChunk->userData;
        evt.as.data.length = dataChunk->userDataLength;
        WuHostPushEvent(wu, evt);
      }

      SctpPacket sack;
      sack.sourcePort = sctpPacket.destionationPort;
      sack.destionationPort = sctpPacket.sourcePort;
      sack.verificationTag = client->sctpVerificationTag;

      SctpChunk rc;
      rc.type = Sctp_Sack;
      rc.flags = 0;
      rc.length = SctpChunkLength(12);
      rc.as.sack.cumulativeTsnAck = client->remoteTsn;
      rc.as.sack.advRecvWindow = kSctpDefaultBufferSpace;
      rc.as.sack.numGapAckBlocks = 0;
      rc.as.sack.numDupTsn = 0;

      WuSendSctp(wu, client, &sack, &rc, 1);
    } else if (chunk->type == Sctp_Init) {
      SctpPacket response;
      response.sourcePort = sctpPacket.destionationPort;
      response.destionationPort = sctpPacket.sourcePort;
      response.verificationTag = chunk->as.init.initiateTag;
      client->sctpVerificationTag = response.verificationTag;
      client->remoteTsn = chunk->as.init.initialTsn - 1;

      SctpChunk rc;
      rc.type = Sctp_InitAck;
      rc.flags = 0;
      rc.length = kSctpMinInitAckLength;

      rc.as.init.initiateTag = WuRandomU32();
      rc.as.init.windowCredit = kSctpDefaultBufferSpace;
      rc.as.init.numOutboundStreams = chunk->as.init.numInboundStreams;
      rc.as.init.numInboundStreams = chunk->as.init.numOutboundStreams;
      rc.as.init.initialTsn = client->tsn;

      WuSendSctp(wu, client, &response, &rc, 1);
      break;
    } else if (chunk->type == Sctp_CookieEcho) {
      if (client->state < WuClient_SCTPEstablished) {
        client->state = WuClient_SCTPEstablished;
      }
      SctpPacket response;
      response.sourcePort = sctpPacket.destionationPort;
      response.destionationPort = sctpPacket.sourcePort;
      response.verificationTag = client->sctpVerificationTag;

      SctpChunk rc;
      rc.type = Sctp_CookieAck;
      rc.flags = 0;
      rc.length = SctpChunkLength(0);

      WuSendSctp(wu, client, &response, &rc, 1);
    } else if (chunk->type == Sctp_Heartbeat) {
      SctpPacket response;
      response.sourcePort = sctpPacket.destionationPort;
      response.destionationPort = sctpPacket.sourcePort;
      response.verificationTag = client->sctpVerificationTag;

      SctpChunk rc;
      rc.type = Sctp_HeartbeatAck;
      rc.flags = 0;
      rc.length = chunk->length;
      rc.as.heartbeat.heartbeatInfoLen = chunk->as.heartbeat.heartbeatInfoLen;
      rc.as.heartbeat.heartbeatInfo = chunk->as.heartbeat.heartbeatInfo;

      client->ttl = kMaxClientTtl;

      WuSendSctp(wu, client, &response, &rc, 1);
    } else if (chunk->type == Sctp_HeartbeatAck) {
      client->ttl = kMaxClientTtl;
    } else if (chunk->type == Sctp_Abort) {
      client->state = WuClient_WaitingRemoval;
      return;
    } else if (chunk->type == Sctp_Sack) {
      auto* sack = &chunk->as.sack;
      if (sack->numGapAckBlocks > 0) {
        SctpPacket fwdResponse;
        fwdResponse.sourcePort = sctpPacket.destionationPort;
        fwdResponse.destionationPort = sctpPacket.sourcePort;
        fwdResponse.verificationTag = client->sctpVerificationTag;

        SctpChunk fwdTsnChunk;
        fwdTsnChunk.type = SctpChunk_ForwardTsn;
        fwdTsnChunk.flags = 0;
        fwdTsnChunk.length = SctpChunkLength(4);
        fwdTsnChunk.as.forwardTsn.newCumulativeTsn = client->tsn;
        WuSendSctp(wu, client, &fwdResponse, &fwdTsnChunk, 1);
      }
    }
  }
}

void WuHostReceiveDTLSPacket(WuHost* wu, uint8_t* data, size_t length,
                             sockaddr_in* address) {
  WuClient* client = WuHostFindClient(wu, address);
  if (!client) {
    return;
  }

  BIO_write(client->inBio, data, length);

  if (!SSL_is_init_finished(client->ssl)) {
    int r = SSL_do_handshake(client->ssl);

    if (r < 0) {
      r = SSL_get_error(client->ssl, r);
      if (SSL_ERROR_WANT_READ == r) {
        WuClientSendPendingDTLS(wu, client);
      }
    }
  } else {
    WuClientSendPendingDTLS(wu, client);

    while (BIO_ctrl_pending(client->inBio) > 0) {
      uint8_t receiveBuffer[8092];
      int bytes = SSL_read(client->ssl, receiveBuffer, sizeof(receiveBuffer));

      if (bytes > 0) {
        uint8_t* buf = (uint8_t*)WuArenaAcquire(&wu->arena, bytes);
        memcpy(buf, receiveBuffer, bytes);
        WuHostHandleSctp(wu, client, buf, bytes);
      }
    }
  }
}

void WuHostHandleStun(WuHost* wu, const StunPacket* packet,
                      const sockaddr_in* address) {
  WuClient* client =
      WuHostFindClientByCreds(wu, &packet->serverUser, &packet->remoteUser);

  if (!client) {
    // TODO: Send unauthorized
    return;
  }

  StunPacket outPacket;
  outPacket.type = Stun_SuccessResponse;
  memcpy(outPacket.transactionId, packet->transactionId,
         kStunTransactionIdLength);
  outPacket.xorMappedAddress.family = Stun_IPV4;
  outPacket.xorMappedAddress.port =
      htons(ntohs(address->sin_port) ^ kStunXorMagic);
  outPacket.xorMappedAddress.address.ipv4 =
      htonl(ntohl(address->sin_addr.s_addr) ^ kStunCookie);

  uint8_t stunResponse[512];
  size_t serializedSize =
      SerializeStunPacket(&outPacket, client->serverPassword.identifier,
                          client->serverPassword.length, stunResponse, 512);
  sendto(wu->udpfd, stunResponse, serializedSize, 0, (struct sockaddr*)address,
         sizeof(sockaddr_in));

  client->localSctpPort = ntohs(address->sin_port);
  client->address = *address;
}

void WuHostPurgeDeadClients(WuHost* wu) {
  for (int32_t i = 0; i < wu->numClients; i++) {
    WuClient* client = wu->clients[i];
    if (client->ttl <= 0.0 || client->state == WuClient_WaitingRemoval) {
      WuEvent evt;
      evt.type = WuEvent_ClientLeave;
      evt.client = client;
      WuHostPushEvent(wu, evt);
    }
  }
}

int32_t WuCryptoInit(WuHost* wu, const WuConf* conf) {
  static bool initDone = false;

  if (!initDone) {
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    initDone = true;
  }

  wu->sslCtx = SSL_CTX_new(DTLSv1_method());
  if (!wu->sslCtx) {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  int sslStatus =
      SSL_CTX_set_cipher_list(wu->sslCtx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
  if (sslStatus != 1) {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  SSL_CTX_set_verify(wu->sslCtx, SSL_VERIFY_NONE, NULL);

  wu->cert = WuCertNew();

  sslStatus = SSL_CTX_use_PrivateKey(wu->sslCtx, wu->cert->key);

  if (sslStatus != 1) {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  sslStatus = SSL_CTX_use_certificate(wu->sslCtx, wu->cert->x509);

  if (sslStatus != 1) {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  sslStatus = SSL_CTX_check_private_key(wu->sslCtx);

  if (sslStatus != 1) {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  return 1;
}

int32_t WuInit(WuHost* wu, const WuConf* conf) {
  WuArenaInit(&wu->arena, 1 << 20);
  wu->time = MsNow() * 0.001;
  wu->dt = 0.0;

  wu->port = atoi(conf->port);
  if (!WuCryptoInit(wu, conf)) {
    return 0;
  }

  wu->tcpfd = CreateSocket(conf->port, ST_TCP);

  if (wu->tcpfd == -1) {
    return 0;
  }

  int s = MakeNonBlocking(wu->tcpfd);
  if (s == -1) {
    return 0;
  }

  s = listen(wu->tcpfd, SOMAXCONN);
  if (s == -1) {
    perror("listen");
    return 0;
  }

  wu->udpfd = CreateSocket(conf->port, ST_UDP);

  if (wu->udpfd == -1) {
    return 0;
  }

  s = MakeNonBlocking(wu->udpfd);
  if (s == -1) {
    return 0;
  }

  wu->epfd = epoll_create1(0);
  if (wu->epfd == -1) {
    perror("epoll_create");
    return 0;
  }

  const int32_t maxEvents = 128;

  WuQueueInit(&wu->pendingEvents, sizeof(WuEvent), 1024);
  wu->bufferPool = new WuConnectionBufferPool(maxEvents + 2);

  WuConnectionBuffer* udpBuf = wu->bufferPool->GetBuffer();
  udpBuf->fd = wu->udpfd;

  WuConnectionBuffer* tcpBuf = wu->bufferPool->GetBuffer();
  tcpBuf->fd = wu->tcpfd;

  struct epoll_event event;
  event.data.ptr = tcpBuf;
  event.events = EPOLLIN | EPOLLET;

  s = epoll_ctl(wu->epfd, EPOLL_CTL_ADD, wu->tcpfd, &event);
  if (s == -1) {
    perror("epoll_ctl");
    return 0;
  }

  event.data.ptr = udpBuf;
  s = epoll_ctl(wu->epfd, EPOLL_CTL_ADD, wu->udpfd, &event);
  if (s == -1) {
    perror("epoll_ctl");
    return 0;
  }

  wu->maxEvents = maxEvents;
  wu->events = (struct epoll_event*)calloc(wu->maxEvents, sizeof(event));
  wu->conf = conf;

  wu->maxClients = 256;
  wu->numClients = 0;
  wu->clientPool = WuPoolCreate(sizeof(WuClient), wu->maxClients);
  wu->clients = (WuClient**)calloc(wu->maxClients, sizeof(WuClient*));

  return 1;
}

void WuSendHeartbeat(WuHost* wu, WuClient* client) {
  SctpPacket packet;
  packet.sourcePort = wu->port;
  packet.destionationPort = client->remoteSctpPort;
  packet.verificationTag = client->sctpVerificationTag;

  SctpChunk rc;
  rc.type = Sctp_Heartbeat;
  rc.flags = kSctpFlagCompleteUnreliable;
  rc.length = SctpChunkLength(4 + 8);
  rc.as.heartbeat.heartbeatInfo = (const uint8_t*)&wu->time;
  rc.as.heartbeat.heartbeatInfoLen = sizeof(wu->time);

  WuSendSctp(wu, client, &packet, &rc, 1);
}

void WuHostUpdateClients(WuHost* wu) {
  double t = MsNow() * 0.001;
  wu->dt = t - wu->time;
  wu->time = t;

  for (int32_t i = 0; i < wu->numClients; i++) {
    WuClient* client = wu->clients[i];
    client->ttl -= wu->dt;
    client->nextHeartbeat -= wu->dt;

    if (client->nextHeartbeat <= 0.0) {
      client->nextHeartbeat = heartbeatInterval;
      WuSendHeartbeat(wu, client);
    }

    WuClientSendPendingDTLS(wu, client);
  }
}

int32_t WuServe(WuHost* wu, WuEvent* evt) {
  if (WuQueuePop(&wu->pendingEvents, evt)) {
    return 1;
  }

  WuHostUpdateClients(wu);
  WuArenaReset(&wu->arena);
  int n = epoll_wait(wu->epfd, wu->events, wu->maxEvents, 0);

  WuConnectionBufferPool* pool = wu->bufferPool;
  for (int i = 0; i < n; i++) {
    struct epoll_event* e = &wu->events[i];
    WuConnectionBuffer* c = (WuConnectionBuffer*)e->data.ptr;
    if ((e->events & EPOLLERR) || (e->events & EPOLLHUP) ||
        (!(e->events & EPOLLIN))) {
      close(c->fd);
      pool->Reclaim(c);
      continue;
    } else if (wu->tcpfd == c->fd) {
      for (;;) {
        struct sockaddr_in inAddress;
        socklen_t inLength = sizeof(inAddress);

        int infd = accept(wu->tcpfd, (struct sockaddr*)&inAddress, &inLength);
        if (infd == -1) {
          if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
            break;
          } else {
            perror("accept");
            break;
          }
        }

        if (MakeNonBlocking(infd) == -1) {
          abort();
        }

        WuConnectionBuffer* conn = pool->GetBuffer();
        assert(conn);
        conn->fd = infd;

        struct epoll_event event;
        event.events = EPOLLIN | EPOLLET;
        event.data.ptr = conn;
        if (epoll_ctl(wu->epfd, EPOLL_CTL_ADD, infd, &event) == -1) {
          perror("epoll_ctl");
          abort();
        }
      }
      continue;
    } else if (wu->udpfd == c->fd) {
      struct sockaddr_in remote;
      socklen_t remoteLen = sizeof(remote);
      uint8_t buf[4096];

      ssize_t r = 0;
      do {
        r = recvfrom(wu->udpfd, buf, 4096, 0, (struct sockaddr*)&remote,
                     &remoteLen);
        StunPacket stunPacket;
        if (ParseStun(buf, r, &stunPacket)) {
          WuHostHandleStun(wu, &stunPacket, &remote);
        } else {
          WuHostReceiveDTLSPacket(wu, buf, size_t(r), &remote);
        }
      } while (r > 0);

    } else {
      WuHandleHttpRequest(wu, c);
    }
  }

  if (WuQueuePop(&wu->pendingEvents, evt)) {
    return 1;
  }

  WuHostPurgeDeadClients(wu);

  return 0;
}

int32_t WuSendData(WuHost* wu, WuClient* client, const uint8_t* data,
                   int32_t length, DataChanProtoIdentifier proto) {
  if (client->state < WuClient_DataChannelOpen) {
    return -1;
  }

  SctpPacket packet;
  packet.sourcePort = wu->port;
  packet.destionationPort = client->remoteSctpPort;
  packet.verificationTag = client->sctpVerificationTag;

  SctpChunk rc;
  rc.type = Sctp_Data;
  rc.flags = kSctpFlagCompleteUnreliable;
  rc.length = SctpDataChunkLength(length);

  auto* dc = &rc.as.data;
  dc->tsn = client->tsn++;
  dc->streamId = 0;  // TODO: Does it matter?
  dc->streamSeq = 0;
  dc->protoId = proto;
  dc->userData = data;
  dc->userDataLength = length;

  WuSendSctp(wu, client, &packet, &rc, 1);
  return 0;
}

int32_t WuSendText(WuHost* wu, WuClient* client, const char* text,
                   int32_t length) {
  return WuSendData(wu, client, (const uint8_t*)text, length, DCProto_String);
}

int32_t WuSendBinary(WuHost* wu, WuClient* client, const uint8_t* data,
                     int32_t length) {
  return WuSendData(wu, client, data, length, DCProto_Binary);
}
