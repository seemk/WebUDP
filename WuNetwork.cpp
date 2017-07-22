#include "WuNetwork.h"
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

void HexDump(const uint8_t* src, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (i % 8 == 0) printf("%04x ", uint32_t(i));

    printf("%02x ", src[i]);

    if ((i + 1) % 8 == 0) printf("\n");
  }
  printf("\n");
}

ssize_t SocketWrite(int fd, const uint8_t* buf, size_t len) {
  const ssize_t towrite = (ssize_t)len;
  ssize_t written = 0;
  while (written != towrite) {
    ssize_t r = write(fd, buf + written, towrite - written);
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

int MakeNonBlocking(int sfd) {
  int flags = fcntl(sfd, F_GETFL, 0);
  if (flags == -1) {
    return -1;
  }

  flags |= O_NONBLOCK;

  int s = fcntl(sfd, F_SETFL, flags);
  if (s == -1) {
    return -1;
  }

  return 0;
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
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));

    s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
    if (s == 0) {
      break;
    }

    close(sfd);
  }

  freeaddrinfo(result);

  if (rp == NULL) {
    return -1;
  }

  return sfd;
}
