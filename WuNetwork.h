#pragma once
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#if defined(_MSC_VER)
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif

enum SocketType { ST_TCP, ST_UDP };

ssize_t SocketWrite(int fd, const uint8_t* buf, size_t len);
ssize_t SocketWrite(int fd, const char* buf, size_t len);
void HexDump(const uint8_t* src, size_t len);
int MakeNonBlocking(int sfd);
int CreateSocket(const char* port, SocketType type);
