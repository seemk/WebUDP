#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../WuHost.h"

int main(int argc, char** argv) {
  const char* hostAddr = "127.0.0.1";
  const char* port = "9555";
  int32_t maxClients = 256;

  if (argc > 2) {
    hostAddr = argv[1];
    port = argv[2];
  }

  WuHost* host = NULL;

  int32_t status = WuHostCreate(hostAddr, port, maxClients, &host);
  if (status != WU_OK) {
    printf("init fail\n");
    return 1;
  }

  WuHostSetErrorCallback(host, [](const char* err, void*) {
    printf("error: %s\n", err);
  });

  for (;;) {
    WuEvent evt;
    while (WuHostServe(host, &evt)) {
      switch (evt.type) {
        case WuEvent_ClientJoin: {
          printf("EchoServer: client join\n");
          break;
        }
        case WuEvent_ClientLeave: {
          printf("EchoServer: client leave\n");
          WuHostRemoveClient(host, evt.client);
          break;
        }
        case WuEvent_TextData: {
          const char* text = (const char*)evt.data;
          int32_t length = evt.length;
          WuHostSendText(host, evt.client, text, length);
          break;
        }
        default:
          break;
      }
    }
  }

  return 0;
}
