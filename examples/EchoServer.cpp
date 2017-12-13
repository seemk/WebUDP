#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../Wu.h"
#include "../WuEpoll.h"

int main(int argc, char** argv) {
  WuConf conf;
  memset(&conf, 0, sizeof(conf));

  if (argc > 2) {
    conf.host = argv[1];
    conf.port = argv[2];
  } else {
    conf.host = "127.0.0.1";
    conf.port = "9555";
  }

  conf.errorHandler = [](const char* e, void*) { printf("%s\n", e); };

  // TODO: Rename to host, different backends
  WuEpoll host;
  if (!WuEpollInit(&host, &conf)) {
    printf("init fail\n");
    return 1;
  }

  // TODO: Set blocking
  // The default mode is non-blocking.
  //conf.blocking = 1;

  for (;;) {
    WuEvent evt;
    while (WuServe(&host, &evt)) {
      switch (evt.type) {
        case WuEvent_ClientJoin: {
          printf("EchoServer: client join\n");
          break;
        }
        case WuEvent_ClientLeave: {
          printf("EchoServer: client leave\n");
          WuHostRemoveClient(&host, evt.client);
          break;
        }
        case WuEvent_TextData: {
          const char* text = (const char*)evt.data;
          int32_t length = evt.length;
          WuHostSendText(&host, evt.client, text, length);
          break;
        }
        default:
          break;
      }
    }
  }

  return 0;
}
