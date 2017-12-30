#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../WuHost.h"

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

  WuHost* host = WuHostCreate(&conf);
  if (!host) {
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
