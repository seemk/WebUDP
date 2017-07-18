#include <stdio.h>
#include <stdlib.h>
#include <chrono>
#include <thread>
#include "../Wu.h"

int main(int argc, char** argv) {
  WuHost wu;

  WuConf conf;

  if (argc > 2) {
    conf.host = argv[1];
    conf.port = argv[2];
  } else {
    conf.host = "127.0.0.1";
    conf.port = "9555";
  }

  if (!WuInit(&wu, &conf)) {
    printf("init fail\n");
    return 1;
  }

  for (;;) {
    WuEvent evt;
    while (WuServe(&wu, &evt)) {
      switch (evt.type) {
        case WuEvent_ClientJoin: {
          printf("EchoServer: client join\n");
          break;
        }
        case WuEvent_ClientLeave: {
          printf("EchoServer: client leave\n");
          WuRemoveClient(&wu, evt.client);
          break;
        }
        case WuEvent_TextData: {
          const char* text = (const char*)evt.as.data.buf;
          int32_t length = evt.as.data.length;
          WuSendText(&wu, evt.client, text, length);
          break;
        }
        default:
          break;
      }
    }

    std::this_thread::sleep_for(std::chrono::microseconds(1));
  }

  return 0;
}
