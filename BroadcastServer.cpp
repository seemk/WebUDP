#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <algorithm>
#include "Wu.h"
#include "WuClock.h"

int main(int argc, char** argv) {
  WuHost wu;

  WuConf conf;
  conf.host = "192.168.11.63";
  conf.port = "9555";

  if (!WuInit(&wu, &conf)) {
    return 1;
  }

  std::vector<WuClient*> clients;

  double startTime = MsNow();
  double endTime = startTime;
  const double broadcastInterval = 1.0;
  double nextBroadcast = broadcastInterval;
  for (;;) {
    startTime = endTime;
    endTime = MsNow();
    double dt = (endTime - startTime) / 1000.0;
    nextBroadcast -= dt;

    WuEvent evt;
    while (WuServe(&wu, &evt)) {
      switch (evt.type) {
        case WuEvent_ClientJoin: {
          printf("Server: client join\n");
          clients.push_back(evt.client);
          break;
        }
        case WuEvent_ClientLeave: {
          printf("Server: client leave\n");
          clients.erase(std::remove(clients.begin(), clients.end(), evt.client), clients.end());
          break;
        }
        default:
          break;
      }
    }

    if (nextBroadcast <= 0.0) {
      nextBroadcast = broadcastInterval;
      for (WuClient* client : clients) {
        WuSendText(&wu, client, "foobar", 6);
      }
      //printf("boradcast\n");
    }
  }

  return 0;
}
