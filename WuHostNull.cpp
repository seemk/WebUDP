#include "WuHost.h"

struct WuConf {
  const char* host = "127.0.0.1";
  const char* port = "9555";
  int maxClients = 256;
};

WuHost* WuHostCreate(const WuConf*) { return NULL; }
int32_t WuHostServe(WuHost*, WuEvent*) { return 0; }
void WuHostRemoveClient(WuHost*, WuClient*) {}
int32_t WuHostSendText(WuHost*, WuClient*, const char*, int32_t) { return 0; }
int32_t WuHostSendBinary(WuHost*, WuClient*, const uint8_t*, int32_t) {
  return 0;
}
void WuHostSetErrorCallback(WuHost*, WuErrorFn) {}
