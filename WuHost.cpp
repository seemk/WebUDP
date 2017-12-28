#ifdef WU_EPOLL
#include "WuHostEpoll.cpp"
#else

#include "WuHost.h"
WuHost* WuHostCreate(const WuConf*) { return NULL; }
void WuHostSetNonblocking(WuHost*, int32_t) {}
int32_t WuHostServe(WuHost*, WuEvent*) { return 0; }
void WuHostRemoveClient(WuHost*, WuClient*) {}
int32_t WuHostSendText(WuHost*, WuClient*, const char*, int32_t) { return 0; }
int32_t WuHostSendBinary(WuHost*, WuClient*, const uint8_t*, int32_t) {
  return 0;
}
void WuHostSetErrorCallback(WuHost*, WuErrorFn) {}

#endif
