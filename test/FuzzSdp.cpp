#include "Fuzz.h"
#include "../Wu.h"

int main(int argc, char** argv) {
  if (argc < 2) return 1;

  size_t length = 0;
  uint8_t* content = LoadFile(argv[1], &length);

  Wu* wu = nullptr;
  const char* host = "127.0.0.1";
  const char*  port = "5000";
  int32_t maxClients = 256;

  if (!WuCreate(host, port, maxClients, &wu)) {
    return 0;
  }

  if (content) {
    WuExchangeSDP(wu, (const char*)content, length);
  }

  return 0;
}
