#include "Fuzz.h"
#include "../Wu.h"

int main(int argc, char** argv) {
  if (argc < 2) return 1;

  size_t length = 0;
  uint8_t* content = LoadFile(argv[1], &length);

  Wu wu;

  WuConf conf;
  conf.host = "127.0.0.1";
  conf.port = "5000";

  if (!WuInit(&wu, &conf)) {
    return 0;
  }

  if (content) {
    WuExchangeSDP(&wu, (const char*)content, length);
  }

  return 0;
}
