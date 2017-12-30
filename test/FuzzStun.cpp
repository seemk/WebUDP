#include "Fuzz.h"
#include "../WuStun.h"

int main(int argc, char** argv) {
  if (argc < 2) return 1;

  size_t length = 0;
  uint8_t* content = LoadFile(argv[1], &length);

  if (content) {
    StunPacket packet;
    ParseStun(content, length, &packet);
  }

  return 0;
}
