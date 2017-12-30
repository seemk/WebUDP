#include "Fuzz.h"
#include "../WuSctp.h"

int main(int argc, char** argv) {
  if (argc < 2) return 1;

  size_t length = 0;
  uint8_t* content = LoadFile(argv[1], &length);

  if (content) {
    const size_t maxChunks = 8;
    SctpChunk chunks[maxChunks];
    SctpPacket sctpPacket;
    size_t nChunk = 0;

    ParseSctpPacket(content, length, &sctpPacket, chunks, maxChunks, &nChunk);
  }

  return 0;
}
