#include "WuDataChannel.h"
#include <stdio.h>
#include "WuBufferOp.h"

int32_t ParseDataChannelControlPacket(const uint8_t* buf, size_t len,
                                      DataChannelPacket* packet) {
  ReadScalarSwapped(buf, &packet->messageType);
  return 0;
}

const char* DataChannelMessageTypeName(uint8_t type) {
  switch (type) {
    case DCMessage_Ack:
      return "ack";
    case DCMessage_Open:
      return "open";
    default:
      return "unknown";
  }
}
