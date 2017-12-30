#include "WuDataChannel.h"
#include <stdio.h>
#include "WuBufferOp.h"

int32_t ParseDataChannelControlPacket(const uint8_t* buf, size_t len,
                                      DataChannelPacket* packet) {
  ReadScalarSwapped(buf, &packet->messageType);
  return 0;
}
