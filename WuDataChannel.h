#pragma once

#include <stddef.h>
#include <stdint.h>

enum DataChannelMessageType { DCMessage_Ack = 0x02, DCMessage_Open = 0x03 };

enum DataChanProtoIdentifier {
  DCProto_Control = 50,
  DCProto_String = 51,
  DCProto_Binary = 53,
  DCProto_EmptyString = 56,
  DCProto_EmptyBinary = 57
};

struct DataChannelPacket {
  uint8_t messageType;

  union {
    struct {
      uint8_t channelType;
      uint16_t priority;
      uint32_t reliability;
    } open;
  } as;
};

int32_t ParseDataChannelControlPacket(const uint8_t* buf, size_t len,
                                      DataChannelPacket* packet);
