#pragma once

#include <stdint.h>
#include <stddef.h>

const size_t kSHA1Length = 20;

struct WuSHA1Digest {
  uint8_t bytes[kSHA1Length];
};

WuSHA1Digest WuSHA1(const uint8_t* src, size_t len, const void* key,
                    size_t keyLen);
