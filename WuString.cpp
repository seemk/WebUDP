#include "WuString.h"
#include <ctype.h>
#include <stdint.h>
#include <string.h>

uint32_t StringToUint(const char* s, size_t len) {
  uint32_t v = 0;
  uint32_t mul = 1;

  for (size_t i = len; i > 0; i--) {
    uint32_t c = s[i - 1];
    v += (c - '0') * mul;
    mul *= 10;
  }

  return v;
}

bool CompareCaseInsensitive(const char* first, size_t lenFirst,
                            const char* second, size_t lenSecond) {
  if (lenFirst != lenSecond) return false;

  for (size_t i = 0; i < lenFirst; i++) {
    if (tolower(first[i]) != second[i]) {
      return false;
    }
  }

  return true;
}

int32_t FindTokenIndex(const char* s, size_t len, char token) {
  for (size_t i = 0; i < len; i++) {
    if (s[i] == token) return i;
  }

  return -1;
}

bool MemEqual(const void* first, size_t firstLen, const void* second,
              size_t secondLen) {
  if (firstLen != secondLen) return false;

  return memcmp(first, second, firstLen) == 0;
}
