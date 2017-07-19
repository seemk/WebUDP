#include <stddef.h>
#include <stdint.h>

#define STRLIT(s) (s), sizeof(s) - 1

uint32_t StringToUint(const char* s, size_t len);
bool CompareCaseInsensitive(const char* first, size_t lenFirst,
                            const char* second, size_t lenSecond);
int32_t FindTokenIndex(const char* s, size_t len, char token);
bool MemEqual(const void* first, size_t firstLen, const void* second,
              size_t secondLen);
