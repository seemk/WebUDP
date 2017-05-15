#include "WuCrypto.h"
#include <openssl/hmac.h>

WuSHA1Digest WuSHA1(const uint8_t* src, size_t len, const void* key,
                    size_t keyLen) {
  WuSHA1Digest digest;
  HMAC(EVP_sha1(), key, keyLen, src, len, digest.bytes, NULL);

  return digest;
}
