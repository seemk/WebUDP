#include "WuCert.h"
#include <assert.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdlib.h>
#include "WuRng.h"

WuCert* WuCertNew() {
  WuCert* cert = (WuCert*)calloc(1, sizeof(WuCert));
  cert->key = EVP_PKEY_new();

  RSA* rsa = RSA_new();
  BIGNUM* n = BN_new();
  BN_set_word(n, RSA_F4);

  if (!RAND_status()) {
    uint64_t seed = WuRandomU64();
    RAND_seed(&seed, sizeof(seed));
  }

  RSA_generate_key_ex(rsa, 1024, n, NULL);
  EVP_PKEY_assign_RSA(cert->key, rsa);

  cert->x509 = X509_new();

  BIGNUM* serial = BN_new();
  X509_NAME* name = X509_NAME_new();
  X509_set_pubkey(cert->x509, cert->key);
  BN_pseudo_rand(serial, 64, 0, 0);

  X509_set_version(cert->x509, 0L);
  X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_UTF8,
                             (unsigned char*)"wusocket", -1, -1, 0);
  X509_set_subject_name(cert->x509, name);
  X509_set_issuer_name(cert->x509, name);
  X509_gmtime_adj(X509_get_notBefore(cert->x509), 0);
  X509_gmtime_adj(X509_get_notAfter(cert->x509), 365 * 24 * 3600);
  X509_sign(cert->x509, cert->key, EVP_sha1());

  unsigned int len = 32;
  uint8_t buf[32] = {0};
  X509_digest(cert->x509, EVP_sha256(), buf, &len);

  assert(len == 32);
  for (unsigned int i = 0; i < len; i++) {
    if (i < 31) {
      snprintf(cert->fingerprint + i * 3, 4, "%02X:", buf[i]);
    } else {
      snprintf(cert->fingerprint + i * 3, 3, "%02X", buf[i]);
    }
  }

  cert->fingerprint[95] = '\0';

  BN_free(n);
  BN_free(serial);
  X509_NAME_free(name);

  return cert;
}

void WuCertDestroy(WuCert* cert) {
  EVP_PKEY_free(cert->key);
  X509_free(cert->x509);
}
