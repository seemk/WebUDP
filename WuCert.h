#pragma once

#include <openssl/x509.h>

struct WuCert {
  X509* x509;
  EVP_PKEY* key;
  char fingerprint[96];
};

WuCert* WuCertNew();
void WuCertDestroy(WuCert* cert);
