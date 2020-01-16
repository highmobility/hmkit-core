#include "hmkit_core_crypto_hal.h"
#include "hmkit_core_persistence_hal.h"
#include "Crypto.h"
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include "hmkit_core_log.h"
#include "hmkit_core_cert.h"

uint32_t hmkit_core_crypto_hal_aes_ecb_block_encrypt(uint64_t appContxtId, uint8_t *key, uint8_t *cleartext, uint8_t *cipertext){
  return hm_crypto_openssl_aes_iv(key, cleartext, cipertext);
}

uint32_t hmkit_core_crypto_hal_ecc_get_ecdh(uint64_t appContxtId, uint8_t *serial, uint8_t *ecdh){

  uint8_t cert[178];
  uint16_t size = 0;
  hmkit_core_certificate_t certificate;

  if(hmkit_core_persistence_hal_get_access_certificate(appContxtId, serial, cert, &size) == 1){
    return 1;
  }

  hmkit_core_cert_get_as_struct(cert, &certificate);

  uint8_t priv[32];
  hmkit_core_persistence_hal_get_local_private_key(appContxtId, priv);

  return hm_crypto_openssl_dh(priv, certificate.public_key, ecdh);
}

uint32_t hmkit_core_crypto_hal_ecc_add_signature(uint64_t appContxtId, uint8_t *data, uint8_t size, uint8_t *signature){
  uint8_t private[32];
  hmkit_core_persistence_hal_get_local_private_key(appContxtId, private);
  return hm_crypto_openssl_signature(data, size, private, signature);
}

uint32_t hmkit_core_crypto_hal_ecc_validate_signature(uint64_t appContxtId, uint8_t *data, uint8_t size, uint8_t *signature, uint8_t *serial){

  uint8_t cert[178];
  uint16_t csize = 0;
  hmkit_core_certificate_t certificate;

  if(hmkit_core_persistence_hal_get_access_certificate(appContxtId, serial, cert, &csize) == 1){
    return 1;
  }

  hmkit_core_cert_get_as_struct(cert, &certificate);

  return hm_crypto_openssl_verify(data, size, certificate.public_key, signature);
}

uint32_t hmkit_core_crypto_hal_ecc_validate_all_signatures(uint64_t appContxtId, uint8_t *data, uint8_t size, uint8_t *signature){
  //TODO if needed
  return 0;
}

uint32_t hmkit_core_crypto_hal_ecc_validate_ca_signature(uint64_t appContxtId, uint8_t *data, uint8_t size, uint8_t *signature){
  uint8_t ca_pub[64];
  hmkit_core_persistence_hal_get_ca_public_key(appContxtId, ca_pub);
  return hm_crypto_openssl_verify(data, size, ca_pub, signature);
}

uint32_t hmkit_core_crypto_hal_ecc_validate_oem_ca_signature(uint64_t appContxtId, uint8_t *data, uint8_t size, uint8_t *signature){
  uint8_t ca_pub[64];
  hmkit_core_persistence_hal_get_oem_ca_public_key(appContxtId, ca_pub);
  return hm_crypto_openssl_verify(data, size, ca_pub, signature);
}

uint32_t hmkit_core_crypto_hal_hmac(uint64_t appContxtId, uint8_t *key, uint8_t *data, uint16_t size, uint8_t *hmac){
  return hm_crypto_openssl_hmac(data, size, key, hmac);
}

uint32_t hmkit_core_crypto_hal_generate_nonce(uint64_t appContxtId, uint8_t *nonce){
  srand(time(NULL));
  nonce[0] = rand();
  nonce[1] = rand();
  nonce[2] = rand();
  nonce[3] = rand();
  nonce[4] = rand();
  nonce[5] = rand();
  nonce[6] = rand();
  nonce[7] = rand();
  nonce[8] = rand();

  return 0;
}
