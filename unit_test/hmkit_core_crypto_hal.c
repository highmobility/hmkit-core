
#include "hmkit_core_crypto_hal.h"
#include <string.h>

#include "test_common_vars.h"

uint32_t hmkit_core_crypto_hal_aes_ecb_block_encrypt(uint64_t appContxtId, uint8_t *key, uint8_t *cleartext, uint8_t *cipertext){
  BTUNUSED(key);
  BTUNUSED(cleartext);
  BTUNUSED(cipertext);
  BTUNUSED(appContxtId);
  return 0;
}

uint32_t hmkit_core_crypto_hal_ecc_get_ecdh(uint64_t appContxtId, uint8_t *serial, uint8_t *ecdh){
  
  BTUNUSED(serial);
  //TODO if(memcmp(serial,test_serial,9) == 0){
    memcpy(ecdh, test_ecdh,32);
  //}

  BTUNUSED(appContxtId);
  return 0;
}

uint32_t hmkit_core_crypto_hal_ecc_add_signature(uint64_t appContxtId, uint8_t *data, uint8_t size, uint8_t *signature){
  BTUNUSED(data);
  BTUNUSED(size);
  BTUNUSED(appContxtId);

  uint8_t mod = 0;
  mod = size % 64;

  if (mod) {
    return 1;
  }

  memcpy(signature,test_signature,64);

  return 0;
}

uint32_t hmkit_core_crypto_hal_ecc_validate_signature(uint64_t appContxtId, uint8_t *data, uint8_t size, uint8_t *signature, uint8_t *serial){
  BTUNUSED(data);
  BTUNUSED(size);

  uint8_t mod = 0;
  mod = size % 64;

  if (mod) {
    return 1;
  }
  
  //if(memcmp(serial,test_serial,9) == 0){
    if(memcmp(signature, test_signature,64) == 0){
      return 0;
    }
  //}

  BTUNUSED(serial);
  BTUNUSED(appContxtId);
  return 1;
}

uint32_t hmkit_core_crypto_hal_ecc_validate_all_signatures(uint64_t appContxtId, uint8_t *data, uint8_t size, uint8_t *signature){
  BTUNUSED(data);
  BTUNUSED(size);

  uint8_t mod = 0;
  mod = size % 64;

  if (mod) {
    return 1;
  }
  
  if(memcmp(signature, test_signature,64) == 0){
      return 0;
    }

  BTUNUSED(appContxtId);
  return 1;
}

uint32_t hmkit_core_crypto_hal_ecc_validate_ca_signature(uint64_t appContxtId, uint8_t *data, uint8_t size, uint8_t *signature){
  BTUNUSED(data);
  BTUNUSED(size);

  uint8_t mod = 0;
  mod = size % 64;

  if (mod) {
    return 1;
  }
  
  if(memcmp(signature, test_signature,64) == 0){
    return 0;
  }

  BTUNUSED(appContxtId);
  return 1;
}

uint32_t hmkit_core_crypto_hal_ecc_validate_oem_ca_signature(uint64_t appContxtId, uint8_t *data, uint8_t size, uint8_t *signature){
  BTUNUSED(data);
  BTUNUSED(size);

  uint8_t mod = 0;
  mod = size % 64;

  if (mod) {
    return 1;
  }
  
  if(memcmp(signature, test_signature,64) == 0){
    return 0;
  }

  BTUNUSED(appContxtId);
  return 1;
}

uint32_t hmkit_core_crypto_hal_hmac(uint64_t appContxtId, uint8_t *key, uint8_t *data, uint16_t size, uint8_t *hmac){
  BTUNUSED(key);
  BTUNUSED(data);
  BTUNUSED(size);
  BTUNUSED(appContxtId);

  uint8_t mod = 0;
  mod = size % 64;

  if (mod) {
    return 1;
  }

  memcpy(hmac, test_hmac, 32);

  return 0;
}

uint32_t hmkit_core_crypto_hal_generate_nonce(uint64_t appContxtId, uint8_t *nonce){
  BTUNUSED(appContxtId);
  memcpy(nonce,test_nonce,9);
  return 0;
}
