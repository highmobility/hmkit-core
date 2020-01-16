
/*
The MIT License

Copyright (c) 2014- High-Mobility GmbH (https://high-mobility.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include "hmkit_core_crypto_hal.h"
#include <string.h>

uint32_t hmkit_core_crypto_hal_aes_ecb_block_encrypt(uint64_t appContxtId, uint8_t *key, uint8_t *cleartext, uint8_t *cipertext){
  BTUNUSED(key);
  BTUNUSED(cleartext);
  BTUNUSED(cipertext);
  BTUNUSED(appContxtId);
  return 0;
}

uint32_t hmkit_core_crypto_hal_ecc_get_ecdh(uint64_t appContxtId, uint8_t *serial, uint8_t *ecdh){
  BTUNUSED(serial);
  BTUNUSED(ecdh);
  BTUNUSED(appContxtId);
  return 0;
}

uint32_t hmkit_core_crypto_hal_ecc_add_signature(uint64_t appContxtId, uint8_t *data, uint8_t size, uint8_t *signature){
  BTUNUSED(data);
  BTUNUSED(size);
  BTUNUSED(signature);
  BTUNUSED(appContxtId);
  return 0;
}

uint32_t hmkit_core_crypto_hal_ecc_validate_signature(uint64_t appContxtId, uint8_t *data, uint8_t size, uint8_t *signature, uint8_t *serial){
  BTUNUSED(data);
  BTUNUSED(size);
  BTUNUSED(signature);
  BTUNUSED(serial);
  BTUNUSED(appContxtId);
  return 0;
}

uint32_t hmkit_core_crypto_hal_ecc_validate_all_signatures(uint64_t appContxtId, uint8_t *data, uint8_t size, uint8_t *signature){
  BTUNUSED(data);
  BTUNUSED(size);
  BTUNUSED(signature);
  BTUNUSED(appContxtId);
  return 0;
}

uint32_t hmkit_core_crypto_hal_ecc_validate_ca_signature(uint64_t appContxtId, uint8_t *data, uint8_t size, uint8_t *signature){
  BTUNUSED(data);
  BTUNUSED(size);
  BTUNUSED(signature);
  BTUNUSED(appContxtId);
  return 0;
}

uint32_t hmkit_core_crypto_hal_ecc_validate_oem_ca_signature(uint64_t appContxtId, uint8_t *data, uint8_t size, uint8_t *signature){
  BTUNUSED(data);
  BTUNUSED(size);
  BTUNUSED(signature);
  BTUNUSED(appContxtId);
  return 0;
}

uint32_t hmkit_core_crypto_hal_hmac(uint64_t appContxtId, uint8_t *key, uint8_t *data, uint16_t size, uint8_t *hmac){
  BTUNUSED(key);
  BTUNUSED(data);
  BTUNUSED(size);
  BTUNUSED(hmac);
  BTUNUSED(appContxtId);
  return 0;
}

uint32_t hmkit_core_crypto_hal_generate_nonce(uint64_t appContxtId, uint8_t *nonce){
  BTUNUSED(nonce);
  BTUNUSED(appContxtId);
  return 0;
}
