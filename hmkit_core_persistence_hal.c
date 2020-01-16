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

#include "hmkit_core_persistence_hal.h"

uint32_t hmkit_core_persistence_hal_get_serial(uint64_t appContxtId, uint8_t *serial){
  BTUNUSED(serial);
  BTUNUSED(appContxtId);
  return 0;
}

uint32_t hmkit_core_persistence_hal_get_local_public_key(uint64_t appContxtId, uint8_t *public){
BTUNUSED(public);
BTUNUSED(appContxtId);
return 0;
}

uint32_t hmkit_core_persistence_hal_get_local_private_key(uint64_t appContxtId, uint8_t *public){
BTUNUSED(public);
BTUNUSED(appContxtId);
return 0;
}

uint32_t hmkit_core_persistence_hal_get_device_certificate(uint64_t appContxtId, uint8_t *cert){
  BTUNUSED(cert);
  BTUNUSED(appContxtId);
  return 0;
}

uint32_t hmkit_core_persistence_hal_get_ca_public_key(uint64_t appContxtId, uint8_t *public){
BTUNUSED(public);
BTUNUSED(appContxtId);
return 0;
}

uint32_t hmkit_core_persistence_hal_get_oem_ca_public_key(uint64_t appContxtId, uint8_t *public){
BTUNUSED(public);
BTUNUSED(appContxtId);
return 0;
}

uint32_t hmkit_core_persistence_hal_add_access_certificate(uint64_t appContxtId, uint8_t *serial, uint8_t *cert, uint16_t size){
  BTUNUSED(serial);
  BTUNUSED(cert);
  BTUNUSED(size);
  BTUNUSED(appContxtId);
  return 0;
}

uint32_t hmkit_core_persistence_hal_get_access_certificate(uint64_t appContxtId, uint8_t *serial, uint8_t *cert, uint16_t *size){
  BTUNUSED(serial);
  BTUNUSED(cert);
  BTUNUSED(size);
  BTUNUSED(appContxtId);
  return 0;
}

uint32_t hmkit_core_persistence_hal_get_access_certificate_by_index(uint64_t appContxtId, uint8_t index, uint8_t *cert, uint16_t *size){
  BTUNUSED(index);
  BTUNUSED(cert);
  BTUNUSED(size);
  BTUNUSED(appContxtId);
  return 0;
}

uint32_t hmkit_core_persistence_hal_get_access_certificate_count(uint64_t appContxtId, uint8_t *count){
  BTUNUSED(count);
  BTUNUSED(appContxtId);
  return 0;
}

uint32_t hmkit_core_persistence_hal_remove_access_certificate(uint64_t appContxtId, hmkit_core_certificate_t *certificate){
  BTUNUSED(certificate);
  BTUNUSED(appContxtId);
  return 0;
}

uint32_t hmkit_core_persistence_hal_erase_access_certificate(uint64_t appContxtId, hmkit_core_certificate_t *certificate){
  BTUNUSED(certificate);
  BTUNUSED(appContxtId);
  return 0;
}

uint32_t hmkit_core_persistence_hal_add_stored_certificate(uint64_t appContxtId, uint8_t *cert, uint16_t size){
  BTUNUSED(cert);
  BTUNUSED(size);
  BTUNUSED(appContxtId);
  return 0;
}

uint32_t hmkit_core_persistence_hal_get_stored_certificate(uint64_t appContxtId, uint8_t *serial, uint8_t *cert, uint16_t *size){
  BTUNUSED(serial);
  BTUNUSED(cert);
  BTUNUSED(size);
  BTUNUSED(appContxtId);
  return 0;
}

uint32_t hmkit_core_persistence_hal_erase_stored_certificate(uint64_t appContxtId, uint8_t *serial){
  BTUNUSED(serial);
  BTUNUSED(appContxtId);
  return 0;
}

uint32_t hmkit_core_persistence_hal_get_appid_for_issuer_count(uint64_t appContxtId, uint8_t *issuer, uint8_t *count){
  BTUNUSED(issuer);
  BTUNUSED(count);
  BTUNUSED(appContxtId);
  return 0;
}

uint32_t hmkit_core_persistence_hal_get_appid_for_issuer(uint64_t appContxtId, uint8_t *issuer, uint8_t index, uint8_t *appid){
  BTUNUSED(issuer);
  BTUNUSED(index);
  BTUNUSED(appid);
  BTUNUSED(appContxtId);
  return 0;
}

uint32_t hmkit_core_persistence_hal_set_command_count(uint64_t appContxtId, uint8_t *serial, uint8_t command, uint8_t count){
  BTUNUSED(serial);
  BTUNUSED(command);
  BTUNUSED(count);
  BTUNUSED(appContxtId);
  return 0;
}

uint32_t hmkit_core_persistence_hal_get_command_count(uint64_t appContxtId, uint8_t *serial, uint8_t command, uint8_t *count){
  BTUNUSED(serial);
  BTUNUSED(command);
  BTUNUSED(count);
  BTUNUSED(appContxtId);
  return 0;
}

uint32_t hmkit_core_persistence_hal_remove_all_command_counts(uint64_t appContxtId, uint8_t *serial){
  BTUNUSED(serial);
  BTUNUSED(appContxtId);
  return 0;
}
