
#include "hmkit_core_persistence_hal.h"
#include "test_common_vars.h"

uint8_t unit_test_per_certificate_data[1024];
uint16_t unit_test_per_certificate_data_size = 0;
uint8_t unit_test_per_serial[9];
uint8_t unit_test_per_erase_serial[9];

uint32_t hmkit_core_persistence_hal_get_serial(uint64_t appContxtId, uint8_t *serial){
  BTUNUSED(appContxtId);

  memcpy(serial, test_serial, 9);

  return 0;
}

uint32_t hmkit_core_persistence_hal_get_local_public_key(uint64_t appContxtId, uint8_t *public){
  BTUNUSED(appContxtId);

  memcpy(public, test_pub_key, 64);

  return 0;
}

uint32_t hmkit_core_persistence_hal_get_local_private_key(uint64_t appContxtId, uint8_t *public){
BTUNUSED(public);
BTUNUSED(appContxtId);
return 0;
}

uint32_t hmkit_core_persistence_hal_get_device_certificate(uint64_t appContxtId, uint8_t *cert){
  BTUNUSED(appContxtId);

  memcpy(cert, test_device_certificate, 153);

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
  memcpy(unit_test_per_serial, serial,9);
  memcpy(unit_test_per_certificate_data,cert,size);
  unit_test_per_certificate_data_size = size;
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
  
  memcpy(unit_test_per_certificate_data,cert,size);
  unit_test_per_certificate_data_size = size;

  BTUNUSED(appContxtId);
  return 0;
}

uint32_t hmkit_core_persistence_hal_get_stored_certificate(uint64_t appContxtId, uint8_t *serial, uint8_t *cert, uint16_t *size){
  
  if(memcmp(serial,test_serial,9) == 0){
    memcpy(cert,test_access_certificate,165);
    *size = 165;
  }

  BTUNUSED(appContxtId);
  return 0;
}

uint32_t hmkit_core_persistence_hal_erase_stored_certificate(uint64_t appContxtId, uint8_t *serial){
  
  memcpy(unit_test_per_erase_serial,serial,9);

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
