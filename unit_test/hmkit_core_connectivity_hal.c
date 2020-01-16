
#include "hmkit_core_connectivity_hal.h"
#include "hmkit_core_conf_access.h"

#define BLE_GATT_HVX_NOTIFICATION 0x01
#define MAX_CLIENTS 5

uint8_t unit_test_character = 0;
uint8_t unit_test_mac[6] = {0x00,0x00,0x00,0x00,0x00,0x00};
uint64_t unit_test_context = 0;
uint16_t unit_test_offset = 0;
uint16_t unit_test_length = 0;
uint8_t unit_test_data[1024];

void hmkit_core_connectivity_hal_delay_ms(uint32_t number_of_ms){
  BTUNUSED(number_of_ms);
}

uint32_t hmkit_core_connectivity_hal_scan_start(){
  return 0;
}

uint32_t hmkit_core_connectivity_hal_scan_stop(){
  return 0;
}

uint32_t hmkit_core_connectivity_hal_advertisement_start(uint8_t *issuerId, uint8_t *appId){
  BTUNUSED(issuerId);
  BTUNUSED(appId);
  return 0;
}

uint32_t hmkit_core_connectivity_hal_advertisement_stop(){
  return 0;
}

uint32_t hmkit_core_connectivity_hal_write_data(uint64_t btcontxtId, uint8_t *mac, uint16_t length, uint8_t *data, hmkit_core_characteristic characteristic){
  unit_test_context = btcontxtId;
  memcpy(unit_test_mac,mac,6);
  unit_test_character = characteristic;
  memcpy(unit_test_data + unit_test_length, data, length);
  unit_test_length = unit_test_length + length;

  //hmkit_core_bt_core_sensing_write_response(btcontxtId, mac, characteristic);

  return 0;
}

uint32_t hmkit_core_connectivity_hal_read_data(uint64_t btcontxtId, uint8_t *mac, uint16_t offset, hmkit_core_characteristic characteristic){
  unit_test_context = btcontxtId;
  memcpy(unit_test_mac,mac,6);
  unit_test_offset = offset;
  unit_test_character = characteristic;
  return 0;
}

uint32_t hmkit_core_connectivity_hal_read_info(uint64_t btcontxtId, uint8_t *mac, uint16_t offset, hmkit_core_characteristic characteristic){
  BTUNUSED(btcontxtId);
  BTUNUSED(mac);
  BTUNUSED(offset);
  BTUNUSED(characteristic);
  return 0;
}

uint32_t hmkit_core_connectivity_hal_service_discovery(uint8_t *mac){
  BTUNUSED(mac);
  return 0;
}

uint32_t hmkit_core_connectivity_hal_init(){
  unit_test_length = 0;
  return 0;
}

uint32_t hmkit_core_connectivity_hal_clock(){
  return 0;
}

uint32_t hmkit_core_connectivity_hal_connect(const uint8_t *mac, uint8_t macType){
  BTUNUSED(mac);
  BTUNUSED(macType);
  return 0;
}

uint32_t hmkit_core_connectivity_hal_disconnect(uint64_t btcontxtId, uint8_t *mac){
  BTUNUSED(btcontxtId);
  BTUNUSED(mac);
  return 0;
}

uint32_t hmkit_core_connectivity_hal_get_current_date_time(uint8_t *day, uint8_t *month, uint8_t *year, uint8_t *minute, uint8_t *hour){
  BTUNUSED(day);
  BTUNUSED(month);
  BTUNUSED(year);
  BTUNUSED(minute);
  BTUNUSED(hour);
  return 0;
}

uint32_t hmkit_core_connectivity_hal_telematics_send_data(uint64_t appContxtId, uint8_t *issuer, uint8_t *serial, uint16_t length, uint8_t *data){
  BTUNUSED(issuer);
  BTUNUSED(serial);
  BTUNUSED(length);
  BTUNUSED(data);
  BTUNUSED(appContxtId);
  return 0;
}
