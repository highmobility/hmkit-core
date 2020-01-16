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

#include "hmkit_core_connectivity_hal.h"
#include "hmkit_core_conf_access.h"

#define BLE_GATT_HVX_NOTIFICATION 0x01
#define MAX_CLIENTS 5

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
  BTUNUSED(mac);
  BTUNUSED(length);
  BTUNUSED(data);
  BTUNUSED(characteristic);
  BTUNUSED(btcontxtId);
  return 0;
}

uint32_t hmkit_core_connectivity_hal_read_data(uint64_t btcontxtId, uint8_t *mac, uint16_t offset, hmkit_core_characteristic characteristic){
  BTUNUSED(mac);
  BTUNUSED(offset);
  BTUNUSED(characteristic);
  BTUNUSED(btcontxtId);
  return 0;
}

uint32_t hmkit_core_connectivity_hal_read_info(uint64_t btcontxtId, uint8_t *mac, uint16_t offset, hmkit_core_characteristic characteristic){
  BTUNUSED(mac);
  BTUNUSED(offset);
  BTUNUSED(characteristic);
  BTUNUSED(btcontxtId);
  return 0;
}

uint32_t hmkit_core_connectivity_hal_service_discovery(uint8_t *mac){
  BTUNUSED(mac);
  return 0;
}

uint32_t hmkit_core_connectivity_hal_init(){
  return 0;
}

uint32_t hmkit_core_connectivity_hal_clock(void){
  return 0;
}

uint32_t hmkit_core_connectivity_hal_connect(const uint8_t *mac, uint8_t macType){
  BTUNUSED(mac);
  BTUNUSED(macType);
  return 0;
}

uint32_t hmkit_core_connectivity_hal_disconnect(uint64_t btcontxtId, uint8_t *mac){
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

uint32_t hmkit_core_connectivity_hal_telematics_send_data(uint64_t appContxtId_Tele, uint8_t *issuer, uint8_t *serial, uint16_t length, uint8_t *data){
  BTUNUSED(issuer);
  BTUNUSED(serial);
  BTUNUSED(length);
  BTUNUSED(data);
  BTUNUSED(appContxtId_Tele);
  return 0;
}
