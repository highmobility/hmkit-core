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

#include "hmkit_core_conf_access.h"
#include "hmkit_core_conf.h"
#include <string.h>

void hmkit_core_conf_access_get_ca_public_key(uint8_t *publicKey){
  uint8_t key[64] = {HMKIT_CORE_CONFIG_CA_PUBLIC_KEY};
  memcpy(publicKey,key,64);
}

void hmkit_core_conf_access_get_ibeacon_uuid(uint8_t *uuid){
  uint8_t uuidNew[16] = {HMKIT_CORE_CONFIG_IBEACON_UUID};
  memcpy(uuid,uuidNew,16);
}

void hmkit_core_conf_access_get_appid_issure_uuid(uint8_t *uuid){
  uint8_t uuidNew[16] = {HMKIT_CORE_CONFIG_APP_ID, HMKIT_CORE_CONFIG_ISSUER};
  memcpy(uuid,uuidNew,16);
}

void hmkit_core_conf_access_get_cu_uuid(uint8_t *uuid){
  uint8_t uuidNew[16] = {HMKIT_CORE_CONFIG_CU_UUID};
  memcpy(uuid,uuidNew,16);
}

void hmkit_core_conf_access_get_txrx_uuid(uint8_t *uuid){
  uint8_t uuidNew[16] = {HMKIT_CORE_CONFIG_TXRX_UUID};
  memcpy(uuid,uuidNew,16);
}

uint16_t hmkit_core_conf_access_get_txrx_service(){
  return HMKIT_CORE_CONFIG_TXRX_SERVICE;
}

uint16_t hmkit_core_conf_access_get_txrx_rx_char(){
  return HMKIT_CORE_CONFIG_TXRX_RX_CHAR;
}

uint16_t hmkit_core_conf_access_get_txrx_tx_char(){
  return HMKIT_CORE_CONFIG_TXRX_TX_CHAR;
}

uint16_t hmkit_core_conf_access_get_txrx_ping_char(){
  return HMKIT_CORE_CONFIG_TXRX_PING_CHAR;
}

uint16_t hmkit_core_conf_access_get_txrx_info_char(){
  return HMKIT_CORE_CONFIG_TXRX_INFO_CHAR;
}

uint16_t hmkit_core_conf_access_get_txrx_incoming_rx_char(){
  return HMKIT_CORE_CONFIG_TXRX_INC_RX_CHAR;
}

uint16_t hmkit_core_conf_access_get_txrx_incoming_tx_char(){
  return HMKIT_CORE_CONFIG_TXRX_INC_TX_CHAR;
}

void hmkit_core_conf_access_get_issuer(uint8_t *issuer){
  uint8_t issuerNew[4] = {HMKIT_CORE_CONFIG_ISSUER};
  memcpy(issuer,issuerNew,4);
}

void hmkit_core_conf_access_get_app_id(uint8_t *appId){
  uint8_t appIdNew[12] = {HMKIT_CORE_CONFIG_APP_ID};
  memcpy(appId,appIdNew,12);
}
