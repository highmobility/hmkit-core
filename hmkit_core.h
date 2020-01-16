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

#ifndef HMKIT_CORE_H_
#define HMKIT_CORE_H_

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "hmkit_core_api.h"

#define SIZE_SER 9

typedef enum {
    hmkit_core_characteristic_link_read     =   0x02,
    hmkit_core_characteristic_link_write    =   0x03,
    hmkit_core_characteristic_alive         =   0x04,
    hmkit_core_characteristic_info          =   0x05,
    hmkit_core_characteristic_sensing_read  =   0x06,
    hmkit_core_characteristic_sensing_write =   0x07
} hmkit_core_characteristic;

// BTUNUSED macro
#define BTUNUSED(x) (void)(sizeof(x))

uint32_t hmkit_core_get_version_major_number(void);
uint32_t hmkit_core_get_version_minor_number(void);
uint32_t hmkit_core_get_version_patch_number(void);

void hmkit_core_init(void);
void hmkit_core_clock(void);

/**@brief Function for setting MTU for BT chunk data size.
 * API to be called in the Link side. MTU in Info characteristics should be updated before setting MTU with this API
 */
uint32_t hmkit_core_set_mtu(uint8_t *mac, uint16_t mtu);

uint16_t hmkit_core_roundof(uint16_t size);

//CORE SENSING

void hmkit_core_sensing_read_notification(uint64_t btcontxtId, uint8_t *mac, hmkit_core_characteristic characteristic);
void hmkit_core_sensing_read_response(uint64_t btcontxtId, uint8_t *data, uint16_t size, uint16_t offset, uint8_t *mac, hmkit_core_characteristic characteristic);

void hmkit_core_sensing_read_info_response(uint64_t btcontxtId, uint8_t *data, uint16_t size, uint16_t offset, uint8_t *mac, hmkit_core_characteristic characteristic);

void hmkit_core_sensing_write_response(uint64_t btcontxtId, uint8_t *mac, hmkit_core_characteristic characteristic);

void hmkit_core_sensing_ping_notification(uint64_t btcontxtId, uint8_t *mac, hmkit_core_characteristic characteristic);

void hmkit_core_sensing_process_advertisement( uint8_t *mac, uint8_t macType, uint8_t *data, uint8_t size);
void hmkit_core_sensing_discovery_event(uint8_t *mac);
void hmkit_core_sensing_scan_start(void);

void hmkit_core_sensing_connect(uint64_t contxtId, uint8_t *mac);
void hmkit_core_sensing_disconnect(uint8_t *mac);

void hmkit_core_explode(uint16_t source, uint8_t *dest);
uint16_t hmkit_core_implode(uint8_t *msb);

//CORE LINK
void hmkit_core_link_connect(uint64_t btcontxtId, uint8_t *mac);
void hmkit_core_link_disconnect(uint8_t *mac);

void hmkit_core_link_incoming_data(uint64_t btcontxtId, uint8_t *data, uint16_t size, uint8_t *mac, hmkit_core_characteristic characteristic);
void hmkit_core_link_write_response(uint64_t btcontxtId, uint8_t *mac, hmkit_core_characteristic characteristic);

//CORE INTERNAL API FOR CTW API
void hmkit_core_ble_on(uint8_t action);
void sendAuthenticate(uint64_t appContxtId, uint8_t *serial);
void sendGetDeviceCertificateRequest(uint64_t appContxtId, uint8_t isctw, uint8_t *requestData, uint8_t *mac);
void sendRegisterCertificate(uint64_t appContxtId, uint8_t isctw, uint8_t *certData, uint8_t size, uint8_t *serial);
void sendRevoke(uint64_t appContxtId, uint8_t *serial);
void sendSecureContainer(uint64_t appContxtId, uint8_t *serial, uint8_t content_type, uint8_t *dataBuffer, uint32_t size, uint8_t *requestID, uint16_t reqID_size, uint8_t version);
void sendSecureContainerUsingMac(uint64_t appContxtId, uint8_t *mac, uint8_t content_type, uint8_t *dataBuffer, uint32_t size, uint8_t *requestID, uint16_t reqID_size, uint8_t version);

void getAuthorisedDevises(uint8_t *device_size, hmkit_core_device_t *devices);

uint8_t hmkit_core_generate_hmac(uint64_t appContxtId, uint8_t* nonce, uint8_t *serial, uint8_t *data, uint16_t size, uint8_t *hmac);
uint8_t hmkit_core_generate_ecdh(uint64_t appContxtId, uint8_t* nonce, uint8_t *serial, uint8_t *ecdh);
void hmkit_core_encrypt_decrypt(uint64_t appContxtId, uint8_t *nonce, uint8_t *transaction_nonce, uint8_t *key, uint8_t *data, uint16_t data_size);

uint32_t hmkit_core_telematics_receive_data(uint64_t appContxtId, uint32_t length, uint8_t *data);

uint16_t hmkit_core_prepare_data(uint16_t size, uint8_t *in_data, uint8_t *out_data);
bool hmkit_core_parse_data( uint8_t *in_data, uint32_t length, uint8_t *out_data, uint32_t *out_data_position);

uint8_t hmkit_core_check_date_validity(uint8_t *start_date, uint8_t *end_date);

bool check_RequestID_length_limit(uint16_t reqID_size);

#endif /* HMKIT_CORE_H_ */
