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

#ifndef HMKIT_CORE_API_H_
#define HMKIT_CORE_API_H_

#include <stdint.h>

typedef struct {
    uint8_t version;
    uint8_t issuer[4];
    uint8_t gaining_serial[9];
    uint8_t public_key[64];
    uint8_t providing_serial[9];
    uint8_t start_date[5];
    uint8_t end_date[5];
    uint8_t permissions_size;
    uint8_t permissions[16];
    uint8_t ca_signature[64];
} hmkit_core_certificate_t;

typedef struct {
    uint8_t   mac[6];
    uint8_t   serial_number[9];
    uint8_t   app_id[12];
    uint8_t   issuer_id[4];
    hmkit_core_certificate_t certificate;
    uint8_t   is_authorised;
    uint16_t   major;
    uint16_t   minor;
    uint8_t info_string[30];
    uint8_t   nonce[9];
} hmkit_core_device_t;

typedef struct {
    uint8_t  id;
    int8_t   rssi;
} hmkit_core_receiver_t;

//COMMUNICATION
/**
* This method is used to send device certificate request
*
* @param mac This is pointer to mac address where this request will be sent
* @param nonce This is pointer to nonce what will be added to request
* @param ca_signature This is pointer to CA signature what will be added to request
*
* @return uint8_t request execution error code
*/
uint8_t hmkit_core_api_send_read_device_certificate(uint64_t appContxtId, uint8_t *mac, uint8_t *nonce, uint8_t *ca_signature);

/**
* This method is used to send register/update access certificate request
*
* @param cert This is pointer to certificate what will be added to request
*
* @return uint8_t request execution error code
*/
uint8_t hmkit_core_api_send_register_access_certificate(uint64_t appContxtId, hmkit_core_certificate_t *cert);

/**
* This method is used to send custom command request
*
* @param serial_number This is pointer to serial number where request will be sent
* @param data This is pointer to data what will be added to request
* @param size This is data size
*
* @return uint8_t request execution error code
*/
uint8_t hmkit_core_api_send_custom_command(uint64_t appContxtId, uint8_t *serial_number, uint8_t content_type, uint8_t *data, uint32_t size, uint8_t *reqID, uint16_t reqID_size, uint8_t version);

//PERSISTENCE
/**
* This method is used to get local public key
*
* @param public_key This is pointer to 64 bytes long public key
*
* @return uint8_t request execution error code
*/
uint8_t hmkit_core_api_get_public_key(uint64_t appContxtId, uint8_t *public_key);

/**
* This method is used to get local serial number
*
* @param public_key This is pointer to 9 bytes long serial number
*
* @return uint8_t request execution error code
*/
uint8_t hmkit_core_api_get_serial_number(uint64_t appContxtId, uint8_t *serial_number);

/**
* This method is used to get access certificate using serial number
*
* @param serial_number This is pointer to 9 bytes long serial number
* @param serial_number This is pointer to access certificate
*
* @return uint8_t request execution error code
*/
uint8_t hmkit_core_api_get_access_certificate(uint64_t appContxtId, uint8_t *serial_number, uint8_t *cert);

/**
* This method is used to store access certificate
*
* @param cert This is pointer to certificate data
*
* @return uint8_t request execution error code
*/
uint8_t hmkit_core_api_store_access_certificate(uint64_t appContxtId, hmkit_core_certificate_t *cert);

/**
* This method is used to remove access certificate
*
* @param serial_number This is pointer to 9 bytes long serial number
*
* @return uint8_t request execution error code
*/
uint8_t hmkit_core_api_remove_access_certificate(uint64_t appContxtId, uint8_t *serial_number);

//RUNTIME INFO
/**
* This method is used to retrieve all currently authorised devices
*
* @param device_size This is pointer to number what contains devices array size
* @param devices This is pointer to hmkit_core_devices_t structure array
*
* @return uint8_t request execution error code
*/
uint8_t hmkit_core_api_retrieve_authorised_devices(uint8_t *device_size, hmkit_core_device_t *devices); //Loeb mälust cerdid ainult

//BLE
/**
* This method is used to turn on/off bluetooth
*
* @param action This is parameter what tells to turn on/of bluetooth. 0 - off, 1 - on
*
* @return uint8_t request execution error code
*/
uint8_t hmkit_core_api_ble_on(uint8_t action);


uint8_t hmkit_core_api_disconnect(uint8_t *mac);


void hmkit_core_api_send_telematics_command(uint64_t appContxtId_Tele, uint8_t *serial, uint8_t *nonce, uint8_t content_type, uint32_t length, uint8_t *data, uint8_t *reqID, uint16_t reqID_size, uint8_t version);

uint32_t hmkit_core_api_get_current_date_time(uint8_t *day, uint8_t *month, uint8_t *year, uint8_t *minute, uint8_t *hour);

#endif /* HMKIT_CORE_API_H_ */
