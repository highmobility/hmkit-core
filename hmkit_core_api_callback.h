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

#ifndef HMKIT_CORE_API_CALLBACK_H_
#define HMKIT_CORE_API_CALLBACK_H_

#include <stdbool.h>
#include "hmkit_core.h"
#include "hmkit_core_api.h"

/**
* This method is called during initialisation process
*/
void hmkit_core_api_callback_init(void);

/**
* This method is called after every clock cycle
*/
void hmkit_core_api_callback_clock(void);

/**
* This method is called when ping notification comes in
*/
void hmkit_core_api_callback_ping(void);

/**
* This method is called when device is entered proximity
*
* @param device This is pointer to hmkit_core_device_t structure, see details in hmkit_core_api.h
*/
void hmkit_core_api_callback_entered_proximity(uint64_t appContxtId, hmkit_core_device_t *device);

/**
* This method is called when device proximity info is mesaured
*
* @param device This is pointer to hmkit_core_device_t structure, see details in hmkit_core_api.h
*/
void hmkit_core_api_callback_proximity_measured(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t receiver_count, hmkit_core_receiver_t *receivers);

/**
* This method is called when device is exited from proximity
*
* @param device This is pointer to hmkit_core_device_t structure, see details in hmkit_core_api.h
*/
void hmkit_core_api_callback_exited_proximity(uint64_t appContxtId, hmkit_core_device_t *device);

/**
* This method is called when custom command is received.
* If you want to send some response data then overwrite data with response data and change length
*
* @param device This is pointer to hmkit_core_device_t structure, see details in hmkit_core_api.h
* @param data This is pointer to custom command data
* @param length This is custom command data length
*/
void hmkit_core_api_callback_command_incoming(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t content_type, uint8_t *data, uint32_t length, uint8_t *respID, uint16_t respID_size, uint8_t version);

/**
* This method is called when custom command response is received after sending custom command.
*
* @param device This is pointer to hmkit_core_device_t structure, see details in hmkit_core_api.h
* @param data This is pointer to response data
* @param length This is response data length
*/
void hmkit_core_api_callback_command_response(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t content_type, uint8_t *data, uint32_t length, uint8_t *respID, uint16_t respID_size, uint8_t version);

/**
* This method is called when Error response is received after sending custom command.
*
* @param appContxtId ContextID handler
* @param device This is pointer to hmkit_core_device_t structure, see details in hmkit_core_api.h
* @param errortype Error Type Received
*/
void hmkit_core_api_callback_command_response_error(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t errortype);

/**
* This method is called when Error Command is received.
*
* @param device This is a pointer to hmkit_core_device_t structure, see details in hmkit_core_api.h
* @param command: Command ID value of the reponse Message which contained erroneous data
* @param errorType: Type of the Error occurred
*/
void hmkit_core_api_callback_error_command_incoming(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t command, uint8_t errorType);

/**
* This method is called when getting device certificate request failed.
* To proceed with getting device cert then ask from CA to get signature
* to get device certificate request using nonce parameter.
* If you return error then identify flow is stopped
*
* @param device This is pointer to hmkit_core_device_t structure, see details in hmkit_core_api.h
* @param nonce This is nonce what to use in CA signed request
*
* @return uint32_t This return error code
*/
uint32_t hmkit_core_api_callback_get_device_certificate_failed(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t *nonce);

/**
* This method is called when register device certificate response is received.
*
* @param device This is pointer to hmkit_core_device_t structure, see details in hmkit_core_api.h
* @param public_key This is pointer to response public key
* @param error This is response error code
*/
void hmkit_core_api_callback_access_certificate_registered(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t *public_key, uint8_t error);

/**
* This method is called when register device certificate request is received.
* If you want to accept the pairing then return success other wise return error.
*
* @param device This is pointer to hmkit_core_device_t structure, see details in hmkit_core_api.h
*
* @return uint32_t This returns error code
*/
uint32_t hmkit_core_api_callback_pairing_requested(uint64_t appContxtId, hmkit_core_device_t *device);

/**
* This method is called when data is coming in from backend.
*
* @param device This is pointer to hmkit_core_device_t structure, see details in hmkit_core_api.h
* @param length This is incoming data length
* @param data This is pointer to incoming data
*/
void hmkit_core_api_callback_telematics_command_incoming(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t id, uint8_t content_type, uint32_t length, uint8_t *data, uint8_t *respID, uint16_t respID_size, uint8_t version);

uint32_t hmkit_core_api_callback_get_current_date_time(uint8_t *day, uint8_t *month, uint8_t *year, uint8_t *minute, uint8_t *hour);

void hmkit_core_api_callback_revoke_response(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t *data, uint16_t length, uint8_t status);

void hmkit_core_api_callback_revoke_incoming(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t *data, uint16_t *size);

#endif /* HMKIT_CORE_API_CALLBACK_H_ */
