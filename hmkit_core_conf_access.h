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

#ifndef HMKIT_CORE_CONF_ACCESS_H_
#define HMKIT_CORE_CONF_ACCESS_H_

#include <stdint.h>

void hmkit_core_conf_access_get_ca_public_key(uint8_t *publicKey);
void hmkit_core_conf_access_get_ibeacon_uuid(uint8_t *uuid);
void hmkit_core_conf_access_get_appid_issure_uuid(uint8_t *uuid);
void hmkit_core_conf_access_get_cu_uuid(uint8_t *uuid);
void hmkit_core_conf_access_get_txrx_uuid(uint8_t *uuid);
uint16_t hmkit_core_conf_access_get_txrx_service(void);
uint16_t hmkit_core_conf_access_get_txrx_rx_char(void);
uint16_t hmkit_core_conf_access_get_txrx_tx_char(void);
uint16_t hmkit_core_conf_access_get_txrx_ping_char(void);
uint16_t hmkit_core_conf_access_get_txrx_info_char(void);
uint16_t hmkit_core_conf_access_get_txrx_incoming_rx_char(void);
uint16_t hmkit_core_conf_access_get_txrx_incoming_tx_char(void);
void hmkit_core_conf_access_get_issuer(uint8_t *issuer);
void hmkit_core_conf_access_get_app_id(uint8_t *appId);

#endif /* HMKIT_CORE_CONF_ACCESS_H_ */
