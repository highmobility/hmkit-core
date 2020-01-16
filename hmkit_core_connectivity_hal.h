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

#include <stdint.h>
#include "hmkit_core.h"

uint32_t hmkit_core_connectivity_hal_init(void);

uint32_t hmkit_core_connectivity_hal_clock(void);

uint32_t hmkit_core_connectivity_hal_scan_start(void);
uint32_t hmkit_core_connectivity_hal_scan_stop(void);

uint32_t hmkit_core_connectivity_hal_advertisement_start(uint8_t *issuerId, uint8_t *appId);
uint32_t hmkit_core_connectivity_hal_advertisement_stop(void);

uint32_t hmkit_core_connectivity_hal_connect(const uint8_t *mac, uint8_t macType);
uint32_t hmkit_core_connectivity_hal_disconnect(uint64_t btcontxtId,uint8_t *mac);

uint32_t hmkit_core_connectivity_hal_service_discovery(uint8_t *mac);

uint32_t hmkit_core_connectivity_hal_write_data(uint64_t btcontxtId, uint8_t *mac, uint16_t length, uint8_t *data, hmkit_core_characteristic characteristic);
uint32_t hmkit_core_connectivity_hal_read_data(uint64_t btcontxtId, uint8_t *mac, uint16_t offset, hmkit_core_characteristic characteristic);

uint32_t hmkit_core_connectivity_hal_read_info(uint64_t btcontxtId, uint8_t *mac, uint16_t offset, hmkit_core_characteristic characteristic);

void hmkit_core_connectivity_hal_delay_ms(uint32_t number_of_ms);

uint32_t hmkit_core_connectivity_hal_get_current_date_time(uint8_t *day, uint8_t *month, uint8_t *year, uint8_t *minute, uint8_t *hour);

uint32_t hmkit_core_connectivity_hal_telematics_send_data(uint64_t appContxtId_Tele, uint8_t *issuer, uint8_t *serial, uint16_t length, uint8_t *data);
