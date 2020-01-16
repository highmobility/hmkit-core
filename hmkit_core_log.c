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

#include "hmkit_core_log.h"
#include "hmkit_core_debug_hal.h"
#include "hmkit_core.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
//#include <stdlib.h>
#ifndef HM_CONFIG
#include "hmkit_core_config.h"
#endif

#ifdef HMKIT_CORE_LOG_LEVEL
static uint8_t hmkit_core_log_level = HMKIT_CORE_LOG_LEVEL;
#else
static uint8_t hmkit_core_log_level = HMKIT_CORE_LOG_OFF;
#endif

void hmkit_core_log_set_level(uint8_t loggingLevel){
    hmkit_core_log_level = loggingLevel;
}

//PROTOTYPES
int hmkit_core_log_add_mac_and_serial(char *buffer, uint8_t *macIn, uint8_t *serialIn);
extern uint16_t hmkit_core_get_dynamic_bufsize(void);

int hmkit_core_log_add_mac_and_serial(char *buffer, uint8_t *macIn, uint8_t *serialIn){
    uint8_t mac[6];
    uint8_t serial[9];

    memset(mac,0x00,6);
    memset(serial,0x00,9);

    if(macIn != NULL){
        memcpy(mac,macIn,6);
    }

    if(serialIn != NULL){
        memcpy(serial,serialIn,9);
    }

    return sprintf(buffer, "%02X:%02X:%02X:%02X:%02X:%02X %02X%02X%02X%02X%02X%02X%02X%02X%02X ",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],serial[0],serial[1],serial[2],serial[3],serial[4],serial[5],serial[6],serial[7],serial[8]);
}

void hmkit_core_log(uint8_t *mac, uint8_t *serial, uint8_t logLevel, const char *str, ...){
#ifdef HMKIT_CORE_LOG_LEVEL

    if(hmkit_core_log_level >= logLevel){
        char buffer[5000];

        int len = hmkit_core_log_add_mac_and_serial(buffer,mac,serial);

        va_list args;
        va_start(args, str);
        len += vsprintf(buffer + len, str, args);
        va_end(args);

        hmkit_core_debug_hal_log("%s", buffer);
    }
#else
    BTUNUSED(mac);
    BTUNUSED(serial);
    BTUNUSED(logLevel);
    BTUNUSED(str);
#endif
}

void hmkit_core_log_data(uint8_t *mac, uint8_t *serial, uint8_t logLevel, uint8_t *data, uint16_t dataSize, const char *str, ...){
#ifdef HMKIT_CORE_LOG_LEVEL

    if(hmkit_core_log_level >= logLevel && dataSize <= MAX_COMMAND_SIZE){

        char buffer[(MAX_COMMAND_SIZE * 5) + 300]; // Every byte value takes 5 chars in Hex print ie. 0x11_ 

        int len = hmkit_core_log_add_mac_and_serial(buffer,mac,serial);

        va_list args;
        va_start(args, str);
        len += vsprintf(buffer + len, str, args);
        va_end(args);

        uint16_t i = 0;

        len += sprintf(buffer + len, "\ndata:");

        for(i = 0 ; i < dataSize; i++){
            len += sprintf(buffer + len, " 0x%02X", data[i]);
        }

        hmkit_core_debug_hal_log("%s", buffer);
   }
#else
    BTUNUSED(mac);
    BTUNUSED(serial);
    BTUNUSED(logLevel);
    BTUNUSED(data);
    BTUNUSED(dataSize);
    BTUNUSED(str);
#endif
}
