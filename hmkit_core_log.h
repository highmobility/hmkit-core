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

#ifndef HMKIT_CORE_LOG_H
#define HMKIT_CORE_LOG_H

#include <stdint.h>

#define HMKIT_CORE_LOG_DEBUG    3
#define HMKIT_CORE_LOG_INFO     2
#define HMKIT_CORE_LOG_ERROR    1
#define HMKIT_CORE_LOG_OFF      0

void hmkit_core_log_set_level(uint8_t loggingLevel);
void hmkit_core_log(uint8_t *mac, uint8_t *serial, uint8_t logLevel, const char *str, ...);
void hmkit_core_log_data(uint8_t *mac, uint8_t *serial, uint8_t logLevel, uint8_t *data, uint16_t dataSize, const char *str, ...);

#endif //HMKIT_CORE_LOG_H
