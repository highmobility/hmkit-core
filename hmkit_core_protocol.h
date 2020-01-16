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

#ifndef HMKIT_CORE_PROTOCOL_H_
#define HMKIT_CORE_PROTOCOL_H_

#define PACKET_BEGIN    0x00
#define PACKET_END      0xFF
#define PACKET_ESCAPE   0xFE

#define SECURE_CONT_HEADER_SIZE_V1 4 // Byte1: 0x36, Byte2: 0x01/0x02(for MAC), Byte3: Size bigger byte (MSB), Byte4: Size Lower byte(LSB)
#define SECURE_CONT_HEADER_SIZE_V2 8 // Byte1: 0x36, Byte2: Version, Byte3: HMAC flag, Byte4: content type, Byte5 to Byte8: Size( 4 bytes)

//BT Commands
#define ID_RESTART_SOFTWARE       0xAA

#define ID_ACK_COMMAND   0x01
#define ID_ERROR         0x02

//TODO REMOVE OLD AUTH
#define ID_SET_AUTHENTICATION_PASSWORD 	0x20
#define ID_CREATE_AUTHENTICATION_TOKEN 	0x21
#define ID_REVOKE_AUTHENTICATION_TOKEN 	0x22
#define ID_AUTHENTICATE 			   	0x23

#define ID_START_PING 			0x24
#define ID_STOP_PING 			0x25
#define ID_PING_NOTIFICATION 	0x26

#define ID_CUSTOM_COMMAND	 	0x27

#define ID_CRYPTO_GET_NONCE 0x30
#define ID_CRYPTO_GET_DEVICE_CERTIFICATE 0x31
#define ID_CRYPTO_REGISTER_CERTIFICATE 0x32
#define ID_CRYPTO_STORE_CERTIFICATE 0x33
#define ID_CRYPTO_GET_CERTIFICATE 0x34
#define ID_CRYPTO_AUTHENTICATE 0x35
#define ID_CRYPTO_CONTAINER 0x36
#define ID_CRYPTO_RESET 0x37
#define ID_CRYPTO_REVOKE 0x38
#define ID_REQUEST_USER_FEEDBACK 0x39
#define ID_CRYPTO_AUTHENTICATE_DONE 0x40
#define ID_ERROR_COMMAND 0x41

#define ID_READ_STORAGE			0xE1
#define ID_WRITE_STORAGE		0xE2
#define ID_DELETE_STORAGE 	    0xE3

#define ID_BEACON_ZONE_CALCULATED      0xB5
#define ID_BEACON_REPORT_RECEIVED      0xB6
#define ID_BEACON_SET_RADAR_RULE       0xB7

#define ID_WRITE_GP_OUTPUT 	0x0C
#define ID_READ_GP_INPUT 	0x0D

#define ID_WRITE_STD_CAN_FRAME   				0x03
#define ID_WRITE_EXT_CAN_FRAME   				0x04
#define ID_READ_STD_CAN_FRAME    				0x05
#define ID_READ_EXT_CAN_FRAME    				0x06
#define ID_GET_CAN_FILTERING_ENABLED_STATUS     0x07
#define ID_SET_CAN_FILTERING_ENABLED_STATUS     0x08
#define ID_GET_CAN_FILTER                    	0x09
#define ID_SET_CAN_FILTER 						0x0A
#define ID_GET_CAN_SYSTEM_STATUS 				0x0B // TODO: error count, packet count, etc.
#define ID_WRITE_ISO_MESSAGE 					0x0F
#define ID_READ_ISO_MESSAGE 					0x10

//BT Errors
// Reserve 0x00
#define ERR_INTERNAL_ERROR       0x01
#define ERR_COMMAND_EMPTY        0x02
#define ERR_COMMAND_UNKNOWN      0x03
#define ERR_INVALID_DATA         0x04
#define ERR_STORAGE_FULL         0x05
#define ERR_INVALID_SIGNATURE    0x06
#define ERR_UNAUTHORISED         0x07
#define ERR_INVALID_HMAC         0x08
#define ERR_TIMEOUT              0x09
#define ERR_NOT_ACCEPTED         0x10

#endif /* HMKIT_CORE_PROTOCOL_H_ */
