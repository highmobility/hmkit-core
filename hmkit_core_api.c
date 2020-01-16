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

#include "hmkit_core_api.h"
#include "string.h"
#include "hmkit_core_cert.h"
#include "hmkit_core.h"
#include "hmkit_core_config.h"

#include "hmkit_core_connectivity_hal.h"
#include "hmkit_core_persistence_hal.h"
#include "hmkit_core_crypto_hal.h"
#include "hmkit_core_log.h"
#include "hmkit_core_error.h"

#include <stdlib.h> 

#define SIZE_NONCE 9
#define SIZE_HMAC 32
#define SIZE_REQID_LEN 2
#define SIZE_TELV2_PAYLD_LEN 4
#define SIZE_TELV1_PAYLD_LEN 2

uint8_t hmkit_core_api_retrieve_authorised_devices(uint8_t *device_size, hmkit_core_device_t *devices){
  //Return all authorised devices

  getAuthorisedDevises(device_size, devices);

  return 0;
}

uint8_t hmkit_core_api_send_read_device_certificate(uint64_t appContxtId, uint8_t *mac, uint8_t *nonce, uint8_t *ca_signature){

  uint8_t data[73];

  memcpy(data,nonce,9);
  memcpy(data + 9,ca_signature,64);

  sendGetDeviceCertificateRequest(appContxtId, 1, data, mac);

  return 0;
}

uint8_t hmkit_core_api_send_register_access_certificate(uint64_t appContxtId, hmkit_core_certificate_t *cert){

#ifdef DYNAMIC_MEM_DATA
  uint8_t *cert_data = (uint8_t*)malloc(92 + 1 + cert->permissions_size + 64);
#else
  uint8_t cert_data[92 + 1 + cert->permissions_size + 64];
#endif
  uint16_t size = 0;

  hmkit_core_cert_get_as_bytes( cert, cert_data, &size);

  sendRegisterCertificate(appContxtId, 1, cert_data, 92 + 1 + cert->permissions_size + 64, cert->providing_serial);

#ifdef DYNAMIC_MEM_DATA
  free(cert_data);
#endif

  return 0;
}

uint8_t hmkit_core_api_get_public_key(uint64_t appContxtId, uint8_t *public_key){
  hmkit_core_persistence_hal_get_local_public_key(appContxtId, public_key);
  return 0;
}

uint8_t hmkit_core_api_get_serial_number(uint64_t appContxtId, uint8_t *serial_number){
  return hmkit_core_persistence_hal_get_serial(appContxtId, serial_number);
}

uint8_t hmkit_core_api_get_access_certificate(uint64_t appContxtId, uint8_t *serial_number, uint8_t *cert){
  hmkit_core_certificate_t cert_get;
  memcpy(cert_get.gaining_serial,serial_number,9);

  uint16_t size = 0;

  if(hmkit_core_persistence_hal_get_access_certificate(appContxtId, serial_number, cert, &size) == 0){
    return size;
  }

  return 0;
}

uint8_t hmkit_core_api_store_access_certificate(uint64_t appContxtId, hmkit_core_certificate_t *cert){

  uint8_t cert_data[HMKIT_CORE_CERT_MAX_SIZE];
  uint16_t size = 0;

  hmkit_core_cert_get_as_bytes(cert, cert_data, &size);
  hmkit_core_persistence_hal_add_access_certificate(appContxtId, cert->gaining_serial, cert_data, size);
  sendAuthenticate(appContxtId, cert->gaining_serial);

  return 0;
}

uint8_t hmkit_core_api_remove_access_certificate(uint64_t appContxtId, uint8_t *serial_number){
  sendRevoke(appContxtId, serial_number);
  return 0;
}

uint8_t hmkit_core_api_ble_on(uint8_t action){
  hmkit_core_ble_on(action);
  return 0;
}

uint8_t hmkit_core_api_send_custom_command(uint64_t appContxtId, uint8_t *serial_number, uint8_t content_type, uint8_t *data, uint32_t size, uint8_t *reqID, uint16_t reqID_size, uint8_t version){
  sendSecureContainer(appContxtId, serial_number, content_type, data, size, reqID, reqID_size, version);

  return 0;
}

uint8_t hmkit_core_api_disconnect(uint8_t *mac){
  hmkit_core_link_disconnect(mac);
  hmkit_core_sensing_disconnect(mac);
  return 0;
}

void hmkit_core_api_send_telematics_command(uint64_t appContxtId_Tele, uint8_t *serial, uint8_t *nonce, uint8_t content_type, uint32_t length, uint8_t *data, uint8_t *reqID, uint16_t reqID_size, uint8_t version){

#ifdef DYNAMIC_MEM_DATA
  uint8_t *out_data = NULL;
  if(version == 2)
  {
      out_data = (uint8_t*) malloc((1 + SIZE_SER + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size + 1 + SIZE_TELV2_PAYLD_LEN + length + SIZE_HMAC + 2) * sizeof(uint8_t));
  }else // Version = 1
  {
      out_data = (uint8_t*) malloc((SIZE_SER + SIZE_NONCE + 1  + 4 + length + SIZE_HMAC + 2) * sizeof(uint8_t));
  }

#else
  uint8_t out_data[MAX_COMMAND_SIZE];
#endif
 
  if(version == 1){
    //Add local serial
    hmkit_core_persistence_hal_get_serial(appContxtId_Tele, out_data);
    //Add nonce
    memcpy(out_data + SIZE_SER, nonce, SIZE_NONCE);  
    //Is encrypted
    out_data[SIZE_SER + SIZE_NONCE] = 0x01;

    //Create custom command
    out_data[SIZE_SER + SIZE_NONCE + 1] = 0x36; // Command ID
    out_data[SIZE_SER + SIZE_NONCE + 2] = 0x01; // Require HMAC
    out_data[SIZE_SER + SIZE_NONCE + 3] = (length & 0xFF00) >> 8; // Command Size
    out_data[SIZE_SER + SIZE_NONCE + 4] = length & 0x00FF;  // Command Size

    memcpy(out_data + (SIZE_SER + SIZE_NONCE + 5),data,length);

    if(hmkit_core_generate_hmac(appContxtId_Tele, nonce, serial, out_data + SIZE_SER + SIZE_NONCE + 1, length + 4, out_data + SIZE_SER + SIZE_NONCE + 1 + 4 + length) == 0){
      uint8_t ecdh[32];
      if( hmkit_core_generate_ecdh(appContxtId_Tele, nonce, serial, ecdh) == 0 ){

        hmkit_core_encrypt_decrypt(appContxtId_Tele, nonce, nonce, ecdh, out_data + SIZE_SER + SIZE_NONCE + 1, 4 + length + SIZE_HMAC);

        uint16_t out_data_prepared_length = 0;
  #ifdef DYNAMIC_MEM_DATA
        uint8_t *out_data_prepared = (uint8_t *)malloc((SIZE_SER + SIZE_NONCE + 1  + 4 + length + SIZE_HMAC + 2) * 2);
  #else
        uint8_t out_data_prepared[MAX_COMMAND_SIZE];
  #endif

        out_data_prepared_length = hmkit_core_prepare_data((SIZE_SER + SIZE_NONCE + 1 + 4 + length + SIZE_HMAC), out_data, out_data_prepared);

        uint8_t issuer[4] = {0x74,0x6D,0x63,0x73};

        uint8_t cert[HMKIT_CORE_CERT_V1_MAX_SIZE];
        uint16_t size = 0;
        hmkit_core_certificate_t certificate;

        if(hmkit_core_persistence_hal_get_access_certificate(appContxtId_Tele, serial, cert, &size) == 0){
          if(hmkit_core_cert_get_as_struct(cert, &certificate) == HM_OK){
            if(certificate.version == HMKIT_CORE_CERT_VER_1){
              memcpy(issuer,certificate.issuer,HMKIT_CORE_CERT_ISSUER_SIZE);
            }

            hmkit_core_connectivity_hal_telematics_send_data(appContxtId_Tele, issuer, serial, out_data_prepared_length, out_data_prepared);
          }
        }

        #ifdef DYNAMIC_MEM_DATA
        free(out_data_prepared);
        #endif
      }
    }

    #ifdef DYNAMIC_MEM_DATA
    free(out_data);
    #endif
  }
  else if(version == 2){

    out_data[0] = 0x02;
    //Add local serial
    hmkit_core_persistence_hal_get_serial(appContxtId_Tele, out_data + 1);
    //Add receiver serial
    memcpy(out_data + 1 + SIZE_SER, serial, 9); 
    //Add nonce
    memcpy(out_data + 1 + SIZE_SER + SIZE_SER, nonce, SIZE_NONCE);  
    //Add request id
    out_data[1 + SIZE_SER + SIZE_SER + SIZE_NONCE] = (reqID_size & 0xFF00)  >> 8;
    out_data[1 + SIZE_SER + SIZE_SER + SIZE_NONCE + 1] = reqID_size & 0x00FF;
    
    memcpy(out_data + 1 + SIZE_SER + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN, reqID, reqID_size);
    
    //Is encrypted
    out_data[1 + SIZE_SER + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size] = 0x01;

    //Content type
    out_data[1 + SIZE_SER + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size + 1] = content_type;

    //Payload
    out_data[1 + SIZE_SER + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size + 1 + 1] = (length & 0xFF000000)  >> 24;
    out_data[1 + SIZE_SER + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size + 1 + 2] = (length & 0x00FF0000)  >> 16;
    out_data[1 + SIZE_SER + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size + 1 + 3] = (length & 0x0000FF00)  >> 8;
    out_data[1 + SIZE_SER + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size + 1 + 4] = length & 0x000000FF;

    memcpy(out_data + (1 + SIZE_SER + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size + 1 + 1 + SIZE_TELV2_PAYLD_LEN),data,length);

      uint8_t ecdh[32];
      if( hmkit_core_generate_ecdh(appContxtId_Tele, nonce, serial, ecdh) == 0 ){

        hmkit_core_encrypt_decrypt(appContxtId_Tele, nonce, nonce, ecdh, (out_data + 1 + SIZE_SER + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size + 1 + 1 + SIZE_TELV2_PAYLD_LEN), length);

          if(hmkit_core_generate_hmac(appContxtId_Tele, nonce, serial, out_data, 1 + SIZE_SER + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size + 1 + 1 + SIZE_TELV2_PAYLD_LEN + length, out_data + 1 + SIZE_SER + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size + 1 + 1 + SIZE_TELV2_PAYLD_LEN + length) == 0){

        uint16_t out_data_prepared_length = 0;
  #ifdef DYNAMIC_MEM_DATA
        uint8_t *out_data_prepared = (uint8_t *)malloc((1 + SIZE_SER + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size + 1 + 1 + SIZE_TELV2_PAYLD_LEN + length + SIZE_HMAC + 2) * 2);
  #else
        uint8_t out_data_prepared[MAX_COMMAND_SIZE];
  #endif

        out_data_prepared_length = hmkit_core_prepare_data((1 + SIZE_SER + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size + 1 + 1 + SIZE_TELV2_PAYLD_LEN + length + SIZE_HMAC), out_data, out_data_prepared);

        uint8_t issuer[4] = {0x74,0x6D,0x63,0x73};

        uint8_t cert[HMKIT_CORE_CERT_V1_MAX_SIZE];
        uint16_t size = 0;
        hmkit_core_certificate_t certificate;

        if(hmkit_core_persistence_hal_get_access_certificate(appContxtId_Tele, serial, cert, &size) == 0){
          if(hmkit_core_cert_get_as_struct(cert, &certificate) == HM_OK){
            if(certificate.version == HMKIT_CORE_CERT_VER_1){
              memcpy(issuer,certificate.issuer,HMKIT_CORE_CERT_ISSUER_SIZE);
            }

            hmkit_core_connectivity_hal_telematics_send_data(appContxtId_Tele, issuer, serial, out_data_prepared_length, out_data_prepared);
          }
        }

        #ifdef DYNAMIC_MEM_DATA
        free(out_data_prepared);
        #endif
      }
    }

    #ifdef DYNAMIC_MEM_DATA
    free(out_data);
    #endif
  }

  //TODO Error
}

uint32_t hmkit_core_api_get_current_date_time(uint8_t *day, uint8_t *month, uint8_t *year, uint8_t *minute, uint8_t *hour){
  return hmkit_core_connectivity_hal_get_current_date_time(day, month, year, minute, hour);
}
