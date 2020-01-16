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

#include "hmkit_core_cert.h"
#include "string.h"
#include "hmkit_core_log.h"
#include "hmkit_core_error.h"

uint8_t hmkit_core_cert_validate_date(uint8_t *date);
uint8_t hmkit_core_cert_validate_v0(uint8_t *cert);
uint8_t hmkit_core_cert_validate_v1(uint8_t *cert);
uint8_t hmkit_core_cert_get_version(uint8_t *cert, uint8_t *version);
uint8_t hmkit_core_cert_get_issuer(uint8_t *cert, uint8_t *issuer);
uint8_t hmkit_core_cert_get_gaining_serial(uint8_t *cert, uint8_t *serial);
uint8_t hmkit_core_cert_get_gaining_public_key(uint8_t *cert, uint8_t *publicKey);
uint8_t hmkit_core_cert_get_providing_serial(uint8_t *cert, uint8_t *serial);
uint8_t hmkit_core_cert_get_start_date(uint8_t *cert, uint8_t *date);
uint8_t hmkit_core_cert_get_end_date(uint8_t *cert, uint8_t *date);
uint8_t hmkit_core_cert_get_permissions(uint8_t *cert, uint8_t *permissionsSize, uint8_t *permissions);
uint8_t hmkit_core_cert_get_signature(uint8_t *cert, uint8_t *signature);

uint8_t hmkit_core_cert_validate_date(uint8_t *date){

  if(date[0] < 17){
    return HM_ERROR_INVALID_DATA;
  }

  if(date[1] > 12){
    return HM_ERROR_INVALID_DATA;
  }

  if(date[2] > 31){
    return HM_ERROR_INVALID_DATA;
  }

  if(date[3] > 23){
    return HM_ERROR_INVALID_DATA;
  }

  if(date[4] > 59){
    return HM_ERROR_INVALID_DATA;
  }

  return HM_OK;
}

uint8_t hmkit_core_cert_validate_v0(uint8_t *cert){

  if(cert[HMKIT_CORE_CERT_V0_PERMISSIONS_SIZE_POSITION] > HMKIT_CORE_CERT_V0_MAX_PERMISSIONS_SIZE){
    return HM_ERROR_INVALID_DATA;
  }

  if((cert[HMKIT_CORE_CERT_V0_PERMISSIONS_SIZE_POSITION] + HMKIT_CORE_CERT_V0_MIN_SIZE) < HMKIT_CORE_CERT_V0_MIN_SIZE || (cert[HMKIT_CORE_CERT_V0_PERMISSIONS_SIZE_POSITION] + HMKIT_CORE_CERT_V0_MIN_SIZE) > HMKIT_CORE_CERT_V0_MAX_SIZE ){
    return HM_ERROR_INVALID_DATA;
  }

  if(hmkit_core_cert_validate_date(&cert[HMKIT_CORE_CERT_V0_START_DATE_POSITION]) != HM_OK){
    return HM_ERROR_INVALID_DATA;
  }

  if(hmkit_core_cert_validate_date(&cert[HMKIT_CORE_CERT_V0_END_DATE_POSITION]) != HM_OK){
    return HM_ERROR_INVALID_DATA;
  }

  return HM_OK;
}

uint8_t hmkit_core_cert_validate_v1(uint8_t *cert){

  if(cert[HMKIT_CORE_CERT_V1_VERSION_POSITION] != HMKIT_CORE_CERT_VER_1){
    return HM_ERROR_INVALID_DATA;
  }

  if(cert[HMKIT_CORE_CERT_V1_PERMISSIONS_SIZE_POSITION] > HMKIT_CORE_CERT_V1_MAX_PERMISSIONS_SIZE){
    return HM_ERROR_INVALID_DATA;
  }

  if((cert[HMKIT_CORE_CERT_V1_PERMISSIONS_SIZE_POSITION] + HMKIT_CORE_CERT_V1_MIN_SIZE) < HMKIT_CORE_CERT_V1_MIN_SIZE || (cert[HMKIT_CORE_CERT_V1_PERMISSIONS_SIZE_POSITION] + HMKIT_CORE_CERT_V1_MIN_SIZE) > HMKIT_CORE_CERT_V1_MAX_SIZE ){
    return HM_ERROR_INVALID_DATA;
  }

  if(hmkit_core_cert_validate_date(&cert[HMKIT_CORE_CERT_V1_START_DATE_POSITION]) != HM_OK){
    return HM_ERROR_INVALID_DATA;
  }

  if(hmkit_core_cert_validate_date(&cert[HMKIT_CORE_CERT_V1_END_DATE_POSITION]) != HM_OK){
    return HM_ERROR_INVALID_DATA;
  }

  return HM_OK;
}

uint8_t hmkit_core_cert_get_version(uint8_t *cert, uint8_t *version){
  if(hmkit_core_cert_validate_v0(cert) == HM_OK){
    *version = HMKIT_CORE_CERT_VER_0;
    return HM_OK;
  }else if (hmkit_core_cert_validate_v1(cert) == HM_OK){
    *version = HMKIT_CORE_CERT_VER_1;
    return HM_OK;
  }

  return HM_ERROR_INVALID_DATA;
}

uint8_t hmkit_core_cert_get_size(uint8_t *cert, uint16_t *size){

  uint8_t version = HMKIT_CORE_CERT_VER_0;

  if(hmkit_core_cert_get_version(cert, &version) == HM_OK){
    if(version == HMKIT_CORE_CERT_VER_0){
      *size = HMKIT_CORE_CERT_V0_MIN_SIZE + cert[HMKIT_CORE_CERT_V0_PERMISSIONS_SIZE_POSITION];
      return HM_OK;
    }else if (version == HMKIT_CORE_CERT_VER_1){
      *size = HMKIT_CORE_CERT_V1_MIN_SIZE + cert[HMKIT_CORE_CERT_V1_PERMISSIONS_SIZE_POSITION];
      return HM_OK;
    }
  }

  return HM_ERROR_INVALID_DATA;
}

uint8_t hmkit_core_cert_get_issuer(uint8_t *cert, uint8_t *issuer){

  uint8_t version = HMKIT_CORE_CERT_VER_0;

  if(hmkit_core_cert_get_version(cert, &version) == HM_OK){
    if(version == HMKIT_CORE_CERT_VER_1){
      memcpy(issuer,&cert[HMKIT_CORE_CERT_V1_ISSUER_POSITION],HMKIT_CORE_CERT_ISSUER_SIZE);
      return HM_OK;
    }
    else{
      memset(issuer,0x00,HMKIT_CORE_CERT_ISSUER_SIZE);
      return HM_OK;
    }
  }

  return HM_ERROR_INVALID_DATA;
}

uint8_t hmkit_core_cert_get_gaining_serial(uint8_t *cert, uint8_t *serial){
  uint8_t version = HMKIT_CORE_CERT_VER_0;

  if(hmkit_core_cert_get_version(cert, &version) == HM_OK){
    if(version == HMKIT_CORE_CERT_VER_0){
      memcpy(serial,&cert[HMKIT_CORE_CERT_V0_GAINING_SERIAL_POSITION],HMKIT_CORE_CERT_SERIAL_SIZE);
      return HM_OK;
    }
    else{
      memcpy(serial,&cert[HMKIT_CORE_CERT_V1_GAINING_SERIAL_POSITION],HMKIT_CORE_CERT_SERIAL_SIZE);
      return HM_OK;
    }
  }

  return HM_ERROR_INVALID_DATA;
}

uint8_t hmkit_core_cert_get_gaining_public_key(uint8_t *cert, uint8_t *publicKey){
  uint8_t version = HMKIT_CORE_CERT_VER_0;

  if(hmkit_core_cert_get_version(cert, &version) == HM_OK){
    if(version == HMKIT_CORE_CERT_VER_0){
      memcpy(publicKey,&cert[HMKIT_CORE_CERT_V0_GAINING_PUBLIC_KEY_POSITION],HMKIT_CORE_CERT_PUBLIC_KEY_SIZE);
      return HM_OK;
    }
    else{
      memcpy(publicKey,&cert[HMKIT_CORE_CERT_V1_GAINING_PUBLIC_KEY_POSITION],HMKIT_CORE_CERT_PUBLIC_KEY_SIZE);
      return HM_OK;
    }
  }

  return HM_ERROR_INVALID_DATA;
}

uint8_t hmkit_core_cert_get_providing_serial(uint8_t *cert, uint8_t *serial){
  uint8_t version = HMKIT_CORE_CERT_VER_0;

  if(hmkit_core_cert_get_version(cert, &version) == HM_OK){
    if(version == HMKIT_CORE_CERT_VER_0){
      memcpy(serial,&cert[HMKIT_CORE_CERT_V0_PROVIDING_SERIAL_POSITION],HMKIT_CORE_CERT_SERIAL_SIZE);
      return HM_OK;
    }
    else{
      memcpy(serial,&cert[HMKIT_CORE_CERT_V1_PROVIDING_SERIAL_POSITION],HMKIT_CORE_CERT_SERIAL_SIZE);
      return HM_OK;
    }
  }

  return HM_ERROR_INVALID_DATA;
}

uint8_t hmkit_core_cert_get_start_date(uint8_t *cert, uint8_t *date){
  uint8_t version = HMKIT_CORE_CERT_VER_0;

  if(hmkit_core_cert_get_version(cert, &version) == HM_OK){
    if(version == HMKIT_CORE_CERT_VER_0){
      memcpy(date,&cert[HMKIT_CORE_CERT_V0_START_DATE_POSITION],HMKIT_CORE_CERT_DATE_SIZE);
      return HM_OK;
    }
    else{
      memcpy(date,&cert[HMKIT_CORE_CERT_V1_START_DATE_POSITION],HMKIT_CORE_CERT_DATE_SIZE);
      return HM_OK;
    }
  }

  return HM_ERROR_INVALID_DATA;
}

uint8_t hmkit_core_cert_get_end_date(uint8_t *cert, uint8_t *date){
  uint8_t version = HMKIT_CORE_CERT_VER_0;

  if(hmkit_core_cert_get_version(cert, &version) == HM_OK){
    if(version == HMKIT_CORE_CERT_VER_0){
      memcpy(date,&cert[HMKIT_CORE_CERT_V0_END_DATE_POSITION],HMKIT_CORE_CERT_DATE_SIZE);
      return HM_OK;
    }
    else{
      memcpy(date,&cert[HMKIT_CORE_CERT_V1_END_DATE_POSITION],HMKIT_CORE_CERT_DATE_SIZE);
      return HM_OK;
    }
  }

  return HM_ERROR_INVALID_DATA;
}

uint8_t hmkit_core_cert_get_permissions(uint8_t *cert, uint8_t *permissionsSize, uint8_t *permissions){
  uint8_t version = HMKIT_CORE_CERT_VER_0;

  if(hmkit_core_cert_get_version(cert, &version) == HM_OK){
    if(version == HMKIT_CORE_CERT_VER_0){
      *permissionsSize = cert[HMKIT_CORE_CERT_V0_PERMISSIONS_SIZE_POSITION];
      memcpy(permissions,&cert[HMKIT_CORE_CERT_V0_PERMISSIONS_POSITION],*permissionsSize);
      return HM_OK;
    }
    else{
      *permissionsSize = cert[HMKIT_CORE_CERT_V1_PERMISSIONS_SIZE_POSITION];
      memcpy(permissions,&cert[HMKIT_CORE_CERT_V1_PERMISSIONS_POSITION],*permissionsSize);
      return HM_OK;
    }
  }

  return HM_ERROR_INVALID_DATA;
}

uint8_t hmkit_core_cert_get_signature(uint8_t *cert, uint8_t *signature){
  uint8_t version = HMKIT_CORE_CERT_VER_0;
  uint8_t permissionsSize = 0;

  if(hmkit_core_cert_get_version(cert, &version) == HM_OK){
    if(version == HMKIT_CORE_CERT_VER_0){
      permissionsSize = cert[HMKIT_CORE_CERT_V0_PERMISSIONS_SIZE_POSITION];
      memcpy(signature,&cert[HMKIT_CORE_CERT_V0_PERMISSIONS_POSITION + permissionsSize],HMKIT_CORE_CERT_PUBLIC_KEY_SIZE);
      return HM_OK;
    }
    else{
      permissionsSize = cert[HMKIT_CORE_CERT_V1_PERMISSIONS_SIZE_POSITION];
      memcpy(signature,&cert[HMKIT_CORE_CERT_V1_PERMISSIONS_POSITION + permissionsSize],HMKIT_CORE_CERT_PUBLIC_KEY_SIZE);
      return HM_OK;
    }
  }

  return HM_ERROR_INVALID_DATA;
}

uint8_t hmkit_core_cert_get_journeyId(uint8_t *cert, uint8_t *pjourneyId){
  uint8_t version = HMKIT_CORE_CERT_VER_0;
  //uint8_t permissionsSize = 0;

  if(hmkit_core_cert_get_version(cert, &version) == HM_OK){

    if(version == HMKIT_CORE_CERT_VER_0){
		return HM_ERROR_INVALID_DATA;
    }
    else{
      //permissionsSize = cert[HMKIT_CORE_CERT_V1_PERMISSIONS_SIZE_POSITION];

	  if(cert[HMKIT_CORE_CERT_V1_PERMISSIONS_POSITION] == HMKIT_CORE_CERT_CAR_RENTAL_PERMISSIONS_ID)
	  {
		memcpy(pjourneyId, &cert[HMKIT_CORE_CERT_V1_PERMISSIONS_POSITION + HMKIT_CORE_CERT_V1_CAR_RENT_BOOK_ID_OFFSET], HMKIT_CORE_CERT_JOURNEY_ID_SIZE);
		return HM_OK;
	  }
	  else
	  {
		return HM_ERROR_INVALID_DATA;
	  }

    }
  }

  return HM_ERROR_INVALID_DATA;
}

uint8_t hmkit_core_cert_get_as_bytes( hmkit_core_certificate_t *certificate, uint8_t *cert, uint16_t *size){

  if(certificate->version == HMKIT_CORE_CERT_VER_0){
    memcpy(&cert[HMKIT_CORE_CERT_V0_GAINING_SERIAL_POSITION], certificate->gaining_serial,HMKIT_CORE_CERT_SERIAL_SIZE);
    memcpy(&cert[HMKIT_CORE_CERT_V0_GAINING_PUBLIC_KEY_POSITION], certificate->public_key,HMKIT_CORE_CERT_PUBLIC_KEY_SIZE);
    memcpy(&cert[HMKIT_CORE_CERT_V0_PROVIDING_SERIAL_POSITION], certificate->providing_serial, HMKIT_CORE_CERT_SERIAL_SIZE);
    memcpy(&cert[HMKIT_CORE_CERT_V0_START_DATE_POSITION], certificate->start_date,HMKIT_CORE_CERT_DATE_SIZE);
    memcpy(&cert[HMKIT_CORE_CERT_V0_END_DATE_POSITION], certificate->end_date,HMKIT_CORE_CERT_DATE_SIZE);
    memcpy(&cert[HMKIT_CORE_CERT_V0_PERMISSIONS_SIZE_POSITION], &certificate->permissions_size,HMKIT_CORE_CERT_PERMISSION_SIZE_BYTE_SIZE);
    memcpy(&cert[HMKIT_CORE_CERT_V0_PERMISSIONS_POSITION], certificate->permissions,certificate->permissions_size);
    memcpy(&cert[HMKIT_CORE_CERT_V0_PERMISSIONS_POSITION + certificate->permissions_size], certificate->ca_signature,HMKIT_CORE_CERT_SIGNATURE_SIZE);

    *size = HMKIT_CORE_CERT_V0_MIN_SIZE + certificate->permissions_size;
  }else if(certificate->version == HMKIT_CORE_CERT_VER_1){
    memcpy(&cert[HMKIT_CORE_CERT_V1_VERSION_POSITION], &certificate->version,HMKIT_CORE_CERT_VERSION_SIZE);
    memcpy(&cert[HMKIT_CORE_CERT_V1_ISSUER_POSITION], certificate->issuer,HMKIT_CORE_CERT_ISSUER_SIZE);
    memcpy(&cert[HMKIT_CORE_CERT_V1_PROVIDING_SERIAL_POSITION], certificate->providing_serial, HMKIT_CORE_CERT_SERIAL_SIZE);
    memcpy(&cert[HMKIT_CORE_CERT_V1_GAINING_SERIAL_POSITION], certificate->gaining_serial,HMKIT_CORE_CERT_SERIAL_SIZE);
    memcpy(&cert[HMKIT_CORE_CERT_V1_GAINING_PUBLIC_KEY_POSITION], certificate->public_key,HMKIT_CORE_CERT_PUBLIC_KEY_SIZE);
    memcpy(&cert[HMKIT_CORE_CERT_V1_START_DATE_POSITION], certificate->start_date,HMKIT_CORE_CERT_DATE_SIZE);
    memcpy(&cert[HMKIT_CORE_CERT_V1_END_DATE_POSITION], certificate->end_date,HMKIT_CORE_CERT_DATE_SIZE);
    memcpy(&cert[HMKIT_CORE_CERT_V1_PERMISSIONS_SIZE_POSITION], &certificate->permissions_size,HMKIT_CORE_CERT_PERMISSION_SIZE_BYTE_SIZE);
    memcpy(&cert[HMKIT_CORE_CERT_V1_PERMISSIONS_POSITION], certificate->permissions,certificate->permissions_size);
    memcpy(&cert[HMKIT_CORE_CERT_V1_PERMISSIONS_POSITION + certificate->permissions_size], certificate->ca_signature,HMKIT_CORE_CERT_SIGNATURE_SIZE);

    *size = HMKIT_CORE_CERT_V1_MIN_SIZE + certificate->permissions_size;
  }else{
    return HM_ERROR_INVALID_DATA;
  }

  return HM_OK;
}

uint8_t hmkit_core_cert_get_as_struct(uint8_t *cert, hmkit_core_certificate_t *certificate){

  uint8_t error = HM_OK;

  error = hmkit_core_cert_get_version(cert, &certificate->version);

  if(error != HM_OK){
    return HM_ERROR_INVALID_DATA;
  }

  error = hmkit_core_cert_get_issuer(cert, certificate->issuer);

  if(error != HM_OK){
    return HM_ERROR_INVALID_DATA;
  }

  error = hmkit_core_cert_get_gaining_serial(cert, certificate->gaining_serial);

  if(error != HM_OK){
    return HM_ERROR_INVALID_DATA;
  }

  error = hmkit_core_cert_get_gaining_public_key(cert, certificate->public_key);

  if(error != HM_OK){
    return HM_ERROR_INVALID_DATA;
  }

  error = hmkit_core_cert_get_providing_serial(cert, certificate->providing_serial);

  if(error != HM_OK){
    return HM_ERROR_INVALID_DATA;
  }

  error = hmkit_core_cert_get_start_date(cert, certificate->start_date);

  if(error != HM_OK){
    return HM_ERROR_INVALID_DATA;
  }

  error = hmkit_core_cert_get_end_date(cert, certificate->end_date);

  if(error != HM_OK){
    return HM_ERROR_INVALID_DATA;
  }

  error = hmkit_core_cert_get_permissions(cert, &certificate->permissions_size, certificate->permissions);

  if(error != HM_OK){
    return HM_ERROR_INVALID_DATA;
  }

  error = hmkit_core_cert_get_signature(cert, certificate->ca_signature);

  if(error != HM_OK){
    return HM_ERROR_INVALID_DATA;
  }

  return HM_OK;
}

uint8_t hmkit_core_cert_print(uint8_t *cert){

  hmkit_core_certificate_t certificate;

  if(hmkit_core_cert_get_as_struct(cert, &certificate) == HM_OK){
    if(certificate.version == HMKIT_CORE_CERT_VER_0 ){
      hmkit_core_log(NULL,NULL,HMKIT_CORE_LOG_DEBUG,"ACCESS CERTIFICATE V0 PRINTOUT");
      hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_DEBUG,certificate.providing_serial,HMKIT_CORE_CERT_SERIAL_SIZE,"Provaiding serial:");
      hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_DEBUG,certificate.gaining_serial,HMKIT_CORE_CERT_SERIAL_SIZE,"Gaining serial:");
      hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_DEBUG,certificate.public_key,HMKIT_CORE_CERT_PUBLIC_KEY_SIZE,"Public key:");
      hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_DEBUG,certificate.start_date,HMKIT_CORE_CERT_DATE_SIZE,"Start date:");
      hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_DEBUG,certificate.end_date,HMKIT_CORE_CERT_DATE_SIZE,"End date:");
      hmkit_core_log(NULL,NULL,HMKIT_CORE_LOG_DEBUG,"Permissions size: %d",certificate.permissions_size);
      hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_DEBUG,certificate.permissions,certificate.permissions_size,"Permissions:");
      hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_DEBUG,certificate.ca_signature,HMKIT_CORE_CERT_SIGNATURE_SIZE,"Signature:");
    }else if(certificate.version == HMKIT_CORE_CERT_VER_1){
      hmkit_core_log(NULL,NULL,HMKIT_CORE_LOG_DEBUG,"ACCESS CERTIFICATE V1 PRINTOUT");
      hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_DEBUG,certificate.issuer,HMKIT_CORE_CERT_ISSUER_SIZE,"Issuer:");
      hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_DEBUG,certificate.providing_serial,HMKIT_CORE_CERT_SERIAL_SIZE,"Provaiding serial:");
      hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_DEBUG,certificate.gaining_serial,HMKIT_CORE_CERT_SERIAL_SIZE,"Gaining serial:");
      hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_DEBUG,certificate.public_key,HMKIT_CORE_CERT_PUBLIC_KEY_SIZE,"Public key:");
      hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_DEBUG,certificate.start_date,HMKIT_CORE_CERT_DATE_SIZE,"Start date:");
      hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_DEBUG,certificate.end_date,HMKIT_CORE_CERT_DATE_SIZE,"End date:");
      hmkit_core_log(NULL,NULL,HMKIT_CORE_LOG_DEBUG,"Permissions size: %d",certificate.permissions_size);
      hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_DEBUG,certificate.permissions,certificate.permissions_size,"Permissions:");
      hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_DEBUG,certificate.ca_signature,HMKIT_CORE_CERT_SIGNATURE_SIZE,"Signature:");
    }else{
      return HM_ERROR_INVALID_DATA;
    }

    return HM_OK;
  }

  return HM_ERROR_INVALID_DATA;
}
