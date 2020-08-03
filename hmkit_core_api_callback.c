
#include "hmkit_core_api_callback.h"
#include "hmkit_core_cert.h"
#include <string.h>

void hmkit_core_api_callback_init(void)
{

}

void hmkit_core_api_callback_clock(void)
{

}

void hmkit_core_api_callback_ping(void)
{

}

void hmkit_core_api_callback_entered_proximity(uint64_t appContxtId, hmkit_core_device_t *device)
{
    BTUNUSED(device);
    BTUNUSED(appContxtId);
    //TODO add also app id to device
}

void hmkit_core_api_callback_proximity_measured(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t receiver_count, hmkit_core_receiver_t *receivers)
{
    BTUNUSED(device);
    BTUNUSED(receiver_count);
    BTUNUSED(receivers);
    BTUNUSED(appContxtId);
}

void hmkit_core_api_callback_exited_proximity(uint64_t appContxtId, hmkit_core_device_t *device)
{
    BTUNUSED(device);
    BTUNUSED(appContxtId);
}

void hmkit_core_api_callback_command_incoming(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t content_type, uint8_t *data, uint32_t length, uint8_t *respID, uint16_t respID_size, uint8_t version)
{
    BTUNUSED(device);
    BTUNUSED(content_type);
    BTUNUSED(data);
    BTUNUSED(length);
    BTUNUSED(appContxtId);
}

void hmkit_core_api_callback_error_command_incoming(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t command, uint8_t errorType)
{
    BTUNUSED(device);
    BTUNUSED(command);
    BTUNUSED(errorType);
    BTUNUSED(appContxtId);
}

void hmkit_core_api_callback_command_response(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t content_type, uint8_t *data, uint32_t length, uint8_t *respID, uint16_t respID_size, uint8_t version){
    BTUNUSED(device);
    BTUNUSED(content_type);
    BTUNUSED(data);
    BTUNUSED(length);
    BTUNUSED(appContxtId);
}

void hmkit_core_api_callback_command_response_error(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t errortype)
{
    BTUNUSED(device);
    BTUNUSED(errortype);
    BTUNUSED(appContxtId);
}

uint32_t hmkit_core_api_callback_get_device_certificate_failed(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t *nonce)
{
    BTUNUSED(device);
    BTUNUSED(nonce);
    BTUNUSED(appContxtId);
    return 0;
}

void hmkit_core_api_callback_access_certificate_registered(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t *public_key, uint8_t error)
{
    BTUNUSED(device);
    BTUNUSED(public_key);
    BTUNUSED(error);
}

uint32_t hmkit_core_api_callback_pairing_requested(uint64_t appContxtId, hmkit_core_device_t *device){
    BTUNUSED(device);
    return 0;
}

void hmkit_core_api_callback_telematics_command_incoming(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t id, uint8_t content_type, uint32_t length, uint8_t *data, uint8_t *respID, uint16_t respID_size, uint8_t version){
    BTUNUSED(device);
    BTUNUSED(id);
    BTUNUSED(content_type);
    BTUNUSED(length);
    BTUNUSED(data);
    BTUNUSED(appContxtId);
}

uint32_t hmkit_core_api_callback_get_current_date_time(uint8_t *day, uint8_t *month, uint8_t *year, uint8_t *minute, uint8_t *hour){
    BTUNUSED(day);
    BTUNUSED(month);
    BTUNUSED(year);
    BTUNUSED(minute);
    BTUNUSED(hour);
    return 0;
}

void hmkit_core_api_callback_revoke_response(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t *data, uint16_t length, uint8_t status){
    BTUNUSED(device);
    BTUNUSED(data);
    BTUNUSED(length);
    BTUNUSED(status);
    BTUNUSED(appContxtId);
}

void hmkit_core_api_callback_revoke_incoming(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t *data, uint16_t *length){
    BTUNUSED(device);
    BTUNUSED(data);
    BTUNUSED(length);
    BTUNUSED(appContxtId);
}
