
#include "hmkit_core_api_callback.h"
#include "hmkit_core_cert.h"
#include <string.h>
#include <gio/gio.h>
#include "hmkit_core_log.h"
#include "hmkit_core_connectivity_hal.h"
#include "stdio.h"

gboolean timeout_callback(gpointer data)
{
    hmkit_core_clock();
    hmkit_core_connectivity_hal_scan_start();
    return TRUE;
}

gpointer superThread(gpointer data){

    GMainLoop *loop = NULL;

    g_timeout_add(60, timeout_callback, loop);

    loop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(loop);

    return 0;
}

void hmkit_core_api_callback_init()
{
    g_thread_new ("SuperThread", superThread, NULL);
}

void hmkit_core_api_callback_clock()
{

}

void hmkit_core_api_callback_ping()
{

}

void hmkit_core_api_callback_entered_proximity(uint64_t appContxtId, hmkit_core_device_t *device)
{
    hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_INFO,NULL,0,"[HMMOC] hmkit_core_api_callback_entered_proximity");
    //Get capabilities
//    uint8_t data[10] = {0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29};
    uint8_t data[3] = {0x00,0x10,0x00};
    uint8_t reqID[9] = {2, 3, 4, 5, 6, 7, 8, 9, 10};
    uint16_t reqID_size = 9;
    uint8_t nonce[9] = {0x00,0x10,0x00,0x11,0x12,0x13,0x14,0x15,0x16};

    hmkit_core_api_send_custom_command(appContxtId, device->serial_number, 0, data,3, reqID, reqID_size, 2);	
    hmkit_core_api_send_telematics_command(appContxtId, device->serial_number, nonce, 0, 3, data, reqID, reqID_size, 1);

}

void hmkit_core_api_callback_proximity_measured(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t receiver_count, hmkit_core_receiver_t *receivers)
{

}

void hmkit_core_api_callback_exited_proximity(uint64_t appContxtId, hmkit_core_device_t *device)
{
    hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_INFO,NULL,0,"[HMMOC] hmkit_core_api_callback_exited_proximity");

}

void hmkit_core_api_callback_command_incoming(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t content_type, uint8_t *data, uint32_t length, uint8_t *respID, uint16_t respID_size, uint8_t version)
{
    hmkit_core_log_data(NULL,device->serial_number,HMKIT_CORE_LOG_INFO,data,length,"[HMMOC] hmkit_core_api_callback_command_incoming");

    hmkit_core_log_data(NULL,device->serial_number,HMKIT_CORE_LOG_INFO,data,length,"[HMMOC] hmkit_core_api_callback_command_incoming data");
    hmkit_core_log_data(NULL,device->serial_number,HMKIT_CORE_LOG_INFO,respID,respID_size,"[HMMOC] hmkit_core_api_callback_command_incoming id");
}

void hmkit_core_api_callback_command_response(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t content_type, uint8_t *data, uint32_t length, uint8_t *respID, uint16_t respID_size, uint8_t version){

    hmkit_core_log_data(NULL,device->serial_number,HMKIT_CORE_LOG_INFO,data,length,"[HMMOC] hmkit_core_api_callback_command_response data");
    hmkit_core_log_data(NULL,device->serial_number,HMKIT_CORE_LOG_INFO,respID,respID_size,"[HMMOC] hmkit_core_api_callback_command_response id");
}

void hmkit_core_api_callback_command_response_error(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t errortype){
    
}

void hmkit_core_api_callback_error_command_incoming(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t command, uint8_t errorType)
{
    BTUNUSED(device);
    BTUNUSED(command);
    BTUNUSED(errorType);
    BTUNUSED(appContxtId);
}

uint32_t hmkit_core_api_callback_get_device_certificate_failed(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t *nonce)
{
    return 0;
}

void hmkit_core_api_callback_access_certificate_registered(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t *public_key, uint8_t error)
{

}

uint32_t hmkit_core_api_callback_pairing_requested(uint64_t appContxtId, hmkit_core_device_t *device){
    return 0;
}

void hmkit_core_api_callback_telematics_command_incoming(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t id, uint8_t content_type, uint32_t length, uint8_t *data, uint8_t *respID, uint16_t respID_size, uint8_t version){

    hmkit_core_log_data(NULL,device->serial_number,HMKIT_CORE_LOG_INFO,data,length,"[HMCore] TELEMATICS IN data");
    hmkit_core_log_data(NULL,device->serial_number,HMKIT_CORE_LOG_INFO,respID,respID_size,"[HMCore] TELEMATICS IN ID");
}

void hmkit_core_api_callback_revoke_response(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t *data, uint16_t length, uint8_t status){

}

void hmkit_core_api_callback_revoke_incoming(uint64_t appContxtId, hmkit_core_device_t *device, uint8_t *data, uint16_t *length){

}
