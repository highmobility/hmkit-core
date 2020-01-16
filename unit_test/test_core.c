//
// Created by Maidu Ule on 05/10/2017.
//

#include "test_core.h"

#define TEST_NO_MAIN

#include "acutest.h"
#include "hmkit_core.h"
#include "test_common_vars.h"
#include "hmkit_core_log.h"

//Connectivity hal
extern uint8_t unit_test_character;
extern uint8_t unit_test_mac[6];
extern uint64_t unit_test_context;
extern uint16_t unit_test_offset;
extern uint16_t unit_test_length;
extern uint8_t unit_test_data[1024];

//Persistence hal
extern uint8_t unit_test_per_certificate_data[1024];
extern uint16_t unit_test_per_certificate_data_size;
extern uint8_t unit_test_per_serial[9];
extern uint8_t unit_test_per_erase_serial[9];

uint64_t contxtId = 100;

void print_data(uint16_t length, uint8_t *data);

void print_data(uint16_t length, uint8_t *data){

    uint16_t i = 0;

    for(i = 0 ; i < length;i++){
        printf(" %02X",data[i]);
    }
}

void test_hmkit_core_get_version_major_number(void){
    uint32_t major = hmkit_core_get_version_major_number();
    TEST_CHECK(major >= 0);
}

void test_hmkit_core_get_version_minor_number(void){
    uint32_t minor = hmkit_core_get_version_minor_number();
    TEST_CHECK(minor >= 0);
}

void test_hmkit_core_get_version_patch_number(void){
    uint32_t patch = hmkit_core_get_version_patch_number();
    TEST_CHECK(patch >= 0);

}

void test_hmkit_core_sensing_read_notification(void){

    hmkit_core_init();

    hmkit_core_sensing_connect(contxtId, test_mac_data);

    hmkit_core_sensing_read_notification(contxtId, test_mac_data, test_character);

    TEST_CHECK(test_character == unit_test_character);
    TEST_CHECK(contxtId == unit_test_context);
    TEST_CHECK(memcmp(test_mac_data,unit_test_mac,6) == 0 );
}

void test_hmkit_core_sensing_read_response_start(void){

    hmkit_core_init();

    hmkit_core_sensing_connect(contxtId, test_mac_data);

    hmkit_core_sensing_read_response(contxtId, test_start_data, 1, 0, test_mac_data, hmkit_core_characteristic_sensing_read);

    TEST_CHECK(hmkit_core_characteristic_sensing_read == unit_test_character);
    TEST_CHECK(contxtId == unit_test_context);
    TEST_CHECK(memcmp(test_mac_data,unit_test_mac,6) == 0 );
    TEST_CHECK(1 == unit_test_offset);
}

void test_hmkit_core_sensing_read_response_end(void){

    hmkit_core_init();

    hmkit_core_sensing_connect(contxtId, test_mac_data);

    hmkit_core_sensing_read_response(contxtId, test_end_data, 1, 0, test_mac_data, hmkit_core_characteristic_sensing_read);

    TEST_CHECK(hmkit_core_characteristic_sensing_read != unit_test_character);
    TEST_CHECK(contxtId != unit_test_context);
    TEST_CHECK(memcmp(test_mac_data,unit_test_mac,6) != 0 );
    TEST_CHECK(1 != unit_test_offset);
}

void test_hmkit_core_sensing_read_response_get_nonce(void){

    hmkit_core_init();

    //MOC ble connect

    hmkit_core_sensing_connect(contxtId, test_mac_data);

    //MOC ble incoming data

    hmkit_core_sensing_read_response(contxtId, test_start_data, 1, 0, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_protocol_get_nonce, 1, 1, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_end_data, 1, 2, test_mac_data, hmkit_core_characteristic_sensing_write);

    //Validate outgoing data

    TEST_CHECK(2 == unit_test_offset);
    TEST_CHECK(hmkit_core_characteristic_sensing_read == unit_test_character);
    TEST_CHECK(contxtId == unit_test_context);
    TEST_CHECK(memcmp(test_mac_data,unit_test_mac,6) == 0 );
    TEST_CHECK(13 == unit_test_length);
    TEST_CHECK(memcmp(unit_test_data,test_get_nonce_result_data, 12) == 0);
}

void test_hmkit_core_sensing_read_response_get_device_cert(void){

    hmkit_core_init();

    //MOC ble connect

    hmkit_core_sensing_connect(contxtId, test_mac_data);

    //MOC ble incoming data

    hmkit_core_sensing_read_response(contxtId, test_start_data, 1, 0, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_protocol_get_device_cert, 1, 1, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_nonce, 9, 2, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_signature, 64, 11, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_end_data, 1, 75, test_mac_data, hmkit_core_characteristic_sensing_write);

    //Moc ble write responses

    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);

    //Validate outgoing data

    TEST_CHECK(75 == unit_test_offset);
    TEST_CHECK(hmkit_core_characteristic_sensing_read == unit_test_character);
    TEST_CHECK(contxtId == unit_test_context);
    TEST_CHECK(memcmp(test_mac_data,unit_test_mac,6) == 0 );
    TEST_CHECK(159 == unit_test_length);
    TEST_CHECK(memcmp(unit_test_data,test_get_device_cert_result_data, 159) == 0);
}

void test_hmkit_core_sensing_read_response_get_device_cert_error_cmd(void){

    //hmkit_core_bt_log(NULL,NULL,hmkit_core_BT_LOG_INFO,"test_hmkit_core_sensing_read_response_get_device_cert_error_cmd\n");

    hmkit_core_init();

    //MOC ble connect

    hmkit_core_sensing_connect(contxtId, test_mac_data);

    //MOC ble incoming data

    hmkit_core_sensing_read_response(contxtId, test_start_data, 1, 0, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_read_response(contxtId, test_ack, 1, 1, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_read_response(contxtId, test_protocol_get_device_cert, 1, 2, test_mac_data, hmkit_core_characteristic_sensing_read);
    // Wrong signature in certificate
    hmkit_core_sensing_read_response(contxtId, test_device_certificate_err, 153, 3, test_mac_data, hmkit_core_characteristic_sensing_read);
    // Correct certificate
    //hmkit_core_sensing_read_response(contxtId, test_device_certificate, 153, 3, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_read_response(contxtId, test_end_data, 1, 156, test_mac_data, hmkit_core_characteristic_sensing_read);

    //Moc ble write responses

    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);

    //Validate outgoing data

    //hmkit_core_bt_log(NULL,NULL,hmkit_core_BT_LOG_INFO,"error_cmd: offset = %d, Len = %d, chartsc = %d \n", unit_test_offset, unit_test_length, unit_test_character);

    TEST_CHECK(156 == unit_test_offset);
    TEST_CHECK(hmkit_core_characteristic_sensing_write == unit_test_character);
    TEST_CHECK(contxtId == unit_test_context);
    TEST_CHECK(memcmp(test_mac_data,unit_test_mac,6) == 0 );
    TEST_CHECK(5 == unit_test_length);

    TEST_CHECK(memcmp(unit_test_data,test_get_device_cert_resp_error_data, 5) == 0);
}

void test_hmkit_core_sensing_read_response_register_certificate(void){

    hmkit_core_init();

    //MOC ble connect

    hmkit_core_sensing_connect(contxtId, test_mac_data);

    //MOC ble incoming data

    hmkit_core_sensing_read_response(contxtId, test_start_data, 1, 0, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_protocol_register_cert, 1, 1, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_access_certificate, 165, 2, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_end_data, 1, 167, test_mac_data, hmkit_core_characteristic_sensing_write);

    //Moc ble write responses

    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);

    //Validate outgoing data

    TEST_CHECK(167 == unit_test_offset);
    TEST_CHECK(hmkit_core_characteristic_sensing_read == unit_test_character);
    TEST_CHECK(contxtId == unit_test_context);
    TEST_CHECK(memcmp(test_mac_data,unit_test_mac,6) == 0 );
    TEST_CHECK(132 == unit_test_length);
    TEST_CHECK(memcmp(unit_test_data,test_register_certificate, 132) == 0);
    TEST_CHECK( 165 == unit_test_per_certificate_data_size);
    TEST_CHECK(memcmp(test_access_certificate,unit_test_per_certificate_data,unit_test_per_certificate_data_size) == 0);
    TEST_CHECK(memcmp(unit_test_per_serial,test_serial,9) == 0);
}

void test_hmkit_core_sensing_read_response_store_certificate(void){
    
    hmkit_core_init();

    //MOC ble connect

    hmkit_core_sensing_connect(contxtId, test_mac_data);

    //MOC ble incoming data

    hmkit_core_sensing_read_response(contxtId, test_start_data, 1, 0, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_protocol_store_cert, 1, 1, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_access_certificate, 165, 2, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_hmac, 32, 167, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_end_data, 1, 199, test_mac_data, hmkit_core_characteristic_sensing_write);

    //Moc ble write responses

    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);

    //Validate outgoing data

    TEST_CHECK(199 == unit_test_offset);
    TEST_CHECK(hmkit_core_characteristic_sensing_read == unit_test_character);
    TEST_CHECK(contxtId == unit_test_context);
    TEST_CHECK(memcmp(test_mac_data,unit_test_mac,6) == 0 );
    TEST_CHECK(4 == unit_test_length);
    TEST_CHECK(memcmp(unit_test_data,test_store_certificate, 4) == 0);
    TEST_CHECK( 165 == unit_test_per_certificate_data_size);
    TEST_CHECK(memcmp(test_access_certificate,unit_test_per_certificate_data,unit_test_per_certificate_data_size) == 0);
}

void test_hmkit_core_sensing_read_response_get_stored_certificate(void){
    
    hmkit_core_init();

    //MOC ble connect

    hmkit_core_sensing_connect(contxtId, test_mac_data);

    //MOC ble incoming data

    hmkit_core_sensing_read_response(contxtId, test_start_data, 1, 0, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_protocol_get_stored_cert, 1, 1, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_serial, 9, 2, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_signature, 64, 11, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_end_data, 1, 75, test_mac_data, hmkit_core_characteristic_sensing_write);

    //Moc ble write responses

    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);

    //Validate outgoing data

    TEST_CHECK(75 == unit_test_offset);
    TEST_CHECK(hmkit_core_characteristic_sensing_read == unit_test_character);
    TEST_CHECK(contxtId == unit_test_context);
    TEST_CHECK(memcmp(test_mac_data,unit_test_mac,6) == 0 );
    TEST_CHECK(169 == unit_test_length);
    TEST_CHECK(memcmp(unit_test_data,test_get_stored_cert_result_data, unit_test_length) == 0);
    TEST_CHECK(memcmp(test_serial,unit_test_per_erase_serial,9) == 0);
}

void test_hmkit_core_sensing_read_response_authenticate(void){
    
    hmkit_core_init();

    //MOC ble connect

    hmkit_core_sensing_connect(contxtId, test_mac_data);

    //MOC ble incoming data

    hmkit_core_sensing_read_response(contxtId, test_start_data, 1, 0, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_protocol_authenticatet, 1, 1, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_serial, 9, 2, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_signature, 64, 11, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_end_data, 1, 75, test_mac_data, hmkit_core_characteristic_sensing_write);

    //Moc ble write responses

    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);

    //Validate outgoing data

    TEST_CHECK(75 == unit_test_offset);
    TEST_CHECK(hmkit_core_characteristic_sensing_read == unit_test_character);
    TEST_CHECK(contxtId == unit_test_context);
    TEST_CHECK(memcmp(test_mac_data,unit_test_mac,6) == 0 );
    TEST_CHECK(77 == unit_test_length);
    TEST_CHECK(memcmp(unit_test_data,test_authenticate_result_data, unit_test_length) == 0);
}

void test_hmkit_core_sensing_read_response_authenticate_done(void){
    
    hmkit_core_init();

    //MOC ble connect

    hmkit_core_sensing_connect(contxtId, test_mac_data);

    //MOC ble incoming data

    hmkit_core_sensing_read_response(contxtId, test_start_data, 1, 0, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_protocol_authenticatet_done, 1, 1, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_nonce, 9, 2, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_signature, 64, 11, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_end_data, 1, 75, test_mac_data, hmkit_core_characteristic_sensing_write);

    //Moc ble write responses

    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);

    //Validate outgoing data

    TEST_CHECK(75 == unit_test_offset);
    TEST_CHECK(hmkit_core_characteristic_sensing_read == unit_test_character);
    TEST_CHECK(contxtId == unit_test_context);
    TEST_CHECK(memcmp(test_mac_data,unit_test_mac,6) == 0 );
    TEST_CHECK(4 == unit_test_length);
    TEST_CHECK(memcmp(unit_test_data,test_authenticate_done_result_data, unit_test_length) == 0);
}

void test_hmkit_core_sensing_read_response_customcommand_v1(void){
    
    hmkit_core_init();

    //MOC ble connect

    hmkit_core_sensing_connect(contxtId, test_mac_data);

    //MOC ble incoming data

    uint8_t protodata[9] = {0x01, 0xFE, 0x00, 0x01, 0x03};

    hmkit_core_sensing_read_response(contxtId, test_start_data, 1, 0, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_protocol_secure_container, 1, 1, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, protodata, 5, 2, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_hmac, 32, 7, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_end_data, 1, 39, test_mac_data, hmkit_core_characteristic_sensing_write);

    //Moc ble write responses

    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);

    //Validate outgoing data

    TEST_CHECK(39 == unit_test_offset);

    if(TEST_CHECK(hmkit_core_characteristic_sensing_read == unit_test_character) == 0){
TEST_MSG("%d",unit_test_character);
TEST_MSG("%d",hmkit_core_characteristic_sensing_read);
    }

    TEST_CHECK(contxtId == unit_test_context);
    TEST_CHECK(memcmp(test_mac_data,unit_test_mac,6) == 0 );
    if(TEST_CHECK(40 == unit_test_length) == 0){
TEST_MSG("%d",unit_test_length);
    }
    TEST_CHECK(memcmp(unit_test_data,test_custom_command_result_data_v1, unit_test_length) == 0);
}

void test_hmkit_core_sensing_read_response_customcommand_v2(void){
    
    hmkit_core_init();

    //MOC ble connect

    hmkit_core_sensing_connect(contxtId, test_mac_data);

    //MOC ble incoming data

    uint8_t protodata[14] = {0x02, 0x01, 0xFE, 0x00, 0xFE, 0x00, 0xFE, 0x00, 0x01, 0x03, 0xFE, 0x00, 0x01, 0x04};

    hmkit_core_sensing_read_response(contxtId, test_start_data, 1, 0, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_protocol_secure_container, 1, 1, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, protodata, 14, 2, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_hmac, 32, 16, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_end_data, 1, 48, test_mac_data, hmkit_core_characteristic_sensing_write);

    //Moc ble write responses

    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);

    //Validate outgoing data

    TEST_CHECK(48 == unit_test_offset);

    if(TEST_CHECK(hmkit_core_characteristic_sensing_read == unit_test_character) == 0){
TEST_MSG("%d",unit_test_character);
TEST_MSG("%d",hmkit_core_characteristic_sensing_read);
    }

    TEST_CHECK(contxtId == unit_test_context);
    TEST_CHECK(memcmp(test_mac_data,unit_test_mac,6) == 0 );
    //if(TEST_CHECK(49 == unit_test_length) == 0){
//TEST_MSG("%d",unit_test_length);
    //}
    //TEST_CHECK(memcmp(unit_test_data,test_custom_command_result_data_v2, unit_test_length) == 0);
}

void test_hmkit_core_telematics_receive_data_v1(void){

    hmkit_core_init();

    uint8_t test_data[1] = {0x00};

    hmkit_core_telematics_receive_data(1,1,test_data);
}

void test_hmkit_core_telematics_receive_data_v2(void){

}

void test_hmkit_core_sensing_read_response_revoke(void){
    
    hmkit_core_init();

    //MOC ble connect

    hmkit_core_sensing_connect(contxtId, test_mac_data);

    //MOC ble incoming data

    hmkit_core_sensing_read_response(contxtId, test_start_data, 1, 0, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_protocol_revoke, 1, 1, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_serial, 9, 2, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_hmac, 32, 11, test_mac_data, hmkit_core_characteristic_sensing_write);
    hmkit_core_sensing_read_response(contxtId, test_end_data, 1, 43, test_mac_data, hmkit_core_characteristic_sensing_write);

    //Moc ble write responses

    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);
    hmkit_core_sensing_write_response(contxtId, test_mac_data, hmkit_core_characteristic_sensing_read);

    //Validate outgoing data

    TEST_CHECK(43 == unit_test_offset);
    TEST_CHECK(hmkit_core_characteristic_sensing_read == unit_test_character);
    TEST_CHECK(contxtId == unit_test_context);
    TEST_CHECK(memcmp(test_mac_data,unit_test_mac,6) == 0 );
    TEST_CHECK(8 == unit_test_length);
    TEST_CHECK(memcmp(unit_test_data,test_revoke_result_data, unit_test_length) == 0);
}

void test_hmkit_core_roundof(void){

    uint16_t result = 0;

    result = hmkit_core_roundof(16);
    TEST_CHECK(64 == result);

    result = hmkit_core_roundof(64);
    TEST_CHECK(64 == result);

    result = hmkit_core_roundof(65);
    TEST_CHECK(128 == result);

    result = hmkit_core_roundof(683);
    TEST_CHECK(704 == result);
}