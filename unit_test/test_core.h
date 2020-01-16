//
// Created by Maidu Ule on 05/10/2017.
//

#ifndef HIGH_MOBILITY_BT_CORE_SYSTEM_MOC_TEST_CORE_H
#define HIGH_MOBILITY_BT_CORE_SYSTEM_MOC_TEST_CORE_H

void test_hmkit_core_get_version_major_number(void);
void test_hmkit_core_get_version_minor_number(void);
void test_hmkit_core_get_version_patch_number(void);

void test_hmkit_core_sensing_read_notification(void);
void test_hmkit_core_sensing_read_response_start(void);
void test_hmkit_core_sensing_read_response_end(void);

void test_hmkit_core_sensing_read_response_get_nonce(void);
void test_hmkit_core_sensing_read_response_get_device_cert(void);
void test_hmkit_core_sensing_read_response_get_device_cert_error_cmd(void);
void test_hmkit_core_sensing_read_response_register_certificate(void);
void test_hmkit_core_sensing_read_response_store_certificate(void);
void test_hmkit_core_sensing_read_response_get_stored_certificate(void);
void test_hmkit_core_sensing_read_response_authenticate(void);
void test_hmkit_core_sensing_read_response_authenticate_done(void);
void test_hmkit_core_sensing_read_response_customcommand_v1(void);
void test_hmkit_core_sensing_read_response_customcommand_v2(void);
void test_hmkit_core_telematics_receive_data_v1(void);
void test_hmkit_core_telematics_receive_data_v2(void);
void test_hmkit_core_sensing_read_response_revoke(void);

void test_hmkit_core_roundof(void);

#endif //HIGH_MOBILITY_BT_CORE_SYSTEM_MOC_TEST_CORE_H