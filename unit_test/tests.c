//
// Created by Maidu Ule on 21/09/2017.
//

#include "acutest.h"
#include "test_common_vars.h"
#include "test_core.h"
#include "test_cert.h"

TEST_LIST = {
        { "test_hmkit_core_cert_v0_get_size", test_hmkit_core_cert_v0_get_size },
        { "test_hmkit_core_cert_v0_get_as_bytes", test_hmkit_core_cert_v0_get_as_bytes },
        { "test_hmkit_core_cert_v0_get_as_struct",test_hmkit_core_cert_v0_get_as_struct },
        { "test_hmkit_core_cert_v1_get_size", test_hmkit_core_cert_v1_get_size },
        { "test_hmkit_core_cert_v1_get_as_bytes", test_hmkit_core_cert_v1_get_as_bytes },
        { "test_hmkit_core_cert_v1_get_as_struct",test_hmkit_core_cert_v1_get_as_struct },
        { "test_hmkit_core_get_version_major_number", test_hmkit_core_get_version_major_number },
        { "test_hmkit_core_get_version_minor_number", test_hmkit_core_get_version_minor_number },
        { "test_hmkit_core_get_version_patch_number", test_hmkit_core_get_version_patch_number },
        { "test_hmkit_core_sensing_read_notification", test_hmkit_core_sensing_read_notification },
        { "test_hmkit_core_sensing_read_response_start", test_hmkit_core_sensing_read_response_start },
        { "test_hmkit_core_sensing_read_response_end", test_hmkit_core_sensing_read_response_end },
        { "test_hmkit_core_sensing_read_response_get_nonce", test_hmkit_core_sensing_read_response_get_nonce },
        { "test_hmkit_core_sensing_read_response_get_device_cert", test_hmkit_core_sensing_read_response_get_device_cert },
        { "test_hmkit_core_sensing_read_response_register_certificate", test_hmkit_core_sensing_read_response_register_certificate },
        { "test_hmkit_core_sensing_read_response_store_certificate", test_hmkit_core_sensing_read_response_store_certificate },
        { "test_hmkit_core_sensing_read_response_get_stored_certificate", test_hmkit_core_sensing_read_response_get_stored_certificate },
        { "test_hmkit_core_sensing_read_response_authenticate", test_hmkit_core_sensing_read_response_authenticate },
        { "test_hmkit_core_sensing_read_response_authenticate_done", test_hmkit_core_sensing_read_response_authenticate_done },
        { "test_hmkit_core_sensing_read_response_customcommand_v1", test_hmkit_core_sensing_read_response_customcommand_v1 },
        { "test_hmkit_core_sensing_read_response_customcommand_v2", test_hmkit_core_sensing_read_response_customcommand_v2 },
        { "test_hmkit_core_sensing_read_response_revoke", test_hmkit_core_sensing_read_response_revoke },
        { "test_hmkit_core_telematics_receive_data_v1", test_hmkit_core_telematics_receive_data_v1 },
        { "test_hmkit_core_telematics_receive_data_v2", test_hmkit_core_telematics_receive_data_v2 },
        { "test_hmkit_core_roundof", test_hmkit_core_roundof },
        { "test_hmkit_core_sensing_read_response_get_device_cert_error_cmd", test_hmkit_core_sensing_read_response_get_device_cert_error_cmd },
        { NULL, NULL }
};
