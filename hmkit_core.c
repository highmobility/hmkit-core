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

#include "hmkit_core.h"
#include "hmkit_core_conf_access.h"
#include "hmkit_core_api.h"
#include "hmkit_core_api_callback.h"
#include "hmkit_core_cert.h"
#include "hmkit_core_connectivity_hal.h"
#include "hmkit_core_crypto_hal.h"
#include "hmkit_core_persistence_hal.h"
#include "hmkit_core_log.h"
#include "hmkit_core_error.h"
#include "hmkit_core_config.h"
#include "hmkit_core_protocol.h"
#include <stdlib.h>

#define hmkit_core_VERSION_MAJOR 1
#define hmkit_core_VERSION_MINOR 0
#define hmkit_core_VERSION_PATCH 0

#define REQUEST_ID_MAX_BYTES_SIZE 16

static uint8_t BLE_ON = 1;

#define PACKET_BEGIN    0x00
#define PACKET_END      0xFF
#define PACKET_ESCAPE   0xFE

static uint32_t clock = 0;
static uint8_t skipBeaconCheck = 0;

#define NRF_SUCCESS 0x0

#define DATE_YEAR_POS	0
#define DATE_MONTH_POS	1
#define DATE_DAY_POS	2
#define DATE_HOUR_POS	3
#define DATE_MINS_POS	4

#define DATE_SIZE		5

#define SIZE_NONCE 9
#define SIZE_CONTENT_TYPE 1
#define SIZE_HMAC 32
#define SIZE_REQID_LEN 2
#define SIZE_TELV2_PAYLD_LEN 4
#define SIZE_TELV1_PAYLD_LEN 2

#define CRYPT_BLOCK_SIZE 64

uint16_t gMaxBufferSize = MAX_COMMAND_SIZE;

/**@brief Variable length data encapsulation in terms of length and pointer to data */
typedef struct
{
    uint8_t     * p_data;                                         /**< Pointer to data. */
    uint16_t      data_len;                                       /**< Length of data. */
}data_t;

typedef enum
{
    BLE_NO_SCAN,                                                  /**< No advertising running. */
    BLE_WHITELIST_SCAN,                                           /**< Advertising with whitelist. */
    BLE_FAST_SCAN,                                                /**< Fast advertising running. */
} ble_advertising_mode_t;

typedef struct
{
    uint16_t major;
    uint16_t minor;
    uint8_t mac[6];
} advertisement_major_minor_t;

typedef struct
{
    uint8_t name[8];
    uint8_t mac[6];
} advertisement_name_t;

typedef struct
{
    uint32_t w_size;
    uint32_t w_offset;
  #ifdef DYNAMIC_MEM_DATA
    uint8_t* txrx_buffer;
    uint32_t txrx_buffer_size;
  #else
    uint8_t txrx_buffer[MAX_COMMAND_SIZE];
  #endif
    bool beginMessageReceived;
    bool escapeNextByte;
    int rx_buffer_ptr;
    bool m_is_writing_data;
    bool m_write_data_failed;
} data_buffer_t;

typedef struct
{
  #ifdef DYNAMIC_MEM_DATA
    uint8_t* txrx_prepare_sensing;
    uint8_t* txrx_prepare_link;
  #else
    uint8_t txrx_prepare_sensing[MAX_COMMAND_SIZE];
    uint8_t txrx_prepare_link[MAX_COMMAND_SIZE];
  #endif
    data_buffer_t txrx_sensing;
    data_buffer_t txrx_link;
    bool isEmpty;
    bool isLeaved;
    uint8_t is_entered_reported;
    uint8_t is_mesaured_reported;
    hmkit_core_receiver_t receivers[5];
    hmkit_core_device_t device;

    //Session
    uint8_t nonce[9];
    uint8_t local_nonce[9];
    uint8_t remote_nonce[9];
    uint16_t local_counter;
    uint16_t remote_counter;
    uint8_t adv_name[8];
    uint16_t mtu;
    // Callback Data
    bool sendCallback;
    uint8_t callbackVersion;
  #ifdef DYNAMIC_MEM_DATA
    uint8_t* callbackData;
  #else
    uint8_t callbackData[MAX_COMMAND_SIZE];
  #endif
    uint8_t callbackContentType;
    uint32_t callbackDataSize;
    uint8_t callbackReqID[REQUEST_ID_MAX_BYTES_SIZE + 1];
    uint16_t callbackReqIDSize;

    bool isLink;
    bool isRegisterAllowed;

    // Bluetooth ContextHandler
    uint64_t btContextHndlr;

    // App ContextHandler
    uint64_t appContextHndlr;

} connected_beacons_t;

// Context Handlers:
//
// APP context handler(appContextHndlr): Needed to track the application context that triggered a flow.
// when the Api flow makes some callback back to the application or persistence or crypto; context handler should
// be passed along. So that in concurrent flow environments(like in Nodejs for every parallel received commands),
// App will be able to match the callbacks with its context that triggered the flow.
// Caching: context handler cached per connection object.
//
// BT context handler(btContextHndlr): same as App contexthandler to track the context but the context handler is specifically needed for Connectivity
// Hal to map the flow with the bluetooth connections(like Connection ID). helps to avoid heavy mappings required in Connectivity Hal.
// Caching: cached per connection object.
//
// Telematics handler: This is specific for the Telematics flow which has limited Apis and single flow.
// Single end to end flow, means there is no asynchronous callbacks(like Bluetooth events, timer etc) involved.
// Caching: Not required, Context handler is passed live through out the Api flow.

static uint8_t is_ctw_call = 0;

//static uint8_t reg_serial[9];
#define MAX_BLE_MTU 512 // can limit to 100 or 200 max for safer side
#define DEFAULT_BLE_MTU 20

static connected_beacons_t mBeacons[MAX_CLIENTS];
static advertisement_major_minor_t mMajorMinor[MAX_CLIENTS];
static advertisement_name_t mName[MAX_CLIENTS];

uint8_t hmkit_core_core_commandinprogress = 0;

//PROTOTYPES
uint8_t hmkit_core_calculate_next_nonce(uint8_t *nonce);
uint8_t hmkit_core_validate_hmac(uint64_t appContxtId, uint8_t* nonce, uint8_t *serial, uint8_t *data, uint16_t size, uint8_t *hmac);

uint32_t hmkit_core_add_signature(uint64_t appContxtId, uint8_t *data, uint8_t size, uint8_t *signature);
uint32_t hmkit_core_validate_signature(uint64_t appContxtId, uint8_t *data, uint8_t size, uint8_t *signature, uint8_t *serial);
uint32_t hmkit_core_validate_all_signatures(uint64_t appContxtId, uint8_t *data, uint8_t size, uint8_t *signature);
uint32_t hmkit_core_validate_ca_signature(uint64_t appContxtId, uint8_t *data, uint8_t size, uint8_t *signature);
uint32_t hmkit_core_validate_oem_ca_signature(uint64_t appContxtId, uint8_t *data, uint8_t size, uint8_t *signature);

void initMajorMinorList(void);
bool addMajorMinorToList( uint8_t *mac, uint16_t major, uint16_t minor);
bool getMajorMinorFromList(uint8_t *mac, uint16_t *major, uint16_t *minor);
bool addNameToList( uint8_t *mac, uint8_t *name);
bool getNameFromList(uint8_t *mac, uint8_t *name);
static uint32_t get_slot_for_client(void);
connected_beacons_t* getBeaconId( uint8_t* mac);
uint32_t client_handling_add_serial(uint8_t *mac, uint8_t *serialNumber );
uint32_t client_handling_set_authorised(connected_beacons_t * p_client, uint8_t authorized );
void hmkit_core_init_slaves(void);
uint32_t client_handling_create(uint8_t *mac, uint16_t major, uint16_t minor, uint8_t *name, bool isLink);
connected_beacons_t* getBeaconIdSerial( uint8_t* serial);
connected_beacons_t* getBeaconIdName( uint8_t* name);
void reportBeaconLeaveForAll(void);
void reportBeaconExitForAll(void);
void initBeaconList(void);
uint32_t client_handling_destroy( uint8_t *mac);
void checkBeacons(void);
void writeNextJunk(uint8_t *mac, hmkit_core_characteristic characteristic);
uint16_t prepareTxPackage(uint16_t size, uint8_t *data, uint8_t *txrx);
void writeData(uint64_t appContxtId, uint32_t size, uint8_t *data, uint8_t *mac, hmkit_core_characteristic characteristic);
hmkit_core_characteristic getCommandCharacteristic(connected_beacons_t * p_client);
void sendGetNonceRequest(uint64_t appContxtId, uint8_t isctw, uint8_t *mac);
void sendAuthenticateDone(uint64_t appContxtId, uint8_t *serial);
void sendGetCertificate(uint8_t *mac);
void processGetNonce(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic);
void processGetDeviceCertificate(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic);
void processGetCertificate(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic);
void processAuthenticate(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic);
void processAuthenticateDone(connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic);
uint32_t hmkit_core_send_telematics_error(uint64_t appContxtId, uint8_t *serial, uint8_t id, uint8_t error, uint8_t *reqID, uint16_t reqID_size, uint8_t version);
void processRegisterCertificate(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic);
void processRevoke(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic);
void processSecureContainer(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic);
void processSecureCommandContainerIncoming(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic);
void processGetNonceIncoming(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic);
void processGetDeviceCertificateIncoming(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic);
void processRegisterCertificateIncoming(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic);
void processStoreCertificateIncoming(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic);
void processGetCertificateIncoming(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic);
void processAuthenticateIncoming(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic);
void processAuthenticateDoneIncoming(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic);
void processRevokeIncoming(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic);
void processIncomingCommand(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic);
void processIncomingAck(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic);
void processIncomingPacket( connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic);
void resetRxBuffer(data_buffer_t * databuffer);
bool bt_data_handler( uint8_t * p_data, uint16_t length, connected_beacons_t * p_client,hmkit_core_characteristic characteristic);
int8_t calcAvRssi(int8_t *rssi);
void processErrorCommandIncoming(uint64_t appContxtId, connected_beacons_t *p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic);

// Sent for Errors found in the received Commands(or Request). Error is sent as response.
void sendError(uint64_t appContxtId, connected_beacons_t * p_client, uint8_t error, uint8_t command, hmkit_core_characteristic characteristic, uint8_t *requestID, uint16_t reqID_size);
// Sent for Errors found in the received Response. This Error will be sent like a command.
void sendError_Command(uint64_t appContxtId, connected_beacons_t * p_client, uint8_t error_type, uint8_t command, hmkit_core_characteristic characteristic);

void timer_garbagecollect_certf(void);
int16_t trigger_persis_garbage_collection(void);
//void update_journeyId_propBlock_accessCertSt(uint8_t *pCertBuff, hdr_prop_block_t *pPropBlock);
void clear_list(void);
void add_to_listend(uint8_t *cert);
void clear_list(void);
void update_btcontext_Hndlr(uint64_t btcontxtId, uint8_t *mac);
uint64_t get_btcontext_Hndlr(uint8_t *mac);

void cache_appContext_Hndlr(uint64_t btcontxtId, uint8_t *mac);
uint64_t get_appContext_Hndlr(uint8_t *mac);

static int parse_MTU_value(uint8_t *data, uint16_t size);

uint8_t hmkit_core_calculate_next_nonce(uint8_t *nonce){
  uint8_t i = 0;
  for(i = 0; i < 9; i++){
    if(nonce[i] < 0xFF){
      nonce[i]++;
      return 1;
    }
  }

  return 0;
}

//H-M specific crypto logic

void hmkit_core_encrypt_decrypt(uint64_t appContxtId, uint8_t *nonce, uint8_t *transaction_nonce, uint8_t *key, uint8_t *data, uint16_t data_size){

  uint8_t random[16];
  uint8_t cipertext[16];

  memcpy(random, nonce, 7);
  memcpy(random + 7, transaction_nonce, 9);

  if(hmkit_core_crypto_hal_aes_ecb_block_encrypt(appContxtId, key, random, cipertext) == 0){

    uint8_t xorPosition = 0;

    uint16_t i = 0;
    for(i = 0; i < data_size; i++){

      data[i] = data[i] ^ cipertext[xorPosition];

      xorPosition++;
      if(xorPosition >= 16){
        xorPosition = 0;
      }
    }
  }
}

uint16_t hmkit_core_roundof(uint16_t size){

  uint8_t mod = 0;
	uint16_t div = 0;

	if (size > CRYPT_BLOCK_SIZE) {
		mod = size % CRYPT_BLOCK_SIZE;
	    div = size/CRYPT_BLOCK_SIZE;

		if (mod) {
			return  CRYPT_BLOCK_SIZE * (div + 1);
		}
		else {
			return  CRYPT_BLOCK_SIZE * div;
		}
	}
	else {
        // minimum block size
		return CRYPT_BLOCK_SIZE;
	}
}

uint8_t hmkit_core_generate_ecdh(uint64_t appContxtId, uint8_t* nonce, uint8_t *serial, uint8_t *ecdh){

  uint8_t ecdh_o[32];
  if(hmkit_core_crypto_hal_ecc_get_ecdh(appContxtId, serial, ecdh_o) == 1){
    return 1;
  }

  //Prepare one crypto block
  uint8_t databuffer[CRYPT_BLOCK_SIZE];
  memset(databuffer,0x00, CRYPT_BLOCK_SIZE);
  memcpy(databuffer,nonce,9);

  return hmkit_core_crypto_hal_hmac(appContxtId, ecdh_o, databuffer, CRYPT_BLOCK_SIZE, ecdh);
}

uint8_t hmkit_core_generate_hmac(uint64_t appContxtId, uint8_t* nonce, uint8_t *serial, uint8_t *data, uint16_t size, uint8_t *hmac){
  uint8_t ecdh[32];

  if(hmkit_core_generate_ecdh(appContxtId, nonce, serial, ecdh) == 1){
    return 1;
  }

  //Prepare proper amount of crypto block's

  uint16_t blockdatasize = hmkit_core_roundof(size);
  
#ifdef DYNAMIC_MEM_DATA
  uint8_t *databuffer = (uint8_t *)malloc(blockdatasize * sizeof(uint8_t));
  memset(databuffer,0x00, blockdatasize);
#else
  uint8_t databuffer[MAX_COMMAND_SIZE];
  memset(databuffer,0x00, MAX_COMMAND_SIZE);
#endif

  memcpy(databuffer,data,size);

  uint8_t ret = hmkit_core_crypto_hal_hmac(appContxtId, ecdh, databuffer, blockdatasize, hmac);

#ifdef DYNAMIC_MEM_DATA
  free(databuffer);
#endif

  return ret;
}

uint8_t hmkit_core_validate_hmac(uint64_t appContxtId, uint8_t* nonce, uint8_t *serial, uint8_t *data, uint16_t size, uint8_t *hmac){

  uint8_t hmac_new[SIZE_HMAC];
  if(hmkit_core_generate_hmac(appContxtId, nonce, serial, data, size, hmac_new) == 1){
    return 1;
  }

  return memcmp(hmac_new,hmac,SIZE_HMAC);
}

uint32_t hmkit_core_add_signature(uint64_t appContxtId, uint8_t *data, uint8_t size, uint8_t *signature){

  uint16_t blockdatasize = hmkit_core_roundof(size);
  
#ifdef DYNAMIC_MEM_DATA
  uint8_t *databuffer = (uint8_t *)malloc(blockdatasize * sizeof(uint8_t));
  memset(databuffer,0x00, blockdatasize);
#else
  uint8_t databuffer[MAX_COMMAND_SIZE];
  memset(databuffer,0x00, MAX_COMMAND_SIZE);
#endif

  memcpy(databuffer,data,size);

  uint32_t ret = hmkit_core_crypto_hal_ecc_add_signature(appContxtId, databuffer, blockdatasize, signature);  

#ifdef DYNAMIC_MEM_DATA
  free(databuffer);
#endif
  
  return ret;
}

uint32_t hmkit_core_validate_signature(uint64_t appContxtId, uint8_t *data, uint8_t size, uint8_t *signature, uint8_t *serial){

  uint16_t blockdatasize = hmkit_core_roundof(size);
  
#ifdef DYNAMIC_MEM_DATA
  uint8_t *databuffer = (uint8_t *)malloc(blockdatasize * sizeof(uint8_t));
  memset(databuffer,0x00, blockdatasize);
#else
  uint8_t databuffer[MAX_COMMAND_SIZE];
  memset(databuffer,0x00, MAX_COMMAND_SIZE);
#endif

  memcpy(databuffer,data,size);

  uint32_t ret = hmkit_core_crypto_hal_ecc_validate_signature(appContxtId, databuffer, blockdatasize, signature, serial);

#ifdef DYNAMIC_MEM_DATA
  free(databuffer);
#endif

  return ret;
}

uint32_t hmkit_core_validate_all_signatures(uint64_t appContxtId, uint8_t *data, uint8_t size, uint8_t *signature){

  uint16_t blockdatasize = hmkit_core_roundof(size);
  
#ifdef DYNAMIC_MEM_DATA
  uint8_t *databuffer = (uint8_t *)malloc(blockdatasize * sizeof(uint8_t));
  memset(databuffer,0x00, blockdatasize);
#else
  uint8_t databuffer[MAX_COMMAND_SIZE];
  memset(databuffer,0x00, MAX_COMMAND_SIZE);
#endif


  memcpy(databuffer,data,size);

  uint32_t ret = hmkit_core_crypto_hal_ecc_validate_all_signatures(appContxtId, databuffer, blockdatasize, signature);

#ifdef DYNAMIC_MEM_DATA
  free(databuffer);
#endif

  return ret;
}

uint32_t hmkit_core_validate_ca_signature(uint64_t appContxtId, uint8_t *data, uint8_t size, uint8_t *signature){

  uint16_t blockdatasize = hmkit_core_roundof(size);
  
#ifdef DYNAMIC_MEM_DATA
  uint8_t *databuffer = (uint8_t *)malloc(blockdatasize * sizeof(uint8_t));
  memset(databuffer,0x00, blockdatasize);
#else
  uint8_t databuffer[MAX_COMMAND_SIZE];
  memset(databuffer,0x00, MAX_COMMAND_SIZE);
#endif

  memcpy(databuffer,data,size);

  uint32_t ret = hmkit_core_crypto_hal_ecc_validate_ca_signature(appContxtId, databuffer, blockdatasize, signature);

#ifdef DYNAMIC_MEM_DATA
  free(databuffer);
#endif

  return ret;
}

uint32_t hmkit_core_validate_oem_ca_signature(uint64_t appContxtId, uint8_t *data, uint8_t size, uint8_t *signature){

  uint16_t blockdatasize = hmkit_core_roundof(size);

#ifdef DYNAMIC_MEM_DATA
  uint8_t *databuffer = (uint8_t *)malloc(blockdatasize * sizeof(uint8_t));
  memset(databuffer,0x00, blockdatasize);
#else
  uint8_t databuffer[MAX_COMMAND_SIZE];
  memset(databuffer,0x00, MAX_COMMAND_SIZE);
#endif

  memcpy(databuffer,data,size);

  uint32_t ret = hmkit_core_crypto_hal_ecc_validate_oem_ca_signature(appContxtId, databuffer, blockdatasize, signature);

#ifdef DYNAMIC_MEM_DATA
  free(databuffer);
#endif

  return ret;
}

void hmkit_core_explode(uint16_t source, uint8_t *dest) {
  dest[0] = source >> 8;
  dest[1] = source & 0xFF;
}

uint16_t hmkit_core_implode(uint8_t *msb) {
  // msb[1] = lsb
  return (((uint16_t) msb[0]) << 8) | msb[1];
}

void initMajorMinorList(){
  uint8_t i = 0 ;
  for(i = 0 ; i < MAX_CLIENTS ; i++){
    memset(mMajorMinor[i].mac,0x00,6);
    memset(mName[i].mac,0x00,6);
  }
}

bool addMajorMinorToList( uint8_t *mac, uint16_t major, uint16_t minor){

uint8_t emptyMac[6];
memset(emptyMac,0x00,6);

//Find existing
uint8_t i = 0 ;
for(i = 0 ; i < MAX_CLIENTS ; i++){
if(memcmp(mMajorMinor[i].mac,mac,6) == 0){
mMajorMinor[i].major = major;
mMajorMinor[i].minor = minor;
return true;
}
}

//Find empty
for(i = 0 ; i < MAX_CLIENTS ; i++){
if(memcmp(mMajorMinor[i].mac,emptyMac,6) == 0){
memcpy(mMajorMinor[i].mac,mac,6);
mMajorMinor[i].major = major;
mMajorMinor[i].minor = minor;
return true;
}
}

return false;
}

bool getMajorMinorFromList(uint8_t *mac, uint16_t *major, uint16_t *minor){

  //Find existing
  uint8_t i = 0 ;
  for(i = 0 ; i < MAX_CLIENTS ; i++){
    if(memcmp(mMajorMinor[i].mac,mac,6) == 0){
      *major = mMajorMinor[i].major;
      *minor = mMajorMinor[i].minor;
      memset(mMajorMinor[i].mac,0x00,6);
      return true;
    }
  }

  return false;
}

bool addNameToList( uint8_t *mac, uint8_t *name){

  uint8_t emptyMac[6];
  memset(emptyMac,0x00,6);

  //Find existing
  uint8_t i = 0 ;
  for(i = 0 ; i < MAX_CLIENTS ; i++){
    if(memcmp(mName[i].mac,mac,6) == 0){
      memcpy(mName[i].name,name,8);
      return true;
    }
  }

  //Find empty
  for(i = 0 ; i < MAX_CLIENTS ; i++){
    if(memcmp(mName[i].mac,emptyMac,6) == 0){
      memcpy(mName[i].mac,mac,6);
      memcpy(mName[i].name,name,8);
      return true;
    }
  }

  return false;
}

bool getNameFromList(uint8_t *mac, uint8_t *name){

  //Find existing
  uint8_t i = 0 ;
  for(i = 0 ; i < MAX_CLIENTS ; i++){
    if(memcmp(mName[i].mac,mac,6) == 0){
      memcpy(name,mName[i].name,8);
      memset(mName[i].mac,0x00,6);
      return true;
    }
  }
  return false;
}

static uint32_t get_slot_for_client()
{
  uint32_t i;

  for (i = 0; i < MAX_CLIENTS; i++)
  {
    if (mBeacons[i].isEmpty == true)
    {
      return i;
    }
    
  }

  return MAX_CLIENTS;
}

/**@brief Function for service discovery.
 *
 * @param[in] p_client Client context information.
 */
static void service_discover(connected_beacons_t * p_client)
{

  hmkit_core_connectivity_hal_service_discovery(p_client->device.mac);
}

connected_beacons_t* getBeaconId(uint8_t* mac)
{
  int i = 0;

  if(mac != NULL)
  {
     for(i = 0 ; i < MAX_CLIENTS ; i++)
     {
        if( mBeacons[i].isEmpty == false )
        {
           if(memcmp(mac,mBeacons[i].device.mac,6) == 0)
           {
             return &mBeacons[i];
           }
        }
     }
  }

  hmkit_core_log(mac,NULL,HMKIT_CORE_LOG_ERROR,"[HMCore] getBeaconId, client not found");
  return NULL;
}

uint32_t client_handling_add_serial(uint8_t *mac, uint8_t *serialNumber )
{

  connected_beacons_t *p_client = getBeaconId(mac);

  if(p_client != NULL){
    memcpy(p_client->device.serial_number,serialNumber,9);
  }

  return NRF_SUCCESS;
}

uint32_t client_handling_set_authorised(connected_beacons_t * p_client, uint8_t authorized ){

  //Set authorized flag and tell to report to CTW
  p_client->device.is_authorised = authorized;
  p_client->is_entered_reported = 0;

  return NRF_SUCCESS;
}

/**@brief Function for setting MTU for BT chunk data size
 * (API to be called in the Link side)
 */
uint32_t hmkit_core_set_mtu(uint8_t *mac, uint16_t mtu)
{
  connected_beacons_t *p_client = getBeaconId(mac);

  if(mtu > MAX_BLE_MTU)
  {
    hmkit_core_log(NULL,NULL,HMKIT_CORE_LOG_ERROR,"[HMCore] invald mtu size %d, max possible = %d", mtu, MAX_BLE_MTU);
    return 1;
  }

  if(p_client != NULL)
  {
    p_client->mtu = mtu - 3; // 3 bytes for header
  }
  else
  {
      hmkit_core_log(NULL,NULL,HMKIT_CORE_LOG_ERROR,"[HMCore] connection not created yet, client not found");
      return 1;
  }

  return 0;
}

/**@brief Function for creating a new client.
 */
uint32_t client_handling_create(uint8_t *mac, uint16_t major, uint16_t minor, uint8_t *name, bool isLink)
{
uint8_t connection_id = get_slot_for_client();

if(connection_id == MAX_CLIENTS){
return 1;
}

memcpy(mBeacons[connection_id].device.mac,mac,6);

// default 20 bytes MTU
mBeacons[connection_id].mtu = DEFAULT_BLE_MTU;

//Set client initial state
mBeacons[connection_id].isEmpty = false;
mBeacons[connection_id].isLeaved = false;
mBeacons[connection_id].isLink = isLink;
mBeacons[connection_id].isRegisterAllowed = false;

mBeacons[connection_id].device.major = major;
mBeacons[connection_id].device.minor = minor;

memset(mBeacons[connection_id].device.info_string,0x00,30);
memcpy(mBeacons[connection_id].adv_name,name,8);

// Initialize Callback parameters
mBeacons[connection_id].sendCallback = 0;
mBeacons[connection_id].callbackContentType = 0;
mBeacons[connection_id].callbackDataSize = 0;
mBeacons[connection_id].callbackReqIDSize = 0;

if(!isLink){
service_discover(&mBeacons[connection_id]);
}

mBeacons[connection_id].btContextHndlr = 0;
mBeacons[connection_id].appContextHndlr = 0;

return NRF_SUCCESS;
}

connected_beacons_t* getBeaconIdSerial( uint8_t* serial){
  int i = 0 ;
  for(i = 0 ; i < MAX_CLIENTS ; i++){
    if( mBeacons[i].isEmpty == false ){
      if(memcmp(serial,mBeacons[i].device.serial_number,9) == 0){
        return &mBeacons[i];
      }
    }
  }

  hmkit_core_log(NULL,NULL,HMKIT_CORE_LOG_ERROR,"[HMCore] getBeaconIdSerial, client not found");
  return NULL;
}

connected_beacons_t* getBeaconIdName( uint8_t* name){
  int i = 0 ;
  for(i = 0 ; i < MAX_CLIENTS ; i++){
    if( mBeacons[i].isEmpty == false ){
      if(memcmp(name,mBeacons[i].adv_name,8) == 0){
        return &mBeacons[i];
      }
    }
  }

  hmkit_core_log(NULL,NULL,HMKIT_CORE_LOG_ERROR,"[HMCore] getBeaconIdName, client not found");
  return NULL;
}

void reportBeaconLeaveForAll(){
  int i = 0 ;
  uint64_t btContxtHndlr;

  for(i = 0 ; i < MAX_CLIENTS ; i++){
    if(mBeacons[i].isEmpty == false){
      if(mBeacons[i].isLink == false) {
        btContxtHndlr = get_btcontext_Hndlr(mBeacons[i].device.mac);
        hmkit_core_connectivity_hal_disconnect(btContxtHndlr, mBeacons[i].device.mac);
      }
    }
  }
}

void reportBeaconExitForAll(){
  int i = 0 ;
  for(i = 0 ; i < MAX_CLIENTS ; i++){
    if(mBeacons[i].isEmpty == false){
      if(mBeacons[i].isLink == false) {
        mBeacons[i].isLeaved = true;
        //mBeacons[i].device.is_authorised = 0;
      }
    }
  }
}

void initBeaconList(){
  int i = 0 ;
  for(i = 0 ; i < MAX_CLIENTS ; i++){
    mBeacons[i].isLink = false;
    mBeacons[i].isEmpty = true;
    mBeacons[i].isLeaved = true;
    mBeacons[i].is_entered_reported = 1;
    mBeacons[i].device.is_authorised = 0;
    memset(mBeacons[i].device.serial_number,0x00,9);
    memset(mBeacons[i].device.mac,0x00,6);
    mBeacons[i].mtu = DEFAULT_BLE_MTU;

  #ifdef DYNAMIC_MEM_DATA
    mBeacons[i].txrx_prepare_sensing = NULL;
    mBeacons[i].txrx_prepare_link = NULL;
    mBeacons[i].txrx_sensing.txrx_buffer = NULL;
    mBeacons[i].txrx_link.txrx_buffer = NULL;
    //mBeacons[i].callbackData = NULL;
  #endif

  }
}

/**@brief Function for freeing up a client by setting its state to idle.
 */
uint32_t client_handling_destroy( uint8_t *mac)
{
  uint32_t err_code = NRF_SUCCESS;

  connected_beacons_t *p_client = getBeaconId(mac);

  if(p_client == NULL){
    return 1;
  }

  p_client->isLeaved = true;

  return err_code;
}

void checkBeacons(){
  uint64_t appContxtId =0;

  if(skipBeaconCheck == 0){
    int i = 0 ;
    for(i = 0 ; i < MAX_CLIENTS ; i++){
      if(mBeacons[i].isEmpty == false){

        if(mBeacons[i].isLeaved == true){
          if(mBeacons[i].isEmpty == false){
            mBeacons[i].isEmpty = true;
            mBeacons[i].isLink = false;

            appContxtId = get_appContext_Hndlr(mBeacons[i].device.mac);
            hmkit_core_api_callback_exited_proximity(appContxtId, &mBeacons[i].device);

            mBeacons[i].device.major = 0;
            mBeacons[i].device.minor = 0;
            mBeacons[i].device.is_authorised = 0;
            memset(mBeacons[i].device.serial_number,0x00,9);
            memset(mBeacons[i].device.mac,0x00,6);
          }
        }

        if(mBeacons[i].is_entered_reported  ==  0){
          mBeacons[i].is_entered_reported = 1;
          hmkit_core_log(NULL,NULL,HMKIT_CORE_LOG_INFO,"[HMCore] hmkit_core_api_callback_entered_proximity");
          appContxtId = get_appContext_Hndlr(mBeacons[i].device.mac);
          hmkit_core_api_callback_entered_proximity(appContxtId, &mBeacons[i].device);
        }
      }
    }
  }
}

data_buffer_t* getDataBuffer(connected_beacons_t * p_client, hmkit_core_characteristic characteristic);
uint8_t* getPrepareDataBuffer(connected_beacons_t * p_client, hmkit_core_characteristic characteristic, uint16_t needeSize);

data_buffer_t* getDataBuffer(connected_beacons_t * p_client, hmkit_core_characteristic characteristic){
  if(characteristic == hmkit_core_characteristic_sensing_write || characteristic == hmkit_core_characteristic_sensing_read){
    return &p_client->txrx_sensing;
  }else{
    return &p_client->txrx_link;
  }
}

uint8_t* getPrepareDataBuffer(connected_beacons_t * p_client, hmkit_core_characteristic characteristic, uint16_t needeSize){
  if(characteristic == hmkit_core_characteristic_sensing_write || characteristic == hmkit_core_characteristic_sensing_read){
    #ifdef DYNAMIC_MEM_DATA
      //If previous buffer exists then delete it before creating new
      if(p_client->txrx_prepare_sensing != NULL){
        free(p_client->txrx_prepare_sensing);
        p_client->txrx_prepare_sensing = NULL;
      }
      return p_client->txrx_prepare_sensing = (uint8_t *)malloc(needeSize * sizeof(uint8_t));
    #else
      BTUNUSED(needeSize);
      return p_client->txrx_prepare_sensing;
    #endif
  }else{
    #ifdef DYNAMIC_MEM_DATA
      //If previous buffer exists then delete it before creating new
      if(p_client->txrx_prepare_link != NULL){
        free(p_client->txrx_prepare_link);
        p_client->txrx_prepare_link = NULL;
      }
      return p_client->txrx_prepare_link = (uint8_t *)malloc(needeSize * sizeof(uint8_t));
    #else
      BTUNUSED(needeSize);
      return p_client->txrx_prepare_link;
    #endif
  }
}

void writeNextJunk(uint8_t *mac, hmkit_core_characteristic characteristic){

  hmkit_core_log(mac,NULL,HMKIT_CORE_LOG_INFO,"[HMCore] Write next junk func");

  connected_beacons_t * p_client = getBeaconId(mac);

  if(p_client == NULL){
    return;
  }

  uint16_t MTU = p_client->mtu;

  uint64_t btContxtHndlr = get_btcontext_Hndlr(mac);

  data_buffer_t * databuffer = getDataBuffer(p_client,characteristic);

  if(databuffer->m_write_data_failed == true){
    databuffer->m_write_data_failed = false;
    databuffer->w_offset = databuffer->w_offset - MTU;
  }

  if(databuffer->w_size > databuffer->w_offset + MTU){
      hmkit_core_log(mac,NULL,HMKIT_CORE_LOG_INFO,"[HMCore] Write next junk");
      uint32_t   err_code = hmkit_core_connectivity_hal_write_data(btContxtHndlr, mac, MTU, databuffer->txrx_buffer + databuffer->w_offset,characteristic);
      databuffer->w_offset = databuffer->w_offset + MTU;
      if(err_code != NRF_SUCCESS){
        databuffer->m_write_data_failed = true;
      }
      //writeNextJunk();
  }else if (databuffer->w_size > databuffer->w_offset){
    hmkit_core_log(mac,NULL,HMKIT_CORE_LOG_INFO,"[HMCore] Write last junk");
    uint32_t   err_code = hmkit_core_connectivity_hal_write_data(btContxtHndlr, mac, databuffer->w_size - databuffer->w_offset, databuffer->txrx_buffer + databuffer->w_offset,characteristic);
    databuffer->w_offset = databuffer->w_offset + ( databuffer->w_size - databuffer->w_offset );
    if(err_code != NRF_SUCCESS){
      databuffer->m_write_data_failed = true;
    }else{
      hmkit_core_log(mac,NULL,HMKIT_CORE_LOG_INFO,"[HMCore] Writing data false");
      databuffer->m_is_writing_data = false;
      skipBeaconCheck = 0;
      return;
    }
  }
}

uint16_t prepareTxPackage(uint16_t size, uint8_t *data, uint8_t *txrx){
  // Prepare the message, with the appropriate data structure
  uint16_t count = 0;

  txrx[count++] = PACKET_BEGIN;

  int i = 0;
  for (i = 0; i < size; i++) {
    if (data[i] == 0x00 || data[i] == 0xFE || data[i] == 0xFF){
      txrx[count++] = PACKET_ESCAPE;
    }

    txrx[count++] = data[i];
  }

  txrx[count++] = PACKET_END;

  return count;
}

void writeData(uint64_t appContxtId, uint32_t size, uint8_t *data, uint8_t *mac, hmkit_core_characteristic characteristic){

  hmkit_core_log_data(mac,NULL,HMKIT_CORE_LOG_INFO,data,size,"[HMCore] DATA OUT");

  connected_beacons_t *p_client = getBeaconId(mac);

  if(p_client == NULL){
    return;
  }

  uint16_t MTU = p_client->mtu;

  uint64_t btContxtHndlr = get_btcontext_Hndlr(mac);

  data_buffer_t * databuffer = getDataBuffer(p_client,characteristic);

#ifdef DYNAMIC_MEM_DATA
  //Clean up previous data buffer
  if(databuffer->txrx_buffer != NULL){
    free(databuffer->txrx_buffer);
    databuffer->txrx_buffer = NULL;
  }

  //Create new buffer
  databuffer->txrx_buffer = (uint8_t *)malloc((size * 2 + 2) * sizeof(uint8_t));
#endif

  databuffer->m_is_writing_data = true;
  databuffer->m_write_data_failed = false;

  if(p_client->device.is_authorised == true){
    hmkit_core_log(mac,NULL,HMKIT_CORE_LOG_INFO,"[HMCore] Crypto on outgoing");
    //If it is ack
    if(characteristic == hmkit_core_characteristic_link_write || characteristic == hmkit_core_characteristic_sensing_read){
      uint8_t ecdh[32];
      hmkit_core_generate_ecdh(appContxtId, p_client->remote_nonce, p_client->device.serial_number, ecdh);
      hmkit_core_encrypt_decrypt(appContxtId, p_client->nonce, p_client->remote_nonce, ecdh, data, size);
    }else{
      uint8_t ecdh[32];
      hmkit_core_generate_ecdh(appContxtId, p_client->local_nonce, p_client->device.serial_number, ecdh);
      hmkit_core_encrypt_decrypt(appContxtId, p_client->nonce, p_client->local_nonce, ecdh, data, size);
    }
  }

  databuffer->w_size = prepareTxPackage(size,data,databuffer->txrx_buffer);

  if(p_client->isLink == true){
    hmkit_core_connectivity_hal_write_data(btContxtHndlr, mac, databuffer->w_size, databuffer->txrx_buffer,characteristic);

    if(p_client->device.is_authorised == true){
      //If it is ack
      if(characteristic == hmkit_core_characteristic_link_write || characteristic == hmkit_core_characteristic_sensing_read){
        hmkit_core_calculate_next_nonce(p_client->remote_nonce);
        p_client->remote_counter++;
      }
    }

        skipBeaconCheck = 0;
    return;
  }

  if( databuffer->w_size <= MTU ){
    databuffer->w_offset = databuffer->w_size;
    databuffer->m_is_writing_data = false;
    skipBeaconCheck = 0;
  }else{
    databuffer->w_offset = MTU;
  }

  uint32_t   err_code = hmkit_core_connectivity_hal_write_data(btContxtHndlr, mac, databuffer->w_offset, databuffer->txrx_buffer,characteristic);
  if(err_code != NRF_SUCCESS){
    databuffer->m_write_data_failed = true;
    return;
  }

  if(p_client->device.is_authorised == true){
    //If it is ack
    if(characteristic == hmkit_core_characteristic_link_write || characteristic == hmkit_core_characteristic_sensing_read){
      hmkit_core_calculate_next_nonce(p_client->remote_nonce);
      p_client->remote_counter++;
    }
  }

}


hmkit_core_characteristic getCommandCharacteristic(connected_beacons_t * p_client){
  if(p_client->isLink){
    return hmkit_core_characteristic_link_read;
  }else{
    return hmkit_core_characteristic_sensing_write;
  }

}

void sendGetNonceRequest(uint64_t appContxtId, uint8_t isctw, uint8_t *mac){

  hmkit_core_log(mac,NULL,HMKIT_CORE_LOG_INFO,"[HMSensing] Getting nonce");
  connected_beacons_t *p_client = getBeaconId(mac);

  if(p_client != NULL){
    is_ctw_call = isctw;
    uint8_t command_buffer[1];
    command_buffer[0] = ID_CRYPTO_GET_NONCE;
    writeData(appContxtId, 1,command_buffer,mac,getCommandCharacteristic(p_client));
  }

  //TODO report nonce read failed
}

void sendGetDeviceCertificateRequest(uint64_t appContxtId, uint8_t isctw, uint8_t *requestData, uint8_t *mac){

  hmkit_core_log(mac,NULL,HMKIT_CORE_LOG_INFO,"[HMSensing] Getting device certificate");

  connected_beacons_t *p_client = getBeaconId(mac);

  if(p_client != NULL){

    is_ctw_call = isctw;
    uint8_t command_buffer[74];

    command_buffer[0] = ID_CRYPTO_GET_DEVICE_CERTIFICATE;
    memset(command_buffer + 1,0x00,9);

    if(is_ctw_call == 1){
      memcpy(command_buffer + 1,requestData,73);
      writeData(appContxtId, 74,command_buffer,mac,getCommandCharacteristic(p_client));
      return;
    }else{
      //Add signature
      if(hmkit_core_add_signature(appContxtId, command_buffer + 1, 9, command_buffer + 10) == 0){

        writeData(appContxtId, 74,command_buffer,mac,getCommandCharacteristic(p_client));
        return;
      }
    }
  }
  else
  {
        hmkit_core_log(NULL, NULL,HMKIT_CORE_LOG_ERROR,"[HMCore] sendGetDeviceCertificateRequest: p_client NULL, client not connected");
  }


  //TODO error handling
}

void sendAuthenticate(uint64_t appContxtId, uint8_t *serial){

  //if authenticated then skip
  connected_beacons_t *p_client = getBeaconIdSerial(serial);

  if(p_client != NULL) {

    hmkit_core_log(p_client->device.mac,p_client->device.serial_number,HMKIT_CORE_LOG_DEBUG,"[HMSensing] Send authenticate");

    if (p_client->device.is_authorised == 1) {
      p_client->is_entered_reported = 0;

      return;
    }

    //Check if we have this device certificate

    uint8_t command_buffer[74];

    hmkit_core_log(p_client->device.mac,p_client->device.serial_number,HMKIT_CORE_LOG_DEBUG,"[HMSensing] Send authenticate get certificate");

    uint16_t access_certificate_size = 0;
    uint8_t access_certificate_buffer[HMKIT_CORE_CERT_MAX_SIZE];

    if(hmkit_core_persistence_hal_get_access_certificate(appContxtId, serial, access_certificate_buffer, &access_certificate_size) != 0){

      //Did not find serial, mark as unknown device
      client_handling_set_authorised(p_client,0);

      return;
    }

    //TODO validate certificate validity

    command_buffer[0] = ID_CRYPTO_AUTHENTICATE;

    hmkit_core_log(p_client->device.mac,p_client->device.serial_number,HMKIT_CORE_LOG_DEBUG,"[HMSensing] Send authenticate get serial");
    //Get serial
    if(hmkit_core_persistence_hal_get_serial(appContxtId, command_buffer + 1) == 0 ){
      hmkit_core_log(p_client->device.mac,p_client->device.serial_number,HMKIT_CORE_LOG_DEBUG,"[HMSensing] Send authenticate add signature");
      //Add signature
      if(hmkit_core_add_signature(appContxtId, command_buffer, 10, command_buffer + 10) == 0){
        hmkit_core_log(p_client->device.mac,p_client->device.serial_number,HMKIT_CORE_LOG_DEBUG,"[HMSensing] Send authenticate write data");
        writeData(appContxtId, 74,command_buffer,p_client->device.mac,getCommandCharacteristic(p_client));
        return;
      }
    }
  }

  hmkit_core_log(NULL, NULL, HMKIT_CORE_LOG_ERROR,"[HMCore] sendAuthenticate: Internal ERROR");

  //TODO error handling
}

void sendAuthenticateDone(uint64_t appContxtId, uint8_t *serial){

  //if authenticated then skip
  connected_beacons_t *p_client = getBeaconIdSerial(serial);

  if(p_client != NULL) {

    hmkit_core_log(p_client->device.mac,p_client->device.serial_number,HMKIT_CORE_LOG_DEBUG,"[HMSensing] Send authenticate done");

    if (p_client->device.is_authorised == 1) {
      p_client->is_entered_reported = 0;

      return;
    }

    uint8_t command_buffer[74];

    command_buffer[0] = ID_CRYPTO_AUTHENTICATE_DONE;

    memcpy(command_buffer + 1, p_client->nonce, 9);

    //Add signature
    if(hmkit_core_add_signature(appContxtId, command_buffer, 10, command_buffer + 10) == 0){

      writeData(appContxtId, 74,command_buffer,p_client->device.mac,getCommandCharacteristic(p_client));

      hmkit_core_log(p_client->device.mac,p_client->device.serial_number,HMKIT_CORE_LOG_INFO,"[HMSensing] Authenticated");
      return;
    }
      hmkit_core_log(p_client->device.mac, p_client->device.serial_number,HMKIT_CORE_LOG_ERROR,"[HMCore] sendAuthenticateDone: Internal ERROR");
  }
  else
  {
    hmkit_core_log(NULL, NULL,HMKIT_CORE_LOG_ERROR,"[HMCore] sendAuthenticateDone: p_client NULL, client not connected");
  }

  //TODO error handling
}

void sendGetCertificate(uint8_t *mac){
  uint64_t appContxtId =0;

  hmkit_core_log(mac,NULL,HMKIT_CORE_LOG_DEBUG,"[HMSensing] Checking for stored Access Certificate");

  connected_beacons_t *p_client = getBeaconId(mac);

  if(p_client != NULL) {

    uint8_t command_buffer[74];

    command_buffer[0] = ID_CRYPTO_GET_CERTIFICATE;
    appContxtId = get_appContext_Hndlr(mac);
    //Get serial
    if (hmkit_core_persistence_hal_get_serial(appContxtId, command_buffer + 1) == 0) {
      //Add signature
      if (hmkit_core_add_signature(appContxtId, command_buffer, 10, command_buffer + 10) == 0) {
        writeData(appContxtId, 74, command_buffer, mac, getCommandCharacteristic(p_client));
        return;
      }
    }

    hmkit_core_log(mac, NULL,HMKIT_CORE_LOG_ERROR,"[HMCore] sendGetCertificate: Internal Error ");
  }
  else
  {
    hmkit_core_log(NULL, NULL,HMKIT_CORE_LOG_ERROR,"[HMCore] sendGetCertificate: p_client NULL, client not connected");
  }
  
  //TODO error handling

}

void sendRegisterCertificate(uint64_t appContxtId, uint8_t isctw, uint8_t *certData, uint8_t size, uint8_t *serial){

  connected_beacons_t *p_client = getBeaconIdSerial(serial);

  if(p_client != NULL){

    cache_appContext_Hndlr(appContxtId, p_client->device.mac);

    //Stop scanning
    hmkit_core_connectivity_hal_scan_stop();

    is_ctw_call = isctw;

    uint8_t command_buffer[ 1 + HMKIT_CORE_CERT_MAX_SIZE ];

    command_buffer[0] = ID_CRYPTO_REGISTER_CERTIFICATE;
    memcpy(command_buffer + 1, certData,size);

    writeData(appContxtId, size + 1, command_buffer, p_client->device.mac, getCommandCharacteristic(p_client));

  }
  else
  {
    hmkit_core_log(NULL, NULL,HMKIT_CORE_LOG_ERROR,"[HMCore] sendRegisterCertificate: p_client NULL, client not connected");
  }

}

void sendRevoke(uint64_t appContxtId, uint8_t *serial){

  connected_beacons_t *p_client = getBeaconIdSerial(serial);

  if(p_client != NULL){

    uint8_t command_buffer[ 42 ];
    command_buffer[0] = ID_CRYPTO_REVOKE;

    cache_appContext_Hndlr(appContxtId, p_client->device.mac);

    //Get serial
    if(hmkit_core_persistence_hal_get_serial(appContxtId, command_buffer + 1) == 0 ){
      //Add hmac
      if( hmkit_core_generate_hmac(appContxtId, p_client->local_nonce, p_client->device.serial_number, command_buffer, 10, command_buffer + 1 + 9)== 0 ){

        writeData(appContxtId, 42,command_buffer,p_client->device.mac,getCommandCharacteristic(p_client));
        return;
      }
    }
  
    hmkit_core_log(NULL, serial, HMKIT_CORE_LOG_ERROR,"[HMCore] sendRevoke: Internal Error ");

  }
  else
  {
    hmkit_core_log(NULL, serial, HMKIT_CORE_LOG_ERROR,"[HMCore] sendRevoke: p_client NULL, client not connected");
  }

}

void sendSecureContainer(uint64_t appContxtId, uint8_t *serial, uint8_t content_type, uint8_t *dataBuffer, uint32_t size, uint8_t *requestID, uint16_t reqID_size, uint8_t version){
  connected_beacons_t *p_client = getBeaconIdSerial(serial);

  if(p_client != NULL){

    if(version == 1){
      //Create version 1 secure container
      uint8_t *databuffer = getPrepareDataBuffer(p_client, getCommandCharacteristic(p_client), 38 + size + reqID_size);
    
      databuffer[0] = ID_CRYPTO_CONTAINER;
      databuffer[1] = 0x01;
      databuffer[2] = (size & 0xFF00) >> 8;
      databuffer[3] = size & 0x00FF;

      memcpy(databuffer + SECURE_CONT_HEADER_SIZE_V1, dataBuffer, size);

      cache_appContext_Hndlr(appContxtId, p_client->device.mac);

      // Add hmac
      if( hmkit_core_generate_hmac(appContxtId, p_client->local_nonce, p_client->device.serial_number, databuffer, SECURE_CONT_HEADER_SIZE_V1 + size, databuffer + SECURE_CONT_HEADER_SIZE_V1 + size) == 0 ){
        writeData(appContxtId, SECURE_CONT_HEADER_SIZE_V1 + size + SIZE_HMAC,databuffer,p_client->device.mac,getCommandCharacteristic(p_client));
        return;
      }
      else
      {
        hmkit_core_log(p_client->device.mac, serial, HMKIT_CORE_LOG_ERROR,"[HMCore] sendSecureContainer: HMAC Error ");
      }
    }else{
      //Create version 2 secure container
      uint8_t *databuffer = getPrepareDataBuffer(p_client, getCommandCharacteristic(p_client), SECURE_CONT_HEADER_SIZE_V2 + size + 2 + reqID_size + 32);
    
      databuffer[0] = ID_CRYPTO_CONTAINER;
      databuffer[1] = 0x02;
      databuffer[2] = 0x01;
      databuffer[3] = content_type;
      databuffer[4] = (size & 0xFF000000)  >> 24;
      databuffer[5] = (size & 0x00FF0000)  >> 16;
      databuffer[6] = (size & 0x0000FF00)  >> 8;
      databuffer[7] = size & 0x000000FF;

      memcpy(databuffer + SECURE_CONT_HEADER_SIZE_V2, dataBuffer, size);

      if(check_RequestID_length_limit(reqID_size) == true)
      {
        // Copy the Request ID block
        databuffer[SECURE_CONT_HEADER_SIZE_V2 + size] = (reqID_size & 0xFF00) >> 8;
        databuffer[SECURE_CONT_HEADER_SIZE_V2 + size + 1] = reqID_size & 0x00FF;
        memcpy((databuffer + SECURE_CONT_HEADER_SIZE_V2 + size + 2), requestID, reqID_size);
      }
      else
      {
        //TODO: return ERROR or make it as 0 ??
        hmkit_core_log(p_client->device.mac,serial,HMKIT_CORE_LOG_ERROR,"[HMCore] sendSecureContainer: RequestID size is Invalid, size = %d", reqID_size);
        return;
      }

      cache_appContext_Hndlr(appContxtId, p_client->device.mac);

      // Add hmac
      if( hmkit_core_generate_hmac(appContxtId, p_client->local_nonce, p_client->device.serial_number, databuffer, SECURE_CONT_HEADER_SIZE_V2 + size + 2 + reqID_size, databuffer + SECURE_CONT_HEADER_SIZE_V2 + size + 2 + reqID_size) == 0 ){
        writeData(appContxtId, SECURE_CONT_HEADER_SIZE_V2 + size + 2 + reqID_size + SIZE_HMAC,databuffer,p_client->device.mac,getCommandCharacteristic(p_client));
        return;
      }
      else     
      {
        hmkit_core_log(NULL, serial, HMKIT_CORE_LOG_ERROR,"[HMCore] sendSecureContainer: HMAC Error ");
      }
    }
  }
  else
  {
    hmkit_core_log(NULL, serial, HMKIT_CORE_LOG_ERROR,"[HMCore] sendSecureContainer: p_client NULL, client not connected");
  }

  //TODO error handling
}

void sendSecureContainerUsingMac(uint64_t appContxtId, uint8_t *mac, uint8_t content_type, uint8_t *dataBuffer, uint32_t size, uint8_t *requestID, uint16_t reqID_size, uint8_t version){
  connected_beacons_t *p_client = getBeaconId(mac);

  if(p_client != NULL){

    if(version == 1){
      //Create version 1 secure container
      uint8_t *databuffer = getPrepareDataBuffer(p_client, getCommandCharacteristic(p_client), 38 + size + reqID_size);
    
      databuffer[0] = ID_CRYPTO_CONTAINER;
      databuffer[1] = 0x01;
      databuffer[2] = (size & 0xFF00) >> 8;
      databuffer[3] = size & 0x00FF;

      memcpy(databuffer + SECURE_CONT_HEADER_SIZE_V1, dataBuffer, size);

      cache_appContext_Hndlr(appContxtId, p_client->device.mac);

      // Add hmac
      if( hmkit_core_generate_hmac(appContxtId, p_client->local_nonce, p_client->device.serial_number, databuffer, SECURE_CONT_HEADER_SIZE_V1 + size, databuffer + SECURE_CONT_HEADER_SIZE_V1 + size) == 0 ){
        writeData(appContxtId, SECURE_CONT_HEADER_SIZE_V1 + size + SIZE_HMAC,databuffer,p_client->device.mac,getCommandCharacteristic(p_client));
        return;
      }
      else
      {
       hmkit_core_log(p_client->device.mac, p_client->device.serial_number, HMKIT_CORE_LOG_ERROR,"[HMCore] sendSecureContainerUsingMac: V1, HMAC Error");
      }

    }else{
      //Create version 2 secure container
      uint8_t *databuffer = getPrepareDataBuffer(p_client, getCommandCharacteristic(p_client), SECURE_CONT_HEADER_SIZE_V2 + size + 2 + reqID_size + 32);
    
      databuffer[0] = ID_CRYPTO_CONTAINER;
      databuffer[1] = 0x02;
      databuffer[2] = 0x01;
      databuffer[3] = content_type;
      databuffer[4] = (size & 0xFF000000)  >> 24;
      databuffer[5] = (size & 0x00FF0000)  >> 16;
      databuffer[6] = (size & 0x0000FF00)  >> 8;
      databuffer[7] = size & 0x000000FF;

      memcpy(databuffer + SECURE_CONT_HEADER_SIZE_V2, dataBuffer, size);

      if(check_RequestID_length_limit(reqID_size) == true)
      {
        // Copy the Request ID block
        databuffer[SECURE_CONT_HEADER_SIZE_V2 + size] = (reqID_size & 0xFF00) >> 8;
        databuffer[SECURE_CONT_HEADER_SIZE_V2 + size + 1] = reqID_size & 0x00FF;
        memcpy((databuffer + SECURE_CONT_HEADER_SIZE_V2 + size + 2), requestID, reqID_size);
      }
      else
      {
        //TODO: return ERROR or make it as 0 ??
        hmkit_core_log(p_client->device.mac,p_client->device.serial_number,HMKIT_CORE_LOG_ERROR,"[HMCore] sendSecureContainer: RequestID size is Invalid, size = %d", reqID_size);
        return;
      }

      cache_appContext_Hndlr(appContxtId, p_client->device.mac);

      // Add hmac
      if( hmkit_core_generate_hmac(appContxtId, p_client->local_nonce, p_client->device.serial_number, databuffer, SECURE_CONT_HEADER_SIZE_V2 + size + 2 + reqID_size, databuffer + SECURE_CONT_HEADER_SIZE_V2 + size + 2 + reqID_size) == 0 ){
        writeData(appContxtId, SECURE_CONT_HEADER_SIZE_V2 + size + 2 + reqID_size + SIZE_HMAC,databuffer,p_client->device.mac,getCommandCharacteristic(p_client));
        return;
      }
      else     
      {
        hmkit_core_log(NULL, p_client->device.serial_number, HMKIT_CORE_LOG_ERROR,"[HMCore] sendSecureContainer: HMAC Error ");
      }
    }
  }
  else
  {
    hmkit_core_log(NULL, NULL, HMKIT_CORE_LOG_ERROR,"[HMCore] sendSecureContainerUsingMac: p_client NULL, client not connected");
  }

  //TODO error handling
}

void processGetNonce(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic){

  uint8_t error_type = 0;
  BTUNUSED(characteristic);

  memcpy(p_client->nonce,databuffer->txrx_buffer + 2,9);

  if(is_ctw_call == 1){
    is_ctw_call = 0;
    return;
  }

  if(databuffer->txrx_buffer[0] == ID_ACK_COMMAND){
    sendGetDeviceCertificateRequest(appContxtId, 0,NULL,p_client->device.mac);
  }
  else if(databuffer->txrx_buffer[0] == ID_ERROR)
  {// Error Response
    error_type = databuffer->txrx_buffer[2];
    hmkit_core_log(NULL, NULL, HMKIT_CORE_LOG_ERROR,"[HMCore] processGetNonce(): Error Response, Type : %d", error_type);
    // TODO: Handle Err Response
    // TODO add to skip list
    //AddBeaconTolist( cur_mac, 0, cur_serial );
  }
}

void processGetDeviceCertificate(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic){

  BTUNUSED(characteristic);

  if(databuffer->txrx_buffer[0] == ID_ACK_COMMAND){

    uint8_t isValidSignature = 0;

    //Validate if device cert has oem ca signature
    if(hmkit_core_validate_oem_ca_signature(appContxtId, databuffer->txrx_buffer + 2, 89, databuffer->txrx_buffer + 2 + 89) == 0){
      isValidSignature = 1;
    }

    //if not oem signature then validate if it is H-M ca signature
    if(isValidSignature == 0){
      if(hmkit_core_validate_ca_signature(appContxtId, databuffer->txrx_buffer + 2, 89, databuffer->txrx_buffer + 2 + 89) == 0){
        isValidSignature = 1;
      }
    }

    if(isValidSignature == 1){

      //Add serial number to device
      //memcpy(p_client->device.serial_number,p_client->txrx_buffer + 2,9);
      client_handling_add_serial(p_client->device.mac,databuffer->txrx_buffer + 2 + 4 + 12);
      memcpy(p_client->device.app_id,databuffer->txrx_buffer + 2 + 4,12);
      memcpy(p_client->device.issuer_id,databuffer->txrx_buffer + 2,4);

      //If ctw call then only start auth when not authenticated before
      if(is_ctw_call == 1){

        is_ctw_call = 0;

        if(p_client->device.is_authorised == 0){
          sendAuthenticate(appContxtId, p_client->device.serial_number);
        }

      }else{
        sendAuthenticate(appContxtId, p_client->device.serial_number);
      }

      return;

    }
    else
    { // Invalid Signature

      /* Error Handling */
      sendError_Command(appContxtId, p_client, ERR_INVALID_SIGNATURE, databuffer->txrx_buffer[1], characteristic);
      hmkit_core_log(NULL, p_client->device.serial_number, HMKIT_CORE_LOG_ERROR,"[HMCore] processGetDeviceCertificate: ERR_INVALID_SIGNATURE");
    }

  }
  // Error Response or invalid signature

  if(hmkit_core_api_callback_get_device_certificate_failed(appContxtId, &p_client->device, p_client->nonce) == 0){
    //Add to list as unauthenticated
    client_handling_set_authorised(p_client,0);
    hmkit_core_connectivity_hal_scan_start();
  }
  // TODO: Handle Error Response
}

void processGetCertificate(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic){

  BTUNUSED(characteristic);

  if(databuffer->txrx_buffer[0] == ID_ACK_COMMAND){

    uint16_t size = 0;
    hmkit_core_certificate_t certificate;

    hmkit_core_cert_get_size(databuffer->txrx_buffer + 2, &size);
    hmkit_core_cert_get_as_struct(databuffer->txrx_buffer + 2, &certificate);

    uint8_t serial[9];

    //Get serial for verify
    if(hmkit_core_persistence_hal_get_serial(appContxtId, serial) == 0 ){

      //Check if serial is OK
      if(memcmp(serial,certificate.providing_serial,9) == 0 ){

        uint16_t certificateSize = 0;

        hmkit_core_cert_get_size(databuffer->txrx_buffer + 2,&certificateSize);

        //Check if CA signature is ok
        if(hmkit_core_validate_oem_ca_signature(appContxtId, databuffer->txrx_buffer + 2, certificateSize - 64, certificate.ca_signature) == 0){

          hmkit_core_log(p_client->device.mac,p_client->device.serial_number,HMKIT_CORE_LOG_INFO,"[HMSensing] processGetCertificate: Access Certificate received");
          hmkit_core_cert_print(databuffer->txrx_buffer + 2);

          //Store public key
          if(hmkit_core_persistence_hal_add_access_certificate(appContxtId, certificate.gaining_serial, databuffer->txrx_buffer + 2, size) == 0 ){

          }else{
            // TODO: Log the Error
            hmkit_core_log(p_client->device.mac,p_client->device.serial_number,HMKIT_CORE_LOG_ERROR,"[HMSensing] processGetCertificate: Add Access cerrtificate Error");
          }
        }else{

          sendError_Command(appContxtId, p_client, ERR_INVALID_SIGNATURE, databuffer->txrx_buffer[1], characteristic);
          hmkit_core_log(p_client->device.mac, p_client->device.serial_number, HMKIT_CORE_LOG_ERROR,"[HMCore] processGetCertificate: process get cert, ERR_INVALID_SIGNATURE");
        }
      }else{
          hmkit_core_log(p_client->device.mac,p_client->device.serial_number,HMKIT_CORE_LOG_ERROR,"[HMSensing] processGetCertificate: Serial Number verification failed");
      }
    }
    else
    {
        hmkit_core_log(p_client->device.mac,p_client->device.serial_number,HMKIT_CORE_LOG_ERROR,"[HMSensing] processGetCertificate: Get Serial Num Error");
    }

  }

  hmkit_core_log(p_client->device.mac,p_client->device.serial_number,HMKIT_CORE_LOG_INFO,"[HMSensing] processGetCertificate: Authenticating...");
  sendGetNonceRequest(appContxtId, 0,p_client->device.mac);

  // TODO: Handle Error Response
}

void processAuthenticate(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic){
  uint8_t error_type = 0;

  if(databuffer->txrx_buffer[0] == ID_ACK_COMMAND){

    if( hmkit_core_validate_signature(appContxtId, databuffer->txrx_buffer, 11, databuffer->txrx_buffer + 11, p_client->device.serial_number) == 0 ){

      //Create shared key
      uint8_t ecdh[32];

      if(hmkit_core_generate_ecdh(appContxtId, databuffer->txrx_buffer + 2, p_client->device.serial_number, ecdh) == 0){

        memcpy(p_client->nonce,databuffer->txrx_buffer + 2,9);
        memcpy(p_client->local_nonce,p_client->nonce,9);
        memcpy(p_client->remote_nonce,p_client->nonce,9);
        p_client->local_counter = 0;
        p_client->remote_counter = 0;

        uint16_t size = 0;
        uint8_t cert_data[HMKIT_CORE_CERT_V1_MAX_SIZE];

        //add device cert to p_client
        hmkit_core_persistence_hal_get_access_certificate(appContxtId, p_client->device.serial_number,cert_data,&size);
        hmkit_core_cert_get_as_struct(cert_data, &p_client->device.certificate);
        //add device cert to p_client

        //client_handling_set_authorised(p_client,1);
        sendAuthenticateDone(appContxtId, p_client->device.serial_number);
      }else{
        client_handling_set_authorised(p_client,0);
        hmkit_core_log(p_client->device.mac,p_client->device.serial_number,HMKIT_CORE_LOG_ERROR,"[HMSensing] processAuthenticate: Authenticate failed ecdh");
        sendError_Command(appContxtId, p_client, ERR_INTERNAL_ERROR, databuffer->txrx_buffer[1], characteristic);
      }
    }else{
      client_handling_set_authorised(p_client,0);
      hmkit_core_log(p_client->device.mac,p_client->device.serial_number,HMKIT_CORE_LOG_ERROR,"[HMSensing] processAuthenticate: Authenticate failed validate");
      sendError_Command(appContxtId, p_client, ERR_INVALID_SIGNATURE, databuffer->txrx_buffer[1], characteristic);
    }
  }else{
    // Error Response
    client_handling_set_authorised(p_client,0);
    hmkit_core_log(p_client->device.mac,p_client->device.serial_number,HMKIT_CORE_LOG_ERROR,"[HMSensing] processAuthenticate: Authenticate failed response");

     if(databuffer->txrx_buffer[0] == ID_ERROR)
     {// Error Response
       error_type = databuffer->txrx_buffer[2];
       hmkit_core_log(NULL, p_client->device.serial_number, HMKIT_CORE_LOG_ERROR,"[HMCore] processAuthenticate(): Error Response received, Type : %d", error_type);
     }
  }

  //Start to scan others
  //TODO PARROT
  //hmkit_core_connectivity_hal_scan_start();
}

void processAuthenticateDone(connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic){

  uint8_t error_type = 0;
  BTUNUSED(characteristic);

  if(databuffer->txrx_buffer[0] == ID_ACK_COMMAND){
    client_handling_set_authorised(p_client,1);
  }

  hmkit_core_connectivity_hal_scan_start();

  // TODO: Handle Err Response
  if(databuffer->txrx_buffer[0] == ID_ERROR)
  {// Error Response
    error_type = databuffer->txrx_buffer[2];
    hmkit_core_log(NULL, p_client->device.serial_number, HMKIT_CORE_LOG_ERROR,"[HMCore] processAuthenticateDone(): Error Response received, Type : %d", error_type);
  }
}

void processRegisterCertificate(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic){
  uint8_t error_type = 0;
  BTUNUSED(characteristic);

  //TODO sometimes response with invalid signature

  if(databuffer->txrx_buffer[0] == ID_ACK_COMMAND){

    //if( hmkit_core_validate_signature(p_client->txrx_buffer, 66, p_client->txrx_buffer + 66, p_client->device.serial_number) == 0 )
    {
      //uint8_t permissionsSize = 0;
      //uint8_t permissions[16];
      //uint8_t startDate[5];
      //uint8_t endDate[5];

      //Store public key

      hmkit_core_api_callback_access_certificate_registered(appContxtId, &p_client->device,databuffer->txrx_buffer + 2,0);

      return;
    }
    // TODO: if sign validation check enabled then add error check as well
  }
  else if(databuffer->txrx_buffer[0] == ID_ERROR)
  {// Error Response
    error_type = databuffer->txrx_buffer[2];
    hmkit_core_log(NULL, NULL, HMKIT_CORE_LOG_ERROR,"[HMCore] processRegisterCertificate(): Error Response received, Type : %d", error_type);
    // TODO: Handle Err Response
  }

}

void processRevoke(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic){

  uint8_t error_type = 0;
  BTUNUSED(characteristic);

  uint8_t ecdh[32];
  hmkit_core_generate_ecdh(appContxtId, p_client->local_nonce, p_client->device.serial_number, ecdh);
  if(databuffer->txrx_buffer[0] == ID_ACK_COMMAND){
    hmkit_core_persistence_hal_remove_access_certificate(appContxtId, &p_client->device.certificate);

    client_handling_set_authorised(p_client,0);

    //sd_ble_gap_disconnect(p_client->srv_db.conn_handle,0x13);
    hmkit_core_api_callback_revoke_response(appContxtId, &p_client->device, NULL, 0, 0);
  }else{
    hmkit_core_api_callback_revoke_response(appContxtId, &p_client->device, NULL, 0, 1);

    if(databuffer->txrx_buffer[0] == ID_ERROR)
    {// Error Response
      error_type = databuffer->txrx_buffer[2];
      hmkit_core_log(NULL, p_client->device.serial_number, HMKIT_CORE_LOG_ERROR,"[HMCore] processRevoke(): Error Response received, Type : %d", error_type);
    }

  }
}

void sendError(uint64_t appContxtId, connected_beacons_t * p_client, uint8_t error, uint8_t command, hmkit_core_characteristic characteristic, uint8_t *requestID, uint16_t reqID_size) {
  uint8_t data[3+2+REQUEST_ID_MAX_BYTES_SIZE+1];
  uint16_t size = 0;
  data[0] = ID_ERROR;
  data[1] = command;
  data[2] = error;
  size = 3;

  if(command == ID_CRYPTO_CONTAINER)
  {
    if(reqID_size == 0 || requestID == NULL)
    {
      // dont send the Request ID as the size is 0
      data[3] = 0;
      data[4] = 0;
      size = size + 2;
    }
    else if(check_RequestID_length_limit(reqID_size) == true)
    {
      //Copy the Request ID block
      data[3] = (reqID_size & 0xFF00) >> 8;
      data[4] = reqID_size & 0x00FF;

      memcpy((data + 5), requestID, reqID_size);
      size = size + 2 + reqID_size;
    }
    else // invalid size
    {
      // dont send the Request ID as its length is invalid
      // TODO: return and print ERROR.
      data[3] = 0;
      data[4] = 0;
      size = size + 2;
      
    }
  }
  else //make request ID always 0 for non crypto container commands(non Secure containers)
  {
    data[3] = 0;
    data[4] = 0;
    size = size + 2;
  }

  writeData(appContxtId, size, data, p_client->device.mac, characteristic);
}

void sendError_Command(uint64_t appContxtId, connected_beacons_t * p_client, uint8_t error_type, uint8_t command, hmkit_core_characteristic characteristic) {
  uint8_t data[3];
  uint16_t size = 0;
  data[0] = ID_ERROR_COMMAND;
  data[1] = command;
  data[2] = error_type;
  size = 3;

  writeData(appContxtId, size, data, p_client->device.mac, characteristic);
}

bool check_RequestID_length_limit(uint16_t reqID_size)
{
  if(reqID_size <= REQUEST_ID_MAX_BYTES_SIZE)
    return true;
  else
    return false;
}

void processSecureContainer(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic){

  BTUNUSED(characteristic);

  hmkit_core_log(NULL,NULL,HMKIT_CORE_LOG_DEBUG,"[HMCore] Process container size %d",databuffer->rx_buffer_ptr);
     

  uint16_t size = 0, reqID_size = 0;
  uint8_t error_type = 0;

  if(databuffer->txrx_buffer[0] == ID_ERROR)
  { // Error Response
     error_type = databuffer->txrx_buffer[2];

     hmkit_core_api_callback_command_response_error(appContxtId, &p_client->device, error_type);
  }
  else if(databuffer->txrx_buffer[0] == ID_ACK_COMMAND)
  {
     // Size store in position [2] amd [3] in Bigendian format
     size = (uint16_t)((databuffer->txrx_buffer[2] << 8) | databuffer->txrx_buffer[3]);

     if(databuffer->rx_buffer_ptr == SECURE_CONT_HEADER_SIZE_V1 || databuffer->rx_buffer_ptr == SECURE_CONT_HEADER_SIZE_V1 + size + 32){
       //OLD
       uint8_t data[1];
       hmkit_core_api_callback_command_response(appContxtId, &p_client->device, 0, databuffer->txrx_buffer + SECURE_CONT_HEADER_SIZE_V1, size, data, reqID_size, 1);
     }else{
       //NEW
       // Request ID Size store in Bigendian format
       uint32_t sizev2 = (uint32_t)((databuffer->txrx_buffer[4] << 24) | (databuffer->txrx_buffer[5] << 16) | (databuffer->txrx_buffer[6] << 8) | databuffer->txrx_buffer[7]);
       reqID_size = (uint16_t)((databuffer->txrx_buffer[SECURE_CONT_HEADER_SIZE_V2 + sizev2] << 8) | databuffer->txrx_buffer[ SECURE_CONT_HEADER_SIZE_V2 + sizev2 + 1]);

       hmkit_core_api_callback_command_response(appContxtId, &p_client->device, databuffer->txrx_buffer[3], databuffer->txrx_buffer + SECURE_CONT_HEADER_SIZE_V2, sizev2, (databuffer->txrx_buffer + SECURE_CONT_HEADER_SIZE_V2 + sizev2 + 2), reqID_size, 2);
     } 
    //TODO Check hmac

  }

}

void processSecureCommandContainerIncoming(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic){

  hmkit_core_core_commandinprogress = 1;

  //Version detect
  if(databuffer->txrx_buffer[1] == 0x02 && databuffer->rx_buffer_ptr > (uint32_t)((databuffer->txrx_buffer[4] << 24) | (databuffer->txrx_buffer[5] << 16) | (databuffer->txrx_buffer[6] << 8) | databuffer->txrx_buffer[7])){

    //VERSION 2

    uint16_t reqID_size = 0;
    uint32_t size=0; 

    size = (uint32_t)((databuffer->txrx_buffer[4] << 24) | (databuffer->txrx_buffer[5] << 16) | (databuffer->txrx_buffer[6] << 8) | databuffer->txrx_buffer[7]);

    // Request ID Size store in Bigendian format
    reqID_size = (uint16_t)((databuffer->txrx_buffer[SECURE_CONT_HEADER_SIZE_V2 + size] << 8) | databuffer->txrx_buffer[ SECURE_CONT_HEADER_SIZE_V2 + size + 1]);

    if(databuffer->rx_buffer_ptr == SECURE_CONT_HEADER_SIZE_V2 + 32 + size + reqID_size + 2)
    {
      if(hmkit_core_validate_hmac(appContxtId, p_client->remote_nonce,p_client->device.serial_number,databuffer->txrx_buffer, (SECURE_CONT_HEADER_SIZE_V2 + size + 2 + reqID_size), databuffer->txrx_buffer + (SECURE_CONT_HEADER_SIZE_V2 + size + 2 + reqID_size)) == 0){

  #ifdef DYNAMIC_MEM_DATA
        uint8_t *data = (uint8_t *)malloc(SECURE_CONT_HEADER_SIZE_V2 + 32 + reqID_size + 2);
  #else
        uint8_t data[SECURE_CONT_HEADER_SIZE_V2 + 32 + reqID_size + 2];
  #endif

        uint8_t withHMAC = databuffer->txrx_buffer[2];

        data[0] = ID_ACK_COMMAND;
        data[1] = ID_CRYPTO_CONTAINER;

        data[2] = 0x02;

        //Content type
        data[3] = 0x00; //Because it is empty currently

        // Store Size in positions [2] amd [3] in Bigendian format
        data[4] = 0x00;
        data[5] = 0x00;
        data[6] = 0x00;
        data[7] = 0x00;

        //Copy the Request ID block to the Ack
        data[SECURE_CONT_HEADER_SIZE_V2] = (reqID_size & 0xFF00) >> 8;
        data[SECURE_CONT_HEADER_SIZE_V2 + 1] = reqID_size & 0x00FF;
        memcpy((data + SECURE_CONT_HEADER_SIZE_V2 + 2), (databuffer->txrx_buffer + SECURE_CONT_HEADER_SIZE_V2 + 2), reqID_size);

        hmkit_core_log_data(p_client->device.mac,p_client->device.serial_number,HMKIT_CORE_LOG_DEBUG,databuffer->txrx_buffer + SECURE_CONT_HEADER_SIZE_V2,size,"[HMCore] CALLBACK DATA");

      #ifdef DYNAMIC_MEM_DATA
        p_client->callbackData = (uint8_t *)malloc(size * sizeof(uint8_t));
        memset(p_client->callbackData,0x00, size);
      #endif

        p_client->sendCallback = 1;
        p_client->callbackVersion = 2;
        p_client->callbackContentType = databuffer->txrx_buffer[3];
        p_client->callbackDataSize = size;
        memcpy(p_client->callbackData,databuffer->txrx_buffer + SECURE_CONT_HEADER_SIZE_V2,size);
        p_client->callbackReqIDSize = reqID_size;
        memcpy(p_client->callbackReqID,(databuffer->txrx_buffer + SECURE_CONT_HEADER_SIZE_V2 + size + 2), reqID_size);

        if(withHMAC == 1){
          hmkit_core_generate_hmac(appContxtId, p_client->remote_nonce, p_client->device.serial_number, data, (SECURE_CONT_HEADER_SIZE_V2 + reqID_size + 2), data + SECURE_CONT_HEADER_SIZE_V2 + reqID_size + 2);
          writeData(appContxtId, (SECURE_CONT_HEADER_SIZE_V2 + 32 + reqID_size + 2),data,p_client->device.mac,characteristic);
        }else{
          writeData(appContxtId, (SECURE_CONT_HEADER_SIZE_V2 + reqID_size + 2),data,p_client->device.mac,characteristic);
        }
        //TODO: BC-127, should pass the custom block to app/sdk ?
        //hmkit_core_api_callback_command_incoming(&p_client->device, dataBuffer, &size, callbackReqID, callbackReqIDSize, &error);

  #ifdef DYNAMIC_MEM_DATA
	free(data);
  #endif

        return;
      }
      else
      {
      // Error sent at the end of the function
      }
    }
  }else{

    //VERSION 1
    
    uint16_t size=0;

    // Size store in position [2] amd [3] in Bigendian format
    size = (uint16_t)((databuffer->txrx_buffer[2] << 8) | databuffer->txrx_buffer[3]);

    if(databuffer->rx_buffer_ptr == 4 + 32 + size)
    {
      if(hmkit_core_validate_hmac(appContxtId, p_client->remote_nonce,p_client->device.serial_number,databuffer->txrx_buffer, (SECURE_CONT_HEADER_SIZE_V1 + size), databuffer->txrx_buffer + (SECURE_CONT_HEADER_SIZE_V1 + size)) == 0)
      {

        uint8_t data[SECURE_CONT_HEADER_SIZE_V1 + 32];

        uint8_t withHMAC = databuffer->txrx_buffer[1];

        data[0] = ID_ACK_COMMAND;
        data[1] = ID_CRYPTO_CONTAINER;

        // Store Size in positions [2] amd [3] in Bigendian format
        data[2] = 0x00;
        data[3] = 0x00;

        hmkit_core_log_data(p_client->device.mac,p_client->device.serial_number,HMKIT_CORE_LOG_DEBUG,databuffer->txrx_buffer + SECURE_CONT_HEADER_SIZE_V1,size,"[HMCore] CALLBACK DATA");

      #ifdef DYNAMIC_MEM_DATA
        p_client->callbackData = (uint8_t *)malloc(size * sizeof(uint8_t));
        memset(p_client->callbackData,0x00, size);
      #endif

        p_client->sendCallback = 1;
        p_client->callbackVersion = 1;
        p_client->callbackDataSize = size;
        memcpy(p_client->callbackData,databuffer->txrx_buffer + SECURE_CONT_HEADER_SIZE_V1,size);
        p_client->callbackReqIDSize = 0;

        if(withHMAC == 1){
          hmkit_core_generate_hmac(appContxtId, p_client->remote_nonce, p_client->device.serial_number, data, (SECURE_CONT_HEADER_SIZE_V1), data + SECURE_CONT_HEADER_SIZE_V1);
          writeData(appContxtId, (SECURE_CONT_HEADER_SIZE_V1 + 32),data,p_client->device.mac,characteristic);
        }else{
          writeData(appContxtId, (SECURE_CONT_HEADER_SIZE_V1),data,p_client->device.mac,characteristic);
        }

        return;
      }
      else
      {
       // Error sent at the end of the function
      }
    }
  }
  hmkit_core_log(p_client->device.mac, p_client->device.serial_number, HMKIT_CORE_LOG_ERROR,"[HMCore] processSecureCommandContainerIncoming, ERR_INVALID_HMAC");
  sendError(appContxtId, p_client, ERR_INVALID_HMAC, databuffer->txrx_buffer[0],characteristic, NULL, 0);
}

void processGetNonceIncoming(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic){

  BTUNUSED(databuffer);

  uint8_t data[11];

  if(hmkit_core_crypto_hal_generate_nonce(appContxtId, data + 2) == 0){

    data[0] = ID_ACK_COMMAND;
    data[1] = ID_CRYPTO_GET_NONCE;

    writeData(appContxtId, 11,data,p_client->device.mac,characteristic);

    return;
  }

  hmkit_core_log(p_client->device.mac, p_client->device.serial_number, HMKIT_CORE_LOG_ERROR,"[HMCore] processGetNonceIncoming, Internal Error");
  sendError(appContxtId, p_client, ERR_INTERNAL_ERROR, ID_CRYPTO_GET_NONCE,characteristic, NULL, 0);
}

void processGetDeviceCertificateIncoming(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic){

  uint8_t zero[9] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  if(memcmp(databuffer->txrx_buffer+1,zero,9) != 0){
    //Validate CA signature
    if(hmkit_core_validate_oem_ca_signature(appContxtId, databuffer->txrx_buffer+1, 9, databuffer->txrx_buffer + 10) != 0){
      if(hmkit_core_validate_ca_signature(appContxtId, databuffer->txrx_buffer+1, 9, databuffer->txrx_buffer + 10) != 0){
        hmkit_core_log(p_client->device.mac, p_client->device.serial_number, HMKIT_CORE_LOG_ERROR,"[HMCore] processGetDeviceCertificateIncoming, INVALID SIGN");
        sendError(appContxtId, p_client, ERR_INVALID_SIGNATURE, ID_CRYPTO_GET_DEVICE_CERTIFICATE,characteristic, NULL, 0);
        return;
      }
    }
  }else{
    //Validate local signature
    if(hmkit_core_validate_all_signatures(appContxtId, databuffer->txrx_buffer+1, 9, databuffer->txrx_buffer + 10) != 0){
      hmkit_core_log(p_client->device.mac, p_client->device.serial_number, HMKIT_CORE_LOG_ERROR,"[HMCore] processGetDeviceCertificateIncoming, INVALID all SIGN");
      sendError(appContxtId, p_client, ERR_INVALID_SIGNATURE, ID_CRYPTO_GET_DEVICE_CERTIFICATE,characteristic, NULL, 0);
      return;
    }
  }

  p_client->isRegisterAllowed = true;

  //Get device certificate for response

  uint8_t deviceCertificate[153];

  hmkit_core_persistence_hal_get_device_certificate(appContxtId, deviceCertificate);

  uint8_t data[155];

  data[0] = ID_ACK_COMMAND;
  data[1] = ID_CRYPTO_GET_DEVICE_CERTIFICATE;
  memcpy(data+2,deviceCertificate,153);
  writeData(appContxtId, 155,data,p_client->device.mac,characteristic);
}

void processRegisterCertificateIncoming(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic){

  hmkit_core_cert_print(databuffer->txrx_buffer + 1);

  uint16_t size = 0;
  hmkit_core_certificate_t certificate;
  hmkit_core_cert_get_size(databuffer->txrx_buffer + 1, &size);
  hmkit_core_cert_get_as_struct(databuffer->txrx_buffer + 1, &certificate);

  client_handling_add_serial(p_client->device.mac,certificate.gaining_serial);

  uint8_t serial[9];

  //IF it is link and get device cert is not done then return error
  if(p_client->isLink == true){
    if(p_client->isRegisterAllowed == false){
      hmkit_core_log(p_client->device.mac, p_client->device.serial_number, HMKIT_CORE_LOG_ERROR,"[HMCore] processRegisterCertificateIncoming, Not Accepted");
      sendError(appContxtId, p_client, ERR_NOT_ACCEPTED, ID_CRYPTO_REGISTER_CERTIFICATE,characteristic, NULL, 0);
      return;
    }
  }

  //Get serial for verify
  if(hmkit_core_persistence_hal_get_serial(appContxtId, serial) == 0 ){

    //Check if serial is OK
    if(memcmp(serial,certificate.providing_serial,9) == 0 ){

      //Check CA signature if it is not Link

      if(p_client->isLink == false){
        if(hmkit_core_validate_oem_ca_signature(appContxtId, databuffer->txrx_buffer + 1, 92 + 1 + certificate.permissions_size, certificate.ca_signature) != 0){
          hmkit_core_log(p_client->device.mac, p_client->device.serial_number, HMKIT_CORE_LOG_ERROR,"[HMCore] processRegisterCertificateIncoming, Invalid Sign");
          sendError(appContxtId, p_client, ERR_NOT_ACCEPTED, ID_CRYPTO_REGISTER_CERTIFICATE,characteristic, NULL, 0);
          return;
        }
      }

      if(hmkit_core_api_callback_pairing_requested(appContxtId, &p_client->device) == 0){
        //Store public key
        if(hmkit_core_persistence_hal_add_access_certificate(appContxtId, certificate.gaining_serial, databuffer->txrx_buffer + 1, size) == 0 ){

          uint8_t data[130];

          //Get publick key for response
          if(hmkit_core_persistence_hal_get_local_public_key(appContxtId, data + 2) == 0){

            data[0] = ID_ACK_COMMAND;
            data[1] = ID_CRYPTO_REGISTER_CERTIFICATE;

            //Add signature
            if(hmkit_core_add_signature(appContxtId, data, 66, data + 66) == 0){

              writeData(appContxtId, 130,data,p_client->device.mac,characteristic);

              return;
            }
          }
        }else{
          hmkit_core_log(p_client->device.mac, p_client->device.serial_number, HMKIT_CORE_LOG_ERROR,"[HMCore] processRegisterCertificateIncoming, ERR_STORAGE_FULL");
          sendError(appContxtId, p_client, ERR_STORAGE_FULL, ID_CRYPTO_REGISTER_CERTIFICATE,characteristic, NULL, 0);
          return;
        }
      }else{
        hmkit_core_log(p_client->device.mac, p_client->device.serial_number, HMKIT_CORE_LOG_ERROR,"[HMCore] processRegisterCertificateIncoming, ERR_INVALID_SIGNATURE");
        sendError(appContxtId, p_client, ERR_INVALID_SIGNATURE, ID_CRYPTO_REGISTER_CERTIFICATE,characteristic, NULL, 0);
        return;
      }
    }else{
      hmkit_core_log(p_client->device.mac, p_client->device.serial_number, HMKIT_CORE_LOG_ERROR,"[HMCore] processRegisterCertificateIncoming, ERR_INVALID_DATA");
      sendError(appContxtId, p_client, ERR_INVALID_DATA, ID_CRYPTO_REGISTER_CERTIFICATE,characteristic, NULL, 0);
      return;
    }
  }

  hmkit_core_log(p_client->device.mac, p_client->device.serial_number, HMKIT_CORE_LOG_ERROR,"[HMCore] processRegisterCertificateIncoming, ERR_TIMEOUT");
  sendError(appContxtId, p_client, ERR_TIMEOUT, ID_CRYPTO_REGISTER_CERTIFICATE,characteristic, NULL, 0); //TODO invalid token
  return;
}

void processStoreCertificateIncoming(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic){

  hmkit_core_cert_print(databuffer->txrx_buffer + 1);

  uint16_t certSize = 0;

  hmkit_core_cert_get_size(databuffer->txrx_buffer + 1, &certSize);

  //Validate hmac
  if(hmkit_core_validate_hmac(appContxtId, p_client->remote_nonce,p_client->device.serial_number,databuffer->txrx_buffer, 1 + certSize , databuffer->txrx_buffer + 1 + certSize) == 0){

    if(hmkit_core_persistence_hal_add_stored_certificate(appContxtId, databuffer->txrx_buffer + 1, certSize) == 0){

      uint8_t data[2];

      data[0] = ID_ACK_COMMAND;
      data[1] = ID_CRYPTO_STORE_CERTIFICATE;

      writeData(appContxtId, 2,data,p_client->device.mac,characteristic);

      return;
    }
  }

  hmkit_core_log(p_client->device.mac, p_client->device.serial_number, HMKIT_CORE_LOG_ERROR,"[HMCore] processStoreCertificateIncoming, ERR_INTERNAL_ERROR");
  sendError(appContxtId, p_client, ERR_INTERNAL_ERROR, ID_CRYPTO_STORE_CERTIFICATE,characteristic, NULL, 0);
  return;
}

void processGetCertificateIncoming(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic){

  uint8_t certificate[HMKIT_CORE_CERT_MAX_SIZE];
  uint16_t certSize = 0;
  hmkit_core_certificate_t certificatestruct;

  hmkit_core_persistence_hal_get_stored_certificate(appContxtId, databuffer->txrx_buffer + 1, certificate, &certSize);
  hmkit_core_cert_get_as_struct(certificate, &certificatestruct);

  if(memcmp(databuffer->txrx_buffer + 1,certificatestruct.providing_serial,9) == 0 ){

    uint8_t data[2 + HMKIT_CORE_CERT_MAX_SIZE];

    data[0] = ID_ACK_COMMAND;
    data[1] = ID_CRYPTO_GET_CERTIFICATE;

    memcpy(data + 2, certificate,certSize);
    writeData(appContxtId, certSize + 2,data,p_client->device.mac,characteristic);
    hmkit_core_persistence_hal_erase_stored_certificate(appContxtId, certificatestruct.providing_serial);

    return;

  }

  hmkit_core_log(p_client->device.mac, p_client->device.serial_number, HMKIT_CORE_LOG_ERROR,"[HMCore] processGetCertificateIncoming, ERR_INVALID_DATA");
  sendError(appContxtId, p_client, ERR_INVALID_DATA, ID_CRYPTO_GET_CERTIFICATE,characteristic, NULL, 0);
  return;
}

void processAuthenticateIncoming(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic){

  //Validate signature
  if(hmkit_core_validate_signature(appContxtId, databuffer->txrx_buffer, 10, databuffer->txrx_buffer + 10, databuffer->txrx_buffer + 1) == 0){

    client_handling_add_serial(p_client->device.mac,databuffer->txrx_buffer + 1);

    uint8_t data[75];

    //Get nonce for response
    if(hmkit_core_crypto_hal_generate_nonce(appContxtId, p_client->nonce) == 0){
      memcpy(data + 2,p_client->nonce,9);
      memcpy(p_client->local_nonce,p_client->nonce,9);
      memcpy(p_client->remote_nonce,p_client->nonce,9);
      p_client->local_counter = 0;
      p_client->remote_counter = 0;

      uint16_t size = 0;
      uint8_t cert_data[HMKIT_CORE_CERT_V1_MAX_SIZE];

      //add device cert to p_client
      hmkit_core_persistence_hal_get_access_certificate(appContxtId, databuffer->txrx_buffer + 1,cert_data,&size);
      hmkit_core_cert_get_as_struct(cert_data, &p_client->device.certificate);

      //Create shared key
      uint8_t ecdh[32];
      if(hmkit_core_crypto_hal_ecc_get_ecdh(appContxtId, databuffer->txrx_buffer + 1, ecdh) == 0){

        data[0] = ID_ACK_COMMAND;
        data[1] = ID_CRYPTO_AUTHENTICATE;

        //Add signature
        if(hmkit_core_add_signature(appContxtId, data, 11, data + 11) == 0){

          writeData(appContxtId, 75,data,p_client->device.mac,characteristic);

          //client_handling_set_authorised(p_client,1);

          //checkBeacons();

          return;
        }
      }
    }
  }else{
    hmkit_core_log(p_client->device.mac, p_client->device.serial_number, HMKIT_CORE_LOG_ERROR,"[HMCore] processAuthenticateIncoming, ERR_INVALID_SIGNATURE");
    sendError(appContxtId, p_client, ERR_INVALID_SIGNATURE, ID_CRYPTO_AUTHENTICATE, characteristic, NULL, 0);
    client_handling_set_authorised(p_client,0);
    return;
  }

  hmkit_core_log(p_client->device.mac, p_client->device.serial_number, HMKIT_CORE_LOG_ERROR,"[HMCore] processAuthenticateIncoming, ERR_INTERNAL_ERROR");
  sendError(appContxtId, p_client, ERR_INTERNAL_ERROR, ID_CRYPTO_AUTHENTICATE,characteristic, NULL, 0); //TODO invalid token
  client_handling_set_authorised(p_client,0);
  return;
}


void processAuthenticateDoneIncoming(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic){
  //Validate signature
  if(hmkit_core_validate_signature(appContxtId, databuffer->txrx_buffer, 10, databuffer->txrx_buffer + 10, p_client->device.serial_number) == 0){

    uint8_t data[2];

    data[0] = ID_ACK_COMMAND;
    data[1] = ID_CRYPTO_AUTHENTICATE_DONE;

    writeData(appContxtId, 2,data,p_client->device.mac,characteristic);

    //Skip beacon check until data is sent out
    hmkit_core_log(NULL,NULL,HMKIT_CORE_LOG_INFO,"[HMSensing] processAuthenticateDoneIncoming skip");
    skipBeaconCheck = 1;
    client_handling_set_authorised(p_client,1);

    return;
  }else{
    hmkit_core_log(p_client->device.mac, p_client->device.serial_number, HMKIT_CORE_LOG_ERROR,"[HMCore] processAuthenticateDoneIncoming, ERR_INVALID_SIGNATURE");
    sendError(appContxtId, p_client, ERR_INVALID_SIGNATURE, ID_CRYPTO_AUTHENTICATE_DONE,characteristic, NULL, 0);
    client_handling_set_authorised(p_client,0);
    return;
  }
}

void processRevokeIncoming(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic){

  if(hmkit_core_validate_hmac(appContxtId, p_client->remote_nonce,p_client->device.serial_number,databuffer->txrx_buffer, 10, databuffer->txrx_buffer + 10) == 0){

    uint8_t data[MAX_COMMAND_SIZE];
    uint8_t retdata[MAX_COMMAND_SIZE-4];

    //Don't delete connection info and keep connection
    //hmkit_core_link_disconnect(p_client->device.mac);
    uint16_t size = 0;
    hmkit_core_api_callback_revoke_incoming(appContxtId, &p_client->device, retdata, &size);

    data[0] = ID_ACK_COMMAND;
    data[1] = ID_CRYPTO_REVOKE;
    data[2] = 0x00;
    data[3] = 0x00;

    if(size <= gMaxBufferSize - 4){
      hmkit_core_explode(size, &data[2]);
      memcpy(&data[4], retdata, size);
      writeData(appContxtId, 4+size,data,p_client->device.mac,characteristic);
    }else{
      writeData(appContxtId, 4,data,p_client->device.mac,characteristic);
    }

    hmkit_core_persistence_hal_remove_access_certificate(appContxtId, &p_client->device.certificate);

    client_handling_set_authorised(p_client, 0 );

    //hmkit_core_connectivity_hal_disconnect(p_client->device.mac);

    return;
  }

  sendError(appContxtId, p_client, ERR_INVALID_HMAC, ID_CRYPTO_REVOKE,characteristic, NULL, 0); //TODO invalid token
  return;
}

void processErrorCommandIncoming(uint64_t appContxtId, connected_beacons_t *p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic)
{
  BTUNUSED(characteristic);

  hmkit_core_log(NULL,NULL,HMKIT_CORE_LOG_INFO,"processErrorCommandIncoming");

  // Command ID(of response sent) that caused the Error
  uint8_t command = databuffer->txrx_buffer[1];
  uint8_t errorType = databuffer->txrx_buffer[2];

  hmkit_core_api_callback_error_command_incoming(appContxtId, &(p_client->device), command, errorType);

}

void processIncomingCommand(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic) {

  //Here we set characteristic where ack should be sent
  if(characteristic == hmkit_core_characteristic_link_read){
    characteristic = hmkit_core_characteristic_link_write;
  }else if(characteristic == hmkit_core_characteristic_sensing_write){
    characteristic = hmkit_core_characteristic_sensing_read;
  }

  switch (databuffer->txrx_buffer[0]) {
    case ID_CRYPTO_GET_NONCE:
      processGetNonceIncoming(appContxtId, p_client, databuffer, characteristic);
          break;
    case ID_CRYPTO_GET_DEVICE_CERTIFICATE:
      processGetDeviceCertificateIncoming(appContxtId, p_client, databuffer, characteristic);
          break;
    case ID_CRYPTO_REGISTER_CERTIFICATE:
      processRegisterCertificateIncoming(appContxtId, p_client, databuffer, characteristic);
          break;
    case ID_CRYPTO_STORE_CERTIFICATE:
      processStoreCertificateIncoming(appContxtId, p_client, databuffer, characteristic);
          break;
    case ID_CRYPTO_GET_CERTIFICATE:
      processGetCertificateIncoming(appContxtId, p_client, databuffer, characteristic);
          break;
    case ID_CRYPTO_AUTHENTICATE:
      processAuthenticateIncoming(appContxtId, p_client, databuffer, characteristic);
          break;
    case ID_CRYPTO_AUTHENTICATE_DONE:
      processAuthenticateDoneIncoming(appContxtId, p_client, databuffer, characteristic);
          break;
    case ID_CRYPTO_CONTAINER:
      processSecureCommandContainerIncoming(appContxtId, p_client, databuffer, characteristic);
          break;
    case ID_CRYPTO_REVOKE:
      processRevokeIncoming(appContxtId, p_client, databuffer, characteristic);
          break;
    case ID_ERROR_COMMAND:
      processErrorCommandIncoming(appContxtId, p_client, databuffer, characteristic);
          break;
    default:
      //TODO what to do when crypto is out of sync or wrong?
      break;
  }

}

void processIncomingAck(uint64_t appContxtId, connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic) {

  //Here we set characteristic where new command should be sent if needed
  if(characteristic == hmkit_core_characteristic_link_write){
    characteristic = hmkit_core_characteristic_link_read;
  }else if(characteristic == hmkit_core_characteristic_sensing_read){
    characteristic = hmkit_core_characteristic_sensing_write;
  }

  switch (databuffer->txrx_buffer[1]) {
    case ID_CRYPTO_GET_NONCE:
      processGetNonce(appContxtId, p_client, databuffer, characteristic);
          if(p_client->device.is_authorised == true){
            hmkit_core_calculate_next_nonce(p_client->local_nonce);
            p_client->local_counter++;
          }
          break;
    case ID_CRYPTO_GET_DEVICE_CERTIFICATE:
      processGetDeviceCertificate(appContxtId, p_client, databuffer, characteristic);
          if(p_client->device.is_authorised == true){
            hmkit_core_calculate_next_nonce(p_client->local_nonce);
            p_client->local_counter++;
          }
          break;
    case ID_CRYPTO_GET_CERTIFICATE:
      processGetCertificate(appContxtId, p_client, databuffer, characteristic);
          if(p_client->device.is_authorised == true){
            hmkit_core_calculate_next_nonce(p_client->local_nonce);
            p_client->local_counter++;
          }
          break;
    case ID_CRYPTO_AUTHENTICATE:
      processAuthenticate(appContxtId, p_client, databuffer, characteristic);
          break;
    case ID_CRYPTO_AUTHENTICATE_DONE:
      processAuthenticateDone(p_client, databuffer, characteristic);
          break;
    case ID_CRYPTO_REGISTER_CERTIFICATE:
      processRegisterCertificate(appContxtId, p_client, databuffer, characteristic);
          if(p_client->device.is_authorised == true){
            hmkit_core_calculate_next_nonce(p_client->local_nonce);
            p_client->local_counter++;
          }
          break;
    case ID_CRYPTO_REVOKE:
      processRevoke(appContxtId, p_client, databuffer, characteristic);
          if(p_client->device.is_authorised == true){
            hmkit_core_calculate_next_nonce(p_client->local_nonce);
            p_client->local_counter++;
          }
          break;
    case ID_CRYPTO_CONTAINER:
      processSecureContainer(appContxtId, p_client, databuffer, characteristic);
          if(p_client->device.is_authorised == true){
            hmkit_core_calculate_next_nonce(p_client->local_nonce);
            p_client->local_counter++;
          }
          break;
    default:
      //TODO add to skip list
      //AddBeaconTolist( cur_mac, 0, cur_serial );
      break;
  }

}

void processIncomingPacket( connected_beacons_t * p_client, data_buffer_t * databuffer, hmkit_core_characteristic characteristic) {
  uint64_t appContxtId =0;
  appContxtId = get_appContext_Hndlr(p_client->device.mac);

  //Incoming package
  if(characteristic == hmkit_core_characteristic_link_read || characteristic == hmkit_core_characteristic_sensing_write){
    if(p_client->device.is_authorised == true){
      hmkit_core_log(p_client->device.mac,p_client->device.serial_number,HMKIT_CORE_LOG_DEBUG,"[HMCore] Crypto command incoming");
      uint8_t ecdh[32];
      hmkit_core_generate_ecdh(appContxtId, p_client->remote_nonce, p_client->device.serial_number, ecdh);
      hmkit_core_encrypt_decrypt(appContxtId, p_client->nonce, p_client->remote_nonce, ecdh, databuffer->txrx_buffer, databuffer->rx_buffer_ptr + 1);
    }

    hmkit_core_log_data(p_client->device.mac,p_client->device.serial_number,HMKIT_CORE_LOG_DEBUG,databuffer->txrx_buffer,databuffer->rx_buffer_ptr,"[HMCore] DATA INCOMING");

    processIncomingCommand(appContxtId, p_client, databuffer, characteristic);
  }
    //Incoming ack
  else if(characteristic == hmkit_core_characteristic_link_write || characteristic == hmkit_core_characteristic_sensing_read){
    if(p_client->device.is_authorised == true){
      hmkit_core_log(p_client->device.mac,p_client->device.serial_number,HMKIT_CORE_LOG_DEBUG,"[HMCore] Crypto ack incoming");
      uint8_t ecdh[32];
      hmkit_core_generate_ecdh(appContxtId, p_client->local_nonce, p_client->device.serial_number, ecdh);
      hmkit_core_encrypt_decrypt(appContxtId, p_client->nonce, p_client->local_nonce, ecdh, databuffer->txrx_buffer, databuffer->rx_buffer_ptr + 1);
    }

    hmkit_core_log_data(p_client->device.mac,p_client->device.serial_number,HMKIT_CORE_LOG_DEBUG,databuffer->txrx_buffer,databuffer->rx_buffer_ptr,"[HMCore] DATA INCOMING");

    processIncomingAck(appContxtId, p_client, databuffer, characteristic);
  }
}

void resetRxBuffer(data_buffer_t * databuffer) {
  databuffer->rx_buffer_ptr = 0;
  databuffer->beginMessageReceived = false;
  databuffer->escapeNextByte = false;
}

bool bt_data_handler( uint8_t * p_data, uint16_t length, connected_beacons_t * p_client,hmkit_core_characteristic characteristic)
{
  data_buffer_t * databuffer;

  if(characteristic == hmkit_core_characteristic_sensing_write || characteristic == hmkit_core_characteristic_sensing_read){
    databuffer = &p_client->txrx_sensing;
  }else{
    databuffer = &p_client->txrx_link;
  }

#ifdef DYNAMIC_MEM_DATA
  uint8_t* more_data = NULL;

  databuffer->txrx_buffer_size = databuffer->txrx_buffer_size + length;
  
  more_data = (uint8_t*) realloc (databuffer->txrx_buffer, (databuffer->txrx_buffer_size) * sizeof(uint8_t));

  if (more_data!=NULL) {
    databuffer->txrx_buffer = more_data;
  }
  else {
    return false;
  }

#endif  

  int i = 0;
  for (i = 0; i < length; i++) {
    bool escape = databuffer->escapeNextByte;
    databuffer->escapeNextByte = false;

    // End of message reached
    if (!escape && p_data[i] == PACKET_END) {
      processIncomingPacket(p_client, databuffer, characteristic);
      resetRxBuffer(databuffer);

      return true;
    }

    // Escape next byte
    if (!escape && p_data[i] == PACKET_ESCAPE) {
      databuffer->escapeNextByte = true;
      continue;
    }

    // Skip begin message byte
    if (!escape && p_data[i] == PACKET_BEGIN) {
      resetRxBuffer(databuffer);
      databuffer->beginMessageReceived = true;

    #ifdef DYNAMIC_MEM_DATA
      //Clean up previous data buffer
      if(databuffer->txrx_buffer != NULL){
        free(databuffer->txrx_buffer);
        databuffer->txrx_buffer = NULL;
      }

      //Create new buffer
      databuffer->txrx_buffer_size = length;
      databuffer->txrx_buffer = (uint8_t *)malloc((databuffer->txrx_buffer_size) * sizeof(uint8_t));
    #endif

      continue;
    }

    // Check for overflow
    if (databuffer->rx_buffer_ptr >= gMaxBufferSize) {
      if (databuffer->beginMessageReceived) {
      // send appropriate nack
      }
      resetRxBuffer(databuffer);
      continue;
    }

    // Write byte in buffer
    databuffer->txrx_buffer[databuffer->rx_buffer_ptr] = p_data[i];
    databuffer->rx_buffer_ptr++;
  }

  return false;
}

void hmkit_core_sensing_connect(uint64_t btcontxtId, uint8_t *mac){

  hmkit_core_log(mac,NULL,HMKIT_CORE_LOG_INFO,"[HMSensing] Connected, checking services");

  uint16_t major = 0;
  uint16_t minor = 0;
  getMajorMinorFromList(mac,&major,&minor);

  uint8_t name[8];
  getNameFromList(mac,name);

  client_handling_create(mac,major,minor,name,false);
  
  update_btcontext_Hndlr(btcontxtId, mac);
}

void hmkit_core_sensing_disconnect(uint8_t *mac){

  hmkit_core_log(mac,NULL,HMKIT_CORE_LOG_INFO,"[HMSensing] Disconnected");

  client_handling_destroy(mac);
  //APP_ERROR_CHECK(err_code);

  //if(BLE_ON != 0){
  //hmkit_core_connectivity_hal_scan_start();
  //}
}

/**
 * @brief Parses advertisement data, providing length and location of the field in case
 *        matching data is found.
 *
 * @param[in]  Type of data to be looked for in advertisement data.
 * @param[in]  Advertisement report length and pointer to report.
 * @param[out] If data type requested is found in the data report, type data length and
 *             pointer to data will be populated here.
 *
 * @retval NRF_SUCCESS if the data type is found in the report.
 * @retval NRF_ERROR_NOT_FOUND if the data type could not be found.
 */
static uint32_t adv_report_parse(uint8_t type, data_t * p_advdata, data_t * p_typedata)
{
  uint32_t index = 0;
  uint8_t * p_data;

  p_data = p_advdata->p_data;

  while (index < p_advdata->data_len)
  {
    uint8_t field_length = p_data[index];
    if(index+1 < p_advdata->data_len){
      uint8_t field_type = p_data[index+1];

      if (field_type == type)
      {
        p_typedata->p_data = &p_data[index+2];
        p_typedata->data_len = field_length-1;
        return NRF_SUCCESS;
      }
      index += field_length+1;
    }else{
      return 1;
    }

  }
  return 1;
}

void update_btcontext_Hndlr(uint64_t btcontxtId, uint8_t *mac)
{
  connected_beacons_t * p_client = getBeaconId(mac);
  if(p_client != NULL){
    p_client->btContextHndlr = btcontxtId;
  }

  //TODO ERROR
}

uint64_t get_btcontext_Hndlr(uint8_t *mac)
{
  connected_beacons_t * p_client = getBeaconId(mac);
  return p_client->btContextHndlr;
}

void cache_appContext_Hndlr(uint64_t appContxtId, uint8_t *mac)
{
  connected_beacons_t * p_client = getBeaconId(mac);
  p_client->appContextHndlr  = appContxtId;
}

uint64_t get_appContext_Hndlr(uint8_t *mac)
{
  connected_beacons_t * p_client = getBeaconId(mac);
  if(p_client != NULL){
    return p_client->appContextHndlr;
  }
  
  return 0;
}

void hmkit_core_sensing_read_response(uint64_t btcontxtId, uint8_t *data, uint16_t size, uint16_t offset, uint8_t *mac, hmkit_core_characteristic characteristic){

  connected_beacons_t * p_client = getBeaconId(mac);

  update_btcontext_Hndlr(btcontxtId, mac);

  if(p_client != NULL){
    if(bt_data_handler(data,size,p_client, characteristic) != true){
      hmkit_core_connectivity_hal_read_data(btcontxtId, mac,offset + size,characteristic);
    }
  }
}


void hmkit_core_sensing_read_info_response(uint64_t btcontxtId, uint8_t *data, uint16_t size, uint16_t offset, uint8_t *mac, hmkit_core_characteristic characteristic){
BTUNUSED(characteristic);
BTUNUSED(offset);
BTUNUSED(btcontxtId);

uint16_t mtu = 0;
connected_beacons_t * p_client = getBeaconId(mac);

  if(p_client != NULL)
  {
    if(size <= 30+6)
    {
        hmkit_core_log_data(p_client->device.mac,p_client->device.serial_number,HMKIT_CORE_LOG_DEBUG,data,size,"[HMSensing] Store info char");
        memcpy(p_client->device.info_string,data,size);

	// MTU Parsing
        mtu = parse_MTU_value(data, size);
        if(mtu > 0)
        {
           p_client->mtu = mtu - 3; // 3 header
        }
      	else
	      {
	        p_client->mtu = DEFAULT_BLE_MTU;
	      }
    }else{
       //TODO ERROR
    }
  }

  sendGetCertificate(mac);
}

// expected format "MTU000". 3 digit after "MTU". with leading zero for lesser digits
static int parse_MTU_value(uint8_t *data, uint16_t size)
{
 uint8_t i=0;
 uint16_t value=0;

 for(i=0; i<=size-5; i++)
 {
   if(data[i] == 'M' && data[i+1] == 'T' && data[i+2] == 'U')
   {
	value = (value * 10) + data[i+3] - '0';
	value = (value * 10) + data[i+4] - '0';
	value = (value * 10) + data[i+5] - '0';
	break;
    }
  }

  if(value > MAX_BLE_MTU)
    value = DEFAULT_BLE_MTU; // set a default value

  return value;
}

void hmkit_core_sensing_write_response(uint64_t btcontxtId, uint8_t *mac, hmkit_core_characteristic characteristic){

  connected_beacons_t * p_client = getBeaconId(mac);

  update_btcontext_Hndlr(btcontxtId, mac);

  if(p_client != NULL){
    data_buffer_t * databuffer;

    if(characteristic == hmkit_core_characteristic_sensing_write || characteristic == hmkit_core_characteristic_sensing_read){
      databuffer = &p_client->txrx_sensing;
    }else{
      databuffer = &p_client->txrx_link;
    }

    if(databuffer->m_is_writing_data == false){
      if(p_client->sendCallback == 1){
        hmkit_core_log(mac,NULL,HMKIT_CORE_LOG_INFO,"[HMCore] Call callback");
        p_client->sendCallback = 0;
        hmkit_core_core_commandinprogress = 0;
        hmkit_core_api_callback_command_incoming(btcontxtId, &(p_client->device), p_client->callbackContentType, p_client->callbackData, p_client->callbackDataSize, p_client->callbackReqID, p_client->callbackReqIDSize, p_client->callbackVersion);

      //Free up memory  
      #ifdef DYNAMIC_MEM_DATA
        free(p_client->callbackData);
        p_client->callbackData = NULL;
      #endif
      }
    }
    writeNextJunk(mac, characteristic);
  }
}

void hmkit_core_sensing_read_notification(uint64_t btcontxtId, uint8_t *mac, hmkit_core_characteristic characteristic){
  update_btcontext_Hndlr(btcontxtId, mac);

  hmkit_core_connectivity_hal_read_data(btcontxtId,mac,0,characteristic);
}

void hmkit_core_sensing_ping_notification(uint64_t btcontxtId, uint8_t *mac, hmkit_core_characteristic characteristic){
  update_btcontext_Hndlr(btcontxtId, mac);

  BTUNUSED(characteristic);
  BTUNUSED(mac);
  hmkit_core_api_callback_ping();
}

void hmkit_core_sensing_scan_start(void)
{

}

void hmkit_core_sensing_discovery_event(uint8_t *mac)
{
  uint64_t btContxtHndlr = get_btcontext_Hndlr(mac);

  if(hmkit_core_connectivity_hal_read_info(btContxtHndlr, mac, 0, hmkit_core_characteristic_info) != 0){
    sendGetCertificate(mac);
  }
}

void hmkit_core_clock(){
  clock ++;
  checkBeacons();
  hmkit_core_connectivity_hal_clock();
  hmkit_core_api_callback_clock();
}

void hmkit_core_ble_on(uint8_t action){
  if(action == 0x01){
    hmkit_core_connectivity_hal_scan_start();
    BLE_ON = 1;
  }else{
    BLE_ON = 0;
    hmkit_core_connectivity_hal_scan_stop();
    reportBeaconLeaveForAll();
  }
}

uint32_t hmkit_core_get_version_major_number(void){
  return hmkit_core_VERSION_MAJOR;
}

uint32_t hmkit_core_get_version_minor_number(void){
  return hmkit_core_VERSION_MINOR;
}

uint32_t hmkit_core_get_version_patch_number(void){
  return hmkit_core_VERSION_PATCH;
}

/**
 * Initializes the SoftDevice and the BLE event interrupt, which dispatches
 * all events to this application.
 */
void hmkit_core_init(void) {

  hmkit_core_log(NULL,NULL,HMKIT_CORE_LOG_INFO,"[HMSensing] Initialised");

  //Init BLE
  initBeaconList();
  initMajorMinorList();

  hmkit_core_connectivity_hal_init();

  hmkit_core_connectivity_hal_scan_start();

  uint8_t cert[153];
  uint64_t appContxtId = 0;
  //TODO: BC-130 Review, ID=0
  hmkit_core_persistence_hal_get_device_certificate(appContxtId, cert);

  hmkit_core_connectivity_hal_advertisement_start(cert,cert + 4);

  hmkit_core_api_callback_init();
}

void hmkit_core_link_disconnect(uint8_t *mac){
  connected_beacons_t * p_client = getBeaconId(mac);
  if(p_client != NULL){
    client_handling_destroy(mac);
    checkBeacons();
  }
}

#define BLE_GAP_AD_TYPE_MANUFACTURER_SPECIFIC_DATA 0xFF
#define BLE_GAP_AD_TYPE_COMPLETE_LOCAL_NAME 0x09
#define BLE_GAP_AD_TYPE_128BIT_SERVICE_UUID_COMPLETE 0x07

void hmkit_core_sensing_process_advertisement( uint8_t *mac, uint8_t macType, uint8_t * data, uint8_t size){

    data_t adv_data;
    adv_data.data_len = size;
    adv_data.p_data = data;
    data_t type_data;

    uint16_t major = 0;
    uint16_t minor = 0;

    uint32_t err_code = adv_report_parse(BLE_GAP_AD_TYPE_MANUFACTURER_SPECIFIC_DATA, &adv_data, &type_data);

    if (err_code == NRF_SUCCESS){
        major = type_data.p_data[21] | (type_data.p_data[20] << 8);
        minor = type_data.p_data[23] | (type_data.p_data[22] << 8);
    }

    //IF parrot then we have service uuid in adv package
    connected_beacons_t * p_client = getBeaconId(mac);

    if(p_client == NULL){

        err_code = adv_report_parse(BLE_GAP_AD_TYPE_COMPLETE_LOCAL_NAME, &adv_data, &type_data);

        uint8_t name[8];

        if (err_code == NRF_SUCCESS){
            memcpy(name,type_data.p_data,8);
        }

        //TODO update beacon mac
        if(p_client != NULL){
            //memcpy(mBeacons[id].device.mac,mac,6);
        }

        if(p_client == NULL){

            err_code = adv_report_parse(BLE_GAP_AD_TYPE_128BIT_SERVICE_UUID_COMPLETE, &adv_data, &type_data);

            //err_code = adv_report_parse(BLE_GAP_AD_TYPE_MANUFACTURER_SPECIFIC_DATA, &adv_data, &type_data);

            if(err_code == NRF_SUCCESS){

                addMajorMinorToList(mac,major,minor);
                addNameToList(mac,name);

                uint8_t count;
                uint64_t appContxtId = 0;
                appContxtId = get_appContext_Hndlr(mac);

                if(hmkit_core_persistence_hal_get_appid_for_issuer_count(appContxtId, type_data.p_data, &count)==0)
                {
                    uint8_t appidbuffer[12];

                    //Not allowed device
                    if(count == 0){
                        return;
                    }

                    //Check if all appid's are allowed
                    if(count == 1){
                        uint8_t zero[12];
                        memset(zero,0x00,12);
                        if(hmkit_core_persistence_hal_get_appid_for_issuer(appContxtId, type_data.p_data,0,appidbuffer)==0){
                            if(memcmp(appidbuffer,zero,12)==0){
                                hmkit_core_connectivity_hal_connect(mac,macType);
                                return;
                            }
                        }
                    }
                    //Check if we find appid from list
                    uint8_t i = 0;
                    for(i = 0; i < count; i++){
                        if(hmkit_core_persistence_hal_get_appid_for_issuer(appContxtId, type_data.p_data,i,appidbuffer)==0){
                            if(memcmp(appidbuffer,type_data.p_data + 4,12)==0){
                                hmkit_core_connectivity_hal_connect(mac,macType);
                            }
                        }
                    }
                }
            }
        }
    }
}

void hmkit_core_link_connect(uint64_t btcontxtId, uint8_t *mac){
  if(getBeaconId(mac) == NULL){
    uint8_t name[8];
    client_handling_create(mac, 0, 0, name, true);
  }

  update_btcontext_Hndlr(btcontxtId, mac);
}

void hmkit_core_link_incoming_data(uint64_t btcontxtId, uint8_t *data, uint16_t size, uint8_t *mac, hmkit_core_characteristic characteristic){
  connected_beacons_t * p_client = getBeaconId(mac);
  update_btcontext_Hndlr(btcontxtId, mac);

  if(p_client != NULL){
    bt_data_handler(data, size, p_client, characteristic);
  }
}

void hmkit_core_link_write_response(uint64_t btcontxtId, uint8_t *mac, hmkit_core_characteristic characteristic){
  connected_beacons_t * p_client = getBeaconId(mac);
  update_btcontext_Hndlr(btcontxtId, mac);
  uint64_t appContxtId =0;
  appContxtId = get_appContext_Hndlr(mac);

  BTUNUSED(characteristic);
  skipBeaconCheck = 0;
  checkBeacons();

  if(p_client && p_client->sendCallback == 1){
    hmkit_core_log(mac,NULL,HMKIT_CORE_LOG_INFO,"[HMCore] Call callback");
    p_client->sendCallback = 0;
    hmkit_core_api_callback_command_incoming(appContxtId, &p_client->device, p_client->callbackContentType, p_client->callbackData, p_client->callbackDataSize, p_client->callbackReqID, p_client->callbackReqIDSize, p_client->callbackVersion);
  }
}

void getAuthorisedDevises(uint8_t *device_size, hmkit_core_device_t *devices){

  uint8_t i = 0;
  *device_size = 0;

  for(i = 0;i<MAX_CLIENTS;i++){
    if(mBeacons[i].device.is_authorised == 1){
      memcpy(devices[*device_size].serial_number,mBeacons[i].device.serial_number,9);
      *device_size = *device_size + 1;
    }
  }
}

bool hmkit_core_parse_data( uint8_t *in_data, uint32_t length, uint8_t *out_data, uint32_t *out_data_position)
{
  bool escapeNextByte = false;
  uint32_t i = 0;
  for (i = 0; i < length; i++) {
    bool escape = escapeNextByte;
    escapeNextByte = false;

    // End of message reached
    if (!escape && in_data[i] == PACKET_END) {
      return true;
    }

    // Escape next byte
    if (!escape && in_data[i] == PACKET_ESCAPE) {
      escapeNextByte = true;
      continue;
    }

    // Skip begin message byte
    if (!escape && in_data[i] == PACKET_BEGIN) {
      continue;
    }

    // Check for overflow
    if (*out_data_position >= gMaxBufferSize) {
      //TODO ERROR
      continue;
    }

    // Write byte in buffer
    out_data[*out_data_position] = in_data[i];
    *out_data_position = *out_data_position+1;
  }

  return false;
}

uint16_t hmkit_core_prepare_data(uint16_t size, uint8_t *in_data, uint8_t *out_data){
  // Prepare the message, with the appropriate data structure
  uint16_t count = 0;

  out_data[count++] = PACKET_BEGIN;

  int i = 0;
  for (i = 0; i < size; i++) {
    if (in_data[i] == 0x00 || in_data[i] == 0xFE || in_data[i] == 0xFF){
      out_data[count++] = PACKET_ESCAPE;
    }

    out_data[count++] = in_data[i];
  }

  out_data[count++] = PACKET_END;

  return count;
}

uint32_t hmkit_core_send_telematics_error(uint64_t appContxtId_Tele, uint8_t *serial, uint8_t id, uint8_t error, uint8_t *reqID, uint16_t reqID_size, uint8_t version)
{
  uint8_t local_serial[9];
  uint16_t out_data_prepared_length = 0;
  uint8_t issuer[4] = {0x74,0x6D,0x63,0x73};
  uint8_t out_data[1 + SIZE_SER + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + REQUEST_ID_MAX_BYTES_SIZE + 1 + SIZE_TELV2_PAYLD_LEN + 4 + SIZE_HMAC];
  uint8_t out_data_prepared[(1 + SIZE_SER + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + REQUEST_ID_MAX_BYTES_SIZE + 1 + SIZE_TELV2_PAYLD_LEN + 4 + SIZE_HMAC + 2)*2];

  hmkit_core_persistence_hal_get_serial(appContxtId_Tele, local_serial);

  if(version == 0x02)
  {
    uint32_t payld_len = 0;
    uint16_t payld_len_start_index = 0;

    // Version
    out_data[0] = 0x02;
    // local serial
    memcpy(out_data + 1, local_serial, SIZE_SER);
    //Add receiver serial
    memcpy(out_data + 1 + SIZE_SER, serial, SIZE_SER);
    // Add Nonce
    memset(out_data + 1 + SIZE_SER + SIZE_SER, 0x00, SIZE_NONCE);
    //Add request id Length
    out_data[1 + SIZE_SER + SIZE_SER + SIZE_NONCE] = (reqID_size & 0xFF00)  >> 8;
    out_data[1 + SIZE_SER + SIZE_SER + SIZE_NONCE + 1] = reqID_size & 0x00FF;
    // Copy Req ID
    memcpy(out_data + 1 + SIZE_SER + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN, reqID, reqID_size);

    //Is encrypted. Not encrypted
    out_data[1 + SIZE_SER + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size] = 0x00;

    //Content type unknown because of error
    out_data[1 + SIZE_SER + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size +1] = 0x00;

    payld_len_start_index = 1 + SIZE_SER + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size + 1 +1;

    payld_len = 3;

    //Payload Length
    out_data[payld_len_start_index] = (payld_len & 0xFF000000)  >> 24;
    out_data[payld_len_start_index + 1] = (payld_len & 0x00FF0000)  >> 16;
    out_data[payld_len_start_index + 2] = (payld_len & 0x0000FF00)  >> 8;
    out_data[payld_len_start_index + 3] = payld_len & 0x000000FF;

    // Payload
    out_data[(payld_len_start_index + SIZE_TELV2_PAYLD_LEN) ] = ID_ERROR;
    out_data[(payld_len_start_index + SIZE_TELV2_PAYLD_LEN) + 1] = id;
    out_data[(payld_len_start_index + SIZE_TELV2_PAYLD_LEN) + 2] = error;

    // HMAC left with garbage value

    // Payload
    out_data_prepared_length = hmkit_core_prepare_data((payld_len_start_index + SIZE_TELV2_PAYLD_LEN + payld_len + SIZE_HMAC), out_data, out_data_prepared);

  }
  else // Version 1 (default)
  {
    // Local Serial
    memcpy(out_data, local_serial, SIZE_SER);
    // Nonce
    memset(out_data + SIZE_SER, 0x00, SIZE_NONCE);
    // isEncrypted, Not Encrypted
    out_data[SIZE_SER + SIZE_NONCE] = 0x00;

    // Payload
    out_data[SIZE_SER + SIZE_NONCE + 1 ] = ID_ERROR;
    out_data[SIZE_SER + SIZE_NONCE + 2 ] = id;
    out_data[SIZE_SER + SIZE_NONCE + 3 ] = error;

    out_data_prepared_length = hmkit_core_prepare_data((SIZE_SER + SIZE_NONCE + 4), out_data, out_data_prepared);
  }

  hmkit_core_connectivity_hal_telematics_send_data(appContxtId_Tele, issuer,serial, out_data_prepared_length, out_data_prepared);

  return 0;
}


uint32_t hmkit_core_telematics_receive_data(uint64_t appContxtId_Tele, uint32_t length, uint8_t *data){

  uint32_t out_data_position = 0;

  if(hmkit_core_parse_data(data, length, data, &out_data_position) == true)
  {
      uint8_t nonce[SIZE_NONCE];
      connected_beacons_t device;
      uint8_t is_encrypted = 0x00;
      uint8_t reqID[REQUEST_ID_MAX_BYTES_SIZE + 1];
      uint16_t reqID_size = 0;

      //Check version
      if(data[0] == 0x02)
      {
          reqID_size = (uint16_t)((data[1 + SIZE_SER + SIZE_SER + SIZE_NONCE] << 8) | data[1 + SIZE_SER + SIZE_SER + SIZE_NONCE + 1]);
          uint32_t payload_size = (uint32_t)((data[1 + SIZE_SER + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size + 1 + 1] << 24) | (data[1 + SIZE_SER + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size + 1 + 1 + 1] << 16) | (data[1 + SIZE_SER + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size + 1 + 1 + 2] << 8) | data[1 + SIZE_SER + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size + 1 + 1 + 3]);

          if(out_data_position == (1 + SIZE_SER + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size + 1 + 1 + SIZE_TELV2_PAYLD_LEN + payload_size + SIZE_HMAC))
          {
            //Ver 2
              memcpy(device.device.serial_number, data + 1, SIZE_SER);
              memcpy(nonce , data + 1 + SIZE_SER + SIZE_SER, SIZE_NONCE);
              memcpy(device.device.nonce , data + 1 + SIZE_SER + SIZE_SER , SIZE_NONCE);

              memcpy(reqID, data + 1 + SIZE_SER + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN, reqID_size);

              is_encrypted = data[1 + SIZE_SER  + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size];

              if(is_encrypted == 0 && (data[1 + SIZE_SER  + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size + 1 + 1 + SIZE_TELV2_PAYLD_LEN] == 0x2))
              {// Error Message, not encrypted and dummy HMAC
                  hmkit_core_log(NULL, NULL,HMKIT_CORE_LOG_INFO,"[HMCore] hmkit_core_telematics_receive_data() Error Msg received ");
                  hmkit_core_api_callback_telematics_command_incoming(appContxtId_Tele, &device.device, ID_ERROR, 0, payload_size, data + 1 + SIZE_SER  + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size + 1 + 1 + SIZE_TELV2_PAYLD_LEN, reqID, reqID_size, 0x02);
              }
              else if(hmkit_core_validate_hmac(appContxtId_Tele, nonce,device.device.serial_number,data, 1 + SIZE_SER  + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size + 1 + 1 + SIZE_TELV2_PAYLD_LEN + payload_size, (data + 1 + SIZE_SER  + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size + 1 + 1 + SIZE_TELV2_PAYLD_LEN + payload_size) ) == 0)
              {
                  if(is_encrypted == 0x01)
                  {
                      uint8_t ecdh[32];
                      if(hmkit_core_generate_ecdh(appContxtId_Tele, nonce, device.device.serial_number, ecdh) == 0)
                      {
                          hmkit_core_encrypt_decrypt(appContxtId_Tele, nonce, nonce, ecdh, data + 1 + SIZE_SER  + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size + 1 + 1 + SIZE_TELV2_PAYLD_LEN, payload_size);
                      }
                      else
                      {
                          hmkit_core_send_telematics_error(appContxtId_Tele, device.device.serial_number, 0x01, ERR_INTERNAL_ERROR, reqID, reqID_size, 0x02);
                          return 1;
                      }
                  }

                  hmkit_core_api_callback_telematics_command_incoming(appContxtId_Tele, &device.device, ID_CRYPTO_CONTAINER, data[1 + SIZE_SER  + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size + 1], payload_size, data + 1 + SIZE_SER  + SIZE_SER + SIZE_NONCE + SIZE_REQID_LEN + reqID_size + 1 + 1 + SIZE_TELV2_PAYLD_LEN, reqID, reqID_size, 0x02);
              }
              else
              {
                  hmkit_core_send_telematics_error(appContxtId_Tele, device.device.serial_number, 0x01, ERR_INVALID_HMAC, reqID, reqID_size, 0x02);
                  return 1;
              }
          }
          else // out postion, size cross check
          {
              hmkit_core_log(NULL,NULL,HMKIT_CORE_LOG_ERROR,"[HMCore]  ERROR: invalid positions, out_data_position = %d, reqID_size = %d, payload_size = %d", out_data_position, reqID_size, payload_size);
              //Invalid
              //TODO IN this case can be also ver 1
              return 1;
          }

      }
      else //Version 1, default
      {
          // no reqId in Custom Command V1 hence set it as 0 and its size 1
          reqID[0] = 0;
          reqID_size = 1;

          // from Telematics Header
          memcpy(device.device.serial_number, data, SIZE_SER);
          memcpy(nonce , data + SIZE_SER, SIZE_NONCE);
          memcpy(device.device.nonce , data + SIZE_SER , SIZE_NONCE);
          is_encrypted = data[SIZE_SER + SIZE_NONCE];

          hmkit_core_log(NULL,device.device.serial_number,HMKIT_CORE_LOG_INFO,"[HMCore] CRYPTED %d", is_encrypted);

          if(is_encrypted == 0x01){
              uint8_t ecdh[32];
              if(hmkit_core_generate_ecdh(appContxtId_Tele, nonce, device.device.serial_number, ecdh) == 0){
                  hmkit_core_encrypt_decrypt(appContxtId_Tele, nonce, nonce, ecdh, data + (SIZE_SER + SIZE_NONCE + 1), out_data_position - (SIZE_SER + SIZE_NONCE + 1));
              }else{
                  hmkit_core_send_telematics_error(appContxtId_Tele, device.device.serial_number, 0x01, ERR_INTERNAL_ERROR, reqID, reqID_size, 0x01);
                  return 1;
              }
          }

          hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_INFO,data,out_data_position,"[HMCORE] hmkit_core_telematics_receive_data %d %d",SIZE_SER + SIZE_NONCE + 1 , out_data_position - SIZE_SER - SIZE_NONCE - 1);

          switch(data[SIZE_SER + SIZE_NONCE + 1])
          {
              case ID_CRYPTO_CONTAINER:
              {
                  uint16_t size=0;

                  // Size in Big Endian
                  size = (uint16_t)((data[SIZE_SER + SIZE_NONCE + 1 + 2] << 8) | (data[SIZE_SER + SIZE_NONCE + 1 + 2 + 1 ]));

                  if(hmkit_core_validate_hmac(appContxtId_Tele, nonce,device.device.serial_number, data + SIZE_SER + SIZE_NONCE + 1, SECURE_CONT_HEADER_SIZE_V1 + size , data + SIZE_SER + SIZE_NONCE + 1 + SECURE_CONT_HEADER_SIZE_V1 + size ) == 0)
                  {
                      hmkit_core_api_callback_telematics_command_incoming(appContxtId_Tele, &device.device, ID_CRYPTO_CONTAINER, 0, size, data + SIZE_SER + SIZE_NONCE + 1 + SECURE_CONT_HEADER_SIZE_V1, reqID, reqID_size, 0x01);

                  }else{
                      hmkit_core_send_telematics_error(appContxtId_Tele, device.device.serial_number, ID_CRYPTO_CONTAINER, ERR_INVALID_HMAC, reqID, reqID_size, 0x01);
                      return 1;
                  }

                  break;
              }
              case ID_ERROR:
              {
                  hmkit_core_api_callback_telematics_command_incoming(appContxtId_Tele, &device.device, ID_ERROR, 0, 3, data + SIZE_SER + SIZE_NONCE + 1, reqID, reqID_size, 0x01);
                  break;
              }
          }// End Switch
      } // End Version checks

  }
  else // Core parsing failed
  {
      //Corrupted data just ignore
      return 1;
  }

  return 0;
}

//----------- Certificates Garbage collection ------------//

#define GARBAGE_TMP_CERTST_LIST_SIZE 10

// Structure Array to be used during garbage collection
// for temporarly booking keeping the identified invalid certificates
hmkit_core_certificate_t Cert_invalid_list[GARBAGE_TMP_CERTST_LIST_SIZE];

uint8_t invalid_list_count = 0;

/**
*
*
*
*/
void add_to_listend(uint8_t *data)
{

  if(invalid_list_count >= GARBAGE_TMP_CERTST_LIST_SIZE)
  {
    hmkit_core_log(NULL,NULL,HMKIT_CORE_LOG_ERROR,"[HMCore] ***** Overflow: Garbage Collect, Increase the Invalid Cert List size");
    return;
  }

  invalid_list_count++;
  // copy the whole structure to the invalid list structure elements
  hmkit_core_cert_get_as_struct(data, &(Cert_invalid_list[invalid_list_count]));
}

/**
*
*
*
*/
void clear_list()
{
  invalid_list_count = 0;
}

#define GARBAGE_COLLECT_INTERVAL_MS 600
#define TIMER_INPUT_INTERVAL_MS 65

/**
*
*
*/
void timer_garbagecollect_certf()
{
  static uint16_t count = 0;

  // check the garbage collect interval reach and trigger garbage collection
  if((count * TIMER_INPUT_INTERVAL_MS) > GARBAGE_COLLECT_INTERVAL_MS )
  {
    trigger_persis_garbage_collection();

    count = 0;
  }
  else
  {
    count++;
  }

}

int16_t trigger_persis_garbage_collection()
{
  uint8_t count=0, index =0;
  uint16_t i =0;
  uint64_t appContxtId =0; // TODO: BC-130 Review
  hmkit_core_persistence_hal_get_access_certificate_count(appContxtId, &count);

  // loop through the available access certificates and check their date-time
  // validity
  while(count > index)
  {

    uint8_t cert_data[HMKIT_CORE_CERT_V1_MAX_SIZE];
    uint16_t cert_size = 0;
    appContxtId =0; // TODO: BC-130 Review
    hmkit_core_persistence_hal_get_access_certificate_by_index(appContxtId, index, cert_data, &cert_size);

    hmkit_core_certificate_t certificate;
    if(hmkit_core_cert_get_as_struct(cert_data, &certificate) == HM_OK){
        // remove the certificate if the validity has expired
        if(hmkit_core_check_date_validity(certificate.start_date, certificate.end_date) == 0)
        {
          // Store the expired certificates in a list
          // erase them after the iteration. deletion inbetween the loop
          // alters the index order of the certificates in database
          // hence delete it only after the iteration

          add_to_listend(cert_data);
        }
    }

    index++;
  }

  // Erase the expired certificates from persistence
  for(i=0; i < invalid_list_count; i++)
  {
    // Erase the access certificate
    hmkit_core_persistence_hal_erase_access_certificate(appContxtId, &(Cert_invalid_list[i]) );
  }

  // clear the list
  clear_list();

  return HM_OK;
}

uint8_t hmkit_core_check_date_validity(uint8_t *start_date, uint8_t *end_date){
    uint8_t day, month, year, minute, hour;
    hmkit_core_api_get_current_date_time(&day, &month, &year, &minute, &hour);

    if(day == 0x00 && month == 0x00 && year == 0x00 && minute == 0x00 && hour == 0x00){
        return 1;
    }

    //Check if it is in year range
    if(start_date[0] <= year && end_date[0] >= year){
        //Check if it is expired
        if(end_date[0] == year){
            //If year is same but month bigger then expired
            if(end_date[1] < month){
                return 0;
            }else if(end_date[1] == month){
                //If month is same but day is bigger the expired
                if(end_date[2] < day){

                    return 0;
                }else if(end_date[2] == day){
                    //If day is same but hour is bigger then expired
                    if(end_date[3] < hour){

                        return 0;
                    }else if(end_date[3] == hour){
                        //If hour is same but minute is bigger then expired
                        if(end_date[4] < minute){

                            return 0;
                        }
                    }
                }
            }
        }
        //Check if it is not started
        if(start_date[0] == year){
            //If year is same but month is smaller then not started
            if(start_date[1] > month){

                return 0;
            }else if(start_date[1] == month){
                //If month is same but day is smaller then not started
                if(start_date[2] > day){

                    return 0;
                }else if(start_date[2] == day){
                    //If day is same but hour is smaller then not started
                    if(start_date[3] > hour){

                        return 0;
                    }else if(start_date[3] == hour){
                        //If hour is same but minute is smaller then not started
                        if(start_date[4] > minute){

                            return 0;
                        }
                    }
                }
            }
        }

        return 1;
    }

    return 0;
}
