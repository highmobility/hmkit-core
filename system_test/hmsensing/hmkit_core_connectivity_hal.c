
#include "hmkit_core_connectivity_hal.h"
#include "hmkit_core.h"
#include "hmkit_core_conf_access.h"
#include <gio/gio.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "hmkit_core_log.h"

#define MAX_BUF 1024

static int h_fifo_advertisement;
static int h_fifo_link_read;
static int h_fifo_link_write;
static int h_fifo_info;
static int h_fifo_sensing_read;
static int h_fifo_sensing_write;
static int h_fifo_link_ble;
static int h_fifo_sensing_ble;
static int h_fifo_telematics;

char * fifo_advertisement = "/tmp/hmadvertisement";
char * fifo_link_read     = "/tmp/hmlinkread";
char * fifo_link_write    = "/tmp/hmlinkwrite";
char * fifo_info          = "/tmp/hminfo";
char * fifo_sensing_read  = "/tmp/hmsensingread";
char * fifo_sensing_write = "/tmp/hmsensingwrite";
char * fifo_link_ble      = "/tmp/hmlinkble";
char * fifo_sensing_ble   = "/tmp/hmsensingble";
char * fifo_telematics   = "/tmp/hmtelematics";

uint8_t remote_mac[6] = {0x06,0x05,0x04,0x03,0x02,0x01};

static uint8_t data_sensing_read[500];
static uint16_t data_sensing_read_size = 0;

static uint8_t data_link_read[500];
static uint16_t data_link_read_size = 0;

uint64_t gContxtId = 100;

void hmkit_core_connectivity_hal_explode(uint16_t source, uint8_t *dest) {
  dest[0] = source >> 8;
  dest[1] = source & 0xFF;
}

uint16_t hmkit_core_connectivity_hal_implode(uint8_t *msb) {
  // msb[1] = lsb
  return (((uint16_t) msb[0]) << 8) | msb[1];
}

void hmkit_core_connectivity_hal_pipe_send(uint8_t *data, uint16_t size, int pipe){
  if(write(pipe, data, size)){

  }
}

gpointer thread_advertisement(gpointer data){

  uint8_t buf[MAX_BUF];

  int nbytes;

  while(true){
    //Read advertisement
    nbytes  = read(h_fifo_advertisement, buf, MAX_BUF);
    if(nbytes > 0){
      hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_INFO,buf,nbytes,"[MOC] ADVERTISEMENT");
      hmkit_core_sensing_process_advertisement(remote_mac, 0, buf, nbytes);
    }
  }
}

gpointer thread_link_read(gpointer data){

  uint8_t buf[MAX_BUF];

  int nbytes;

  while(true){
    //Read link command
    nbytes  = read(h_fifo_link_read, buf, MAX_BUF);
    if(nbytes > 0){
      memcpy(data_link_read,buf,nbytes);
      data_link_read_size = nbytes;
      hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_INFO,buf,nbytes,"[MOC] LINK READ NTFY");
      hmkit_core_sensing_read_notification(gContxtId, remote_mac, hmkit_core_characteristic_link_read);
    }
  }
}

gpointer thread_sensing_read(gpointer data){

  uint8_t buf[MAX_BUF];

  int nbytes;

  while(true){
    //Read sensing ack
    nbytes  = read(h_fifo_sensing_read, buf, MAX_BUF);
    if(nbytes > 0){
      memcpy(data_sensing_read,buf,nbytes);
      data_sensing_read_size = nbytes;
      hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_INFO,buf,nbytes,"[MOC] SENSING READ NTFY");
      hmkit_core_sensing_read_notification(gContxtId, remote_mac, hmkit_core_characteristic_sensing_read);
    }
  }
}

gpointer thread_link_ble(gpointer data){

  uint8_t buf[MAX_BUF];

  int nbytes;

  while(true){
    nbytes  = read(h_fifo_link_ble, buf, MAX_BUF);
    if(nbytes > 0){
      hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_INFO,buf,nbytes,"[MOC] LINK BLE");
      switch(buf[0]){
        case 0x00:
        {
          hmkit_core_sensing_connect(gContxtId, remote_mac);
          hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_INFO,buf,nbytes,"[MOC] CONNECTED");
          break;
        }
        case 0x01:
        {
          hmkit_core_sensing_disconnect(remote_mac);
          hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_INFO,buf,nbytes,"[MOC] DISCONNECTED");
          break;
        }
        //RSP next byte shows character
        case 0x03:
        {
          switch(buf[1]){
            case hmkit_core_characteristic_link_write:
            {
              hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_INFO,buf,nbytes,"[MOC] LINK WRITE RSP");
              hmkit_core_sensing_write_response(gContxtId, remote_mac, hmkit_core_characteristic_link_write);
              break;
            }
            case hmkit_core_characteristic_sensing_write:
            {
              hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_INFO,buf,nbytes,"[MOC] SENSING WRITE RSP");
              hmkit_core_sensing_write_response(gContxtId, remote_mac, hmkit_core_characteristic_sensing_write);
              break;
            }
            case hmkit_core_characteristic_sensing_read:
            {
              hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_INFO,buf,nbytes,"[MOC] SENSING READ RSP");
              hmkit_core_sensing_read_response(gContxtId, data_sensing_read, data_sensing_read_size, 0, remote_mac, hmkit_core_characteristic_sensing_read);
              break;
            }
            case hmkit_core_characteristic_link_read:
            {
              hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_INFO,buf,nbytes,"[MOC] LINK READ RSP");
              hmkit_core_sensing_read_response(gContxtId, data_link_read, data_link_read_size, 0, remote_mac, hmkit_core_characteristic_link_read);
              break;
            }
            default:
              break;
          }
          break;
        }//REQUEST next byte shows character
        case 0x04:
        {
          switch(buf[1]){
            default:
              break;
          }
          break;
        }
        default:
          break;
      }
    }
  }
}

void hmkit_core_connectivity_hal_delay_ms(uint32_t number_of_ms){

}

uint32_t hmkit_core_connectivity_hal_scan_start(){
  return 0;
}

uint32_t hmkit_core_connectivity_hal_scan_stop(){
  return 0;
}

uint32_t hmkit_core_connectivity_hal_advertisement_start(uint8_t *issuerId, uint8_t *appId){
  return 0;
}

uint32_t hmkit_core_connectivity_hal_advertisement_stop(){
  return 0;
}

uint32_t hmkit_core_connectivity_hal_write_data(uint64_t contxtId, uint8_t *mac, uint16_t length, uint8_t *data, hmkit_core_characteristic characteristic){

  hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_INFO,data,length,"[MOC Hal] WRITE DATA CHANNEL %02X, CntxtID 0x%x", characteristic, contxtId);

  switch(characteristic){
    case hmkit_core_characteristic_link_read:
    {
      hmkit_core_connectivity_hal_pipe_send(data, length, h_fifo_link_read);
      break;
    }
    case hmkit_core_characteristic_link_write:
    {
      hmkit_core_connectivity_hal_pipe_send(data, length, h_fifo_link_write);
      break;
    }
    case hmkit_core_characteristic_info:
    {
      hmkit_core_connectivity_hal_pipe_send(data, length, h_fifo_info);
      break;
    }
    case hmkit_core_characteristic_sensing_read:
    {
      hmkit_core_connectivity_hal_pipe_send(data, length, h_fifo_sensing_read);
      break;
    }
    case hmkit_core_characteristic_sensing_write:
    {
      hmkit_core_connectivity_hal_pipe_send(data, length, h_fifo_sensing_write);
      break;
    }
    default:
      break;
  }

  return 0;
}

uint32_t hmkit_core_connectivity_hal_read_data(uint64_t contxtId, uint8_t *mac, uint16_t offset, hmkit_core_characteristic characteristic){

  uint8_t dataout[4];
  dataout[0] = 0x04;
  dataout[1] = characteristic;

  hmkit_core_log(NULL,NULL,HMKIT_CORE_LOG_INFO,"[MOC] Hal Read Data, Characteristics %02X, ContxtId 0x%x", characteristic, contxtId);

  hmkit_core_connectivity_hal_explode(offset, dataout + 2);

  hmkit_core_connectivity_hal_pipe_send(dataout, 4, h_fifo_sensing_ble);

  return 0;
}

uint32_t hmkit_core_connectivity_hal_read_info(uint64_t contxtId, uint8_t *mac, uint16_t offset, hmkit_core_characteristic characteristic){

  uint8_t name[] = "tere vana kere";
  hmkit_core_log(NULL,NULL,HMKIT_CORE_LOG_INFO,"[MOC] Hal Read Info, Characteristics %02X, ContxtId 0x%x", characteristic, contxtId);
  hmkit_core_sensing_read_info_response(contxtId, name, 10, 0, mac, hmkit_core_characteristic_info);

  return 0;
}

uint32_t hmkit_core_connectivity_hal_service_discovery(uint8_t *mac){
  hmkit_core_sensing_discovery_event(mac);
  return 0;
}

uint32_t hmkit_core_connectivity_hal_init(){

  mkfifo(fifo_advertisement, 0777);
  mkfifo(fifo_link_read, 0777);
  mkfifo(fifo_link_write, 0777);
  mkfifo(fifo_info, 0777);
  mkfifo(fifo_sensing_read, 0777);
  mkfifo(fifo_sensing_write, 0777);
  mkfifo(fifo_link_ble, 0777);
  mkfifo(fifo_sensing_ble, 0777);
  mkfifo(fifo_telematics, 0777);

  hmkit_core_log(NULL,NULL,HMKIT_CORE_LOG_INFO,"[MOC] INIT pipes");

  h_fifo_advertisement = open(fifo_advertisement, O_RDONLY);
  h_fifo_link_read = open(fifo_link_read, O_RDONLY);
  h_fifo_link_write = open(fifo_link_write, O_WRONLY);
  //h_fifo_info = open(fifo_info, O_WRONLY);
  h_fifo_sensing_read = open(fifo_sensing_read, O_RDONLY);
  h_fifo_sensing_write = open(fifo_sensing_write, O_WRONLY);
  h_fifo_link_ble = open(fifo_link_ble, O_RDONLY);
  h_fifo_sensing_ble = open(fifo_sensing_ble, O_WRONLY);
  h_fifo_telematics = open(fifo_telematics, O_WRONLY);

  hmkit_core_log(NULL,NULL,HMKIT_CORE_LOG_INFO,"[MOC] INIT pipes done");

  g_thread_new ("PipeThread", thread_advertisement, NULL);
  g_thread_new ("PipeThread", thread_link_read, NULL);
  g_thread_new ("PipeThread", thread_sensing_read, NULL);
  g_thread_new ("PipeThread", thread_link_ble, NULL);

  return 0;
}

uint32_t hmkit_core_connectivity_hal_connect(const uint8_t *mac, uint8_t macType){
  uint8_t dataout[1];
  dataout[0] = 0x00;
  hmkit_core_connectivity_hal_pipe_send(dataout, 1, h_fifo_sensing_ble);
  return 0;
}

uint32_t hmkit_core_connectivity_hal_disconnect(uint64_t contxtId, uint8_t *mac){
  return 0;
}

uint32_t hmkit_core_connectivity_hal_get_current_date_time(uint8_t *day, uint8_t *month, uint8_t *year, uint8_t *minute, uint8_t *hour){
  return 0;
}

uint32_t hmkit_core_connectivity_hal_telematics_send_data(uint64_t appContxtId_Tele, uint8_t *issuer, uint8_t *serial, uint16_t length, uint8_t *data){
  hmkit_core_connectivity_hal_pipe_send(data, length, h_fifo_telematics);
  return 0;
}

uint32_t hmkit_core_connectivity_hal_clock(){

return 0;
}

