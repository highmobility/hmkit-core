
#include "hmkit_core_connectivity_hal.h"
#include "hmkit_core.h"
#include "hmkit_core_conf_access.h"
#include <gio/gio.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "hmkit_core_log.h"
#include <unistd.h>

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

uint8_t remote_mac[6] = {0x01,0x02,0x03,0x04,0x05,0x06};

uint64_t gContxtId = 100;

//static uint8_t out_data[500];
//static uint16_t out_data_size = 0;

void hmkit_core_connectivity_hal_explode(uint16_t source, uint8_t *dest) {
  dest[0] = source >> 8;
  dest[1] = source & 0xFF;
}

uint16_t hmkit_core_connectivity_hal_implode(uint8_t *msb) {
  // msb[1] = lsb
  return (((uint16_t) msb[0]) << 8) | msb[1];
}

void hmkit_core_connectivity_hal_pipe_send(uint8_t *data, uint16_t size, int pipe){
  write(pipe, data, size);
}

gpointer thread_link_write(gpointer data){

  uint8_t buf[MAX_BUF];

  int nbytes;

  while(true){
    //Read incoming ack
    nbytes  = read(h_fifo_link_write, buf, MAX_BUF);
    if(nbytes > 0){
      hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_INFO,buf,nbytes,"[MOC] LINK WRITE");

      uint8_t dataout[2];
      dataout[0] = 0x03;
      dataout[1] = hmkit_core_characteristic_link_write;
      hmkit_core_connectivity_hal_pipe_send(dataout, 2, h_fifo_link_ble);

      //usleep(100000);

      hmkit_core_link_incoming_data(gContxtId, buf, nbytes, remote_mac, hmkit_core_characteristic_link_write);
    }
  }
}

gpointer thread_telematics_read(gpointer data){

  uint8_t buf[MAX_BUF];
  int nbytes;
  uint16_t ret = 0;

  while(true){
    //Read incoming ack
    nbytes  = read(h_fifo_telematics, buf, MAX_BUF);
    if(nbytes > 0){
      hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_INFO,buf,nbytes,"[MOC] LINK Telematics thread read");

	  ret = hmkit_core_telematics_receive_data(0, nbytes, buf);
	  printf("%s(), ret = %d\n",__FUNCTION__, ret);
    }
  }
}


gpointer thread_sensing_write(gpointer data){

  uint8_t buf[MAX_BUF];

  int nbytes;

  while(true){
    //Read incoming command
    nbytes  = read(h_fifo_sensing_write, buf, MAX_BUF);
    if(nbytes > 0){
      hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_INFO,buf,nbytes,"[MOC] SENSING WRITE");

      uint8_t dataout[2];
      dataout[0] = 0x03;
      dataout[1] = hmkit_core_characteristic_sensing_write;
      hmkit_core_connectivity_hal_pipe_send(dataout, 2, h_fifo_link_ble);

      usleep(10000);

      hmkit_core_link_incoming_data(gContxtId, buf, nbytes, remote_mac, hmkit_core_characteristic_sensing_write);
    }
  }
}

gpointer thread_sensing_ble(gpointer data){

  uint8_t buf[MAX_BUF];

  int nbytes;

  while(true){
    //Read incoming command
    nbytes  = read(h_fifo_sensing_ble, buf, MAX_BUF);
    if(nbytes > 0){
      hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_INFO,buf,nbytes,"[MOC] SENSING BLE");
      switch(buf[0]){
        case 0x00:
        {
          hmkit_core_link_connect(gContxtId, remote_mac);
          hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_INFO,buf,nbytes,"[MOC] CONNECT");

          uint8_t dataout[1];
          dataout[0] = 0x00;
          hmkit_core_connectivity_hal_pipe_send(dataout, 1, h_fifo_link_ble);
          break;
        }
        case 0x01:
        {
          hmkit_core_link_disconnect(remote_mac);
          hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_INFO,buf,nbytes,"[MOC] DISCONNECT");

          uint8_t dataout[1];
          dataout[0] = 0x01;
          hmkit_core_connectivity_hal_pipe_send(dataout, 1, h_fifo_link_ble);
          break;
        }
              //RSP next byte shows character
        case 0x03:
        {
          switch(buf[1]){
            default:
              break;
          }
          break;
        }//REQUEST next byte shows character
        case 0x04:
        {
          switch(buf[1]){
            case hmkit_core_characteristic_sensing_read:
            {
              hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_INFO,buf,nbytes,"[MOC] SENSING READ REQUEST");
              uint8_t dataout[4];
              dataout[0] = 0x03;
              dataout[1] = hmkit_core_characteristic_sensing_read;
              hmkit_core_connectivity_hal_pipe_send(dataout, 4, h_fifo_link_ble);
              break;
            }
            case hmkit_core_characteristic_link_read:
            {
              hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_INFO,buf,nbytes,"[MOC] LINK READ REQUEST");
              uint8_t dataout[4];
              dataout[0] = 0x03;
              dataout[1] = hmkit_core_characteristic_link_read;
              hmkit_core_connectivity_hal_pipe_send(dataout, 4, h_fifo_link_ble);
              break;
            }
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
  uint8_t data[20];
  data[0] = 0x11;
  data[1] = 0x07;

  memcpy(data + 2, issuerId, 4);
  memcpy(data + 6, appId, 12);

  hmkit_core_connectivity_hal_pipe_send(data,18,h_fifo_advertisement);
  return 0;
}

uint32_t hmkit_core_connectivity_hal_advertisement_stop(){
  return 0;
}

uint32_t hmkit_core_connectivity_hal_write_data(uint64_t contxtId, uint8_t *mac, uint16_t length, uint8_t *data, hmkit_core_characteristic characteristic){

  switch(characteristic){
    case hmkit_core_characteristic_link_read:
    {
      hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_INFO,data,length,"[MOC] WRITE LINK READ %02X, ContxtID 0x%x",characteristic, contxtId);
      hmkit_core_connectivity_hal_pipe_send(data, length, h_fifo_link_read);
      break;
    }
    case hmkit_core_characteristic_link_write:
    {
      hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_INFO,data,length,"[MOC] WRITE LINK WRITE %02X, ContxtID 0x%x",characteristic, contxtId);
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
      hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_INFO,data,length,"[MOC] WRITE SENSING READ %02X, ContxtID 0x%x",characteristic, contxtId);
      hmkit_core_connectivity_hal_pipe_send(data, length, h_fifo_sensing_read);
      break;
    }
    case hmkit_core_characteristic_sensing_write:
    {
      hmkit_core_log_data(NULL,NULL,HMKIT_CORE_LOG_INFO,data,length,"[MOC] WRITE SENSING WRITE %02X, ContxtId 0x%x",characteristic, contxtId);
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

  hmkit_core_connectivity_hal_pipe_send(dataout, 4, h_fifo_link_ble);

  return 0;
}

uint32_t hmkit_core_connectivity_hal_read_info(uint64_t contxtId, uint8_t *mac, uint16_t offset, hmkit_core_characteristic characteristic){

  uint8_t off[2];

  hmkit_core_log(NULL,NULL,HMKIT_CORE_LOG_INFO,"[MOC] Hal Read Info, Characteristics %02X, ContxtId 0x%x", characteristic, contxtId);

  hmkit_core_connectivity_hal_explode(offset, off);

  hmkit_core_connectivity_hal_pipe_send(off, 2, h_fifo_info);

  return 0;
}

uint32_t hmkit_core_connectivity_hal_service_discovery(uint8_t *mac){
  return 0;
}

uint32_t hmkit_core_connectivity_hal_init(){

  hmkit_core_log(NULL,NULL,HMKIT_CORE_LOG_INFO,"[MOC] INIT pipes");

  h_fifo_advertisement = open(fifo_advertisement, O_WRONLY);
  h_fifo_link_read = open(fifo_link_read, O_WRONLY);
  h_fifo_link_write = open(fifo_link_write, O_RDONLY);
  //h_fifo_info = open(fifo_info, O_WRONLY);
  h_fifo_sensing_read = open(fifo_sensing_read, O_WRONLY);
  h_fifo_sensing_write = open(fifo_sensing_write, O_RDONLY);
  h_fifo_link_ble = open(fifo_link_ble, O_WRONLY);
  h_fifo_sensing_ble = open(fifo_sensing_ble, O_RDONLY);
  h_fifo_telematics = open(fifo_telematics, O_RDONLY);

  hmkit_core_log(NULL,NULL,HMKIT_CORE_LOG_INFO,"[MOC] INIT pipes done");

  g_thread_new ("PipeThread_lnk_wrt", thread_link_write, NULL);
  g_thread_new ("PipeThread_sens_wrt", thread_sensing_write, NULL);
  g_thread_new ("PipeThread_sens_ble", thread_sensing_ble, NULL);
  g_thread_new ("PipeThread_telem_rd", thread_telematics_read, NULL);

  return 0;
}

uint32_t hmkit_core_connectivity_hal_connect(const uint8_t *mac, uint8_t macType){
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

uint32_t hmkit_core_connectivity_hal_clock()
{

  return 0;
}

