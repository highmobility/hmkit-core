
#include "hmkit_core_debug_hal.h"
#include "hmkit_core.h"
#include <stdarg.h>
#include <stdio.h>

// if console print does not work, can redirect the logs to a file /tmp/unittest_log.txt
// Enable the flag FILE_LOG for file logging
//#define FILE_LOG

#ifdef FILE_LOG
const char *log_file = "/tmp/unittest_log.txt";
static bool file_create = false;
static char fmode[2] = "w";
#endif

void hmkit_core_debug_hal_log(const char *str, ...){

#ifndef FILE_LOG
  BTUNUSED(str);

  /*va_list args;
  va_start(args, str);
  char output[1000];
  vsprintf(output, str, args);
  printf(output);
  printf("\n");
  va_end(args);*/

#else
  va_list args;
  FILE *fptr = NULL;
  va_start(args, str);
  char output[5000];
  vsprintf(output, str, args);
  va_end(args);

  fptr = fopen(log_file,fmode);
  if(fptr == NULL)
  {
    printf("Fopen Error!");
    return;
  }
  fprintf(fptr,"%s\n",output);

  if(file_create == false)
  {
    file_create = true;
    // convert the file open mode to append
    fmode[0] = 'a';
  }
  fclose(fptr);
#endif

}

void hmkit_core_debug_hal_log_hex(const uint8_t *data, const uint16_t length){

#ifndef FILE_LOG
  BTUNUSED(data);
  BTUNUSED(length);
  /*uint16_t i;
  for(i = 0 ; i < length ; i++){
    printf("0x%02X ", data[i]);
  }
  printf("\n");*/
#else
  FILE *fptr = NULL;

  fptr = fopen(log_file,fmode);
  fprintf(fptr,"\n");
  uint16_t i;
  for(i = 0 ; i < length ; i++){
    fprintf(fptr,"0x%02X ", data[i]);
  }
  fprintf(fptr,"\n");
  fflush(fptr);
  fclose(fptr);

  if(file_create == false)
  {
    file_create = true;
    // convert the file open mode to append
    fmode[0] = 'a';
  }
#endif
}
