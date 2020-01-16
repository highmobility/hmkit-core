
#include "hmkit_core_debug_hal.h"
#include <stdarg.h>
#include <stdio.h>


static FILE *log_fp = NULL;
 
void hmkit_core_debug_hal_log(const char *str, ...){
  va_list args;

  if (!log_fp)
    log_fp = stdout;

  printf("HMLINK :: ");

  va_start(args, str);
  if(vfprintf(log_fp, str, args)  == -1)
  {
    printf("ERROR: from vfprintf \n");
    va_end(args);
    return;
  }
  printf("\n");
  fflush(log_fp);
  va_end(args);

}

void hmkit_core_debug_hal_log_hex(const uint8_t *data, const uint16_t length){
  uint16_t i;
  for(i = 0 ; i < length ; i++){
    printf("0x%02X ", data[i]);
  }
  printf("\n");
}
