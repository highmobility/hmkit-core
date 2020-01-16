#Include HM bt core
HM_BT_CORE  := $(shell cd ../; pwd)

VPATH += ./
#VPATH += $(HM_BT_CORE)

#BTCORE
SRC += tests.c
SRC += test_core.c
SRC += test_cert.c
SRC += hmkit_core_crypto_hal.c
SRC += hmkit_core_debug_hal.c
SRC += hmkit_core_connectivity_hal.c
SRC += hmkit_core_persistence_hal.c
SRC += hmkit_core_api_callback.c

SRC += ../hmkit_core.c
SRC += ../hmkit_core_cert.c
SRC += ../hmkit_core_conf_access.c
SRC += ../hmkit_core_api.c
SRC += ../hmkit_core_log.c

# .o for .c
SRC_OBJ = $(SRC:.c=.o)

CC=gcc
CFLAGS  += -g -std=gnu99 -Wall -Wmissing-prototypes -Wstrict-prototypes -Wshadow -Wunused-parameter
CFLAGS += -I$(HM_BT_CORE)
APP_SOURCES := ./
CFLAGS += -I$(APP_SOURCES)

default: hmservice
all: hmservice

hmservice: ${SRC_OBJ}
	${CC} $^ ${CFLAGS} -o hmservice

clean:
	rm -f  *.o
	rm -f  ../*.o
	rm -f  hmservice
	rm -rf ${BTCORE_OBJ}/*.o
