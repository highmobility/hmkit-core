#Include openssl crypto
HM_OPENSSL_C  := $(shell cd ./hmkit-crypto-c/; pwd)
dir += $(HM_OPENSSL_C)
#HM_CRYPTO_OPENSSL
SRC += Crypto.c
#Include HM bt core
HM_BT_CORE  := $(shell cd ../; pwd)
dir += $(HM_BT_CORE)
#HM_BT_CORE
SRC += hmkit_core.c
SRC += hmkit_core_cert.c
SRC += hmkit_core_conf_access.c
SRC += hmkit_core_api.c
SRC += hmkit_core_log.c

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
    OPENSSL := /usr/lib/ssl/
    LDFLAGS += -L/usr/lib/ssl/
endif
ifeq ($(UNAME_S),Darwin)
    OPENSSL := /usr/local/opt/openssl/include/
    LDFLAGS += -L/usr/local/opt/openssl/lib/
endif

#add source paths to vpath
VPATH = $(dir)

APP_SOURCES := ./

SRC += main.c
SRC += hmlink/hmkit_core_api_callback.c
SRC += hmlink/hmkit_core_crypto_hal.c
SRC += hmlink/hmkit_core_debug_hal.c
SRC += hmlink/hmkit_core_connectivity_hal.c
SRC += hmlink/hmkit_core_persistence_hal.c

CFLAGS += -O0 -g -std=gnu99 -Wall -Werror -Wshadow

CFLAGS += -I$(APP_SOURCES)\
	-I$(HM_BT_CORE)\
	-I$(HM_OPENSSL_C)\
	-I$(HM_AUTO_API_C)\

CC = gcc
TARGET = systemtest

#Get libs include paths
LIBS = glib-2.0 gio-2.0
CFLAGS += -c -I. `pkg-config --cflags $(LIBS)`

#add source paths to vpath
VPATH = $(dir)

APP_SOURCES := ./

SRC += main.c

CFLAGS += -O0 -g -std=gnu99 -Wall -Werror -Wshadow

CFLAGS += -I$(APP_SOURCES)

CC = gcc
TARGET = systemtest

all: $(TARGET)
	$(MAKE) -C hmlink
	$(MAKE) -C hmsensing

#  Compiling sll src files
$(SRC):
	$(CC) $(CFLAGS) -g $@

# Linking all object files
$(TARGET): $(SRC:.c=.o)
	$(CC) $(LDFLAGS) -g $^ -o $(TARGET) -lpthread -lssl -lcrypto -lglib-2.0 -lgio-2.0 -lm

$(TARGET): 

clean:
	rm -f $(TARGET) *.o *~
	$(MAKE) clean -C hmlink
	$(MAKE) clean -C hmsensing