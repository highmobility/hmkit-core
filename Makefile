HM_BT_CORE  := $(shell cd ../high-mobility-bt-core/; pwd)
dir += $(HM_BT_CORE)

#HM_BT_CORE
SRC += hmkit_core_core.c
SRC += hmkit_core_cert.c
SRC += hmkit_core_conf_access.c
SRC += hmkit_core_api.c
SRC += hmkit_core_log.c
