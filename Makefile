#*******************************************************************************
#   Ledger App
#   (c) 2017 Ledger
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#*******************************************************************************

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif
include $(BOLOS_SDK)/Makefile.defines

#########
#  App  #
#########

APPNAME    = Sia
APPVERSION = 0.4.4
ifeq ($(TARGET_NAME),TARGET_NANOS)
ICONNAME=nanos_app_sia.gif
else ifeq ($(TARGET_NAME),TARGET_NANOS2)
ICONNAME=nanos2_app_sia.gif
else ifeq ($(TARGET_NAME),TARGET_NANOX)
ICONNAME=nanox_app_sia.gif
else ifeq ($(TARGET_NAME),TARGET_STAX)
ICONNAME=stax_app_sia.gif
endif

# The --path argument here restricts which BIP32 paths the app is allowed to derive.
APP_LOAD_PARAMS = --path "44'/93'" --curve ed25519 $(COMMON_LOAD_PARAMS)
ifeq ($(TARGET_NAME),$(filter $(TARGET_NAME),TARGET_NANOS TARGET_NANOS2))
APP_LOAD_PARAMS += --appFlags 0x40
else ifeq ($(TARGET_NAME),TARGET_NANOX)
APP_LOAD_PARAMS += --appFlags 0x40
else ifeq ($(TARGET_NAME), TARGET_STAX)
APP_LOAD_PARAMS += --appFlags 0x240
endif

APP_SOURCE_PATH += src
SDK_SOURCE_PATH += lib_stusb lib_stusb_impl
ifneq ($(TARGET_NAME),TARGET_STAX)
SDK_SOURCE_PATH += lib_ux
endif

all: default

load: all
	python -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

delete:
	python -m ledgerblue.deleteApp $(COMMON_DELETE_PARAMS)

############
# Platform #
############

DEFINES += OS_IO_SEPROXYHAL
DEFINES += HAVE_SPRINTF
DEFINES += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=7 IO_HID_EP_LENGTH=64 HAVE_USB_APDU
DEFINES += HAVE_LEGACY_PID
DEFINES += APPNAME=\"$(APPNAME)\"
DEFINES += APPVERSION=\"$(APPVERSION)\"
DEFINES += UNUSED\(x\)=\(void\)x

ifeq ($(TARGET_NAME),$(filter $(TARGET_NAME),TARGET_NANOX TARGET_NANOS TARGET_NANOS2))
DEFINES += HAVE_BAGL
DEFINES += HAVE_UX_FLOW
endif

### Nano X
ifeq ($(TARGET_NAME),$(filter $(TARGET_NAME),TARGET_NANOS TARGET_NANOS2))
DEFINES += IO_SEPROXYHAL_BUFFER_SIZE_B=128
else ifeq ($(TARGET_NAME),$(filter $(TARGET_NAME),TARGET_NANOX TARGET_STAX))
DEFINES += IO_SEPROXYHAL_BUFFER_SIZE_B=300
# bluetooth
DEFINES += HAVE_BLE BLE_COMMAND_TIMEOUT_MS=2000
DEFINES += HAVE_BLE_APDU
# include fonts or ui will be empty
SDK_SOURCE_PATH += lib_blewbxx lib_blewbxx_impl
endif

ifeq ($(TARGET_NAME),TARGET_NANOX)
DEFINES += HAVE_BAGL_ELLIPSIS
DEFINES += BAGL_WIDTH=128 BAGL_HEIGHT=64
DEFINES += HAVE_BAGL_FONT_OPEN_SANS_REGULAR_11PX
DEFINES += HAVE_BAGL_FONT_OPEN_SANS_EXTRABOLD_11PX
DEFINES += HAVE_BAGL_FONT_OPEN_SANS_LIGHT_16PX
endif
 

##############
#  Compiler  #
##############

CC := $(CLANGPATH)clang
CFLAGS += -O3 -Os

AS := $(GCCPATH)arm-none-eabi-gcc
LD := $(GCCPATH)arm-none-eabi-gcc
LDFLAGS += -O3 -Os
LDLIBS += -lm -lgcc -lc 

##################
#  Dependencies  #
##################

# import rules to compile glyphs
include $(BOLOS_SDK)/Makefile.glyphs
# import generic rules from the sdk
include $(BOLOS_SDK)/Makefile.rules

dep/%.d: %.c Makefile

listvariants:
	@echo VARIANTS COIN sia
