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
#
#  Modifications copyright (C) 2019 Hathor Labs
#*******************************************************************************

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif
include $(BOLOS_SDK)/Makefile.defines

#########
#  App  #
#########

APPNAME    = Hathor
ICONNAME   = nanos_app_hathor.gif
# APPVERSION has the format "X.Y.Z", where X, Y, and Z must be a single digit between 0 and 9
APPVERSION = 0.0.1
#P2PKH_VERSION_BYTE = 0x49	# testnet
P2PKH_VERSION_BYTE = 0x28
HATHOR_BIP44_CODE = 280

# The --path argument here restricts which BIP32 paths the app is allowed to derive.
APP_LOAD_PARAMS = --appFlags 0x40 --path "44'/$(HATHOR_BIP44_CODE)'" --curve secp256k1 $(COMMON_LOAD_PARAMS)
APP_SOURCE_PATH = src
SDK_SOURCE_PATH = lib_stusb lib_stusb_impl

all: default

load: all
	python -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

delete:
	python -m ledgerblue.deleteApp $(COMMON_DELETE_PARAMS)

############
# Platform #
############

DEFINES += OS_IO_SEPROXYHAL IO_SEPROXYHAL_BUFFER_SIZE_B=128
DEFINES += HAVE_BAGL HAVE_SPRINTF
DEFINES += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=7 IO_HID_EP_LENGTH=64 HAVE_USB_APDU
DEFINES += APPVERSION=\"$(APPVERSION)\"
DEFINES += P2PKH_VERSION_BYTE=$(P2PKH_VERSION_BYTE)
DEFINES += HATHOR_BIP44_CODE=$(HATHOR_BIP44_CODE)

# this enables the PRINTF macro, used for debugging
# https://ledger.readthedocs.io/en/latest/userspace/debugging.html#printf-macro
#DEFINES += HAVE_SPRINTF HAVE_PRINTF PRINTF=screen_printf

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
	@echo VARIANTS COIN hathor
