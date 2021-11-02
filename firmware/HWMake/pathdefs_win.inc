#
# include file for makefiles
#
# Copy this file to your local PC. Adjust entries to your locality.
# Set environment variable PATHDEFS to the path where you copy this file to.
# ATTENTION! Use forward slashes (/) only
#

UTIMACO_ROOT = D:/work/IBM/Doc/Utimaco/CryptoServer-SDK-V4.40.0.2

# location of SDK
SDK_PATH = $(UTIMACO_ROOT)/SDK

# location of global CS directory
CS2_PATH = $(UTIMACO_ROOT)/SDK/cs2

# location of global include directory
GINC = $(UTIMACO_ROOT)/SDK/cs2/include

# location of global lib directory
GLIB = $(UTIMACO_ROOT)/SDK/lib

# location of global bin directory
GBIN = $(UTIMACO_ROOT)/software/Windows/x86-64/Administration

# MS Visual Studio version: VS 9 (use ARCH = i686 for VS 6)
ARCH = x86

# location of TI tools; compiler will be referenced as $(TMS_PATH)/bin/cl6x
# please install TI tools (see SDK Guide) + 
TMS_PATH = d:/work/ibm/dev/ticompiler
TMSVER = 7.4.24

#SIGNKEY.wirk  :=  $(CS2_PATH)/keys/ERP_MTG_DEV.key
#SIGNKEY.ref   :=  $(CS2_PATH)/keys/ERP_MTG_DEV.key
#MMCSIGNKEY:= ${SIGNKEY.${BUILD}}
MMCSIGNKEY = IBM_eRP_RU_AltMdlSig.key#password
