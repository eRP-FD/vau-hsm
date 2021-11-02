#
# include file for makefiles
#
# Copy this file to your local PC. Adjust entries to your locality.
# Set environment variable PATHDEFS to the path where you copy this file to.
# ATTENTION! Use forward slashes (/) only
#

UTIMACO_ROOT = /opt/cryptoserversdk

# location of SDK
SDK_PATH = $(UTIMACO_ROOT)/SDK

# location of global CS directory
CS2_PATH = $(UTIMACO_ROOT)/SDK/cs2

# location of global include directory
GINC = $(UTIMACO_ROOT)/SDK/cs2/include

# location of global lib directory
GLIB = $(UTIMACO_ROOT)/SDK/lib

# location of global bin directory
GBIN = $(UTIMACO_ROOT)/Software/Linux/x86-64/Administration

# MS Visual Studio version: VS 9 (use ARCH = i686 for VS 6)
ARCH = x86


TMS_PATH = /opt/c6000_7.4.24
TMSVER = 7.4.24

MMCSIGNKEY = IBM_eRP_RU_AltMdlSig.key#password
