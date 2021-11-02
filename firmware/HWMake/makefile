# makefile for GNU make


include ./pathdefs_win.inc
include ./makedefs4.inc


########################
###   NAME AND PATH  ###
########################

NAME = ERP

SRC  = ../src
DEF  = .
EXE  = ../hwmake
MAK  = ../hwmake


########################
###  CONFIGURATION   ###
########################

OBJECTS = ERP_Blob ERP_Audit ERP_ASNUtils ERP_CryptoUtils ERP_ExternalAPI ERP_GlobalGlue ERP_InternalGlue


########################
###   DEPENDENCIES   ###
########################

all: $(TARGET)
                                                          
$(TARGET): $(call OBJ_NAME,$(OBJECTS)) $(MAK)/makefile

    
include $(RULES)



