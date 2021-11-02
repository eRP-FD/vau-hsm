# global include file for CryptoServer makefiles

# force unix shell
SHELL = sh

# evaluate operating system
ifndef OSYS
  ifdef COMSPEC
    OSYS = win
  else
    OSYS := $(shell uname | sed s/-/_/g )
  endif
endif

# evaluate architecture
ifndef ARCH
  ifeq ($(OSYS),win)
    ifeq ($(PROCESSOR_ARCHITEW6432),AMD64)
      ARCH := x64
    else
      ARCH := x86
    endif
  else
    ARCH := $(shell uname -m)
  endif
endif

ifeq ($(ARCH),x86_64)
  override ARCH=i686
endif

# if CS2_PATH not set, construct it from LX_PATH
ifndef CS2_PATH
  ifdef LX_PATH
    CS2_PATH = $(LX_PATH)/cs2
  endif
endif

# include directorys
GBL_INC ?= $(CS2_PATH)/include

# location of csadm tool
ifeq ($(OSYS),win)
  CSADMBIN += csadm.exe
else
  CSADMBIN += csadm
endif

ifdef GBIN
  CSADM ?= $(GBIN)/$(CSADMBIN)
else
  CSADM ?= $(CSADMBIN)
endif


#---------------------------------------------------------------------------------------------------
# CS3 / Se-Series (TMS320C6416)
#---------------------------------------------------------------------------------------------------

#
# TI Release
#
ifeq ($(CFG),rel86)
  ifndef MODEL
    MODEL = CS3
  endif

  CFG_DEBUG =
  CFG_SDK =

  ifndef OBJ
    OBJ = ../obj/$(CFG)
  endif

  ifdef TMS_PATH_86
    TMS_PATH= $(TMS_PATH_86)
  endif
  ifndef TMS_PATH
    ifndef TMSVER
      TMSVER = 6.0.8
    endif
    TMS_PATH = $(CS2_PATH)/tms2/$(TMSVER)
  endif

  ifndef RTSLIB
    RTSLIB = rts6400e.lib
  endif

  CC     = $(TMS_PATH)/bin/cl6x
  CFLAGS = -c -q -me -mb -k -mv6400 -DOS_SMOS -DMODEL=3 -fr$(OBJ) -ea=.asm_ \
           --symdebug:none -fs$(OBJ) -ft$(OBJ) -pden -pds169 \
           --mem_model:data=far -I$(TMS_PATH)/include

  AS     = $(TMS_PATH)/bin/asm6x
  AFLAGS = -e -q -mv6400 --symdebug:none

  LD     = $(TMS_PATH)/bin/lnk6x
  LFLAGS = -ar -heap 0 -stack 0 -w \
           -i $(TMS_PATH)/lib -i $(CS2_PATH)/lib

  TARGET = $(EXE)86/$(NAME).mtc
  RULES = $(GBL_INC)/rules_tms86.inc
  GBL_EXE = $(CS2_PATH)/firmware/release86
endif

#
# TI Debug
#
ifeq ($(CFG),dbg86)
  ifndef MODEL
    MODEL = CS3
  endif

  CFG_DEBUG = 1
  CFG_SDK =

  ifndef OBJ
    OBJ = ../obj/$(CFG)
  endif

  ifdef TMS_PATH_86
    TMS_PATH= $(TMS_PATH_86)
  endif
  ifndef TMS_PATH
    ifndef TMSVER
      TMSVER = 6.0.8
    endif
    TMS_PATH = $(CS2_PATH)/tms2/$(TMSVER)
  endif

  ifndef RTSLIB
    RTSLIB = rts6400e.lib
  endif

  CC     = $(TMS_PATH)/bin/cl6x
  CFLAGS = -c -q -me -mb -k -mv6400 -DOS_SMOS -DDEBUG -DMODEL=3 -fr$(OBJ) -ea=.asm_ \
           --symdebug:none -fs$(OBJ) -ft$(OBJ) -pden -pds169 \
           --mem_model:data=far -I$(TMS_PATH)/include

  AS     = $(TMS_PATH)/bin/asm6x
  AFLAGS = -e -q -mv6400 --symdebug:none

  LD     = $(TMS_PATH)/bin/lnk6x
  LFLAGS = -ar -heap 0 -stack 0 -w \
           -i $(TMS_PATH)/lib -i $(CS2_PATH)/lib

  TARGET = $(EXE)86/$(NAME)_dbg.mtc
  RULES = $(GBL_INC)/rules_tms86.inc
  GBL_EXE = $(CS2_PATH)/firmware/debug86
endif


#---------------------------------------------------------------------------------------------------
# CS4 / CSe-Series (TMS320C6457)
#---------------------------------------------------------------------------------------------------

#
# TI Release
#
ifeq ($(CFG),rel57)
  MODEL = CS4
  CFG_DEBUG =
  CFG_SDK =

  ifndef OBJ
    OBJ = ../obj/$(CFG)
  endif

  ifdef TMS_PATH_57
    TMS_PATH= $(TMS_PATH_57)
  endif
  ifndef TMS_PATH
    ifndef TMSVER
      TMSVER = 7.4.1
    endif
    TMS_PATH = $(CS2_PATH)/tms2/$(TMSVER)
  endif

  ifndef RTSLIB
    RTSLIB = rts64pluse.lib
  endif

  CC     = $(TMS_PATH)/bin/cl6x
  CFLAGS = -c -q -me -mb -k -mv64+ -D_TMS320C6457 -DOS_SMOS -fr$(OBJ) -ea=.asm_ \
           --abi=coffabi --symdebug:none -fs$(OBJ) -ft$(OBJ) -pden -pds169 \
           --mem_model:data=far -I$(TMS_PATH)/include

  AS     = $(TMS_PATH)/bin/asm6x
  AFLAGS = -e -q -mv64+ --symdebug:none

  LD     = $(TMS_PATH)/bin/lnk6x
  LFLAGS = -ar -heap 0 -stack 0 -w \
           -i $(TMS_PATH)/lib -i $(CS2_PATH)/lib

  TARGET = $(EXE)57/$(NAME).mtc
  RULES = $(GBL_INC)/rules_tms57.inc
  GBL_EXE = $(CS2_PATH)/firmware/release57
endif

#
# TI Debug
#
ifeq ($(CFG),dbg57)
  MODEL = CS4
  CFG_DEBUG = 1
  CFG_SDK =

  ifndef OBJ
    OBJ = ../obj/$(CFG)
  endif

  ifdef TMS_PATH_57
    TMS_PATH= $(TMS_PATH_57)
  endif
  ifndef TMS_PATH
    ifndef TMSVER
      TMSVER = 7.4.1
    endif
    TMS_PATH = $(CS2_PATH)/tms2/$(TMSVER)
  endif

  ifndef RTSLIB
    RTSLIB = rts64pluse.lib
  endif

  CC     = $(TMS_PATH)/bin/cl6x
  CFLAGS = -c -q -me -mb -k -mv64+ -D_TMS320C6457 -DOS_SMOS -DDEBUG -fr$(OBJ) -ea=.asm_ \
           --abi=coffabi --symdebug:none -fs$(OBJ) -ft$(OBJ) -pden -pds169 \
           --mem_model:data=far -I$(TMS_PATH)/include

  AS     = $(TMS_PATH)/bin/asm6x
  AFLAGS = -e -q -mv64+ --symdebug:none

  LD     = $(TMS_PATH)/bin/lnk6x
  LFLAGS = -ar -heap 0 -stack 0 -w \
           -i $(TMS_PATH)/lib -i $(CS2_PATH)/lib

  TARGET = $(EXE)57/$(NAME)_dbg.mtc
  RULES = $(GBL_INC)/rules_tms57.inc
  GBL_EXE = $(CS2_PATH)/firmware/debug57
endif

#---------------------------------------------------------------------------------------------------
# CS5 / Se2-Series (TMS320C6416)
#---------------------------------------------------------------------------------------------------

#
# TI Release
#
ifeq ($(CFG),rel50)
  MODEL = CS5
  CFG_DEBUG =
  CFG_SDK =

  ifndef OBJ
    OBJ = ../obj/$(CFG)
  endif

  ifdef TMS_PATH_50
    TMS_PATH= $(TMS_PATH_50)
  endif
  ifndef TMS_PATH
    ifndef TMSVER
      TMSVER = 7.4.8
    endif
    TMS_PATH = $(CS2_PATH)/tms2/$(TMSVER)
  endif

  ifndef RTSLIB
    RTSLIB = rts6400e.lib
  endif

  CC     = $(TMS_PATH)/bin/cl6x
  CFLAGS = -c -q -me -mb -k -mv6400 -DOS_SMOS -DMODEL=5 -fr$(OBJ) -ea=.asm_ \
           --abi=coffabi --symdebug:none -fs$(OBJ) -ft$(OBJ) -pden -pds169 \
           --mem_model:data=far -I$(TMS_PATH)/include $(COMPILE_DEFS)

  AS     = $(TMS_PATH)/bin/asm6x
  AFLAGS = -e -q -mv6400 --symdebug:none

  LD     = $(TMS_PATH)/bin/lnk6x
  LFLAGS = -ar -heap 0 -stack 0 -w \
           -i $(TMS_PATH)/lib -i $(CS2_PATH)/lib

  TARGET = $(EXE)50/$(NAME).mtc
  RULES = $(GBL_INC)/rules_tms50.inc
  GBL_EXE = $(CS2_PATH)/firmware/release50
endif

#
# TI Debug
#
ifeq ($(CFG),dbg50)
  MODEL = CS5
  CFG_DEBUG = 1
  CFG_SDK =

  ifndef OBJ
    OBJ = ../obj/$(CFG)
  endif

  ifdef TMS_PATH_50
    TMS_PATH= $(TMS_PATH_50)
  endif
  ifndef TMS_PATH
    ifndef TMSVER
      TMSVER = 7.4.8
    endif
    TMS_PATH = $(CS2_PATH)/tms2/$(TMSVER)
  endif

  ifndef RTSLIB
    RTSLIB = rts6400e.lib
  endif

  CC     = $(TMS_PATH)/bin/cl6x
  CFLAGS = -c -q -me -mb -k -mv6400 -DOS_SMOS -DMODEL=5 -DDEBUG -fr$(OBJ) -ea=.asm_ \
           --abi=coffabi --symdebug:none -fs$(OBJ) -ft$(OBJ) -pden -pds169 \
           --mem_model:data=far -I$(TMS_PATH)/include $(COMPILE_DEFS)

  AS     = $(TMS_PATH)/bin/asm6x
  AFLAGS = -e -q -mv6400 --symdebug:none

  LD     = $(TMS_PATH)/bin/lnk6x
  LFLAGS = -ar -heap 0 -stack 0 -w \
           -i $(TMS_PATH)/lib -i $(CS2_PATH)/lib

  TARGET = $(EXE)50/$(NAME)_dbg.mtc
  RULES = $(GBL_INC)/rules_tms50.inc
  GBL_EXE = $(CS2_PATH)/firmware/debug50
endif


#---------------------------------------------------------------------------------------------------
# SIM5
#---------------------------------------------------------------------------------------------------

#
# SIM5 Windows Release
#
ifeq ($(CFG)-$(OSYS),sim5-win)
  CFG_DEBUG =
  CFG_SDK = $(OSYS)

  ifndef OBJ
    OBJ = ../obj/$(CFG)-$(OSYS)-$(ARCH)
  endif

  CC      = cl.exe
  CFLAGS  = -nologo -W3 -Fo"$(OBJ)/" -c -MD -TC -O2 -FS \
            -D"WIN32" -D"OSYS_win" -D"CS2_SDK" -D"OS_SMOS" -D"MODEL=5" -D"_CRT_SECURE_NO_WARNINGS"

  LD      = link.exe
  LFLAGS  = -dll -incremental:no -machine:I386 -nologo

  TARGET = $(EXE)50/$(NAME)_sim_win.mtc
  RULES  = $(GBL_INC)/rules_sim5_win.inc
  GBL_EXE = $(CS2_PATH)/firmware/$(CFG)-$(OSYS)
endif

#
# SIM5 Windows Debug
#
ifeq ($(CFG)-$(OSYS),sim5_dbg-win)
  CFG_DEBUG = 1
  CFG_SDK = $(OSYS)

  ifndef OBJ
    OBJ = ../obj/$(CFG)-$(OSYS)-$(ARCH)
  endif

  CC     = cl.exe
  CFLAGS = -nologo -W3 -Fo"$(OBJ)/" -Fd"$(OBJ)/$(NAME)_$$$$.pdb" -c -MDd -Gm -RTC1 -ZI -TC -Od -FS \
           -D"DEBUG" -D"WIN32" -D"OSYS_win" -D"CS2_SDK" -D"OS_SMOS" -D"MODEL=5" -D"_CRT_SECURE_NO_WARNINGS"

  LD      = link.exe
  LFLAGS  = -dll -incremental:no -machine:I386 -nologo

  TARGET = $(EXE)50/$(NAME)_sim_win_dbg.mtc
  RULES  = $(GBL_INC)/rules_sim5_win.inc
  GBL_EXE = $(CS2_PATH)/firmware/$(CFG)-$(OSYS)
endif

#
# SIM5 Linux Release
#
ifeq ($(CFG)-$(OSYS),sim5-Linux)
  CFG_DEBUG =
  CFG_SDK = $(OSYS)

  ifndef OBJ
    OBJ = ../obj/$(CFG)-$(OSYS)-$(ARCH)
  endif

  CFLAGS = -Wall -O2 -fPIC -DOS_SMOS -DCS2_SDK -Wno-pointer-sign
  LFLAGS = -shared -Wl,--no-whole-archive -s

  ifeq ($(ARCH),x86_64)
    override ARCH=i686
  endif

  ifeq ($(ARCH),i686)
    CFLAGS += -m32
    LFLAGS += -m32
  endif

  TARGET = $(EXE)50/$(NAME)_sim_linux.mtc
  RULES  = $(GBL_INC)/rules_sim5_linux.inc
  GBL_EXE = $(CS2_PATH)/firmware/$(CFG)-$(OSYS)
endif

#
# SIM5 Linux Debug
#
ifeq ($(CFG)-$(OSYS),sim5_dbg-Linux)
  CFG_DEBUG = 1
  CFG_SDK = $(OSYS)

  ifndef OBJ
    OBJ = ../obj/$(CFG)-$(OSYS)-$(ARCH)
  endif

  CFLAGS = -Wall -O0 -fPIC -DDEBUG -DOS_SMOS -DCS2_SDK -Wno-pointer-sign
  LFLAGS = -shared -Wl,--no-whole-archive

  ifeq ($(ARCH),x86_64)
    override ARCH=i686
  endif

  ifeq ($(ARCH),i686)
    CFLAGS += -m32
    LFLAGS += -m32
  endif

  TARGET = $(EXE)50/$(NAME)_sim_linux_dbg.mtc
  RULES  = $(GBL_INC)/rules_sim5_linux.inc
  GBL_EXE = $(CS2_PATH)/firmware/$(CFG)-$(OSYS)
endif


#--------------------------------------------------------------------------------
# Configuration
#--------------------------------------------------------------------------------

ifndef RULES
  $(error bad configuration setting CFG=$(CFG) ARCH=$(ARCH) )
endif

CFLAGS += -I$(DEF) -I$(GBL_INC)

ifndef OBJ
  OBJ = ../obj/$(CFG)
endif

ifeq ($(findstring win,$(OSYS)),win)
  OBJ_NAME = $(foreach file,$(notdir $(basename $(1))),$(OBJ)/$(file).obj)
else
  OBJ_NAME = $(foreach file,$(notdir $(basename $(1))),$(OBJ)/$(file).o)
  CFLAGS += -eo=.o
endif

ifndef CFG_SDK
  PATH := $(TMS_PATH)/bin:$(PATH)
endif

ifdef TMSVER
  PATH := $(subst /tms/bin:,/tms2/$(TMSVER)/bin:,$(PATH))
endif

