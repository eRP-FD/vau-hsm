/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021, 2024
 * (C) Copyright IBM Corp. 2021, 2024
 *
 * non-exclusively licensed to gematik GmbH
 **************************************************************************************************/

#define _ERP_C_INT_

#include <cryptoserversdk/module_1.5.h>
#include <cryptoserversdk/stype.h>
#include <cryptoserversdk/os_log.h>
#include <cryptoserversdk/os_file.h>
#include <cryptoserversdk/cmds.h>

#include "ERP.h"
#include "ERP_ExternalAPI.h"
#include "ERP_Blob.h"

//-----------------------------------------------------------------------------
// module identification
//-----------------------------------------------------------------------------
FILE_CONST T_MODULE_INFO Module_info =
{
  MODULE_INFO_TAG,
  ERP_MDL_NAME,
  CS2_U32_TO_BIG_ENDIAN(ERP_MDL_ID),
  CS2_U32_TO_BIG_ENDIAN(ERP_MDL_VERSION),
  ERP_MDL_NAMEX
};

//-----------------------------------------------------------------------------
// public interface
//-----------------------------------------------------------------------------
FILE_CONST T_ERP_TABLE_PUB Module_pub =
{
  NULL,
  ERP_start,
  ERP_stop,
  ERP_pre_replace,
  ERP_pre_delete,
  NULL,
  &Module_info,

  // add your public functions here
    // Currently no user public functions
};


//-----------------------------------------------------------------------------
// external references to other modules
//-----------------------------------------------------------------------------
#define MODULE_NEEDS_EXT_REFS                    // module needs functions of other modules

MDL_GLOBAL T_OS_MDL_HDL P_SMOS;
MDL_GLOBAL T_OS_MDL_HDL P_CMDS;
MDL_GLOBAL T_OS_MDL_HDL P_UTIL;
MDL_GLOBAL T_OS_MDL_HDL P_DB;
MDL_GLOBAL T_OS_MDL_HDL P_PP;
MDL_GLOBAL T_OS_MDL_HDL P_MBK;
MDL_GLOBAL T_OS_MDL_HDL P_VDES;
MDL_GLOBAL T_OS_MDL_HDL P_AES;
MDL_GLOBAL T_OS_MDL_HDL P_VRSA;
MDL_GLOBAL T_OS_MDL_HDL P_ECA;
MDL_GLOBAL T_OS_MDL_HDL P_ECDSA;
MDL_GLOBAL T_OS_MDL_HDL P_HASH;
MDL_GLOBAL T_OS_MDL_HDL P_CXI;
MDL_GLOBAL T_OS_MDL_HDL P_ADM;
MDL_GLOBAL T_OS_MDL_HDL P_ASN1;


FILE_CONST T_MODULE_LINK_TAB Module_link_tab[] =
{
  // handle      name.       version      flags
  {  &P_CMDS,    "CMDS",     0,              0  },
  {  &P_UTIL,    "UTIL",     0,              0  },
  {  &P_DB,      "DB",       0,              0  },
  {  &P_PP,      "PP",       0,              0  },
  {  &P_MBK,     "MBK",      0x02010200,  MODULE_OPTIONAL  },
  {  &P_AES,     "AES",      0,              0  },
  {  &P_VDES,    "VDES",     0,              0  },
  {  &P_VRSA,    "VRSA",     0,           0  },
  {  &P_ECA,     "ECA",      0,           0  },
  {  &P_ECDSA,   "ECDSA",    0,           0  },
  {  &P_HASH,    "HASH",     0,              0  },
  {  &P_CXI,     "CXI",      0x02000800,  0  },
  {  &P_ADM,     "ADM",      0x03000600,  MODULE_OPTIONAL  },
  {  &P_ASN1,    "ASN1",     0,              0  },
  {  NULL,       "",         0,              0  }         // end of table is marked with NULL pointer
};

//-----------------------------------------------------------------------------
// external interface
//-----------------------------------------------------------------------------
#define MODULE_HAS_EXT_INTERFACE                 // module has external interface

// This table defines the external interface of the firmware.   The positions in this list
//   must match the values defined in client file ERP_SFC.h
FILE_CONST P_CMDS_FCT Module_func_tab[] =
{
    ERP_GenerateBlobKey         // SFC = 0
    ,ERP_ListBlobKeys           // SFC = 1
    ,ERP_GenerateHashKey        // SFC = 2
    ,ERP_UnwrapHashKey          // SFC = 3
    ,ERP_GenerateECIESKeyPair   // SFC = 4
    ,ERP_GenerateECIESCSR       // SFC = 5
    ,ERP_DumpHSMMemory          // SFC = 6 // Devtime only.
    ,ERP_DeleteBlobKey          // SFC = 7
    ,ERP_GenerateNONCE          // SFC = 8
    ,ERP_GenerateDerivationKey  // SFC = 9
    ,ERP_DoECIES128             // SFC = 10
    ,ERP_TrustTPMMfr            // SFC = 11
    ,ERP_EnrollTPMEK            // SFC = 12
    ,ERP_GetAKChallenge         // SFC = 13
    ,ERP_EnrollTPMAK            // SFC = 14
    ,ERP_EnrollEnclave          // SFC = 15
    ,ERP_GetTEEToken            // SFC = 16
    ,ERP_DeriveTaskKey          // SFC = 17
    ,ERP_DeriveAuditKey         // SFC = 18
    ,ERP_DeriveCommsKey         // SFC = 19
    ,ERP_GetECPublicKey         // SFC = 20
    ,ERP_GetRNDBytes            // SFC = 21
    ,ERP_GenerateVAUSIGKeyPair  // SFC = 22
    ,ERP_GenerateVAUSIGCSR      // SFC = 23
    ,ERP_GetVAUSIGPrivateKey    // SFC = 24
    ,ERP_ExportSingleBlobKey    // SFC = 25
    ,ERP_ImportSingleBlobKey    // SFC = 26
    ,ERP_MigrateBlob            // SFC = 27
    ,ERP_GetBlobContentHash     // SFC = 28
    ,ERP_GetBlobContentHashWithToken   // SFC = 29
    ,ERP_DeriveChargeItemKey    // SFC = 30
    ,ERP_GeneratePseudonameKey  // SFC = 31
    ,ERP_UnwrapPseudonameKey    // SFC = 32
    ,ERP_WrapRawPayload         // SFC = 33
    ,ERP_WrapRawPayloadWithToken// SFC = 34
    ,ERP_UnwrapRawPayload       // SFC = 35
    ,ERP_GenerateAUTKeyPair     // SFC = 36
    ,ERP_GenerateAUTCSR         // SFC = 37
    ,ERP_SignVAUAUTToken        // SFC = 38
};

MDL_GLOBAL DB* p_BlobKDB;

/******************************************************************************
 * ERP_start
 ******************************************************************************/
int ERP_start(T_OS_MDL_HDL p_smos, OS_FILE_HANDLE p_spf, void *p_coff_mem)
{
    P_SMOS = p_smos;

    return module_start(p_coff_mem);
}

// setup init task parameters
#define MODULE_INIT_TASK_STACK_SIZE    0x1000     // adapt to your needs
#define MODULE_INIT_TASK_FUNCTION      ERP_init
#define MODULE_INIT_TASK_NAME          "INIT_ERP"

extern MDL_GLOBAL T_BLOBK** LoadedBlobKeyList;
extern MDL_GLOBAL unsigned int HighestLoadedBlobGeneration;
extern MDL_GLOBAL unsigned int NumLoadedBlobGenerations;

/******************************************************************************
 * ERP_init
 ******************************************************************************/
int ERP_init(void)
{
    int err = E_ERP_SUCCESS;
    INIT_STAT DB_INFO db_info = { DB_INFO_TAG, 8, 0x100000 };

    //-----------------------------------------------------------------------------
    // initialize global vars here
    //-----------------------------------------------------------------------------
    p_BlobKDB = NULL;
    LoadedBlobKeyList = NULL;
    HighestLoadedBlobGeneration = 0;
    NumLoadedBlobGenerations = 0;

    //-----------------------------------------------------------------------------
    // open /create databases
    //-----------------------------------------------------------------------------
    err = db_open("ERP_BlobK", DB_CREAT, &db_info, &p_BlobKDB);

    return(err);
}

/******************************************************************************
 * ERP_stop
 ******************************************************************************/
int ERP_stop(void)
{
    int err=E_ERP_SUCCESS;

    err = db_close(p_BlobKDB);

    return(err);
}

/******************************************************************************
 * ERP_pre_replace
 ******************************************************************************/
int ERP_pre_replace(void)
{
  return(E_ERP_SUCCESS);
}

/******************************************************************************
 * ERP_pre_delete
 ******************************************************************************/
int ERP_pre_delete(void)
{
    return(E_ERP_SUCCESS);
}

#undef _ERP_C_INT_

// Replace the macro so that the build path for IBM ERP is self-contained.
// #include MODULE_INIT_C
#include <cryptoserversdk/module_init_1.5.c>
