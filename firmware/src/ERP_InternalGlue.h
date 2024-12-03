/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021, 2024
 * (C) Copyright IBM Corp. 2021, 2024
 *
 * non-exclusively licensed to gematik GmbH
 **************************************************************************************************/

#ifndef ERP_INTERNAL_GLUE_H
#define ERP_INTERNAL_GLUE_H

#include <cryptoserversdk/eca.h>
#include <cryptoserversdk/db.h>

 /******************************************************************************
  * Defines
  ******************************************************************************/
#define CMDS_MAX_CMD_SIZE 0x40000

// #define CHECK_PERMISSION
#define ERP_PERM_GROUP     0
#define ERP_PERM_LEVEL     2

#define ENABLE_AUDIT_LOGGING
#define ERP_AUDIT_LOG_TAG  "ERP "
// First of custom audit classes.   Mask 0x01000000
#define ERP_AUDIT_CLASS 24

/******************************************************************************
 * Globals
 ******************************************************************************/
extern MDL_GLOBAL DB* p_BlobKDB;
extern MDL_GLOBAL DB* p_TrustDB;
extern MDL_GLOBAL DB* p_DerivationDB;

/******************************************************************************
 * Definitions
 ******************************************************************************/
#include "ERP_Blob.h"
#include "ERP_ASNUtils.h"

/******************************************************************************
 * Macros
 ******************************************************************************/
#define MIN(a,b) (a)<(b)?(a):(b)
#define MAX(a,b) (a)>(b)?(a):(b)

#define CLEANUP(x) { err = (x); goto cleanup; }

/******************************************************************************
 * Functions
 ******************************************************************************/

extern unsigned int DumpHSMMemory(void);

#endif
