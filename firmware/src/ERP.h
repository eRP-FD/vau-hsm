/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021
 * (C) Copyright IBM Corp. 2021
 * SPDX-License-Identifier: CC BY-NC-ND 3.0 DE
 *
 * Description: Global header file of CryptoServer module ERP.
 *                This module implements the IBM eRezept custom HSM firmware.
 *              Must be included in every CryptoServer software that uses functions of this module.
 **************************************************************************************************/

#ifndef ERP_ERP_H
#define ERP_ERP_H

#include <cryptoserversdk/os_mdl.h>
#include <cryptoserversdk/os_file.h>

//-----------------------------------------------------------------------------
// module identification:
//-----------------------------------------------------------------------------
/** @ingroup ERP
  * \def ERP_MDL_ID
  * Module functioncode
  */
#define ERP_MDL_ID          0x101                    // ID of the module
#define ERP_MDL_NAME        "ERP"                   // Abbreviation of the module
#ifdef CS2_SDK
   #define ERP_MDL_NAMEX     "IBM eRezept Module"     // Long module name for the simulator
#else
    #ifdef DEBUG
        #define ERP_MDL_NAMEX   "IBM eRezept Module DEBUG"   // Long module name for the debug version
    #else
        #define ERP_MDL_NAMEX   "IBM eRezept Module"         // Long module name for the release version
    #endif
#endif

// The intention is that this can be set from the build process.
#ifndef ERP_MDL_VERSION
    #define ERP_MDL_VERSION     0x00090001            // Version of the module  (d.x.d.d)
#endif

//-----------------------------------------------------------------------------
// public interface:
//-----------------------------------------------------------------------------
typedef struct
{
    void   *p_data;
    int    (*p_start)(T_OS_MDL_HDL, OS_FILE_HANDLE, void*);
    int    (*p_stop)(void);
    int    (*p_pre_replace)(void);
    int    (*p_pre_delete)(void);
    void   *dumy;
    const void *p_module_info;

    // add your public functions here
    // Currently no user public functions.
}
T_ERP_TABLE_PUB;

#ifdef _ERP_C_INT_
    //-----------------------------------------------------------------------------
    // function prototypes used by the module (internal)
    //-----------------------------------------------------------------------------
    int  ERP_start(T_OS_MDL_HDL,OS_FILE_HANDLE,void *);
    int  ERP_stop(void);
    int  ERP_pre_replace(void);
    int  ERP_pre_delete(void);
    int  ERP_sync(void);

    // add your public functions here
    // Currently no user public functions.
#else
    //-----------------------------------------------------------------------------
    // external interface to be used by other modules
    //-----------------------------------------------------------------------------
    extern MDL_GLOBAL T_OS_MDL_HDL P_ERP;

    #define _P_ERP  ((T_ERP_TABLE_PUB *)P_ERP)         // shortcut

    #define P_ERP_data         (_P_ERP->_p_data);

    #define ERP_start          _P_ERP->p_start
    #define ERP_stop           _P_ERP->p_stop
    #define ERP_pre_replace    _P_ERP->p_pre_replace
    #define ERP_pre_delete     _P_ERP->p_pre_delete
    #define ERP_sync           _P_ERP->p_sync

    // add your public functions here
    #define ERP_pub_func1      _P_ERP->p_pub_func1
    #define ERP_pub_func2      _P_ERP->p_pub_func2

#endif // _ERP_C_INT_

#include "ERP_MDLError.h"

#endif // __ERP_H_PUB_INCLUDED__
