/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021, 2024
 * (C) Copyright IBM Corp. 2021, 2024
 *
 * non-exclusively licensed to gematik GmbH
 **************************************************************************************************/
#define _BSD_SOURCE
#define _DEFAULT_SOURCE
#include "ERP_Client.h"

#include "ERP_ASNUtils.h"
#include "ERP_Error.h"

#ifdef _WIN32
 //  Windows warning complaining of C5105 entries in winbase.h...
#pragma warning (push)
#pragma warning (disable: 5105)
#endif

#include <asn1_hsmclient/AES128.h>
#include <asn1_hsmclient/AES256.h>
#include <asn1_hsmclient/AKChallengeResponse.h>
#include <asn1_hsmclient/BackupBlobRequest.h>
#include <asn1_hsmclient/BlobKeyInfo.h>
#include <asn1_hsmclient/BlobKeyInfoList.h>
#include <asn1_hsmclient/DeriveKeyRequest.h>
#include <asn1_hsmclient/DerivedKey.h>
#include <asn1_hsmclient/DoVAUECIESRequest.h>
#include <asn1_hsmclient/ERPOctetString.h>
#include <asn1_hsmclient/EnrollAKRequest.h>
#include <asn1_hsmclient/EnrollEnclaveRequest.h>
#include <asn1_hsmclient/EnrollTPMRequest.h>
#include <asn1_hsmclient/GetAKChallenge.h>
#include <asn1_hsmclient/GetVAUCSRRequest.h>
#include <asn1_hsmclient/INTSequence.h>
#include <asn1_hsmclient/MigrateBlobRequest.h>
#include <asn1_hsmclient/NONCEAndBlob.h>
#include <asn1_hsmclient/SingleBlob.h>
#include <asn1_hsmclient/SingleBlobRequest.h>
#include <asn1_hsmclient/TEETokenRequest.h>
#include <asn1_hsmclient/TrustTPMMfrRequest.h>
#include <asn1_hsmclient/TwoBlobKeyRequest.h>
#include <asn1_hsmclient/UnwrapRawPayloadRequest.h>
#include <asn1_hsmclient/WrapPseudonameLogKeyRequest.h>
#include <asn1_hsmclient/WrapRawPayloadRequest.h>
#include <asn1_hsmclient/WrapRawPayloadWithTokenRequest.h>
#include <asn1_hsmclient/SignVAUAUTTokenRequest.h>
#include <asn1_hsmclient/X509CSR.h>

#ifdef _WIN32
 // renenable the C5105
#pragma warning (pop)
#endif

#include <csxapi/csxapi.h>

#include <stdio.h>
#include <string.h>

//******************************************************************************
// * Definitions
// *****************************************************************************

//#define TRACE_HSM_API

#include "ERP_SFC.h"

typedef struct {
    unsigned int handle;
    void* pSessionContext;
} SessionContext_t;

SessionContext_t g_SessionTable[MAX_HSM_SESSIONS] = {
    {0,NULL}
    ,{0,NULL}
    ,{0,NULL}
    ,{0,NULL}
    ,{0,NULL}
    ,{0,NULL}
    ,{0,NULL}
    ,{0,NULL}
    ,{0,NULL}
    ,{0,NULL}
    ,{0,NULL}
    ,{0,NULL}
    ,{0,NULL}
    ,{0,NULL}
    ,{0,NULL}
    ,{0,NULL}
    ,{0,NULL}
    ,{0,NULL}
    ,{0,NULL}
    ,{0,NULL}
};

void* getSessionContext(unsigned int inHandle)
{
    if (inHandle == 0)
    {
        return NULL;
    }
    for (unsigned int i = 0; i < MAX_HSM_SESSIONS; i++)
    {
        if (g_SessionTable[i].handle == inHandle)
        {
            return g_SessionTable[i].pSessionContext;
        }
    }
    return NULL;
}

unsigned int checkSessionContext(unsigned int inHandle, void** ppSessionContext)
{
    if (((*ppSessionContext) = getSessionContext(inHandle)) != NULL)
    {
        return ERP_ERR_BAD_SESSION_HANDLE;
    }
    return ERP_ERR_NOERROR;
}

// Pass in 0 as the handle and a new session will be created, otherwise the
//   existing session with that handle will be updated.
unsigned int setSessionContext(unsigned int * newHandle, void* pSessionContext)
{
    for (unsigned int i = 0; i < MAX_HSM_SESSIONS; i++)
    {
        if (g_SessionTable[i].handle == (*newHandle))
        {
            g_SessionTable[i].handle = i+1;
            g_SessionTable[i].pSessionContext = pSessionContext;
            *newHandle = g_SessionTable[i].handle;
            return ERP_ERR_NOERROR;
        }
    }
    return ERP_ERR_TOO_MANY_SESSIONS;
}

unsigned int closeSessionContext(unsigned int inHandle)
{
    for (unsigned int i = 0; i < MAX_HSM_SESSIONS; i++)
    {
        if (g_SessionTable[i].handle == inHandle)
        {
            g_SessionTable[i].handle = 0;
            g_SessionTable[i].pSessionContext = NULL;
            return ERP_ERR_NOERROR;
        }
    }
    return ERP_ERR_BAD_SESSION_HANDLE;
}

void API_xtrace(const char * message, const unsigned char * data, size_t dataLength)
{
    fprintf(stderr,"%s",message);
    fprintf(stderr,": \n");

    const int newlineThreshold = 16;
    for (size_t i = 0; i < dataLength; ++i)
    {
        fprintf(stderr,"%2x ", data[i]);
        if ((i > 0) && ((i % newlineThreshold) == 0))
        {
            printf ("\n");
        }
    }
    fprintf(stderr,"\n");
}

ERP_API_FUNC HSMSession ERP_Connect(
    const char    *device,          // I: device specifier (e.g. PCI:0 / 192.168.1.1)
    unsigned int  connect_timeout,  // I: connection timeout [ms]
    unsigned int  read_timeout     // I: read (command) timeout [ms]
)
{
    HSMSession retVal = { 0, 0, 0, HSMUninitialised, 0, ERP_ERR_NOERROR , 0 };

    retVal.bIsCluster = 0;

    if ((retVal.errorCode = cs_open_connection(
                                device,
                                connect_timeout,
                                read_timeout,
                                &retVal.h_cs)) != 0)
    {
        if (retVal.h_cs >= 0)
        {
            cs_close_connection(retVal.h_cs);
        }
    }
    if (retVal.errorCode == 0)
    {
        retVal.status = HSMAnonymousOpen;
    }
    else {
        retVal.status = HSMError;
    }
    retVal.LogonCount = 0;
    retVal.reconnectInterval = 0;
    return retVal;
}

ERP_API_FUNC HSMSession ERP_ClusterConnect(
    const char** devices,          // I: device specifier (e.g. PCI:0 / 192.168.1.1)
    unsigned int  connect_timeout,  // I: connection timeout [ms]
    unsigned int  read_timeout,     // I: read (command) timeout [ms]
    unsigned int  reconnect_interval // I: interval after a failover before retrying a connection to the original HSM
)
{
    HSMSession retVal = { 0, 0, 0, HSMUninitialised, 0, ERP_ERR_NOERROR, 1 };
    int ndevs = 0;
    if (devices == NULL)
    {
        retVal.errorCode = ERP_ERR_BAD_DEVICE_SPEC;
    }
    if (retVal.errorCode == ERP_ERR_NOERROR)
    {
        // I am assuming ndevs
        const int maxNdevs = MAX_CLUSTER_HSMS;
        while ((ndevs < maxNdevs) && (devices[ndevs] != NULL))
        {
            ndevs++;
        }
        if (ndevs >= maxNdevs)
        {
            retVal.errorCode = ERP_ERR_BAD_DEVICE_SPEC;
        }
    }
    if (retVal.errorCode == ERP_ERR_NOERROR)
    {
        retVal.bIsCluster = 1;

        if ((retVal.errorCode = cs_cluster_open(devices,
            ndevs,
            connect_timeout,
            read_timeout,
            &retVal.h_cs)) != 0)
        {
            if (retVal.h_cs >= 0)
            {
                cs_cluster_close(retVal.h_cs);
            }
        }
    }
    if (retVal.errorCode == 0)
    {
        retVal.status = HSMAnonymousOpen;
    }
    else {
        retVal.status = HSMError;
    }
    retVal.LogonCount = 0;
    retVal.reconnectInterval = reconnect_interval;
    return retVal;
}

// One of Password or KeySpec must be NULL.
HSMSession ERP_SingleLogonImplementation(
    HSMSession sesh,
    const char * user,
    const char * password,
    const char * KeySpec)
{
    HSMSession retVal = sesh;
    // (sesh.h_cs == 0) is not a problem
    // Multiple Logons are not a problem.
    if ((sesh.status != HSMAnonymousOpen) &&
        (sesh.status != HSMLoggedIn))
    {
        retVal.errorCode = ERP_ERR_BAD_CONNECTION;
        return retVal;
    }

    void* pSessionContext = getSessionContext(sesh.hSessionContext);

    if ((retVal.errorCode = cs_prepare_auth(
                                retVal.h_cs,
                                CSA_AUTH_MECH_AUTO,
                                (const unsigned char*)user,
                                (unsigned int)strlen(user),
                                (const unsigned char*)KeySpec,
                                (const unsigned char*)password,
                                ((password != NULL) ? (unsigned int)strlen(password) : 0),
                                pSessionContext, // input context
                                &pSessionContext)) != 0) // output context.
    {
        retVal.status = HSMLoginFailed;
        return retVal;
    }

    retVal.status = HSMLoggedIn;
    // This method will reuse a table entry for a given session if present, or if zero is the handle
    //    then it will create a new one.
    retVal.errorCode = setSessionContext(&(retVal.hSessionContext), pSessionContext);

    if ((retVal.errorCode = cs_get_sessionkey_ex(
                                retVal.h_cs,
                                pSessionContext)) != 0)
    {
        retVal.status = HSMError;
    }

    return retVal;
}

HSMSession ERP_ClusterLogonImplementation(
    HSMSession sesh,
    const char* user,
    const char* password,
    const char* KeySpec)
{
    HSMSession retVal = sesh;
    //    (sesh.h_cs == 0) is not a problem
    if ((sesh.status != HSMAnonymousOpen) &&
        (sesh.status != HSMLoggedIn))
    {
        retVal.errorCode = ERP_ERR_BAD_CONNECTION;
        return retVal;
    }

    if (0 != (retVal.errorCode = cs_cluster_logon(
        retVal.h_cs,
        (const unsigned char*)user,
        (unsigned int)strlen(user),
        (const unsigned char*)KeySpec,
        (const unsigned char*)password,
        ((password != NULL) ? (unsigned int)strlen(password) : 0)))) // output context.
    {
        retVal.status = HSMLoginFailed;
        return retVal;
    }

    retVal.status = HSMLoggedIn;
    retVal.hSessionContext = 0;
    if (0 != cs_cluster_set_fallback_interval(retVal.h_cs, retVal.reconnectInterval))
    {
        retVal.errorCode = ERP_ERR_SET_CLUSTER_FALLBACK;
    }

    return retVal;
}

ERP_API_FUNC HSMSession ERP_LogonPassword(
    HSMSession sesh,
    const char * user,
    const char * password
)
{
    if (sesh.bIsCluster == 0)
    {
        return ERP_SingleLogonImplementation(sesh, user, password, NULL);
    }

    return ERP_ClusterLogonImplementation(sesh, user, password, NULL);
}

ERP_API_FUNC HSMSession ERP_LogonKeySpec(
    HSMSession sesh,
    const char * user,
    const char * KeySpec,
    const char * password
)
{
    if (sesh.bIsCluster == 0)
    {
        return ERP_SingleLogonImplementation(sesh, user, password, KeySpec);
    }

    return ERP_ClusterLogonImplementation(sesh, user, password, KeySpec);
}

ERP_API_FUNC HSMSession ERP_SingleLogoff(HSMSession sesh)
{
    HSMSession retVal = sesh;
    retVal.errorCode = ERP_ERR_NOERROR;
    void* pSessionContext = getSessionContext(sesh.hSessionContext);
    // h_cs == 0 is a valid session.
    if ((sesh.status != HSMLoggedIn) ||
        (pSessionContext == NULL))
    {
        retVal.errorCode = ERP_ERR_NOT_LOGGED_IN;
        return retVal;
    }

    if (retVal.errorCode == ERP_ERR_NOERROR)
    {
        cs_end_session(retVal.h_cs, pSessionContext);
        retVal.errorCode = closeSessionContext(sesh.hSessionContext);
        retVal.hSessionContext = 0;
        retVal.status = HSMAnonymousOpen;
        retVal.LogonCount = 0;
    }
    return retVal;
}

ERP_API_FUNC HSMSession ERP_ClusterLogoff(HSMSession sesh)
{
    HSMSession retVal = sesh;
    retVal.errorCode = ERP_ERR_NOERROR;
    // h_cs == 0 is a valid session.
    if (sesh.status != HSMLoggedIn)
    {
        retVal.errorCode = ERP_ERR_NOT_LOGGED_IN;
        return retVal;
    }

    if (retVal.errorCode == ERP_ERR_NOERROR)
    {
        cs_cluster_logoff(retVal.h_cs);
        retVal.hSessionContext = 0;
        retVal.status = HSMAnonymousOpen;
        retVal.LogonCount = 0;
    }
    return retVal;
}

ERP_API_FUNC HSMSession ERP_Logoff(HSMSession sesh)
{
    if (sesh.bIsCluster == 0)
    {
        return ERP_SingleLogoff(sesh);
    }

    return ERP_ClusterLogoff(sesh);
}

ERP_API_FUNC HSMSession ERP_SingleDisconnect(HSMSession sesh)
{
    HSMSession retVal = sesh;
    // h_cs == 0 is a valid connection!
    if ((sesh.status == HSMUninitialised) ||
        (sesh.status == HSMClosed))
    {
        retVal.errorCode = ERP_ERR_NO_CONNECTION;
        return retVal;
    }
    if (sesh.status == HSMLoggedIn)
    {
        retVal = ERP_Logoff(retVal);
        // Ignore possible failure here.
    }
    // Whatever the error, continue to try to close the session
    retVal.errorCode = cs_close_connection(retVal.h_cs);

    // Set the session state to closed, whatever happened here.
    // Intentionally ignore result of the close call here.
    closeSessionContext(retVal.hSessionContext);
    retVal.h_cs = 0;
    retVal.status = HSMClosed;
    retVal.hSessionContext = 0;

    return retVal;
}

ERP_API_FUNC HSMSession ERP_ClusterDisconnect(HSMSession sesh)
{
    HSMSession retVal = sesh;
    // h_cs == 0 is a valid connection!
    if ((sesh.status == HSMUninitialised) ||
        (sesh.status == HSMClosed))
    {
        retVal.errorCode = ERP_ERR_NO_CONNECTION;
        return retVal;
    }
    if (sesh.status == HSMLoggedIn)
    {
        retVal = ERP_Logoff(retVal);
        // Ignore possible failure here.
    }
    // Whatever the error, continue to try to close the session
    retVal.errorCode = cs_cluster_close(retVal.h_cs);

    // Set the session state to closed, whatever happened here.
    // Intentionally ignore result of the close call here.
    retVal.h_cs = 0;
    retVal.status = HSMClosed;
    retVal.hSessionContext = 0;

    return retVal;
}

ERP_API_FUNC HSMSession ERP_Disconnect(HSMSession sesh)
{
    if (sesh.bIsCluster == 0)
    {
        return ERP_SingleDisconnect(sesh);
    }

    return ERP_ClusterDisconnect(sesh);
}

// Method to encapsulate single and cluster configurations for the execute firmware command calls.
// Not exported in the API.
int ERP_FirmwareExec(HSMSession sesh,
    unsigned int fc,
    unsigned int sfc,
    unsigned char* p_cmd,
    unsigned int l_cmd,
    unsigned char** pp_answ,
    unsigned int* p_l_answ)
{
    if (sesh.bIsCluster > 0)
    {
        return cs_cluster_exec(sesh.h_cs,
            fc, sfc,
            p_cmd, l_cmd,
            pp_answ, p_l_answ);
    }

    return cs_exec_command(sesh.h_cs,
                           getSessionContext(sesh.hSessionContext),
                           fc, sfc,
                           p_cmd, l_cmd,
                           pp_answ, p_l_answ);
}

// DirectIO is only intended to be used for unit testing of the HSM interface
//   formal handling of parameters.   i.e. bouncing it with invalid inputs.
// It may be removed for the final build, or not - it represents no security risk
//   since the security is provided inside the HSM.
// For the production build, this will return  ERP_ERR_DEV_FUNCTION_ONLY.
ERP_API_FUNC DirectIOOutput ERP_DirectIO(HSMSession sesh,
    DirectIOInput input) // input for the command.
{
    // Note, it should not be possible to blow this method up, but all that will happen if you do
    //    is that the HSM will reject the input.
    DirectIOOutput retVal = { 0 ,0,{'\0'} };
    if (input.DataLength > (MAX_BUFFER * 2))
    {
        retVal.returnCode = ERP_ERR_BUFFER_TOO_SMALL;
    }

    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
#ifdef TRACE_HSM_API
        fprintf(stderr,"\nExecuting DIRECT IO for command code: %.08x ...\n", input.SFCCode);
        API_xtrace("Command Data: %s\n", &(input.DataBody[0]), (int) input.DataLength);
#endif
        retVal.returnCode = ERP_FirmwareExec(sesh,
            ERP_MDL_ID,
            input.SFCCode,
            &(input.DataBody[0]),
            (unsigned int)input.DataLength,
            &p_answ,
            &p_l_answ);
    }

#ifdef TRACE_HSM_API    // API_xtrace("Answ", p_answ, p_l_answ);
    API_xtrace("Answ", p_answ, p_l_answ);
#endif
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        if (p_l_answ > (MAX_BUFFER * 2))
        {
            retVal.returnCode = ERP_ERR_BUFFER_TOO_SMALL;
            retVal.DataLength = 0;
        }
        else {
            retVal.DataLength = p_l_answ;
            memcpy(&(retVal.DataBody[0]), p_answ, retVal.DataLength);
        }
    }

    if (p_answ != NULL)
    {
        cs_free_answ(p_answ);
    }
    return retVal;
}

ERP_API_FUNC UIntOutput ERP_GenerateBlobKey(
    HSMSession sesh,            // HSM Session
    UIntInput input) // input for command.   Desired Generation
{
    UIntOutput retVal = { 0 , 0 };

    // Need to use calloc because lib relies on zeroing of empty structure memory.
    INTSequence_t* intIn = (INTSequence_t * )calloc(1, sizeof(INTSequence_t));
    if (intIn == NULL)
    {
        retVal.returnCode = ERP_ERR_CALLOC_ERROR;
    }
    size_t cmdLength = 0;
    unsigned char* pCmdData = NULL;
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        intIn->anInt = input.intValue;

        asn_enc_rval_t er;  /* Encoder return value */
        er = der_encode_dynamic_buffer(&asn_DEF_INTSequence, intIn,
                &cmdLength, &pCmdData);
        if (er.encoded == -1)
        { // Failed to encode the data.
            retVal.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        }
    }
    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;

#ifdef TRACE_HSM_API
    fprintf(stderr,"\nExecuting GenerateBlobKey command ...\n");
    API_xtrace("Command: %s\n", pCmdData, (int) cmdLength);
#endif

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = ERP_FirmwareExec(sesh,
            ERP_MDL_ID,
            ERP_SFC_GENERATE_BLOB_KEY,
            pCmdData,
            (unsigned int)cmdLength,
            &p_answ,
            &p_l_answ);
    }

#ifdef TRACE_HSM_API
    API_xtrace("Answ", p_answ, p_l_answ);
#endif

    INTSequence_t* GenKeyOut = NULL;    /* Note this 0! */

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_dec_rval_t rval;

        rval = asn_DEF_INTSequence.op->ber_decoder(0,
            &asn_DEF_INTSequence,
            (void**)&GenKeyOut,
            p_answ, p_l_answ,
            0);

        if (rval.code != RC_OK)
        {
            retVal.returnCode = ERP_ERR_ASN1DECODING_ERROR;
        }
    }

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.intValue = GenKeyOut->anInt;
    }
    if (intIn != NULL)
    {
        asn_DEF_INTSequence.op->free_struct(
            &asn_DEF_INTSequence, intIn, ASFM_FREE_EVERYTHING);
    }
    if (GenKeyOut != NULL)
    { // Free decoded or partially decoded result.
        asn_DEF_INTSequence.op->free_struct(
            &asn_DEF_INTSequence, GenKeyOut, ASFM_FREE_EVERYTHING);
    }

    if (p_answ != NULL)
    {
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        free(pCmdData);
    }
    return retVal;
}

ERP_API_FUNC EmptyOutput ERP_DeleteBlobKey(
    HSMSession sesh,            // HSM Session
    UIntInput input) // input for command.   Undesired Generation
{
    EmptyOutput retVal = { 0 };

    // Need to use calloc because lib relies on zeroing of empty structure memory.
    INTSequence_t* intIn = (INTSequence_t * )calloc(1, sizeof(INTSequence_t));
    if (intIn == NULL)
    {
        retVal.returnCode = ERP_ERR_CALLOC_ERROR;
    }
    size_t cmdLength = 0;
    unsigned char* pCmdData = NULL;
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        intIn->anInt = input.intValue;
        asn_enc_rval_t er;  /* Encoder return value */

        er = der_encode_dynamic_buffer(&asn_DEF_INTSequence, intIn,
                &cmdLength, &pCmdData);
        if (er.encoded == -1)
        { // Failed to encode the data.
            retVal.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        }
    }
    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;

#ifdef TRACE_HSM_API
    fprintf(stderr,"\nExecuting DeleteBlobKey command ...\n");
    API_xtrace("Command: %s\n", pCmdData, (int) cmdLength);
#endif

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = ERP_FirmwareExec(sesh,
            ERP_MDL_ID,
            ERP_SFC_DELETE_BLOB_KEY,
            pCmdData,
            (unsigned int)cmdLength,
            &p_answ,
            &p_l_answ);
    }
    if (p_answ != NULL)
    {

#ifdef TRACE_HSM_API
        API_xtrace("(Unexpected) Answ", p_answ, p_l_answ);
#endif
    }
    if (intIn != NULL)
    {
        asn_DEF_INTSequence.op->free_struct(
            &asn_DEF_INTSequence, intIn, ASFM_FREE_EVERYTHING);
    }
    if (p_answ != NULL)
    {
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        free(pCmdData);
    }
    return retVal;
}

ERP_API_FUNC NONCEOutput ERP_GenerateNONCE(
    HSMSession sesh,            // HSM Session
    UIntInput input) // input for command.   Desired Generation
{
    NONCEOutput retVal = { 0, {0}, {0,0,{0}} };

    // Need to use calloc because lib relies on zeroing of empty structure memory.
    INTSequence_t* intIn = (INTSequence_t *)calloc(1, sizeof(INTSequence_t));
    if (intIn == NULL)
    {
        retVal.returnCode = ERP_ERR_CALLOC_ERROR;
    }
    size_t cmdLength = 0;
    unsigned char* pCmdData = NULL;
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        intIn->anInt = input.intValue;
        asn_enc_rval_t er;  /* Encoder return value */

        er = der_encode_dynamic_buffer(&asn_DEF_INTSequence, intIn,
                &cmdLength, &pCmdData);
        if (er.encoded == -1)
        { // Failed to encode the data.
            retVal.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        }
    }
    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;

#ifdef TRACE_HSM_API
    fprintf(stderr,"\nExecuting generateNONCE command ...\n");
    API_xtrace("Command: %s\n", pCmdData, (int) cmdLength);
#endif

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = ERP_FirmwareExec(sesh,
            ERP_MDL_ID,
            ERP_SFC_GENERATE_NONCE,
            pCmdData,
            (unsigned int)cmdLength,
            &p_answ,
            &p_l_answ);
    }

#ifdef TRACE_HSM_API
    API_xtrace("Answ", p_answ, p_l_answ);
#endif

    // Extract Single Blob from result:
    NONCEAndBlob_t* NONCEOut = NULL;    /* Note this 0! */

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_dec_rval_t rval;

        rval = asn_DEF_NONCEAndBlob.op->ber_decoder(0,
            &asn_DEF_NONCEAndBlob,
            (void**)&NONCEOut,
            p_answ, p_l_answ,
            0);

        if (rval.code != RC_OK)
        {
            retVal.returnCode = ERP_ERR_ASN1DECODING_ERROR;
        }
    }

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        if (NONCEOut->aNONCEBlob.aBlob.size > MAX_BUFFER)
        {
            retVal.returnCode = ERP_ERR_BUFFER_TOO_SMALL;
        }
        else {
            retVal.BlobOut.BlobLength = NONCEOut->aNONCEBlob.aBlob.size;
            memcpy(retVal.BlobOut.BlobData, NONCEOut->aNONCEBlob.aBlob.buf, NONCEOut->aNONCEBlob.aBlob.size);
            // First four bytes of
            retVal.BlobOut.BlobGeneration = NONCEOut->aNONCEBlob.blobGeneration;
            if (NONCEOut->aNONCE.size != NONCE_LEN)
            {
                retVal.returnCode = ERP_ERR_BAD_RETURN_FORMAT;
            }
            memcpy(&(retVal.NONCE[0]), &(NONCEOut->aNONCE.buf[0]), NONCE_LEN);
        }
    }
    else {
        retVal.BlobOut.BlobGeneration = 0;
        retVal.BlobOut.BlobLength = 0;
        retVal.BlobOut.BlobData[0] = '\0';

        memset(&(retVal.NONCE[0]), 0, RND_256_LEN);
    }

    if (NONCEOut != NULL)
    { // Free decoded or partially decoded result.
        asn_DEF_NONCEAndBlob.op->free_struct(
            &asn_DEF_NONCEAndBlob, NONCEOut, ASFM_FREE_EVERYTHING);
    }

    if (intIn != NULL)
    {
        asn_DEF_INTSequence.op->free_struct(
            &asn_DEF_INTSequence, intIn, ASFM_FREE_EVERYTHING);
    }
    if (p_answ != NULL)
    {
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        free(pCmdData);
    }
    return retVal;
}

ERP_API_FUNC BlobKeyListOutput ERP_ListLoadedBlobKeys(
    HSMSession sesh)            // HSM Session
{
    BlobKeyListOutput retVal = { ERP_ERR_NOERROR , 0, { { 0, ""} } };

    if ((sesh.status != HSMAnonymousOpen) &&
        (sesh.status != HSMLoggedIn))
    {
        retVal.returnCode = ERP_ERR_NO_CONNECTION;
        return retVal;
    }

    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;

#ifdef TRACE_HSM_API
    fprintf(stderr,"\nERP_LIB Executing ListLoadedBlobKeys command ...\n");
#endif
    if ((retVal.returnCode = ERP_FirmwareExec(sesh,
        ERP_MDL_ID,
        ERP_SFC_LIST_BLOB_KEYS,
        NULL,
        0,
        &p_answ,
        &p_l_answ)) != 0)
    {
        if (p_answ != NULL)
        {
            cs_free_answ(p_answ);
        }
        return retVal;
    }
    if (p_answ != NULL)
    { // Answer Data:

#ifdef TRACE_HSM_API
        API_xtrace("Answ", p_answ, p_l_answ);
#endif
    }

    BlobKeyInfoList_t* blobKeyListOut = NULL;    /* Note this 0! */

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_dec_rval_t rval;

        rval = asn_DEF_BlobKeyInfoList.op->ber_decoder(0,
            &asn_DEF_BlobKeyInfoList,
            (void**)&blobKeyListOut,
            p_answ, p_l_answ,
            0);

        if (rval.code != RC_OK)
        {
            retVal.returnCode = ERP_ERR_ASN1DECODING_ERROR;
        }
    }

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        int i = 0;
        for (i = 0; (i < blobKeyListOut->blobKeyInfos.list.count) && ( i < MAX_BLOB_GENERATIONS); i++)
        {
            retVal.Generations[i].Generation = blobKeyListOut->blobKeyInfos.list.array[i]->generation;
            // SHA_256_LEN is length in bytes, i.e. 32.
            if (blobKeyListOut->blobKeyInfos.list.array[i]->keyHash.hashValue.size != (SHA_256_LEN))
            {
                retVal.returnCode = ERP_ERR_BAD_RETURN_FORMAT;
                break;
            }
            memcpy(&(retVal.Generations[i].KeyHash[0]),
                &(blobKeyListOut->blobKeyInfos.list.array[i]->keyHash.hashValue.buf[0]),
                (unsigned int)blobKeyListOut->blobKeyInfos.list.array[i]->keyHash.hashValue.size);
        }
        // Number of actual keys decoded...
        retVal.NumKeys = i;
    }
    if (blobKeyListOut != NULL)
    {
        asn_DEF_BlobKeyInfoList.op->free_struct(
            &asn_DEF_BlobKeyInfoList, blobKeyListOut, ASFM_FREE_EVERYTHING);
    }

    if (p_answ != NULL)
    {
        cs_free_answ(p_answ);
    }

    return retVal;
}

EmptyOutput ERP_DumpHSMMemory(
    HSMSession sesh)            // HSM Session
{
    EmptyOutput retVal = { ERP_ERR_NOERROR };

    if ((sesh.status != HSMAnonymousOpen) &&
        (sesh.status != HSMLoggedIn))
    {
        retVal.returnCode = ERP_ERR_NO_CONNECTION;
        return retVal;
    }

    unsigned char *p_answ = NULL;
    unsigned int p_l_answ = 0;

#ifdef TRACE_HSM_API
    fprintf(stderr,"\nERP_LIB Executing DumpHSMMemory command ...\n");
#endif

    if ((retVal.returnCode = ERP_FirmwareExec(sesh,
        ERP_MDL_ID,
        ERP_SFC_DUMP_HSM_MEMORY,
        NULL,
        0,
        &p_answ,
        &p_l_answ)) != 0)
    {
        if (p_answ != NULL)
        {
            cs_free_answ(p_answ);
        }
        return retVal;
    }
    if (p_answ != NULL)
    { // There should not be any answer data here, but clean it up anyway in case.

#ifdef TRACE_HSM_API
        API_xtrace("Answ", p_answ, p_l_answ);
#endif

        cs_free_answ(p_answ);
    }

    return retVal;
}

ERP_API_FUNC SingleBlobOutput ERP_GenerateAES256Key(
    HSMSession sesh,            // HSM Session
    UIntInput input,
    int SFCCode) // input for command.   Desired Generation
{
    SingleBlobOutput retVal = { 0 , {0,0,"" } };

    // Need to use calloc because lib relies on zeroing of empty structure memory.
    INTSequence_t* intIn = (INTSequence_t*)calloc(1, sizeof(INTSequence_t));
    if (intIn == NULL)
    {
        retVal.returnCode = ERP_ERR_CALLOC_ERROR;
    }
    size_t cmdLength = 0;
    unsigned char* pCmdData = NULL;
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        intIn->anInt = input.intValue;
        asn_enc_rval_t er;  /* Encoder return value */

        er = der_encode_dynamic_buffer(&asn_DEF_INTSequence, intIn,
                &cmdLength, &pCmdData);
         if (er.encoded == -1)
        { // Failed to encode the data.
            retVal.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        }
    }
    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;

#ifdef TRACE_HSM_API
    fprintf(stderr,"\nExecuting GenerateDerivationKey command ...\n");
    API_xtrace("Command: %s\n", pCmdData, (int) cmdLength);
#endif

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = ERP_FirmwareExec(sesh,
            ERP_MDL_ID,
            SFCCode,
            pCmdData,
            (unsigned int)cmdLength,
            &p_answ,
            &p_l_answ);
    }

#ifdef TRACE_HSM_API
    API_xtrace("Answ", p_answ, p_l_answ);
#endif

    HandleSingleBlobResult(p_answ, p_l_answ, &retVal);

    if (intIn != NULL)
    {
        asn_DEF_INTSequence.op->free_struct(
            &asn_DEF_INTSequence, intIn, ASFM_FREE_EVERYTHING);
    }

    if (p_answ != NULL)
    {
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        free(pCmdData);
    }
    return retVal;
}

ERP_API_FUNC SingleBlobOutput ERP_GenerateDerivationKey(
    HSMSession sesh,            // HSM Session
    UIntInput input) // input for command.   Desired Generation
{
    return ERP_GenerateAES256Key(sesh, input, ERP_SFC_GENERATE_DERIVATION_KEY);
}

ERP_API_FUNC SingleBlobOutput ERP_GenerateHashKey(
    HSMSession sesh,            // HSM Session
    UIntInput input) // input for command.   Desired Generation
{
    return ERP_GenerateAES256Key(sesh, input, ERP_SFC_GENERATE_HASH_KEY);
}

ERP_API_FUNC SingleBlobOutput ERP_GeneratePseudonameKey(
    HSMSession sesh,            // HSM Session
    UIntInput input) // input for command.   Desired Generation
{
    return ERP_GenerateAES256Key(sesh, input, ERP_SFC_GENERATE_PSEUDONAME_KEY);
}

ERP_API_FUNC SingleBlobOutput ERP_GenerateECKeyPair(
    HSMSession sesh,            // HSM Session
    UIntInput input, // input for command.   Desired Generation
    int SFCCode)
{
    SingleBlobOutput retVal = { 0 , {0,0,"" } };

    // Need to use calloc because lib relies on zeroing of empty structure memory.
    INTSequence_t* intIn = (INTSequence_t*)calloc(1, sizeof(INTSequence_t));
    if (intIn == NULL)
    {
        retVal.returnCode = ERP_ERR_CALLOC_ERROR;
    }
    size_t cmdLength = 0;
    unsigned char* pCmdData = NULL;
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        intIn->anInt = input.intValue;
        asn_enc_rval_t er;  /* Encoder return value */

        er = der_encode_dynamic_buffer(&asn_DEF_INTSequence, intIn,
                            &cmdLength,&pCmdData);
        if (er.encoded == -1)
        { // Failed to encode the data.
            retVal.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        }
    }
    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;

#ifdef TRACE_HSM_API
    fprintf(stderr,"\nExecuting GenerateECIESKeyPair command ...\n");
    API_xtrace("Command: %s\n", pCmdData, (int) cmdLength);
#endif

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = ERP_FirmwareExec(sesh,
            ERP_MDL_ID,
            SFCCode,
            pCmdData,
            (unsigned int)cmdLength,
            &p_answ,
            &p_l_answ);
    }

#ifdef TRACE_HSM_API
    API_xtrace("Answ", p_answ, p_l_answ);
#endif

    HandleSingleBlobResult(p_answ, p_l_answ, &retVal);

    if (intIn != NULL)
    {
        asn_DEF_INTSequence.op->free_struct(
            &asn_DEF_INTSequence, intIn, ASFM_FREE_EVERYTHING);
    }

    if (p_answ != NULL)
    {
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        free(pCmdData);
    }
    return retVal;
}

ERP_API_FUNC SingleBlobOutput ERP_GenerateECIESKeyPair(
    HSMSession sesh,            // HSM Session
    UIntInput input) // input for command.   Desired Generation
{
    return ERP_GenerateECKeyPair(sesh, input, ERP_SFC_GENERATE_ECIES_KEYPAIR);
}

ERP_API_FUNC SingleBlobOutput ERP_GenerateVAUSIGKeyPair(
    HSMSession sesh,            // HSM Session
    UIntInput input) // input for command.   Desired Generation
{
    return ERP_GenerateECKeyPair(sesh, input, ERP_SFC_GENERATE_VAUSIG_KEYPAIR);
}

ERP_API_FUNC SingleBlobOutput ERP_GenerateAUTKeyPair(
    HSMSession sesh,            // HSM Session
    UIntInput input) // input for command.   Desired Generation
{
    return ERP_GenerateECKeyPair(sesh, input, ERP_SFC_GENERATE_AUT_KEYPAIR);
}

ERP_API_FUNC x509CSROutput ERP_Generate_EC_CSR(
    HSMSession sesh,            // HSM Session
    GetVAUCSRInput input, // input for command.
    int SFCCode)
{
    x509CSROutput retVal = { ERP_ERR_NOERROR, 0,"" };

    // Need to use calloc because lib relies on zeroing of empty structure memory.
    GetVAUCSRRequest_t* request = (GetVAUCSRRequest_t *)calloc(1, sizeof(GetVAUCSRRequest_t));
    if (request == NULL)
    {
        retVal.returnCode = ERP_ERR_CALLOC_ERROR;
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->keyPair), &(input.KeyPair));
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_buffer2OctetString(&(request->candidateCSR), input.candidateCSR, input.candidateCSRLength);
    }
    size_t cmdLength = 0;
    unsigned char* pCmdData = NULL;
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_enc_rval_t er;  /* Encoder return value */

        er = der_encode_dynamic_buffer(&asn_DEF_GetVAUCSRRequest, request,
                        &cmdLength,&pCmdData);
        if (er.encoded == -1)
        { // Failed to encode the data.
            retVal.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        }
    }
    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;

#ifdef TRACE_HSM_API
    fprintf(stderr,"\nExecuting GenerateECIESCSR command ...\n");
    API_xtrace("Command Data: %s\n", pCmdData, (int) cmdLength);
#endif

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = ERP_FirmwareExec(sesh,
            ERP_MDL_ID,
            SFCCode,
            pCmdData,
            (unsigned int)cmdLength,
            &p_answ,
            &p_l_answ);
    }

#ifdef TRACE_HSM_API
    API_xtrace("Answ", p_answ, p_l_answ);
#endif

    // Extract Single Blob from result:
    X509CSR_t* response = NULL;    /* Note this 0! */

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_dec_rval_t rval;

        rval = asn_DEF_X509CSR.op->ber_decoder(0,
            &asn_DEF_X509CSR,
            (void**)&response,
            p_answ, p_l_answ,
            0);

        if (rval.code != RC_OK)
        {
            retVal.returnCode = ERP_ERR_ASN1DECODING_ERROR;
        }
    }

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        if (response->csrData.size > MAX_BUFFER)
        {
            retVal.returnCode = ERP_ERR_BUFFER_TOO_SMALL;
        }
        else {
            retVal.CSRDataLength = response->csrData.size;
            memcpy(retVal.CSRData,
                response->csrData.buf,
                response->csrData.size);
        }
    }
    if (response != NULL)
    {
        asn_DEF_X509CSR.op->free_struct(
            &asn_DEF_X509CSR, response, ASFM_FREE_EVERYTHING);
    }

    if (request != NULL)
    {
        asn_DEF_GetVAUCSRRequest.op->free_struct(
            &asn_DEF_GetVAUCSRRequest, request, ASFM_FREE_EVERYTHING);
    }
    if (p_answ != NULL)
    {
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        free(pCmdData);
    }
    return retVal;
}

ERP_API_FUNC x509CSROutput ERP_GenerateECIESCSR(
    HSMSession sesh,            // HSM Session
    GetVAUCSRInput input) // input for command.
{
    return ERP_Generate_EC_CSR(sesh, input, ERP_SFC_GENERATE_ECIES_CSR);
}

ERP_API_FUNC x509CSROutput ERP_GenerateVAUSIGCSR(
    HSMSession sesh,            // HSM Session
    GetVAUCSRInput input) // input for command.
{
    return ERP_Generate_EC_CSR(sesh, input, ERP_SFC_GENERATE_VAUSIG_CSR);
}

ERP_API_FUNC x509CSROutput ERP_GenerateAUTCSR(
    HSMSession sesh,            // HSM Session
    GetVAUCSRInput input) // input for command.
{
    return ERP_Generate_EC_CSR(sesh, input, ERP_SFC_GENERATE_AUT_CSR);
}

ERP_API_FUNC SingleBlobOutput ERP_TrustTPMMfr(
    HSMSession sesh,            // HSM Session
    TrustTPMMfrInput input) // input for command.
{
    SingleBlobOutput retVal = { 0, {0,0,""} };

    // Need to use calloc because lib relies on zeroing of empty structure memory.
    TrustTPMMfrRequest_t* request = (TrustTPMMfrRequest_t *)calloc(1, sizeof(TrustTPMMfrRequest_t));
    if (request == NULL)
    {
        retVal.returnCode = ERP_ERR_CALLOC_ERROR;
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        request->desiredGeneration = input.desiredGeneration;
        retVal.returnCode = asn_buffer2OctetString(&(request->certificateData), input.certData, input.certLength);

    }
    size_t cmdLength = 0;
    unsigned char* pCmdData = NULL;
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_enc_rval_t er;  /* Encoder return value */

        er = der_encode_dynamic_buffer(&asn_DEF_TrustTPMMfrRequest, request,
            &cmdLength,&pCmdData);
        if (er.encoded == -1)
        { // Failed to encode the data.
            retVal.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        }
    }
    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;

#ifdef TRACE_HSM_API
    fprintf(stderr,"\nExecuting TrustTPMMfr command ...\n");
    API_xtrace("Command: %s\n", pCmdData, (int) cmdLength);
#endif

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = ERP_FirmwareExec(sesh,
            ERP_MDL_ID,
            ERP_SFC_TRUST_TPM_MFR,
            pCmdData,
            (unsigned int)cmdLength,
            &p_answ,
            &p_l_answ);
    }

#ifdef TRACE_HSM_API
    API_xtrace("Answ", p_answ, p_l_answ);
#endif

    // Extract Single Blob from result:
    SingleBlob_t* TokenOut = NULL;    /* Note this 0! */

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_dec_rval_t rval;

        rval = asn_DEF_SingleBlob.op->ber_decoder(0,
            &asn_DEF_SingleBlob,
            (void**)&TokenOut,
            p_answ, p_l_answ,
            0);

        if (rval.code != RC_OK)
        {
            retVal.returnCode = ERP_ERR_ASN1DECODING_ERROR;
        }
    }
    else {
        retVal.BlobOut.BlobGeneration = 0;
        retVal.BlobOut.BlobLength = 0;
        retVal.BlobOut.BlobData[0] = '\0';
    }

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        if (TokenOut->aBlob.size > MAX_BUFFER)
        {
            retVal.returnCode = ERP_ERR_BUFFER_TOO_SMALL;
        }
        else {
            retVal.BlobOut.BlobLength = TokenOut->aBlob.size;
            memcpy(retVal.BlobOut.BlobData, TokenOut->aBlob.buf, TokenOut->aBlob.size);
            // First four bytes of
            retVal.BlobOut.BlobGeneration = TokenOut->blobGeneration;
        }
    }
    if (TokenOut != NULL)
    {
        asn_DEF_SingleBlob.op->free_struct(
            &asn_DEF_SingleBlob, TokenOut, ASFM_FREE_EVERYTHING);
    }
    if (request != NULL)
    {
        asn_DEF_TrustTPMMfrRequest.op->free_struct(
            &asn_DEF_TrustTPMMfrRequest, request, ASFM_FREE_EVERYTHING);
    }
    if (p_answ != NULL)
    {
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        free(pCmdData);
    }
    return retVal;
}

ERP_API_FUNC SingleBlobOutput ERP_EnrollTPMEK(
    HSMSession sesh,            // HSM Session
    EnrollTPMEKInput input) // input for command.
{
    SingleBlobOutput retVal = { 0, {0,0,""} };

    // Need to use calloc because lib relies on zeroing of empty structure memory.
    EnrollTPMRequest_t* request = (EnrollTPMRequest_t *)calloc(1, sizeof(EnrollTPMRequest_t));
    if (request == NULL)
    {
        retVal.returnCode = ERP_ERR_CALLOC_ERROR;
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        request->desiredGeneration = input.desiredGeneration;
        retVal.returnCode = asn_buffer2OctetString(&(request->certificateEK), input.EKCertData, input.EKCertLength);
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->certTPMMfrBlob), &(input.TPMMfrBlob));
    }

    size_t cmdLength = 0;
    unsigned char* pCmdData = NULL;
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_enc_rval_t er;  /* Encoder return value */

        er = der_encode_dynamic_buffer(
            &asn_DEF_EnrollTPMRequest,
            request,
            &cmdLength,
            &pCmdData);
        if (er.encoded == -1)
        { // Failed to encode the data.
            retVal.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        }
    }
    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;

#ifdef TRACE_HSM_API
    fprintf(stderr,"\nExecuting EnrollTPMEK command ...\n");
    API_xtrace("Command Data: %s\n", pCmdData, (int) cmdLength);
#endif

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = ERP_FirmwareExec(sesh,
            ERP_MDL_ID,
            ERP_SFC_ENROLL_TPM_EK,
            pCmdData,
            (unsigned int)cmdLength,
            &p_answ,
            &p_l_answ);
    }

#ifdef TRACE_HSM_API
    API_xtrace("Answ", p_answ, p_l_answ);
#endif

    HandleSingleBlobResult(p_answ, p_l_answ, &retVal);

    if (request != NULL)
    {
        asn_DEF_EnrollTPMRequest.op->free_struct(
            &asn_DEF_EnrollTPMRequest, request, ASFM_FREE_EVERYTHING);
    }
    if (p_answ != NULL)
    {
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        free(pCmdData);
    }
    return retVal;
}

ERP_API_FUNC AKChallengeOutput ERP_GetAKChallenge(
    HSMSession sesh,            // HSM Session
    AKChallengeInput input) // input for command.
{
    AKChallengeOutput retVal = { ERP_ERR_NOERROR, {0,0,""},0,"",0,"" };

    // Need to use calloc because lib relies on zeroing of empty structure memory.
    GetAKChallenge_t* request = (GetAKChallenge_t *)calloc(1, sizeof(GetAKChallenge_t));
    if (request == NULL)
    {
        retVal.returnCode = ERP_ERR_CALLOC_ERROR;
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        request->desiredGeneration = input.desiredGeneration;
        retVal.returnCode = asn_buffer2OctetString(&(request->certAK), input.AKPubData, input.AKPubLength);
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_buffer2OctetString(&(request->nameAK), input.AKName, TPM_NAME_LEN);
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->trustedEKBlob), &(input.KnownEKBlob));
    }
    size_t cmdLength = 0;
    unsigned char* pCmdData = NULL;
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_enc_rval_t er;  /* Encoder return value */

        er = der_encode_dynamic_buffer(&asn_DEF_GetAKChallenge, request,
                        &cmdLength,&pCmdData);
        if (er.encoded == -1)
        { // Failed to encode the data.
            retVal.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        }
    }
    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;

#ifdef TRACE_HSM_API
    fprintf(stderr,"\nExecuting GetAKChallenge command ...\n");
    API_xtrace("Command Data: %s\n", pCmdData, (int) cmdLength);
#endif

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = ERP_FirmwareExec(sesh,
            ERP_MDL_ID,
            ERP_SFC_GET_AK_CHALLENGE,
            pCmdData,
            (unsigned int)cmdLength,
            &p_answ,
            &p_l_answ);
    }

#ifdef TRACE_HSM_API
    API_xtrace("Answ", p_answ, p_l_answ);
#endif

    // Extract Single Blob from result:
    AKChallengeResponse_t* response = NULL;    /* Note this 0! */

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_dec_rval_t rval;

        rval = asn_DEF_AKChallengeResponse.op->ber_decoder(0,
            &asn_DEF_AKChallengeResponse,
            (void**)&response,
            p_answ, p_l_answ,
            0);

        if (rval.code != RC_OK)
        {
            retVal.returnCode = ERP_ERR_ASN1DECODING_ERROR;
        }
    }

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        if (response->challengeBlob.aBlob.size > MAX_BUFFER)
        {
            retVal.returnCode = ERP_ERR_BUFFER_TOO_SMALL;
        }
        else {
            retVal.ChallengeBlob.BlobLength = response->challengeBlob.aBlob.size;
            memcpy(    retVal.ChallengeBlob.BlobData,
                    response->challengeBlob.aBlob.buf,
                    response->challengeBlob.aBlob.size);
            // First four bytes of
            retVal.ChallengeBlob.BlobGeneration = response->challengeBlob.blobGeneration;
        }
        if (response->credential.size > MAX_BUFFER)
        {
            retVal.returnCode = ERP_ERR_BUFFER_TOO_SMALL;
        }
        else {
            retVal.encCredentialLength = response->credential.size;
            memcpy(retVal.encCredentialData, response->credential.buf, response->credential.size);
        }
        if (response->secret.size > MAX_BUFFER)
        {
            retVal.returnCode = ERP_ERR_BUFFER_TOO_SMALL;
        }
        else {
            retVal.secretLength = response->secret.size;
            memcpy(retVal.secretData, response->secret.buf, response->secret.size);
        }
    }
    if (response != NULL)
    {
        asn_DEF_AKChallengeResponse.op->free_struct(
            &asn_DEF_AKChallengeResponse, response, ASFM_FREE_EVERYTHING);
    }

    if (request != NULL)
    {
        asn_DEF_GetAKChallenge.op->free_struct(
            &asn_DEF_GetAKChallenge, request, ASFM_FREE_EVERYTHING);
    }
    if (p_answ != NULL)
    {
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        free(pCmdData);
    }
    return retVal;
}

ERP_API_FUNC SingleBlobOutput ERP_EnrollTPMAK(
    HSMSession sesh,            // HSM Session
    EnrollTPMAKInput input) // input for command.
{
    SingleBlobOutput retVal = { 0, {0,0,""} };

    // Need to use calloc because lib relies on zeroing of empty structure memory.
    EnrollAKRequest_t* request = calloc(1, sizeof(EnrollAKRequest_t));
    if (request == NULL)
    {
        retVal.returnCode = ERP_ERR_CALLOC_ERROR;
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        request->desiredGeneration = input.desiredGeneration;
        retVal.returnCode = asn_buffer2OctetString(&(request->certAK), input.AKPubData, input.AKPubLength);
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_buffer2OctetString(
            &(request->decryptedCredential),
            input.decCredentialData,
            input.decCredentialLength);
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_buffer2OctetString(&(request->nameAK), input.AKName, TPM_NAME_LEN);
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->challengeBlob), &(input.challengeBlob));
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->trustedEKBlob), &(input.KnownEKBlob));
    }

    size_t cmdLength = 0;
    unsigned char* pCmdData = NULL;
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_enc_rval_t er;  /* Encoder return value */

        er = der_encode_dynamic_buffer(&asn_DEF_EnrollAKRequest, request,
                            &cmdLength,&pCmdData);
        if (er.encoded == -1)
        { // Failed to encode the data.
            retVal.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        }
    }
    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;

#ifdef TRACE_HSM_API
    fprintf(stderr,"\nExecuting EnrollTPMAK command ...\n");
    API_xtrace("Command Data: %s\n", pCmdData, (int) cmdLength);
#endif

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = ERP_FirmwareExec(sesh,
            ERP_MDL_ID,
            ERP_SFC_ENROLL_TPM_AK,
            pCmdData,
            (unsigned int)cmdLength,
            &p_answ,
            &p_l_answ);
    }

#ifdef TRACE_HSM_API
    API_xtrace("Answ", p_answ, p_l_answ);
#endif

    HandleSingleBlobResult(p_answ, p_l_answ, &retVal);

    if (request != NULL)
    {
        asn_DEF_EnrollAKRequest.op->free_struct(
            &asn_DEF_EnrollAKRequest, request, 0);
    }
    if (p_answ != NULL)
    {
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        free(pCmdData);
    }
    return retVal;
}

ERP_API_FUNC SingleBlobOutput ERP_EnrollEnclave(
    HSMSession sesh,            // HSM Session
    EnrollEnclaveInput input) // input for command.
{
    SingleBlobOutput retVal = { 0, {0,0,""} };

    // Need to use calloc because lib relies on zeroing of empty structure memory.
    EnrollEnclaveRequest_t* request = calloc(1, sizeof(EnrollEnclaveRequest_t));
    if (request == NULL)
    {
        retVal.returnCode = ERP_ERR_CALLOC_ERROR;
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        request->desiredGeneration = input.desiredGeneration;
        retVal.returnCode = asn_buffer2OctetString(&(request->quotedData), input.quoteData, input.quoteLength);
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_buffer2OctetString(
            &(request->signature),
            input.signatureData,
            input.signatureLength);
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_buffer2OctetString(&(request->nameAK), input.AKName, TPM_NAME_LEN);
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->aNONCEBlob), &(input.NONCEBlob));
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->trustedAKBlob), &(input.KnownAKBlob));
    }

    size_t cmdLength = 0;
    unsigned char* pCmdData = NULL;
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_enc_rval_t er;  /* Encoder return value */

        er = der_encode_dynamic_buffer(&asn_DEF_EnrollEnclaveRequest, request,
                            &cmdLength,&pCmdData);
        if (er.encoded == -1)
        { // Failed to encode the data.
            retVal.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        }
    }
    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;

#ifdef TRACE_HSM_API
    fprintf(stderr,"\nExecuting EnrollEnclave command ...\n");
    API_xtrace("Command Data: %s\n", pCmdData, (int) cmdLength);
#endif

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = ERP_FirmwareExec(sesh,
            ERP_MDL_ID,
            ERP_SFC_ENROLL_ENCLAVE,
            pCmdData,
            (unsigned int)cmdLength,
            &p_answ,
            &p_l_answ);
    }

#ifdef TRACE_HSM_API
    API_xtrace("Answ", p_answ, p_l_answ);
#endif

    HandleSingleBlobResult(p_answ, p_l_answ, &retVal);

    if (request != NULL)
    {
        asn_DEF_EnrollEnclaveRequest.op->free_struct(
            &asn_DEF_EnrollEnclaveRequest, request, 0);
    }
    if (p_answ != NULL)
    {
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        free(pCmdData);
    }
    return retVal;
}

ERP_API_FUNC SingleBlobOutput ERP_GetTEEToken(
    HSMSession sesh,            // HSM Session
    TEETokenRequestInput input) // input for command.
{
    SingleBlobOutput retVal = { 0,{0,0,""} };

    // Need to use calloc because lib relies on zeroing of empty structure memory.
    TEETokenRequest_t* request = calloc(1, sizeof(TEETokenRequest_t));
    if (request == NULL)
    {
        retVal.returnCode = ERP_ERR_CALLOC_ERROR;
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->aNONCEBlob), &(input.NONCEBlob));
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_buffer2OctetString(&(request->nameAK), input.AKName, TPM_NAME_LEN);
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_buffer2OctetString(&(request->quoteData), input.QuoteData, input.QuoteDataLength);
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_buffer2OctetString(&(request->quoteSignature), input.QuoteSignature, input.QuoteSignatureLength);
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->knownAKBlob), &(input.KnownAKBlob));
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->knownQuoteBlob), &(input.KnownQuoteBlob));
    }

    size_t cmdLength = 0;
    unsigned char* pCmdData = NULL;
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_enc_rval_t er;  /* Encoder return value */

        er = der_encode_dynamic_buffer(&asn_DEF_TEETokenRequest, request,
                            &cmdLength,&pCmdData);
        if (er.encoded == -1)
        { // Failed to encode the data.
            retVal.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        }
    }
    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;

#ifdef TRACE_HSM_API
    fprintf(stderr,"\nExecuting getTEEToken command ...\n");
    API_xtrace("Command: %s\n", pCmdData, (int) cmdLength);
#endif

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = ERP_FirmwareExec(sesh,
            ERP_MDL_ID,
            ERP_SFC_GET_TEE_TOKEN,
            pCmdData,
            (unsigned int)cmdLength,
            &p_answ,
            &p_l_answ);
    }

#ifdef TRACE_HSM_API
    API_xtrace("Answ", p_answ, p_l_answ);
#endif

    HandleSingleBlobResult(p_answ, p_l_answ, &retVal);

    if (request != NULL)
    {
        asn_DEF_TEETokenRequest.op->free_struct(
            &asn_DEF_TEETokenRequest, request, 0);
    }
    if (p_answ != NULL)
    {
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        free(pCmdData);
    }
    return retVal;
}

// Shared method for different versions of derivexxxKey command.
DeriveKeyOutput ERP_DeriveKey(
    HSMSession sesh,            // HSM Session
    unsigned int SFC_Code, // Firmware command code.
    DeriveKeyInput input)    // Input Data for command
{
    DeriveKeyOutput retVal = { ERP_ERR_NOERROR,0,{0},{0} };

    // Need to use calloc because lib relies on zeroing of empty structure memory.
    DeriveKeyRequest_t* request = calloc(1, sizeof(DeriveKeyRequest_t));
    if (request == NULL)
    {
        retVal.returnCode = ERP_ERR_CALLOC_ERROR;
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->tokenTEE), &(input.TEEToken));
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_buffer2OctetString(&(request->nameAK), input.AKName, TPM_NAME_LEN);
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->derivationKeyBlob), &(input.derivationKey));
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_buffer2OctetString(&(request->derivationData),
            input.derivationData, input.derivationDataLength);
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        request->initialDerivation = (input.initialDerivation == 1 ? 1 : 0);
    }

    size_t cmdLength = 0;
    unsigned char* pCmdData = NULL;
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_enc_rval_t er;  /* Encoder return value */

        er = der_encode_dynamic_buffer(&asn_DEF_DeriveKeyRequest, request,
                                &cmdLength,&pCmdData);
        if (er.encoded == -1)
        { // Failed to encode the data.
            retVal.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        }
    }
    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;

#ifdef TRACE_HSM_API
    fprintf(stderr,"\nExecuting deriveKeycommand %.8x...\n",SFC_Code);
    API_xtrace("Command: %s\n", pCmdData, (int) cmdLength);
#endif

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = ERP_FirmwareExec(sesh,
            ERP_MDL_ID,
            SFC_Code,
            pCmdData,
            (unsigned int)cmdLength,
            &p_answ,
            &p_l_answ);
    }

#ifdef TRACE_HSM_API
    API_xtrace("Answ", p_answ, p_l_answ);
#endif

    // Extract Single Blob from result:
    DerivedKey_t* response = NULL;    /* Note this 0! */

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_dec_rval_t rval;

        rval = asn_DEF_DerivedKey.op->ber_decoder(0,
            &asn_DEF_DerivedKey,
            (void**)&response,
            p_answ, p_l_answ,
            0);

        if (rval.code != RC_OK)
        {
            retVal.returnCode = ERP_ERR_ASN1DECODING_ERROR;
        }
    }

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        if ((response->derivedKey.size != AES_256_LEN) ||
            (response->usedDerivationData.size > MAX_BUFFER))
        {
            retVal.returnCode = ERP_ERR_BUFFER_TOO_SMALL;
        }
        else {
            retVal.derivationDataLength = response->usedDerivationData.size;
            memcpy(retVal.derivationData,
                response->usedDerivationData.buf,
                response->usedDerivationData.size);
            memcpy(retVal.derivedKey, response->derivedKey.buf, AES_256_LEN);
        }
    }
    if (response != NULL)
    {
        asn_DEF_DerivedKey.op->free_struct(
            &asn_DEF_DerivedKey, response, 0);
    }
    if (request != NULL)
    {
        asn_DEF_DeriveKeyRequest.op->free_struct(
            &asn_DEF_DeriveKeyRequest, request, 0);
    }
    if (p_answ != NULL)
    {
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        free(pCmdData);
    }
    return retVal;
}

// Shared method for different versions of derivexxxKey command.
AES128KeyOutput ERP_DoVAUECIES128(
    HSMSession sesh,            // HSM Session
    DoVAUECIESInput input)    // Input Data for command
{
    AES128KeyOutput retVal = { ERP_ERR_NOERROR, "" };

    // Need to use calloc because lib relies on zeroing of empty structure memory.
    DoVAUECIESRequest_t* request = calloc(1, sizeof(DoVAUECIESRequest_t));
    if (request == NULL)
    {
        retVal.returnCode = ERP_ERR_CALLOC_ERROR;
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->tokenTEE), &(input.TEEToken));
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->keyPair), &(input.ECIESKeyPair));
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_buffer2OctetString(&(request->clientPublicKey), input.clientPublicKeyData, input.clientPublicKeyLength);
    }

    size_t cmdLength = 0;
    unsigned char* pCmdData = NULL;
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_enc_rval_t er;  /* Encoder return value */

        er = der_encode_dynamic_buffer(&asn_DEF_DoVAUECIESRequest, request,
                                &cmdLength,&pCmdData);
        if (er.encoded == -1)
        { // Failed to encode the data.
            retVal.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        }
    }
    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;

#ifdef TRACE_HSM_API
    fprintf(stderr,"\nExecuting DoVAUECIES command ...\n");
    API_xtrace("Command: %s\n", pCmdData, (int) cmdLength);
#endif

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = ERP_FirmwareExec(sesh,
            ERP_MDL_ID,
            ERP_SFC_DO_ECIES_128,
            pCmdData,
            (unsigned int)cmdLength,
            &p_answ,
            &p_l_answ);
    }

#ifdef TRACE_HSM_API
    API_xtrace("Answ", p_answ, p_l_answ);
#endif

    // Extract Single Blob from result:
    AES128_t* response = NULL;    /* Note this 0! */

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_dec_rval_t rval;

        rval = asn_DEF_AES128.op->ber_decoder(0,
            &asn_DEF_AES128,
            (void**)&response,
            p_answ, p_l_answ,
            0);

        if (rval.code != RC_OK)
        {
            retVal.returnCode = ERP_ERR_ASN1DECODING_ERROR;
        }
    }

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        if ((response->keyValue.size != AES_128_LEN) ||
            (response->keyValue.size > MAX_BUFFER))
        {
            retVal.returnCode = ERP_ERR_BUFFER_TOO_SMALL;
        }
        else {
            memcpy(&(retVal.AESKey[0]),
                response->keyValue.buf,
                response->keyValue.size); // Already checked to be AES_128_LEN
        }
    }
    if (response != NULL)
    {
        asn_DEF_AES128.op->free_struct(
            &asn_DEF_AES128, response, 0);
    }
    if (request != NULL)
    {
        asn_DEF_DoVAUECIESRequest.op->free_struct(
            &asn_DEF_DoVAUECIESRequest, request, 0);
    }
    if (p_answ != NULL)
    {
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        free(pCmdData);
    }
    return retVal;
}


ERP_API_FUNC DeriveKeyOutput ERP_DeriveTaskKey(
    HSMSession sesh,            // HSM Session
    DeriveKeyInput input)    // Input Data for command
{
    return ERP_DeriveKey(sesh, ERP_SFC_DERIVE_TASK_KEY, input);
}
ERP_API_FUNC DeriveKeyOutput ERP_DeriveAuditKey(
    HSMSession sesh,            // HSM Session
    DeriveKeyInput input)    // Input Data for command
{
    return ERP_DeriveKey(sesh, ERP_SFC_DERIVE_AUDIT_KEY, input);
}

ERP_API_FUNC DeriveKeyOutput ERP_DeriveCommsKey(
    HSMSession sesh,            // HSM Session
    DeriveKeyInput input)    // Input Data for command
{
    return ERP_DeriveKey(sesh, ERP_SFC_DERIVE_COMMS_KEY, input);
}

ERP_API_FUNC DeriveKeyOutput ERP_DeriveChargeItemKey(
    HSMSession sesh,            // HSM Session
    DeriveKeyInput input)    // Input Data for command
{
    return ERP_DeriveKey(sesh, ERP_SFC_DERIVE_CHARGE_ITEM_KEY, input);
}

ERP_API_FUNC PublicKeyOutput ERP_GetECPublicKey(
    HSMSession sesh,            // HSM Session
    SingleBlobInput input) // input for command.
{
    PublicKeyOutput retVal = { ERP_ERR_NOERROR, 0,"" };

    // Need to use calloc because lib relies on zeroing of empty structure memory.
    SingleBlobRequest_t* request = calloc(1, sizeof(SingleBlobRequest_t));
    if (request == NULL)
    {
        retVal.returnCode = ERP_ERR_CALLOC_ERROR;
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->blobIn), &(input.BlobIn));
    }
    size_t cmdLength = 0;
    unsigned char* pCmdData = NULL;
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_enc_rval_t er;  /* Encoder return value */

        er = der_encode_dynamic_buffer(&asn_DEF_SingleBlobRequest, request,
            &cmdLength, &pCmdData);
        if (er.encoded == -1)
        { // Failed to encode the data.
            retVal.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        }
    }
    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;

#ifdef TRACE_HSM_API
    fprintf(stderr,"\nExecuting GetECPublicKey command ...\n");
    API_xtrace("Command Data: %s\n", pCmdData, (int)cmdLength);
#endif

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = ERP_FirmwareExec(sesh,
            ERP_MDL_ID,
            ERP_SFC_GET_EC_PUBLIC_KEY,
            pCmdData,
            (unsigned int)cmdLength,
            &p_answ,
            &p_l_answ);
    }

#ifdef TRACE_HSM_API
    API_xtrace("Answ", p_answ, p_l_answ);
#endif

    // Extract ECC Public Key from result:
    ERPOctetString_t* response = NULL;    /* Note this 0! */

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_dec_rval_t rval;

        rval = asn_DEF_ERPOctetString.op->ber_decoder(0,
            &asn_DEF_ERPOctetString,
            (void**)&response,
            p_answ, p_l_answ,
            0);

        if (rval.code != RC_OK)
        {
            retVal.returnCode = ERP_ERR_ASN1DECODING_ERROR;
        }
    }

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        if (response->octets.size > MAX_BUFFER)
        {
            retVal.returnCode = ERP_ERR_BUFFER_TOO_SMALL;
        }
        else {
            retVal.keyLength = response->octets.size;
            memcpy(retVal.keyData,
                response->octets.buf,
                response->octets.size);
        }
    }
    if (response != NULL)
    {
        asn_DEF_ERPOctetString.op->free_struct(
            &asn_DEF_ERPOctetString, response, 0);
    }

    if (request != NULL)
    {
        asn_DEF_SingleBlobRequest.op->free_struct(
            &asn_DEF_SingleBlobRequest, request, 0);
    }
    if (p_answ != NULL)
    {
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        free(pCmdData);
    }
    return retVal;
}

ERP_API_FUNC PrivateKeyOutput ERP_GetVAUSIGPrivateKey(
    HSMSession sesh,            // HSM Session
    TwoBlobGetKeyInput input) // input for command.
{
    PrivateKeyOutput retVal = { ERP_ERR_NOERROR, 0,"" };

    // Need to use calloc because lib relies on zeroing of empty structure memory.
    TwoBlobKeyRequest_t* request = calloc(1, sizeof(TwoBlobKeyRequest_t));
    if (request == NULL)
    {
        retVal.returnCode = ERP_ERR_CALLOC_ERROR;
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->teeToken), &(input.TEEToken));
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->key), &(input.Key));
    }
    size_t cmdLength = 0;
    unsigned char* pCmdData = NULL;
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_enc_rval_t er;  /* Encoder return value */

        er = der_encode_dynamic_buffer(&asn_DEF_TwoBlobKeyRequest, request,
                            &cmdLength,&pCmdData);
        if (er.encoded == -1)
        { // Failed to encode the data.
            retVal.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        }
    }
    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;

#ifdef TRACE_HSM_API
    fprintf(stderr,"\nExecuting GetECPublicKey command ...\n");
    API_xtrace("Command Data: %s\n", pCmdData, (int) cmdLength);
#endif

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = ERP_FirmwareExec(sesh,
            ERP_MDL_ID,
            ERP_SFC_GET_VAUSIG_PRIVATE_KEY,
            pCmdData,
            (unsigned int)cmdLength,
            &p_answ,
            &p_l_answ);
    }

#ifdef TRACE_HSM_API
    API_xtrace("Answ", p_answ, p_l_answ);
#endif

    // Extract ECC Public Key from result:
    ERPOctetString_t* response = NULL;    /* Note this 0! */

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_dec_rval_t rval;

        rval = asn_DEF_ERPOctetString.op->ber_decoder(0,
            &asn_DEF_ERPOctetString,
            (void**)&response,
            p_answ, p_l_answ,
            0);

        if (rval.code != RC_OK)
        {
            retVal.returnCode = ERP_ERR_ASN1DECODING_ERROR;
        }
    }

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        if (response->octets.size > MAX_BUFFER)
        {
            retVal.returnCode = ERP_ERR_BUFFER_TOO_SMALL;
        }
        else {
            retVal.keyLength = response->octets.size;
            memcpy(retVal.keyData,
                response->octets.buf,
                response->octets.size);
        }
    }
    if (response != NULL)
    {
        asn_DEF_ERPOctetString.op->free_struct(
            &asn_DEF_ERPOctetString, response, 0);
    }

    if (request != NULL)
    {
        asn_DEF_TwoBlobKeyRequest.op->free_struct(
            &asn_DEF_TwoBlobKeyRequest, request, 0);
    }
    if (p_answ != NULL)
    {
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        free(pCmdData);
    }
    return retVal;
}

/**
 * Returns the requested number of bytes of hardware generated random data.  Intended for seeding of software PRNGs.
 *
 * @param sesh                                    a valid HSM session, i.e. sesh.status == HSMLoggedIn erp working
 * @param input                                   <= MAX_RND_BYTES (320) number of requested random bytes
 * @param RNDBytesOutput.returnCode               0 for no error, error code otherwise
 *        RNDBytesOutput.RNDDataLen               <= input <= MAX_RND_BYTES number of returned random bytes
 *        RNDBytesOutput.RNDData                  the requested random data
 */
ERP_API_FUNC RNDBytesOutput ERP_GetRNDBytes(
    HSMSession sesh,            // HSM Session
    UIntInput input) // The number of bytes of RND to return.   Maximum MAX_RND_BYTES = 320.
{
    RNDBytesOutput retVal = { ERP_ERR_NOERROR, 0, {0} };

    // Need to use calloc because lib relies on zeroing of empty structure memory.
    INTSequence_t* intIn = calloc(1, sizeof(INTSequence_t));
    if (intIn == NULL)
    {
        retVal.returnCode = ERP_ERR_CALLOC_ERROR;
    }
    size_t cmdLength = 0;
    unsigned char* pCmdData = NULL;
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        intIn->anInt = input.intValue;
        asn_enc_rval_t er;  /* Encoder return value */

        er = der_encode_dynamic_buffer(&asn_DEF_INTSequence, intIn,
            &cmdLength, &pCmdData);
        if (er.encoded == -1)
        { // Failed to encode the data.
            retVal.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        }
    }

    if (intIn != NULL)
    {
        asn_DEF_INTSequence.op->free_struct(
                &asn_DEF_INTSequence, intIn, ASFM_FREE_EVERYTHING);
    }

    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;

#ifdef TRACE_HSM_API
    fprintf(stderr,"\nExecuting GetRND256 command ...\n");
#endif

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = ERP_FirmwareExec(sesh,
            ERP_MDL_ID,
            ERP_SFC_GET_RND_BYTES,
            pCmdData,
            (unsigned int)cmdLength,
            &p_answ,
            &p_l_answ);
    }

#ifdef TRACE_HSM_API
    API_xtrace("Answ", p_answ, p_l_answ);
#endif

    // Extract Single Blob from result:
    ERPOctetString_t* response = NULL;    /* Note this 0! */

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_dec_rval_t rval;

        rval = asn_DEF_ERPOctetString.op->ber_decoder(0,
            &asn_DEF_ERPOctetString,
            (void**)&response,
            p_answ, p_l_answ,
            0);

        if (rval.code != RC_OK)
        {
            retVal.returnCode = ERP_ERR_ASN1DECODING_ERROR;
        }
    }

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        if (response->octets.size > MAX_RND_BYTES)
        {
            retVal.returnCode = ERP_ERR_RESPONSE_TOO_LONG;
        }
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.RNDDataLen = response->octets.size;
        memcpy(retVal.RNDData,
                response->octets.buf,
                retVal.RNDDataLen);
    }
    if (response != NULL)
    {
        asn_DEF_ERPOctetString.op->free_struct(
            &asn_DEF_ERPOctetString, response, 0);
    }
    if (p_answ != NULL)
    {
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        free(pCmdData);
    }
    return retVal;
}

/**
 * Shared Implementation Method.
 * Return the secret value of an AES256 Key from a Blob.
 *    Accepted Blob types are Hash Key Blobs or Pseudoname Key Blobs.
`*    This requires a valid TEE Token.
 *
 * @param sesh                                    a valid HSM session, i.e. sesh.status == HSMLoggedIn with erp working or erp setup
 * @param input.TEEToken                          currently valid TEE Token
 * @param input.KeyPair                           ERP Blob containing a Hash Key encrypted AES 256 key which is provided by independent configuration process.
 * @param SFCCode                                 Firmware method id which this function will call.
 * @return PublicKeyOutput.returnCode             0 for no error, error code otherwise
 *         PublicKeyOutput.keyLength              AES 256 key length
 *         PublicKeyOutput.keyData                AES 256 Key length of binary data containing the raw key value
 */
ERP_API_FUNC AES256KeyOutput UnwrapAES256Key(
    HSMSession sesh,
    TwoBlobGetKeyInput input,
    unsigned int SFCCode)
{
    AES256KeyOutput retVal = { ERP_ERR_NOERROR,{0} };

    // Need to use calloc because lib relies on zeroing of empty structure memory.
    TwoBlobKeyRequest_t* request = calloc(1, sizeof(TwoBlobKeyRequest_t));
    if (request == NULL)
    {
        retVal.returnCode = ERP_ERR_CALLOC_ERROR;
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->teeToken), &(input.TEEToken));
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->key), &(input.Key));
    }

    size_t cmdLength = 0;
    unsigned char* pCmdData = NULL;
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_enc_rval_t er;  /* Encoder return value */

        er = der_encode_dynamic_buffer(&asn_DEF_TwoBlobKeyRequest, request,
            &cmdLength, &pCmdData);
        if (er.encoded == -1)
        { // Failed to encode the data.
            retVal.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        }
    }
    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;

#ifdef TRACE_HSM_API
    fprintf(stderr,"\nExecuting UnwrapXXXKeycommand %.8x...\n", SFCCode);
    API_xtrace("Command: %s\n", pCmdData, (int)cmdLength);
#endif

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = ERP_FirmwareExec(sesh,
            ERP_MDL_ID,
            SFCCode,
            pCmdData,
            (unsigned int)cmdLength,
            &p_answ,
            &p_l_answ);
    }

#ifdef TRACE_HSM_API
    API_xtrace("Answ", p_answ, p_l_answ);
#endif

    // Extract AES 256 Key from result:
    AES256_t* response = NULL;    /* Note this 0! */

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_dec_rval_t rval;

        rval = asn_DEF_AES256.op->ber_decoder(0,
            &asn_DEF_AES256,
            (void**)&response,
            p_answ, p_l_answ,
            0);

        if (rval.code != RC_OK)
        {
            retVal.returnCode = ERP_ERR_ASN1DECODING_ERROR;
        }
    }

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        if (response->keyValue.size != AES_256_LEN)
        {
            retVal.returnCode = ERP_ERR_BUFFER_TOO_SMALL;
        }
        else {
            memcpy(retVal.Key, response->keyValue.buf, AES_256_LEN);
        }
    }
    if (response != NULL)
    {
        asn_DEF_AES256.op->free_struct(
            &asn_DEF_AES256, response, 0);
    }
    if (request != NULL)
    {
        asn_DEF_TwoBlobKeyRequest.op->free_struct(
            &asn_DEF_TwoBlobKeyRequest, request, 0);
    }
    if (p_answ != NULL)
    {
        explicit_bzero(p_answ, p_l_answ);
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        explicit_bzero(pCmdData, cmdLength);
        free(pCmdData);
    }
    return retVal;
}

/**
 * Return the secret value of a Hash Key to be used for HMAC ID calculation in the VAU.   This requires a valid TEE Token.
 *
 * @param sesh                                    a valid HSM session, i.e. sesh.status == HSMLoggedIn with erp working or erp setup
 * @param input.TEEToken                          currently valid TEE Token
 * @param input.KeyPair                           ERP Blob containing a Hash Key encrypted AES 256 key which is provided by independent configuration process.
 * @return PublicKeyOutput.returnCode             0 for no error, error code otherwise
 *         PublicKeyOutput.keyLength              AES 256 key length
 *         PublicKeyOutput.keyData                AES 256 Key length of binary data containing the raw key value
 */
ERP_API_FUNC AES256KeyOutput ERP_UnwrapHashKey(
    HSMSession sesh,
    TwoBlobGetKeyInput input)
{
    return UnwrapAES256Key(sesh, input, ERP_SFC_UNWRAP_HASH_KEY);
}

/**
 * Return the secret value of a Pseudoname Key to be used for Bowdlerisation in the VAU.   This requires a valid TEE Token.
 *
 * @param sesh                                    a valid HSM session, i.e. sesh.status == HSMLoggedIn with erp working or erp setup
 * @param input.TEEToken                          currently valid TEE Token
 * @param input.KeyPair                           ERP Blob containing a Pseudoname Key encrypted AES 256 key which has been generated
 *                                                  by the ERP_GeneratePseudonameKey method called by the VAU.
 * @return PublicKeyOutput.returnCode             0 for no error, error code otherwise
 *         PublicKeyOutput.keyLength              AES 256 key length
 *         PublicKeyOutput.keyData                AES 256 Key length of binary data containing the raw key value
 */
ERP_API_FUNC AES256KeyOutput ERP_UnwrapPseudonameKey(
    HSMSession sesh,
    TwoBlobGetKeyInput input)
{
    return UnwrapAES256Key(sesh, input, ERP_SFC_UNWRAP_PSEUDONAME_KEY);
}

/**
 * Export a single Blob Generation using the AES256 MBK.
 * @pre Requires 20000000 - Administrator permission.
 * @pre Requires Blob Generation must exist in the HSM
 * @param sesh                                  a valid HSM session, i.e. sesh.status == HSMLoggedIn with 20000000 Admin permission.
 * @param input.intValue                        The generation of the blob key to be exported.
 *                                              May NOT be zero.
 * @return BUBlobOutput.returnCode              0 for no error, error code otherwise
 *         BUBlobOutput.BUBlob                  The backup Blob object containing the backup data.
 */
ERP_API_FUNC BUBlobOutput_t ERP_ExportSingleBlobKey(
    HSMSession sesh,
    UIntInput input)
{
    BUBlobOutput_t retVal = { 0 , {0,{0},{0},{0},{0},0,{0} } };

    // Need to use calloc because lib relies on zeroing of empty structure memory.
    INTSequence_t* intIn = (INTSequence_t*)calloc(1, sizeof(INTSequence_t));
    if (intIn == NULL)
    {
        retVal.returnCode = ERP_ERR_CALLOC_ERROR;
    }
    size_t cmdLength = 0;
    unsigned char* pCmdData = NULL;
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        intIn->anInt = input.intValue;
        asn_enc_rval_t er;  /* Encoder return value */

        er = der_encode_dynamic_buffer(&asn_DEF_INTSequence, intIn,
            &cmdLength, &pCmdData);
        if (er.encoded == -1)
        { // Failed to encode the data.
            retVal.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        }
    }
    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;

#ifdef TRACE_HSM_API
    fprintf(stderr, "\nExecuting ExportSingleBlobKey command ...\n");
    API_xtrace("Command: %s\n", pCmdData, (int)cmdLength);
#endif

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = ERP_FirmwareExec(sesh,
            ERP_MDL_ID,
            ERP_SFC_EXPORT_SINGLE_BLOB_KEY,
            pCmdData,
            (unsigned int)cmdLength,
            &p_answ,
            &p_l_answ);
    }

#ifdef TRACE_HSM_API
    API_xtrace("Answ", p_answ, p_l_answ);
#endif

    HandleBUBlobResult(p_answ, p_l_answ, &retVal);

    if (intIn != NULL)
    {
        asn_DEF_INTSequence.op->free_struct(
            &asn_DEF_INTSequence, intIn, ASFM_FREE_EVERYTHING);
    }

    if (p_answ != NULL)
    {
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        free(pCmdData);
    }
    return retVal;
}

/**
 * Import a single Blob Generation using the AES256 MBK.
 * @pre Requires: 20000000 - Administrator permission.
 * @pre Requires The MBK loaded in the HSM must match that in the BUBlob
 * @pre Requires There is no blobkey already present in the HSM for that generation,neither with the same key value, nor a different one.
 * @param sesh                                  a valid HSM session, i.e. sesh.status == HSMLoggedIn with 20000000 Admin permission.
 * @param input.BUBlob                          Backup Blob Structure containing the blob key to be imported.
 * @return EmptyOutput.returnCode               0 for no error, error code otherwise
 */
ERP_API_FUNC EmptyOutput ERP_ImportSingleBlobKey(
    HSMSession sesh,            // HSM Session
    BUBlobInput input)
{
    EmptyOutput retVal = { 0 };

    // Need to use calloc because lib relies on zeroing of empty structure memory.
    BackupBlobRequest_t* blobIn = (BackupBlobRequest_t*)calloc(1, sizeof(BackupBlobRequest_t));
    if (blobIn == NULL)
    {
        retVal.returnCode = ERP_ERR_CALLOC_ERROR;
    }
    size_t cmdLength = 0;
    unsigned char* pCmdData = NULL;

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        if (input.BUBlob.encDataLength > MAX_BUFFER)
        {
            retVal.returnCode = ERP_ERR_BUFFER_TOO_SMALL;
        }
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_buffer2OctetString(&(blobIn->buBlob.blobEncData), input.BUBlob.encData, input.BUBlob.encDataLength);
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        blobIn->buBlob.generation = input.BUBlob.Generation;
        retVal.returnCode = asn_buffer2OctetString(&(blobIn->buBlob.mbkName), input.BUBlob.MBKName, MBK_NAME_LEN);
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_buffer2OctetString(&(blobIn->buBlob.domain), input.BUBlob.Domain, BLOB_DOMAIN_LEN);
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_buffer2OctetString(&(blobIn->buBlob.mbkKCV), input.BUBlob.MBKKCV, MBK_KCV_LEN);
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_buffer2OctetString(&(blobIn->buBlob.blobKeyKCV), input.BUBlob.BlobKeyKCV, SHA_256_LEN);
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_enc_rval_t er;  /* Encoder return value */

        er = der_encode_dynamic_buffer(&asn_DEF_BackupBlobRequest, blobIn,
            &cmdLength, &pCmdData);
        if (er.encoded == -1)
        { // Failed to encode the data.
            retVal.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        }
    }
    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;

#ifdef TRACE_HSM_API
    fprintf(stderr, "\nExecuting ImportSingleBlobKey command ...\n");
    API_xtrace("Command: %s\n", pCmdData, (int)cmdLength);
#endif

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = ERP_FirmwareExec(sesh,
            ERP_MDL_ID,
            ERP_SFC_IMPORT_SINGLE_BLOB_KEY,
            pCmdData,
            (unsigned int)cmdLength,
            &p_answ,
            &p_l_answ);
    }

#ifdef TRACE_HSM_API
    API_xtrace("Answ", p_answ, p_l_answ);
#endif

    // No result data.

    if (blobIn != NULL)
    {
        asn_DEF_BackupBlobRequest.op->free_struct(
            &asn_DEF_BackupBlobRequest, blobIn, ASFM_FREE_EVERYTHING);
    }

    if (p_answ != NULL)
    {
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        free(pCmdData);
    }
    return retVal;
}
/**
 * Create a new Blob containing the contents of an existing blob but reencoded with a different Generation.
 * The intention here is to allow preservation of blob contents when the blob generation of the original blob is to be deleted.   The
 *   intention is that only special cases will require this treatment, e.g. Security reasons mandate hard retiral of some keys
 * There is a guarantee that the new blob and the old blob will return the same Check Value in calls to GetBlobContentsHash()
 * @pre Requires: 00000200 ERP Setup or 00002000 ERP Update Permission
 * @pre The Generation of the blob must be present in the HSM.
 * @pre The input blob must be one os Task, Communications or Audit Derivation Key Blobs.
 * @param sesh                                  a valid HSM session, i.e. sesh.status == HSMLoggedIn with one of the required permissions.
 * @param input.BUBlob                          Backup Blob Structure containing the blob key to be imported.
 * @return SHA256Output.returnCode              0 for no error, error code otherwise
 *         SHA256Outpu.hash                     SHA 256 Hash of Key Derivation Key contained in the blob.
*/
ERP_API_FUNC SingleBlobOutput ERP_MigrateBlob(
    HSMSession sesh,
    MigrateBlobInput_t input)
{
    SingleBlobOutput retVal = { 0,{0,0,""} };

    // Need to use calloc because lib relies on zeroing of empty structure memory.
    MigrateBlobRequest_t* request = calloc(1, sizeof(MigrateBlobRequest_t));
    if (request == NULL)
    {
        retVal.returnCode = ERP_ERR_CALLOC_ERROR;
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        request->newGeneration = input.NewBlobGeneration;
        retVal.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->blobIn), &(input.BlobIn));
    }

    size_t cmdLength = 0;
    unsigned char* pCmdData = NULL;
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_enc_rval_t er;  /* Encoder return value */

        er = der_encode_dynamic_buffer(&asn_DEF_MigrateBlobRequest, request,
            &cmdLength, &pCmdData);
        if (er.encoded == -1)
        { // Failed to encode the data.
            retVal.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        }
    }
    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;

#ifdef TRACE_HSM_API
    fprintf(stderr, "\nExecuting MigrateBlob command ...\n");
    API_xtrace("Command: %s\n", pCmdData, (int)cmdLength);
#endif

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = ERP_FirmwareExec(sesh,
            ERP_MDL_ID,
            ERP_SFC_MIGRATE_BLOB,
            pCmdData,
            (unsigned int)cmdLength,
            &p_answ,
            &p_l_answ);
    }

#ifdef TRACE_HSM_API
    API_xtrace("Answ", p_answ, p_l_answ);
#endif

    HandleSingleBlobResult(p_answ, p_l_answ, &retVal);

    if (request != NULL)
    {
        asn_DEF_MigrateBlobRequest.op->free_struct(
            &asn_DEF_MigrateBlobRequest, request, 0);
    }
    if (p_answ != NULL)
    {
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        free(pCmdData);
    }
    return retVal;
}

/**
 * For Setup and Update Users:   Calculate and return the SHA256 hash of the contents of a Blob.
 * The intention here is to allow identification of a key that may be stored in multiple blobs with different generations as a result
 *   of Blob Migration.
 * The hash is calculated over the derivation key value BEFORE the key value is varied to Task, Comms or Audit purposes.
 * The only guarantee is that multiple calls to this method with blobs containing the same key value will return the same hash.
 * @pre Requires: 00000200 ERP Setup or 00002000 ERP Update Permission
 * @pre The Generation of the blob must be present in the HSM.
 * @pre The input blob must be one os Task, Communications or Audit Derivation Key Blobs.
 * @param sesh                                  a valid HSM session, i.e. sesh.status == HSMLoggedIn with one of the required permissions.
 * @param input.BUBlob                          Backup Blob Structure containing the blob key to be imported.
 * @return SHA256Output.returnCode              0 for no error, error code otherwise
 *         SHA256Outpu.hash                     SHA 256 Hash of Key Derivation Key contained in the blob.
*/
ERP_API_FUNC SHA256Output ERP_GetBlobContentHash(
    HSMSession sesh,
    SingleBlobInput input)
{
    SHA256Output retVal = { ERP_ERR_NOERROR,{0} };

    // Need to use calloc because lib relies on zeroing of empty structure memory.
    SingleBlobRequest_t* request = calloc(1, sizeof(SingleBlobRequest_t));
    if (request == NULL)
    {
        retVal.returnCode = ERP_ERR_CALLOC_ERROR;
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->blobIn), &(input.BlobIn));
    }

    size_t cmdLength = 0;
    unsigned char* pCmdData = NULL;
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_enc_rval_t er;  /* Encoder return value */

        er = der_encode_dynamic_buffer(&asn_DEF_SingleBlobRequest, request,
            &cmdLength, &pCmdData);
        if (er.encoded == -1)
        { // Failed to encode the data.
            retVal.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        }
    }
    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;

#ifdef TRACE_HSM_API
    fprintf(stderr, "\nExecuting GetDerivationKeyHash command %.8x...\n", ERP_SFC_UNWRAP_HASH_KEY);
    API_xtrace("Command: %s\n", pCmdData, (int)cmdLength);
#endif

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = ERP_FirmwareExec(sesh,
            ERP_MDL_ID,
            ERP_SFC_GET_BLOB_CONTENT_HASH,
            pCmdData,
            (unsigned int)cmdLength,
            &p_answ,
            &p_l_answ);
    }

#ifdef TRACE_HSM_API
    API_xtrace("Answ", p_answ, p_l_answ);
#endif

    // Extract SHA 256 Hash from result:
    SHA256Hash_t* response = NULL;    /* Note this 0! */

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_dec_rval_t rval;

        rval = asn_DEF_SHA256Hash.op->ber_decoder(0,
            &asn_DEF_SHA256Hash,
            (void**)&response,
            p_answ, p_l_answ,
            0);

        if (rval.code != RC_OK)
        {
            retVal.returnCode = ERP_ERR_ASN1DECODING_ERROR;
        }
    }

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        if (response->hashValue.size != SHA_256_LEN)
        {
            retVal.returnCode = ERP_ERR_BUFFER_TOO_SMALL;
        }
        else {
            memcpy(retVal.hash, response->hashValue.buf, SHA_256_LEN);
        }
    }
    if (response != NULL)
    {
        asn_DEF_AES256.op->free_struct(
            &asn_DEF_AES256, response, 0);
    }
    if (request != NULL)
    {
        asn_DEF_SingleBlobRequest.op->free_struct(
            &asn_DEF_SingleBlobRequest, request, 0);
    }
    if (p_answ != NULL)
    {
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        free(pCmdData);
    }
    return retVal;
}

/**
 * For Working User:   Calculate and return the SHA256 hash of the contents of a Blob.
 * The intention here is to allow identification of a key that may be stored in multiple blobs with different generations as a result
 *   of Blob Migration.
 * The hash is calculated over the derivation key value BEFORE the key value is varied to Task, Comms or Audit purposes.
 * The only guarantee is that multiple calls to this method with blobs containing the same key value will return the same hash.
 * @pre Requires: 00000020 ERP Working and a currently valid TEEToken.
 * @pre The Generation of the blob must be present in the HSM.
 * @pre The input blob must be one os Task, Communications or Audit Derivation Key Blobs.
 * @param sesh                                  a valid HSM session, i.e. sesh.status == HSMLoggedIn with one of the required permissions.
 * @param input.TEEToken                        currently valid TEE Token
 * @param input.Key                             ERP Blob for which the contents Check Value is to be generated.
 * @return SHA256Output.returnCode              0 for no error, error code otherwise
 *         SHA256Outpu.hash                     SHA 256 Hash of Key Derivation Key contained in the blob.
*/
ERP_API_FUNC SHA256Output ERP_GetBlobContentHashWithToken(
    HSMSession sesh,
    TwoBlobGetKeyInput input)
{
    SHA256Output retVal = { ERP_ERR_NOERROR,{0} };

    // Need to use calloc because lib relies on zeroing of empty structure memory.
    TwoBlobKeyRequest_t* request = calloc(1, sizeof(TwoBlobKeyRequest_t));
    if (request == NULL)
    {
        retVal.returnCode = ERP_ERR_CALLOC_ERROR;
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->teeToken), &(input.TEEToken));
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->key), &(input.Key));
    }

    size_t cmdLength = 0;
    unsigned char* pCmdData = NULL;
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_enc_rval_t er;  /* Encoder return value */

        er = der_encode_dynamic_buffer(&asn_DEF_TwoBlobKeyRequest, request,
            &cmdLength, &pCmdData);
        if (er.encoded == -1)
        { // Failed to encode the data.
            retVal.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        }
    }
    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;

#ifdef TRACE_HSM_API
    fprintf(stderr, "\nExecuting UnwrapHashKeycommand %.8x...\n", ERP_SFC_UNWRAP_HASH_KEY);
    API_xtrace("Command: %s\n", pCmdData, (int)cmdLength);
#endif

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        retVal.returnCode = ERP_FirmwareExec(sesh,
            ERP_MDL_ID,
            ERP_SFC_GET_BLOB_CONTENT_HASH_WITH_TOKEN,
            pCmdData,
            (unsigned int)cmdLength,
            &p_answ,
            &p_l_answ);
    }

#ifdef TRACE_HSM_API
    API_xtrace("Answ", p_answ, p_l_answ);
#endif
    // Extract SHA 256 Hash from result:
    SHA256Hash_t* response = NULL;    /* Note this 0! */

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        asn_dec_rval_t rval;

        rval = asn_DEF_SHA256Hash.op->ber_decoder(0,
            &asn_DEF_SHA256Hash,
            (void**)&response,
            p_answ, p_l_answ,
            0);

        if (rval.code != RC_OK)
        {
            retVal.returnCode = ERP_ERR_ASN1DECODING_ERROR;
        }
    }

    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        if (response->hashValue.size != SHA_256_LEN)
        {
            retVal.returnCode = ERP_ERR_BUFFER_TOO_SMALL;
        }
        else {
            memcpy(retVal.hash, response->hashValue.buf, SHA_256_LEN);
        }
    }
    if (response != NULL)
    {
        asn_DEF_AES256.op->free_struct(
            &asn_DEF_AES256, response, 0);
    }
    if (request != NULL)
    {
        asn_DEF_TwoBlobKeyRequest.op->free_struct(
            &asn_DEF_TwoBlobKeyRequest, request, 0);
    }
    if (p_answ != NULL)
    {
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        free(pCmdData);
    }
    return retVal;
}

/**
* Does not require an HSM Session.   This is computationally executed on the client.
* This method will parse a TPM Quote and return the system-invariant parts of the quote data.
* The Signature of the quote is NOT checked.
* The Qualified Signer Name, NONCE, PCR Set and hash are returned.
* For the meaning of these fields see the TPM2.0 Specification
*   "Trusted Platform Module Library - Part 2: Structures" for TPM2B_ATTEST
* Only quotes using SHA256 as the hash are supported.
**/
ERP_API_FUNC TPMParsedQuote_t ERP_ParseTPMQuote(
    TPMQuoteInput input)
{
    TPMParsedQuote_t retVal = { ERP_ERR_NOERROR,{0},{0},{0},{0} };
    // Quote Length is enforced by calling concenvtion.

    size_t offset = 0;
    // Comments describe sample parsing for a simulated TPM Quote:
    // ------------------------------------------
    //    TPM Magic Number
    //        FF 54 43 47 // TPM_GENERATED_VALUE - Always 0xff"TCG"
//        80 18 // TPMI_ST_ATTEST - TPMI_ST_ATTEST_QUOTE 0x8018
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        if ((input.QuoteData[offset] != 0xff) || //NOLINT  (readability-magic-numbers)
            (input.QuoteData[offset + 1] != 0x54) || //NOLINT  (readability-magic-numbers)
            (input.QuoteData[offset + 2] != 0x43) || //NOLINT  (readability-magic-numbers)
            (input.QuoteData[offset + 3] != 0x47) || //NOLINT  (readability-magic-numbers)
            (input.QuoteData[offset + 4] != 0x80) || //NOLINT  (readability-magic-numbers)
            (input.QuoteData[offset + 5] != 0x18)) //NOLINT  (readability-magic-numbers)
        {
            retVal.returnCode = ERP_ERR_BAD_QUOTE_HEADER;
        }
        offset += 6; //NOLINT  (readability-magic-numbers)
    }
    //        Signing key qualified name TPM2B_NAME
    //        00 22 // size 2 bytes
    //        // TPMU_NAME -
    //        00 0B // TPMI_ALG_HASH - TPM_ALG_SHA256 - 0x000B
    //        9A 9D 5C 78 E6 F2 9B 6A DB 8D 9F C0 16 4E B3 C4 92 0A 7C C3 FB 74 82 59 E7 06 74 40 FB E4 8E 3C
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        if ((input.QuoteData[offset] != 0x00) || //NOLINT  (readability-magic-numbers)
            (input.QuoteData[offset + 1] != 0x22)) //NOLINT  (readability-magic-numbers)
        {
            retVal.returnCode = ERP_ERR_BAD_QUOTE_FORMAT;
        }
        offset += 2; //NOLINT  (readability-magic-numbers)
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        if ((input.QuoteData[offset] != 0x00) || //NOLINT  (readability-magic-numbers)
            (input.QuoteData[offset + 1] != 0x0B)) //NOLINT  (readability-magic-numbers)
        {
            retVal.returnCode = ERP_ERR_BAD_TPM_NAME_ALGORITHM;
        }
    }
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        memcpy(&(retVal.qualifiedSignerName[0]), &(input.QuoteData[offset]),TPM_NAME_LEN);
        offset += TPM_NAME_LEN;
    }
    //    Qualifying Data(NONCE) - comes from me.
    //        00 20 35 6F 9C 3A 24 8D 82 A9 76 9D 27 EF 6F 08 A3 C5 4D FE 40 82 FC C9 C1 04 71 80 F3 6B 40 F3 97 B2
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        if ((input.QuoteData[offset] != 0x00) || //NOLINT  (readability-magic-numbers)
            (input.QuoteData[offset + 1] != 0x20)) //NOLINT  (readability-magic-numbers)
        {
            retVal.returnCode = ERP_ERR_BAD_QUOTE_HASH_FORMAT;
        }
        offset += 2; // Past the length field //NOLINT  (readability-magic-numbers)
        memcpy(&(retVal.qualifyingInformation[0]), &(input.QuoteData[offset]), NONCE_LEN);
        offset += NONCE_LEN;   // The Initial 2 bytes were already bypassed by the previous step.
    }
    //    TPMS_CLOCK_INFO
    //        00 00 00 00 01 F1 4D 6B // uint64 clock.
    //        00 00 00 09 // UINT32 reset count
    //        00 00 00 00 // unint32 Restart Count
    //        01 // Safe - TPMI_YES_NO - TRUE = 1
    //        20 19 10 23 00 16 36 36 // uint64 Firmware Version
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        offset += 8; // Clock - nothing sensible to check here. //NOLINT  (readability-magic-numbers)
        offset += 4; // Reset Count - nothing sensible to check here. //NOLINT  (readability-magic-numbers)
        offset += 4; // Restart Count - nothing sensible to check here. //NOLINT  (readability-magic-numbers)
        offset += 1; // Safe = TRUE?   Is this relevant? //NOLINT  (readability-magic-numbers)
        offset += 8; // TPM Firmware version, also nothing to check here. //NOLINT  (readability-magic-numbers)
    }
    //  TPMS_QUOTE_INFO(
    //    TPML_PCR_SELECTION
    //        00 00 00 01 // Count - we only accept one digest.
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        if ((input.QuoteData[offset] != 0x00) || //NOLINT  (readability-magic-numbers)
            (input.QuoteData[offset + 1] != 0x00) || //NOLINT  (readability-magic-numbers)
            (input.QuoteData[offset + 2] != 0x00) || //NOLINT  (readability-magic-numbers)
            (input.QuoteData[offset + 3] != 0x01)) //NOLINT  (readability-magic-numbers)
        {
            retVal.returnCode = ERP_ERR_BAD_QUOTE_FORMAT;
        }
        offset += 4; //NOLINT  (readability-magic-numbers)
    }
    //        // TPMS_PCR_SELECTION
    //        00 0B // TPMI_ALG_HASH - TPM_ALG_SHA256 - 0x000B
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        if ((input.QuoteData[offset] != 0x00) || //NOLINT  (readability-magic-numbers)
            (input.QuoteData[offset + 1] != 0x0B)) //NOLINT  (readability-magic-numbers)
        {
            retVal.returnCode = ERP_ERR_BAD_QUOTE_HASH_FORMAT;
        }
        offset += 2; //NOLINT  (readability-magic-numbers)
    }
    //        03 // Size of select array
    if (retVal.returnCode == ERP_ERR_NOERROR)
    { // Selection array is always 3 bytes.
        if (input.QuoteData[offset] != 0x03) //NOLINT  (readability-magic-numbers)
        {
            retVal.returnCode = ERP_ERR_BAD_QUOTE_FORMAT;
        }
        offset += 1; //NOLINT  (readability-magic-numbers)
    }
    //        01 00 00 // Bitmap of selected PCRs.    Example is for PCR 0 only.
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        memcpy(&(retVal.PCRSETFlags[0]), &(input.QuoteData[offset]), TPM_PCRSET_LENGTH);
        offset += 3; //NOLINT  (readability-magic-numbers)
    }
    //    Digest of hashes in quote.
    //        00 20 66 68 7A AD F8 62 BD 77 6C 8F C1 8B 8E 9F 8E 20 08 97 14 85 6E E2 33 B3 90 2A 59 1D 0D 5F 29 25
    if (retVal.returnCode == ERP_ERR_NOERROR)
    {
        if ((input.QuoteData[offset] != 0x00) || //NOLINT  (readability-magic-numbers)
            (input.QuoteData[offset + 1] != 0x20)) //NOLINT  (readability-magic-numbers)
        {
            retVal.returnCode = ERP_ERR_BAD_QUOTE_FORMAT;
        }
        offset += 2; //NOLINT  (readability-magic-numbers)
        memcpy(&(retVal.PCRHash[0]),&(input.QuoteData[offset]),TPM_PCR_DIGESTHASH_LENGTH);
    }
    // Alternative example for more PCRs:
    //        00 00 00 01
    //        00 0B
    //        03
    //        0F 00 00 // Flags of PCRs. <--- Here there are more bits set.   i.e.PCRs 0,1,2,3.
    //        00 20 38 72 3A 2E 5E 8A 17 AA 79 50 DC 00 82 09 94 4E 89 8F 69 A7 BD 10 A2 3C 83 9D 34 1E 93 5F D5 CA

    return retVal;
}

static SingleBlobOutput WrapRawPayloadRequest(HSMSession sesh,
    RawPayloadInput input, unsigned int sfc)
{
        SingleBlobOutput retval = {ERP_ERR_NOERROR, {0} };
    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;
    unsigned char* pCmdData = NULL;
    size_t cmdLength = 0;

    // send WrapRawPayloadRequest
    WrapRawPayloadRequest_t* request = (WrapRawPayloadRequest_t *)calloc(1, sizeof(WrapRawPayloadRequest_t));
    if (request == NULL)
    {
        retval.returnCode = ERP_ERR_CALLOC_ERROR;
        goto out;
    }

    request->desiredGeneration = input.desiredGeneration;
    if (input.payloadLen > sizeof(input.rawPayload))
    {
        retval.returnCode = ERP_ERR_BUFFER_TOO_SMALL;
        goto out;
    }
    retval.returnCode = asn_buffer2OctetString(&(request->rawPayload), input.rawPayload, input.payloadLen);
    if (retval.returnCode != ERP_ERR_NOERROR)
    {
        goto out;
    }

    asn_enc_rval_t er; /* Encoder return value */

    er = der_encode_dynamic_buffer(
        &asn_DEF_WrapRawPayloadRequest,
        request,
        &cmdLength,
        &pCmdData);
    // Failed to encode the data.
    if (er.encoded == -1)
    {
        retval.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        goto out;
    }

    // recieve SingleBlob
    retval.returnCode = ERP_FirmwareExec(sesh,
                                         ERP_MDL_ID,
                                         sfc,
                                         pCmdData,
                                         (unsigned int)cmdLength,
                                         &p_answ,
                                         &p_l_answ);
#ifdef TRACE_HSM_API
    API_xtrace("Answ", p_answ, p_l_answ);
#endif
    if (retval.returnCode != ERP_ERR_NOERROR)
    {
        goto out;
    }
    HandleSingleBlobResult(p_answ, p_l_answ, &retval);

out:
    if (request != NULL)
    {
        asn_DEF_WrapRawPayloadRequest.op->free_struct(
            &asn_DEF_WrapRawPayloadRequest, request, ASFM_FREE_EVERYTHING);
    }
    if (p_answ != NULL)
    {
        explicit_bzero(p_answ, p_l_answ);
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        explicit_bzero(pCmdData, cmdLength);
        free(pCmdData);
    }

    return retval;
}


ERP_API_FUNC SingleBlobOutput ERP_WrapRawPayload(
    HSMSession sesh,
    RawPayloadInput input)
{
    return WrapRawPayloadRequest(sesh, input, ERP_SFC_WRAP_PAYLOAD);
}

ERP_API_FUNC SingleBlobOutput ERP_WrapRawPayloadWithToken(
    HSMSession sesh,
    RawPayloadWithTokenInput input)
{
    SingleBlobOutput retval = {ERP_ERR_NOERROR, {0} };
    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;
    unsigned char* pCmdData = NULL;
    size_t cmdLength = 0;

    // send WrapRawPayloadWithTokenRequest
    WrapRawPayloadWithTokenRequest_t* request = (WrapRawPayloadWithTokenRequest_t *)calloc(1, sizeof(WrapRawPayloadWithTokenRequest_t));
    if (request == NULL)
    {
        retval.returnCode = ERP_ERR_CALLOC_ERROR;
        goto out;
    }

    retval.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->tokenTEE), &(input.TEEToken));
    if (retval.returnCode != ERP_ERR_NOERROR)
    {
        goto out;
    }
    request->desiredGeneration = input.desiredGeneration;
    if (input.payloadLen > sizeof(input.rawPayload))
    {
        retval.returnCode = ERP_ERR_BUFFER_TOO_SMALL;
        goto out;
    }
    retval.returnCode = asn_buffer2OctetString(&(request->rawPayload), input.rawPayload, input.payloadLen);
    if (retval.returnCode != ERP_ERR_NOERROR)
    {
        goto out;
    }

    asn_enc_rval_t er; /* Encoder return value */

    er = der_encode_dynamic_buffer(
        &asn_DEF_WrapRawPayloadWithTokenRequest,
        request,
        &cmdLength,
        &pCmdData);
    // Failed to encode the data.
    if (er.encoded == -1)
    {
        retval.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        goto out;
    }

    // recieve SingleBlob
    retval.returnCode = ERP_FirmwareExec(sesh,
                                         ERP_MDL_ID,
                                         ERP_SFC_WRAP_PAYLOAD_WITH_TOKEN,
                                         pCmdData,
                                         (unsigned int)cmdLength,
                                         &p_answ,
                                         &p_l_answ);
#ifdef TRACE_HSM_API
    API_xtrace("Answ", p_answ, p_l_answ);
#endif
    if (retval.returnCode != ERP_ERR_NOERROR)
    {
        goto out;
    }
    HandleSingleBlobResult(p_answ, p_l_answ, &retval);

out:
    if (request != NULL)
    {
        asn_DEF_WrapRawPayloadWithTokenRequest.op->free_struct(
            &asn_DEF_WrapRawPayloadWithTokenRequest, request, ASFM_FREE_EVERYTHING);
    }
    if (p_answ != NULL)
    {
        explicit_bzero(p_answ, p_l_answ);
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        explicit_bzero(pCmdData, cmdLength);
        free(pCmdData);
    }

    return retval;
}

static RawPayloadOutput UnwrapRawPayloadRequest(HSMSession sesh,
    WrappedPayloadInput input, unsigned int sfc)
{
    RawPayloadOutput retval = {ERP_ERR_NOERROR, 0, {0}};
    unsigned char *p_answ = NULL;
    unsigned int p_l_answ = 0;
    unsigned char *pCmdData = NULL;
    ERPOctetString_t *response = NULL;
    size_t cmdLength = 0;

    // send UnwrapRawPayloadRequest
    UnwrapRawPayloadRequest_t *request = (UnwrapRawPayloadRequest_t *)calloc(1, sizeof(UnwrapRawPayloadRequest_t));
    if (request == NULL)
    {
        retval.returnCode = ERP_ERR_CALLOC_ERROR;
        goto out;
    }
    retval.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->tokenTEE), &(input.TEEToken));
    if (retval.returnCode != ERP_ERR_NOERROR)
    {
        goto out;
    }
    retval.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->wrappedRawPayload), &(input.wrappedRawPayload));
    if (retval.returnCode != ERP_ERR_NOERROR)
    {
        goto out;
    }

    asn_enc_rval_t er; /* Encoder return value */
    er = der_encode_dynamic_buffer(&asn_DEF_UnwrapRawPayloadRequest, request,
                                   &cmdLength, &pCmdData);

    if (er.encoded == -1)
    {
        retval.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        goto out;
    }

    // recieve ERPOctetString
    retval.returnCode = ERP_FirmwareExec(sesh,
                                         ERP_MDL_ID,
                                         sfc,
                                         pCmdData,
                                         (unsigned int)cmdLength,
                                         &p_answ,
                                         &p_l_answ);
    if (retval.returnCode != ERP_ERR_NOERROR)
    {
        goto out;
    }
    asn_dec_rval_t rval;
    rval = asn_DEF_ERPOctetString.op->ber_decoder(0,
                                                  &asn_DEF_ERPOctetString,
                                                  (void **)&response,
                                                  p_answ, p_l_answ,
                                                  0);

    if (rval.code != RC_OK)
    {
        retval.returnCode = ERP_ERR_ASN1DECODING_ERROR;
        goto out;
    }
    if (response->octets.size > MAX_BUFFER)
    {
        retval.returnCode = ERP_ERR_BUFFER_TOO_SMALL;
        goto out;
    }
    retval.payloadLen = response->octets.size;
    memcpy(retval.rawPayload,
           response->octets.buf,
           response->octets.size);

out:
    if (response != NULL)
    {
        asn_DEF_ERPOctetString.op->free_struct(
            &asn_DEF_ERPOctetString, response, 0);
    }
    if (request != NULL)
    {
        asn_DEF_UnwrapRawPayloadRequest.op->free_struct(
            &asn_DEF_UnwrapRawPayloadRequest, request, ASFM_FREE_EVERYTHING);
    }
    if (p_answ != NULL)
    {
        explicit_bzero(p_answ, p_l_answ);
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        explicit_bzero(pCmdData, cmdLength);
        free(pCmdData);
    }

    return retval;
}

ERP_API_FUNC RawPayloadOutput ERP_UnwrapRawPayload(
    HSMSession sesh,
    WrappedPayloadInput input)
{
    return UnwrapRawPayloadRequest(sesh, input, ERP_SFC_UNWRAP_PAYLOAD);
}


ERP_API_FUNC AutSignatureOutput ERP_SignVAUAUTToken(
    HSMSession sesh,
    AutSignatureInput input)
{
    AutSignatureOutput retval = {ERP_ERR_NOERROR, 0, {0} };
    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;
    unsigned char* pCmdData = NULL;
    ERPOctetString_t* response = NULL;
    size_t cmdLength = 0;

    // send SignVAUAUTTokenRequest
    SignVAUAUTTokenRequest_t* request = (SignVAUAUTTokenRequest_t *)calloc(1, sizeof(SignVAUAUTTokenRequest_t));
    if (request == NULL)
    {
        retval.returnCode = ERP_ERR_CALLOC_ERROR;
        goto out;
    }
    retval.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->tokenTEE), &(input.TEEToken));
    if (retval.returnCode != ERP_ERR_NOERROR)
    {
        goto out;
    }
    retval.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->keyPair), &(input.AutKeyPair));
    if (retval.returnCode != ERP_ERR_NOERROR)
    {
        goto out;
    }
    if (input.signableLength > sizeof(input.signableData))
    {
        retval.returnCode = ERP_ERR_BUFFER_TOO_SMALL;
        goto out;
    }
    retval.returnCode = asn_buffer2OctetString(&(request->signableData), input.signableData, input.signableLength);
    if (retval.returnCode != ERP_ERR_NOERROR)
    {
        goto out;
    }

    asn_enc_rval_t er; /* Encoder return value */
    er = der_encode_dynamic_buffer(&asn_DEF_SignVAUAUTTokenRequest, request,
                                   &cmdLength, &pCmdData);

    if (er.encoded == -1)
    {
        retval.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        goto out;
    }

    // recieve ERPOctetString
    retval.returnCode = ERP_FirmwareExec(sesh,
                                         ERP_MDL_ID,
                                         ERP_SFC_SIGN_AUT_TOKEN,
                                         pCmdData,
                                         (unsigned int)cmdLength,
                                         &p_answ,
                                         &p_l_answ);
    if (retval.returnCode != ERP_ERR_NOERROR)
    {
        goto out;
    }
    asn_dec_rval_t rval;
    rval = asn_DEF_ERPOctetString.op->ber_decoder(0,
            &asn_DEF_ERPOctetString,
            (void**)&response,
            p_answ, p_l_answ,
            0);

    if (rval.code != RC_OK)
    {
        retval.returnCode = ERP_ERR_ASN1DECODING_ERROR;
        goto out;
    }
    if (response->octets.size > MAX_BUFFER)
    {
        retval.returnCode = ERP_ERR_BUFFER_TOO_SMALL;
        goto out;
    }
    retval.signatureLength = response->octets.size;
    memcpy(retval.signatureData,
           response->octets.buf,
           response->octets.size);

out:
    if (response != NULL)
    {
        asn_DEF_ERPOctetString.op->free_struct(
            &asn_DEF_ERPOctetString, response, 0);
    }
    if (request != NULL)
    {
        asn_DEF_SignVAUAUTTokenRequest.op->free_struct(
            &asn_DEF_SignVAUAUTTokenRequest, request, ASFM_FREE_EVERYTHING);
    }
    if (p_answ != NULL)
    {
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        free(pCmdData);
    }

    return retval;
}


SingleBlobOutput ERP_WrapPseudonameLogKeyPackage(
    HSMSession sesh,
    RawPayloadInput input)
{
    return WrapRawPayloadRequest(sesh, input, ERP_SFC_WRAP_PSEUDONAME_LOG_KEY_PACKAGE);
}


RawPayloadOutput ERP_UnwrapPseudonameLogKeyPackage(
    HSMSession sesh,
    WrappedPayloadInput input)
{
    return UnwrapRawPayloadRequest(sesh, input, ERP_SFC_UNWRAP_PSEUDONAME_LOG_KEY_PACKAGE);
}

SingleBlobOutput ERP_WrapPseudonameLogKey(HSMSession sesh, AESKey128Input input)
{
    SingleBlobOutput retVal = {ERP_ERR_NOERROR, {0}};
    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;
    unsigned char* pCmdData = NULL;
    size_t cmdLength = 0;

    WrapPseudonameLogKeyRequest_t *request = calloc(1, sizeof(WrapPseudonameLogKeyRequest_t));
    if (request == NULL)
    {
        retVal.returnCode = ERP_ERR_CALLOC_ERROR;
        goto out;
    }
    retVal.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->tokenTEE), &(input.TEEToken));
    if (retVal.returnCode != ERP_ERR_NOERROR)
    {
        goto out;
    }
    request->desiredGeneration = input.desiredGeneration;
    retVal.returnCode = asn_buffer2OctetString(&(request->keyValue), input.AESKey, AES_128_LEN);
    if (retVal.returnCode != ERP_ERR_NOERROR)
    {
        goto out;
    }

    asn_enc_rval_t er = der_encode_dynamic_buffer(
        &asn_DEF_WrapPseudonameLogKeyRequest,
        request,
        &cmdLength,
        &pCmdData);
    // Failed to encode the data.
    if (er.encoded == -1)
    {
        retVal.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        goto out;
    }

    // recieve SingleBlob
    retVal.returnCode = ERP_FirmwareExec(sesh,
                                         ERP_MDL_ID,
                                         ERP_SFC_WRAP_PSEUDONAME_LOG_KEY,
                                         pCmdData,
                                         (unsigned int)cmdLength,
                                         &p_answ,
                                         &p_l_answ);
#ifdef TRACE_HSM_API
    API_xtrace("Answ", p_answ, p_l_answ);
#endif
    if (retVal.returnCode != ERP_ERR_NOERROR)
    {
        goto out;
    }

    HandleSingleBlobResult(p_answ, p_l_answ, &retVal);
out:
    if (request != NULL)
    {
        asn_DEF_WrapPseudonameLogKeyRequest.op->free_struct(&asn_DEF_WrapPseudonameLogKeyRequest, request, 0);
    }
    if (p_answ != NULL)
    {
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        explicit_bzero(pCmdData, cmdLength);
        free(pCmdData);
    }
    return retVal;
}

AES128KeyOutput ERP_UnwrapPseudonameLogKey(HSMSession sesh, TwoBlobGetKeyInput input)
{
    AES128KeyOutput retVal = {ERP_ERR_NOERROR, {0}};
    // Need to use calloc because lib relies on zeroing of empty structure memory.
    TwoBlobKeyRequest_t *request = calloc(1, sizeof(TwoBlobKeyRequest_t));
    AES128_t* response = NULL;
    unsigned char* p_answ = NULL;
    unsigned int p_l_answ = 0;
    size_t cmdLength = 0;
    unsigned char *pCmdData = NULL;
    if (request == NULL)
    {
        retVal.returnCode = ERP_ERR_CALLOC_ERROR;
        goto out;
    }
    retVal.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->teeToken), &(input.TEEToken));
    if (retVal.returnCode != ERP_ERR_NOERROR)
    {
        goto out;
    }
    retVal.returnCode = asn_ERPBlob2ASNSingleBlob(&(request->key), &(input.Key));
    if (retVal.returnCode != ERP_ERR_NOERROR)
    {
        goto out;
    }
    asn_enc_rval_t er; /* Encoder return value */
    er = der_encode_dynamic_buffer(&asn_DEF_TwoBlobKeyRequest, request,
                                   &cmdLength, &pCmdData);
    if (er.encoded == -1)
    {
        retVal.returnCode = ERP_ERR_ASN1ENCODING_ERROR;
        goto out;
    }

    retVal.returnCode = ERP_FirmwareExec(sesh,
                                         ERP_MDL_ID,
                                         ERP_SFC_UNWRAP_PSEUDONAME_LOG_KEY,
                                         pCmdData,
                                         (unsigned int)cmdLength,
                                         &p_answ,
                                         &p_l_answ);
    if (retVal.returnCode != ERP_ERR_NOERROR)
    {
        goto out;
    }

    asn_dec_rval_t rval = asn_DEF_AES128.op->ber_decoder(0,
                                                         &asn_DEF_AES128,
                                                         (void **)&response,
                                                         p_answ, p_l_answ,
                                                         0);
    if (rval.code != RC_OK)
    {
        retVal.returnCode = ERP_ERR_ASN1DECODING_ERROR;
        goto out;
    }
    if ((response->keyValue.size != AES_128_LEN) ||
        (response->keyValue.size > MAX_BUFFER))
    {
        retVal.returnCode = ERP_ERR_BUFFER_TOO_SMALL;
        goto out;
    }
    // Already checked to be AES_128_LEN
    memcpy(&(retVal.AESKey[0]), response->keyValue.buf, response->keyValue.size);

out:
    if (response != NULL)
    {
        asn_DEF_AES128.op->free_struct(&asn_DEF_AES128, response, 0);
    }
    if (request != NULL)
    {
        asn_DEF_TwoBlobKeyRequest.op->free_struct(&asn_DEF_TwoBlobKeyRequest, request, 0);
    }
    if (p_answ != NULL)
    {
        explicit_bzero(p_answ, p_l_answ);
        cs_free_answ(p_answ);
    }
    if (pCmdData != NULL)
    {
        explicit_bzero(pCmdData, cmdLength);
        free(pCmdData);
    }

    return retVal;
}
