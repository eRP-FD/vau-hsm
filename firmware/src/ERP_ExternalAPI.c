/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021, 2023
 * (C) Copyright IBM Corp. 2021, 2023
 *
 * non-exclusively licensed to gematik GmbH
 *
 * Description: Implementation of extern Functions (called by the host application).
 *              This module implements the IBM eRezept custom HSM firmware.
 **************************************************************************************************/

// Needed to avoid bug warning in winnt.h
#define no_init_all

#include <cryptoserversdk/load_store.h>
#include <cryptoserversdk/stype.h>
#include <cryptoserversdk/memutil.h>
#include <cryptoserversdk/os_mem.h>
#include <cryptoserversdk/os_str.h>
#include <cryptoserversdk/os_log.h>
#include <cryptoserversdk/os_task.h>
#include <cryptoserversdk/os_file.h>
#include <cryptoserversdk/os_audit.h>
#include <cryptoserversdk/os_crypt.h>
#include <cryptoserversdk/cmds.h>
#include <cryptoserversdk/util.h>
#include <cryptoserversdk/db.h>
#include <cryptoserversdk/pp.h>
#include <cryptoserversdk/mbk.h>
#include <cryptoserversdk/aes.h>
#include <cryptoserversdk/vdes.h>
#include <cryptoserversdk/vrsa.h>
#include <cryptoserversdk/eca.h>
#include <cryptoserversdk/ecdsa.h>
#include <cryptoserversdk/hash.h>
#include <cryptoserversdk/cxi.h>
#include <cryptoserversdk/cxi_defs.h>
#include <cryptoserversdk/adm.h>
#include <cryptoserversdk/asn1.h>

#include "ERP_InternalGlue.h"
#include "ERP.h"
#include "ERP_Audit.h"
#include "ERP_CryptoUtils.h"

/******************************************************************************
 * Globals
 ******************************************************************************/

// Externally callable FWAPI Command to carry out a dump of currently allocated HSM Heap.
// Output will be printed in the simulator.
// In Production the method will return E_ERP_DEV_FUNCTION_ONLY
// Return: Success or Error code.
int ERP_DumpHSMMemory(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)
{
    // This is a build-dependent return error or do work
#ifdef DEBUG
    unsigned int err = E_ERP_SUCCESS;
    if (0 != check_permission(p_hdl, ERP_WORKING_PERMISSION, 2))
    {
        err = E_ERP_PERMISSION_DENIED;
    }
    err = DumpHSMMemory();
    // No Audit error here -this is diagnostic time only.
    return (int)err;
#else
    return E_ERP_DEV_FUNCTION_ONLY;
#endif
}

// Externally callable FWAPI Command
// This method may be used as a place holder in the SFC Code table.
// Return: Success or Error code.
int ERP_NotUsed(T_CMDS_HANDLE *p_hdl, int l_cmd, unsigned char *p_cmd)
{
    return E_ERP_OBSOLETE_FUNCTION;
}

// Externally callable FWAPI Command
// Command to generate a new Blob Trust Key with a new Generation
// Input: unsigned int Desired Generation - if zero, then the highest available Generation
//           in the HSM is incremented by one and used.   Otherwise the input value must
//           not match any existing Blob Key Generations present in the HSM.
// Output: Integer Generation of newly created Blob key.
// Return: Success or Error code.
int ERP_GenerateBlobKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)
{
    unsigned int err = E_ERP_SUCCESS;
    ERP_AuditID_t auditID = ERP_AUDIT_Failed_New_Blob_Generation_Key_Generated;
    unsigned int Generation = 0;

    // This operation requires ERP Setup or ERP Update Rights.
    if ((0 != check_permission(p_hdl, ERP_SETUP_PERMISSION, 2)) &&
        (0 != check_permission(p_hdl, ERP_UPDATE_PERMISSION, 2)))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }
    if (err == E_ERP_SUCCESS)
    {
        err = parseSingleIntInput(l_cmd, p_cmd, &Generation);
    }
    if (err == E_ERP_SUCCESS)
    {
        if (Generation == 0)
        {
            Generation = getHighestBlobGeneration(p_hdl) + 1;
        }
        if (getNumLoadedBlobGenerations(p_hdl) >= MAX_LOADED_BLOB_GENERATIONS)
        {
            err = E_ERP_MAX_BLOB_GENERATIONS;
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        if (NULL != getSingleBlobKey(p_hdl, Generation))
        { // Key is already present!   Do not replace it.
            err = E_ERP_BAD_BLOB_GENERATION;
            INDEX_ERR(err, 0x05);
        }
    }
    if (err == E_ERP_SUCCESS)
    { // Create the new key
        err = createNewBlobKey(p_hdl, &Generation);
    }

    // Output is the actual Generation generated.
    // This method will do all the work of building and allocating the firmware
    //   response containing the integer.
    if (err == E_ERP_SUCCESS)
    {
        err = makeSingleIntOutput(p_hdl, Generation);
    }

    if (err == E_ERP_SUCCESS)
    {
        auditErrWithID(err, ERP_AUDIT_New_Blob_Generation_Key_Generated);
    }
    else {
        auditErrWithID(err, auditID);
    }
    return (int)err;
}

// Externally callable FWAPI Command
// Command to list the currently loaded Blob Trust Keys
// Input: none
// Output: List of <Generation,SHA256 Hashes of Key Values>
// Return: Success or Error code.
int ERP_ListBlobKeys(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)
{
    unsigned int err = E_ERP_SUCCESS;
    // Apart from a permission error - this should not fail.
    T_BLOBK* const* pBlobList = NULL;

    // This can be called by either setup or working users.
    if ((0 != check_permission(p_hdl, ERP_SETUP_PERMISSION, 2)) &&
        (0 != check_permission(p_hdl, ERP_UPDATE_PERMISSION, 2)) &&
        (0 != check_permission(p_hdl, ERP_WORKING_PERMISSION, 2)))
    {
        err = E_ERP_PERMISSION_DENIED;
    }
    if (err == E_ERP_SUCCESS)
    {
        err = getLoadedBlobKeys(p_hdl, &pBlobList);
    }
    if (err == E_ERP_SUCCESS)
    {
        // Defensive coding: This really shouldn't happen, since a successful return from getLoadedBlobKeys mandates a non null pBlobList.
        CHECK_NOT_NULL(err, pBlobList, 0x35);
    }
    ASN1_ITEM* ItemList = NULL;
    unsigned int i = 0;
    unsigned int numBlobKeys = 0;
    // pBlobList should not be NULL if err == E_ERP_SUCCESS
    if (err == E_ERP_SUCCESS)
    {
        while (pBlobList[i++] != NULL)
        {
            numBlobKeys++;
        }
        ItemList = os_mem_new_tag(sizeof(ASN1_ITEM) * ((numBlobKeys * 4) + 2), OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, ItemList, 0x36);
    }
    if (err == E_ERP_SUCCESS)
    {
        ItemList[0].tag = ASN_SEQUENCE;
        ItemList[0].len = 0;
        ItemList[0].p_data = NULL;
        ItemList[0].nitems = 1;
        ItemList[1].tag = ASN_SEQUENCE;
        ItemList[1].len = 0;
        ItemList[1].p_data = NULL;
        ItemList[1].nitems = (unsigned short)numBlobKeys;
        i = 0;
        while ((err == E_ERP_SUCCESS) && (i < numBlobKeys))
        { // We need this level of indirection because I made the make method allocate
            // space if none was passed in...
            ASN1_ITEM* pItem = &(ItemList[2 + (i * 4)]);
            err = makeBlobKeyInfoItem(&pItem, pBlobList[i]);
            i++;
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        err = buildOutputBuffer(p_hdl,
            ItemList, // input Items
            2 + (numBlobKeys * 4));
    }

    if (ItemList != NULL)
    { // This method deletes subsidiary structures in ASN1_ITEMs separately.
        deleteASNItemList(ItemList, 2 + (numBlobKeys * 4));
    }
    auditErr(err);
    return(int)err;
}

// Externally callable FWAPI Command
// Command to delete a Blob Trust Key with a given Generation
// Input: unsigned int Undesired Generation - the input value must
//        match an existing Blob Key Generation present in the HSM.
// Output: none
// Return: Success or Error code.
int ERP_DeleteBlobKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)
{
    unsigned int err = E_ERP_SUCCESS;
    ERP_AuditID_t auditID = ERP_AUDIT_Failed_Blob_Generation_Key_Deletion;
    unsigned int Generation = 0;

    if (0 != check_permission(p_hdl, ERP_SETUP_PERMISSION, 2))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }
    if (err == E_ERP_SUCCESS)
    {
        err = parseSingleIntInput(l_cmd, p_cmd, &Generation);
    }
    if (err == E_ERP_SUCCESS)
    {
        if (NULL == getSingleBlobKey(p_hdl,Generation))
        {
            err = E_ERP_UNKNOWN_BLOB_GENERATION;
            INDEX_ERR(err, 0x02);
        }
    }
    if (err == E_ERP_SUCCESS)
    { // Delete the key
        err = deleteBlobKey(p_hdl, Generation);
    }

    if (err == E_ERP_SUCCESS)
    {
        auditErrWithID(err, ERP_AUDIT_Blob_Generation_Key_Deleted);
    }
    else {
        auditErrWithID(err, auditID);
    }
    return (int)err;
}

// Externally callable FWAPI Command
// Command to generate a new Hash Key with an existing Generation
// Input: unsigned int Desired Generation - if zero, then the highest available Generation
//           in the HSM is used.   Otherwise the input value must
//           not match ay existing Blob Key Generations present in the HSM.
// Output: Hash Key Blob
// Return: Success or Error code.
int ERP_GenerateHashKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)
{
    unsigned int err = E_ERP_SUCCESS;
    ERP_AuditID_t auditID = ERP_AUDIT_Failed_Hash_Key_Generation;
    unsigned int Generation = 0;

    // This operation requires ERP Setup or ERP Update Rights.
    if ((0 != check_permission(p_hdl, ERP_SETUP_PERMISSION, 2)) &&
        (0 != check_permission(p_hdl, ERP_UPDATE_PERMISSION, 2)))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }
    if (err == E_ERP_SUCCESS)
    {
        err = parseSingleIntInput(l_cmd, p_cmd, &Generation);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = CheckAvailableGeneration(p_hdl, Generation);
    }
    ClearBlob_t* clear = NULL;

    if (err == E_ERP_SUCCESS)
    { // Create the new hash key
        err = getHashKeyBlob(p_hdl, &clear);
    }
    SealedBlob_t* sealed = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = SealBlob(p_hdl, clear, Generation, &sealed);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = makeSingleSealedBlobOutput(p_hdl, sealed);
    }
    FREE_IF_NOT_NULL(sealed);
    FREE_IF_NOT_NULL(clear);
    if (err == E_ERP_SUCCESS)
    {
        auditErrWithID(err, ERP_AUDIT_Hash_Key_Generated);
    }
    else {
        auditErrWithID(err, auditID);
    }
    return (int)err;
}

// Externally callable FWAPI Command
// Command to generate a new pseudoname Key Blob with an existing Generation.
// Pseudoname Key blobs expire automatically after 8 months.
// Required Permission: Working
// Input: unsigned int Desired Generation - if zero, then the highest available Generation
//           in the HSM is used.   Otherwise the input value must
//           match an existing Blob Key Generation present in the HSM.
// Output: Pseudoname Key Blob
// Return: Success or Error code.
extern int ERP_GeneratePseudonameKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)
{
    unsigned int err = E_ERP_SUCCESS;
    ERP_AuditID_t auditID = ERP_AUDIT_Failed_Pseudoname_Key_Generation;
    unsigned int Generation = 0;

    // This operation requires ERP Working Rights.
    if (0 != check_permission(p_hdl, ERP_WORKING_PERMISSION, 2))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }
    if (err == E_ERP_SUCCESS)
    {
        err = parseSingleIntInput(l_cmd, p_cmd, &Generation);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = CheckAvailableGeneration(p_hdl, Generation);
    }
    ClearBlob_t* clear = NULL;

    if (err == E_ERP_SUCCESS)
    { // Create the new pseudoname key
        err = getPseudonameKeyBlob(p_hdl, &clear);
    }
    SealedBlob_t* sealed = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = SealBlob(p_hdl, clear, Generation, &sealed);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = makeSingleSealedBlobOutput(p_hdl, sealed);
    }
    FREE_IF_NOT_NULL(sealed);
    FREE_IF_NOT_NULL(clear);
    if (err == E_ERP_SUCCESS)
    {
        auditErrWithID(err, ERP_AUDIT_Pseudoname_Key_Generated);
    }
    else {
        auditErrWithID(err, auditID);
    }
    return (int)err;
}

// Externally callable FWAPI Command
// Command to generate a new Derivation Key Blob with an existing Generation
// Input: unsigned int Desired Generation - if zero, then the highest available Generation
//           in the HSM is used.   Otherwise the input value must
//           match an existing Blob Key Generation present in the HSM.
// Output: Derivation Key Blob
// Return: Success or Error code.
int ERP_GenerateDerivationKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)
{
    unsigned int err = E_ERP_SUCCESS;
    ERP_AuditID_t auditID = ERP_AUDIT_Failed_Key_Derivation_Key_Generation;
    unsigned int Generation = 0;

    // This operation requires ERP Setup or ERP Update Rights.
    if ((0 != check_permission(p_hdl, ERP_SETUP_PERMISSION, 2)) &&
        (0 != check_permission(p_hdl, ERP_UPDATE_PERMISSION, 2)))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }
    if (err == E_ERP_SUCCESS)
    {
        err = parseSingleIntInput(l_cmd, p_cmd, &Generation);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = CheckAvailableGeneration(p_hdl, Generation);
    }
    ClearBlob_t* clear = NULL;

    if (err == E_ERP_SUCCESS)
    { // Create the new derivation key
        err = getDerivationKeyBlob(p_hdl, &clear);
    }
    SealedBlob_t* sealed = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = SealBlob(p_hdl, clear, Generation, &sealed);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = makeSingleSealedBlobOutput(p_hdl, sealed);
    }
    FREE_IF_NOT_NULL(sealed);
    FREE_IF_NOT_NULL(clear);
    if (err == E_ERP_SUCCESS)
    {
        auditErrWithID(err, ERP_AUDIT_Key_Derivation_Key_Generated);
    }
    else {
        auditErrWithID(err, auditID);
    }
    return (int)err;
}

// Shared implmentation for multiple externally callable FWAPI Commands
// Command to generate a new EC KeyPair
// Input: unsigned int Desired Generation - if zero, then the highest available Generation
//           in the HSM is used.   Otherwise the input value must
//           match an existing Blob Key Generation present in the HSM.
// Output: ECIES KeyPair Blob
// Return: Success or Error code.
extern int ERP_GenerateECKeyPair(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd, ERPBlobType_t blobType, ERP_AuditID_t auditID)
{
     unsigned int err = E_ERP_SUCCESS;
    unsigned int Generation = 0;

    // This operation requires ERP Setup or ERP Update Rights.
    if ((0 != check_permission(p_hdl, ERP_SETUP_PERMISSION, 2)) &&
        (0 != check_permission(p_hdl, ERP_UPDATE_PERMISSION, 2)))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }
    if (err == E_ERP_SUCCESS)
    {
        err = parseSingleIntInput(l_cmd, p_cmd, &Generation);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = CheckAvailableGeneration(p_hdl, Generation);
    }
    ClearBlob_t* clear = NULL;

    if (err == E_ERP_SUCCESS)
    { // Create the new keypair
        err = getECKeyPairBlob(p_hdl, &clear,blobType);
    }

    SealedBlob_t* sealed = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = SealBlob(p_hdl, clear, Generation, &sealed);
    }

    if (err == E_ERP_SUCCESS)
    {
        err = makeSingleSealedBlobOutput(p_hdl, sealed);
    }
    FREE_IF_NOT_NULL(sealed);
    FREE_IF_NOT_NULL(clear);
    if (err == E_ERP_SUCCESS)
    {
        auditErrWithID(err, ERP_AUDIT_EC_KeyPair_Generated);
    }
    else {
        auditErrWithID(err, auditID);
    }
    return (int)err;
}


// Shared implementation for multiple externally callable FWAPI Commands
// Generate CSR for an EC Keypair
// Input: ECIES or VAUSIG KeyPair Blob
// Input: Candidate CSR with all valid fields, except public key and signature
//    which must be present and formally correct, but the content data is irrelevant.
//    The Signature does not need to be valid either.
// Output: ASN1.DER encoded CSR
// Return: Success or Error code.
extern int ERP_GenerateECCSR(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd, ERPBlobType_t blobType, ERP_AuditID_t auditID)
{
    unsigned int err = E_ERP_SUCCESS;
    SealedBlob_t* pKeyPairBlob = NULL;
    // This operation requires ERP Setup or ERP Update Rights.
    if ((0 != check_permission(p_hdl, ERP_SETUP_PERMISSION, 2)) &&
        (0 != check_permission(p_hdl, ERP_UPDATE_PERMISSION, 2)))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }
    size_t candidateCSRLength = 0;
    unsigned char* pCandidateCSRData = NULL;
    if (err == E_ERP_SUCCESS)
    {
        // To avoid lots of copying and reallocating, the pointers returned by this method are all
        //   referring directly to the elements of the ASN1_ITEM array returned by pItems.
        //   So, to delete them all, we need to call deleteASNItemList with pItems when we are finished.
        err = parseGenerateCSRInput(l_cmd, p_cmd,&pKeyPairBlob,&candidateCSRLength,&pCandidateCSRData);
    }

    ClearBlob_t* clearKeyPair = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = UnsealBlobAndCheckType(p_hdl, blobType, pKeyPairBlob, &clearKeyPair);
    }

    // Now modify the CSR and resign.
    size_t modifiedCSRLength = 0;
    unsigned char* pModifiedCSRData = NULL;
    if (err == E_ERP_SUCCESS)
    {   // This method will replace the public key and resign using the original CSR buffer.
        err = x509ECCSRReplacePublicKeyAndSign(
            p_hdl,
            candidateCSRLength, pCandidateCSRData,
            clearKeyPair,
            &modifiedCSRLength,&pModifiedCSRData);
    }

    if (err == E_ERP_SUCCESS)
    {   // Build the output buffer for the command.
        err = makex509CSROutput(p_hdl, modifiedCSRLength, pModifiedCSRData);
    }
    FREE_IF_NOT_NULL(clearKeyPair);
    FREE_IF_NOT_NULL(pModifiedCSRData);
    FREE_IF_NOT_NULL(pKeyPairBlob);
    if (err == E_ERP_SUCCESS)
    {
        auditErrWithID(err, ERP_AUDIT_EC_CSR_Generated);
    }
    else {
        auditErrWithID(err, auditID);
    }
    return (int)err;
}

// Externally callable FWAPI Command
// Command to generate a new EC Signature KeyPair for VAU Signing operations
// Input: unsigned int Desired Generation - if zero, then the highest available Generation
//           in the HSM is used.   Otherwise the input value must
//           match an existing Blob Key Generation present in the HSM.
// Output: ECIES KeyPair Blob
// Return: Success or Error code.
extern int ERP_GenerateVAUSIGKeyPair(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)
{
    return ERP_GenerateECKeyPair(p_hdl, l_cmd, p_cmd, VAUSIG_KeyPair,ERP_AUDIT_Failed_EC_KeyPair_Generation);
}

// Externally callable FWAPI Command
// Generate CSR for a VAUSIG Keypair
// Input: VAUSIG KeyPair Blob
// Input: Candidate CSR with all valid fields, except public key and signature
//    which must be present and formally correct, but the content data is irrelevant.
//    The Signature does not need to be valid either.
// Output: ASN1.DER encoded CSR
// Return: Success or Error code.
extern int ERP_GenerateVAUSIGCSR(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)
{
    return ERP_GenerateECCSR(p_hdl, l_cmd, p_cmd, VAUSIG_KeyPair, ERP_AUDIT_Failed_EC_CSR_Generation);
}

// Externally callable FWAPI Command
// Command to generate a new ECIES KeyPair for ECIES key exchange with an existing Generation
// Input: unsigned int Desired Generation - if zero, then the highest available Generation
//           in the HSM is used.   Otherwise the input value must
//           match an existing Blob Key Generation present in the HSM.
// Output: ECIES KeyPair Blob
// Return: Success or Error code.
extern int ERP_GenerateECIESKeyPair(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)
{
    return ERP_GenerateECKeyPair(p_hdl, l_cmd, p_cmd, ECIES_KeyPair, ERP_AUDIT_Failed_EC_KeyPair_Generation);
}

// Externally callable FWAPI Command
// Generate CSR for an ECIES Keypair
// Input: ECIES KeyPair Blob
// Input: Candidate CSR with all valid fields, except public key and signature
//    which must be present and formally correct, but the content data is irrelevant.
//    The Signature does not need to be valid either.
// Output: ASN1.DER encoded CSR
// Return: Success or Error code.
extern int ERP_GenerateECIESCSR(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)
{
    return ERP_GenerateECCSR(p_hdl, l_cmd, p_cmd, ECIES_KeyPair, ERP_AUDIT_Failed_EC_CSR_Generation);
}

// Externally callable FWAPI Command
// Command to generate a new NONCE Blob with an existing Generation
// Input: unsigned int Desired Generation - if zero, then the highest available Generation
//           in the HSM is used.   Otherwise the input value must
//           not match ay existing Blob Key Generations present in the HSM.
// Output: NONCE Blob
// Return: Success or Error code.
int ERP_GenerateNONCE(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)
{
    unsigned int err = E_ERP_SUCCESS;
    ERP_AuditID_t auditID = ERP_AUDIT_Failed_Get_NONCE;
    unsigned int Generation = 0;

    // This can be called by either the setup or the working users.
    if ((0 != check_permission(p_hdl, ERP_WORKING_PERMISSION, 2)) &&
        (0 != check_permission(p_hdl, ERP_SETUP_PERMISSION, 2)))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }
    if (err == E_ERP_SUCCESS)
    {
        err = parseSingleIntInput(l_cmd, p_cmd, &Generation);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = CheckAvailableGeneration(p_hdl, Generation);
    }
    ClearBlob_t* clear = NULL;

    if (err == E_ERP_SUCCESS)
    { // Create the NONCE
        err = getNONCEBlob(p_hdl, &clear);
    }
    SealedBlob_t* sealed = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = SealBlob(p_hdl, clear, Generation, &sealed);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = makeNONCEAndBlobOutput(p_hdl, (NONCEBlob_t *)clear->Data, sealed);
    }
    FREE_IF_NOT_NULL(sealed);
    FREE_IF_NOT_NULL(clear);
    if (err != E_ERP_SUCCESS)
    {
        auditErrWithID(err,auditID);
    }
    return (int)err;
}

// Externally callable FWAPI Command
// Command to add a trusted TPM Manufacturer Root CA certificate.
// Input: ASN1.DER encoded x509r3 Certificate for the TPM Manufacturer Root CA.
// Output: Trusted TPM Manufacturer Root Certificate Blob
// Return: Success or Error code.
int ERP_TrustTPMMfr(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)        // SFC = 11
{
    unsigned int err = E_ERP_SUCCESS;
    ERP_AuditID_t auditID = ERP_AUDIT_Failed_TPM_Manufacturer_Root_Certificate_Enrollment;
    unsigned int desiredGeneration = 0;
    unsigned int certLength = 0;
    unsigned char* pCertData = NULL;

    if (0 != check_permission(p_hdl, ERP_SETUP_PERMISSION, 2))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }

    if (err == E_ERP_SUCCESS)
    {
        err = parseTrustTPMMfrInput(l_cmd, p_cmd,
            &desiredGeneration, &certLength, &pCertData);
    }
    size_t signableLength = 0;
    unsigned char* pSignableData = NULL;
    size_t signatureLength = 0;
    unsigned char* pSignatureData = NULL;
    size_t x509ECKeyLength = 0;
    unsigned char* px509ECKeyData = NULL;
    size_t ecPointLength = 0;
    unsigned char* pECPointData = NULL;
    size_t curveIDLen = 0;
    unsigned char* pCurveID = NULL;
    unsigned int bIsCA = 0;
    if (err == E_ERP_SUCCESS)
    {
        err = parsex509ECCertificate(
                    certLength,    pCertData,
                    &signableLength, &pSignableData,
                    &signatureLength, &pSignatureData,
                    &x509ECKeyLength, &px509ECKeyData,
                    &ecPointLength, &pECPointData,
                    &curveIDLen, &pCurveID,
                    &bIsCA);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = CheckAvailableGeneration(p_hdl, desiredGeneration);
    }
    // ERP-5567 - Additional TPMMFRRoot Certicficate checks.
    // Algorithm is ECDSA.   Already checked in parse method.
    if (err == E_ERP_SUCCESS)
    {
        // Certificate is CA
        if (bIsCA == 0)
        {
            err = E_ERP_CERT_WRONG_ISCA_VALUE;
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        // Certificate is self-signed (Root)
        err = verifyECDSAWithANSISHA256Signature(p_hdl,
            signableLength, pSignableData,
            signatureLength, pSignatureData,
            x509ECKeyLength, px509ECKeyData);
        if (err == E_ECDSA_VERIFY_FAILED)
        {
            err = E_ERP_CERT_WRONG_ROOT_STATUS;
        }
    }
    ClearBlob_t* clear = NULL;
    if (err == E_ERP_SUCCESS)
    {
        clear = os_mem_new_tag(sizeof(ClearBlob_t) + sizeof(TPMMfrRootCertBlob_t) + certLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, clear, 0x37);
    }
    TPMMfrRootCertBlob_t* certy = NULL;
    if (err == E_ERP_SUCCESS)
    { // Create the new Root cert Blob
        clear->BlobType = TPM_Mfr_RootCert;
        err = fillGeneric(clear);
    }
    if (err == E_ERP_SUCCESS)
    {
        clear->DataLength = sizeof(TPMMfrRootCertBlob_t) + certLength;
        certy = (TPMMfrRootCertBlob_t *)&(clear->Data[0]);
        certy->CertificateLength = certLength;
        os_mem_cpy(&(certy->CertificateData[0]),pCertData,certLength);
    }

    SealedBlob_t* sealed = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = SealBlob(p_hdl, clear, desiredGeneration, &sealed);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = makeSingleSealedBlobOutput(p_hdl, sealed);
    }
    FREE_IF_NOT_NULL(sealed);
    FREE_IF_NOT_NULL(clear);
    if (err == E_ERP_SUCCESS)
    {
        auditErrWithID(err, ERP_AUDIT_TPM_Manufacturer_Root_Certificate_Enrolled);
    }
    else {
        auditErrWithID(err, auditID);
    }
    return (int)err;
}

// Externally callable FWAPI Command
// Enroll a TPM Endorsement Key.
// Input: TPM Manufacturer Root Blob
// Input: ASN1.DER encoded x509r3 certificate for the Endorsement Key
// Input: NONCE Blob
// Input: Signature with EKPriv over (EKPub | NONCE)
// Output: Trusted EK Blob
// Return: Success or Error code.
int ERP_EnrollTPMEK(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)        // SFC = 12
{
    unsigned int err = E_ERP_SUCCESS;
    ERP_AuditID_t auditID = ERP_AUDIT_Failed_TPM_EK_Enrollment;
    unsigned int desiredGeneration = 0;
    SealedBlob_t * pTrustedTPMMfrRootBlob = NULL;
    unsigned int EKCertLength = 0;
    unsigned char * EKCertData = NULL;
    if (0 != check_permission(p_hdl, ERP_SETUP_PERMISSION, 2))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }
    if (err == E_ERP_SUCCESS)
    {
        // To avoid lots of copying and reallocating, the pointers returned by this method are all
        //   referring directly to the elements of the ASN1_ITEM array returned by pItems.
        //   So, to delete them all, we need to call deleteASNItemList with pItems when we are finished.
        err = parseEnrollTPMEKInput(l_cmd, p_cmd,
            &desiredGeneration,
            &pTrustedTPMMfrRootBlob,
            &EKCertLength, &EKCertData);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = CheckAvailableGeneration(p_hdl, desiredGeneration);
    }

    // - Parse incoming EK Cert.
    size_t EKSignableLength = 0;
    unsigned char* pEKSignableData = NULL;
    size_t EKSignatureLength = 0;
    unsigned char* pEKSignatureData = NULL;
    size_t EKx509ECKeyLength = 0;
    unsigned char* pEKx509ECKeyData = NULL;
    size_t EKECPointLength = 0;
    unsigned char* pEKECPointData = NULL;
    size_t EKCurveIDLen = 0;
    unsigned char* pEKCurveID = NULL;
    unsigned int bIsEKCA = 0;
    if (err == E_ERP_SUCCESS)
    {
        err = parsex509ECCertificate(
            EKCertLength, EKCertData,
            &EKSignableLength, &pEKSignableData,
            &EKSignatureLength, &pEKSignatureData,
            &EKx509ECKeyLength, &pEKx509ECKeyData,
            &EKECPointLength, &pEKECPointData,
            &EKCurveIDLen, &pEKCurveID,
            &bIsEKCA);
    }
    // - Extract TPM MFR cert from blob.
    ClearBlob_t* clearTPMMfrRoot = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = UnsealBlobAndCheckType(p_hdl, TPM_Mfr_RootCert, pTrustedTPMMfrRootBlob, &clearTPMMfrRoot);
    }
    TPMMfrRootCertBlob_t* pMfrRoot = NULL;
    if (err == E_ERP_SUCCESS)
    {
        pMfrRoot = (TPMMfrRootCertBlob_t*)&(clearTPMMfrRoot->Data[0]);
    }
    // - Parse TPM MFR Cert.
    size_t MfrSignableLength = 0;
    unsigned char* pMfrSignableData = NULL;
    size_t MfrSignatureLength = 0;
    unsigned char* pMfrSignatureData = NULL;
    size_t Mfrx509ECKeyLength = 0;
    unsigned char* pMfrx509ECKeyData = NULL;
    size_t MfrECPointLength = 0;
    unsigned char* pMfrECPointData = NULL;
    size_t MfrCurveIDLen = 0;
    unsigned char* pMfrCurveID = NULL;
    unsigned int bIsMfrCA = 0;
    if (err == E_ERP_SUCCESS)
    {
        err = parsex509ECCertificate(
            pMfrRoot->CertificateLength, pMfrRoot->CertificateData,
            &MfrSignableLength, &pMfrSignableData,
            &MfrSignatureLength, &pMfrSignatureData,
            &Mfrx509ECKeyLength, &pMfrx509ECKeyData,
            &MfrECPointLength, &pMfrECPointData,
            &MfrCurveIDLen, &pMfrCurveID,
            &bIsMfrCA);
    }
    // ERP-5568 - Additional EK Certificate checks.
    // Check that: Algorithm is ECDSA.   Already checked in parse method.
    if (err == E_ERP_SUCCESS)
    {
        // Check that: Certificate is NOT a CA
        if (bIsEKCA != 0)
        {
            err = E_ERP_CERT_WRONG_ISCA_VALUE;
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        // Check that: Certificate is NOT self-signed (i.e. is NOT a Root certificate)
        // In this case, it means checking that the Mfr CA key is not the
        //   same as the subject key in this certificate, since we check the signature against
        //   the Mfr Cert in the next step.
        if ((EKx509ECKeyLength == Mfrx509ECKeyLength) &&
            (0 == os_mem_cmp(pEKx509ECKeyData, pMfrx509ECKeyData, EKx509ECKeyLength)))
        {
            err = E_ERP_CERT_WRONG_ROOT_STATUS;
        }
    }
    // - Check signature of EK Cert against the TPM Mfr Root CA cert.
    if (err == E_ERP_SUCCESS)
    {
        err = verifyECDSAWithANSISHA256Signature(p_hdl,
            EKSignableLength, pEKSignableData,
            EKSignatureLength, pEKSignatureData,
            Mfrx509ECKeyLength, pMfrx509ECKeyData);
    }

    // Make the data for the clear blob...   At the moment this is simplistically just the EK Cert.
    ClearBlob_t* clearResponse = NULL;
    if (err == E_ERP_SUCCESS)
    {
        clearResponse = os_mem_new_tag(sizeof(ClearBlob_t) + sizeof(KnownEKBlob_t) + EKCertLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, clearResponse, 0x38);
    }
    KnownEKBlob_t* EKy = NULL;
    if (err == E_ERP_SUCCESS)
    { // Create the new Known EK Blob
        clearResponse->BlobType = Trusted_EK;
        err = fillGeneric(clearResponse);
    }
    // If the TPM EKName is needed then it can be calculated from the public key in the certificate.
    if (err == E_ERP_SUCCESS)
    {
        clearResponse->DataLength = sizeof(KnownEKBlob_t) + EKCertLength;
        EKy = (KnownEKBlob_t *)&(clearResponse->Data[0]);
        EKy->CertificateLength = EKCertLength;
        os_mem_cpy(&(EKy->CertificateData[0]),&(EKCertData[0]),EKCertLength);
    }

    SealedBlob_t* sealed = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = SealBlob(p_hdl, clearResponse, desiredGeneration, &sealed);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = makeSingleSealedBlobOutput(p_hdl, sealed);
    }
    FREE_IF_NOT_NULL(sealed);
    FREE_IF_NOT_NULL(pTrustedTPMMfrRootBlob);
    FREE_IF_NOT_NULL(clearTPMMfrRoot);
    FREE_IF_NOT_NULL(clearResponse);
    if (err == E_ERP_SUCCESS)
    {
        auditErrWithID(err, ERP_AUDIT_TPM_Endorsement_Key_Enrolled);
    }
    else {
        auditErrWithID(err, auditID);
    }
    return (int)err;
}

// Externally callable FWAPI Command
// get an Attestation Key credential Chalenge to be signed by the TPM.
// Input: Known Endorsement Key Blob
// Input: TPM Name hash (0x000b + SHA256) of AK Public - used by TPM as name
// Input: TBD - either ASN1.DER encoded public key or x509r3 certificate for the Attestation Key
// Output: TPM2 Secret
// Output: TPM2 Credential
// Output: Credential Challenge Blob
// Return: Success or Error code.
int ERP_GetAKChallenge(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)        // SFC = 13
{
    unsigned int err = E_ERP_SUCCESS;
    ERP_AuditID_t auditID = ERP_AUDIT_Failed_Get_AK_Challenge;
    unsigned int desiredGeneration = 0;
    SealedBlob_t* pTrustedEKBlob = NULL;
    unsigned int AKPubLength = 0;
    unsigned char* AKPubData = NULL;
    unsigned char* nameAK = 0;
    if (0 != check_permission(p_hdl, ERP_SETUP_PERMISSION, 2))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }
    if (err == E_ERP_SUCCESS)
    {
        // To avoid lots of copying and reallocating, the pointers returned by this method are all
        //   referring directly to nthe elements of the ASN1_ITEM array returned by pItems.
        //   So, to delete them all, we need to call deleteASNItemList with pItems when we are finished.
        err = parseGetAKChallengeInput(l_cmd, p_cmd,
            &desiredGeneration,
            &pTrustedEKBlob,
            &AKPubLength, &AKPubData,
            &nameAK);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = CheckAvailableGeneration(p_hdl, desiredGeneration);
    }

    if (err == E_ERP_SUCCESS)
    {
        err = CheckTPMNameHash(p_hdl, AKPubLength,AKPubData,nameAK);
    }

    ClearBlob_t* clearEK = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = UnsealBlobAndCheckType(p_hdl, Trusted_EK, pTrustedEKBlob, &clearEK);
    }

    // Create a unique Credential challenge.   and
    // Make the Credential challenge Blob.   This is what the TPM will have to decrypt and return in the next step.
    //       This is limited to a TPM2B_DIGEST, i.e. 32 bytes.   So fill that with a RND256 and use that.
    ClearBlob_t* clearResponseBlob = NULL;
    unsigned char challengeData[SHA_256_LEN / 8] = "";
    unsigned int challengeLength = SHA_256_LEN/8;
    if (err == E_ERP_SUCCESS)
    {
        os_crypt_drbg_rnd(DRBG_PSEUDO, &(challengeData[0]),challengeLength );
        clearResponseBlob = os_mem_new_tag(sizeof(ClearBlob_t) + sizeof(AKChallengeBlob_t) + challengeLength + 2, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        if (clearResponseBlob == NULL)
        {
            err = E_ERP_MALLOC;
        }
    }
    AKChallengeBlob_t* challengeBlob = NULL;
    if (err == E_ERP_SUCCESS)
    { // Create the new Challenge
        clearResponseBlob->BlobType = AKChallenge;
        err = fillGeneric(clearResponseBlob);
    }
    if (err == E_ERP_SUCCESS)
    { // Challenge is unique and tied to AK.
        clearResponseBlob->DataLength = sizeof(AKChallengeBlob_t) + challengeLength + 2;
        challengeBlob = (AKChallengeBlob_t *)&(clearResponseBlob->Data[0]);
        // prepend the 2 byte length field here so that the calculations later don't need to recopy the data.
        challengeBlob->DataLength = challengeLength+2;
        challengeBlob->Data[0] = (unsigned char)(challengeLength >> 8);
        challengeBlob->Data[1] = (unsigned char)(challengeLength % 0x100);

        os_mem_cpy(&(challengeBlob->Data[2]), &(challengeData[0]), challengeLength);
        os_mem_cpy(&(challengeBlob->AKName[0]), &(nameAK[0]), TPM_NAME_LEN);
    }
    SealedBlob_t* sealedChallengeBlob = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = SealBlob(p_hdl, clearResponseBlob, desiredGeneration, &sealedChallengeBlob);
    }

    // Generate the TPM2 Credential and Secret.
    unsigned char *pCredentialData= NULL;
    size_t credentialLength = 0;
    unsigned char *pSecretData = NULL;
    size_t secretLength = 0;

    if (err == E_ERP_SUCCESS)
    {
        err = makeAKChallenge(p_hdl,
            clearResponseBlob,
            clearEK,
            AKPubLength,AKPubData,
            nameAK,
            &credentialLength, &pCredentialData,
            &secretLength, &pSecretData);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = makeAKChallengeOutput(
            p_hdl,
            sealedChallengeBlob,
            credentialLength,
            pCredentialData,
            secretLength,
            pSecretData);
    }
    FREE_IF_NOT_NULL(pSecretData);
    FREE_IF_NOT_NULL(pCredentialData);
    FREE_IF_NOT_NULL(sealedChallengeBlob);
    FREE_IF_NOT_NULL(pTrustedEKBlob);
    FREE_IF_NOT_NULL(clearEK);
    FREE_IF_NOT_NULL(clearResponseBlob);
    if (err != E_ERP_SUCCESS)
    {
        auditErrWithID(err, auditID);
    }
    return (int)err;
}

// Externally callable FWAPI Command
// Enroll an Attestation Key using the results of a TPM decryption of the credential challenge.
// Input: Known Endoresement Key Blob
// Input: TPM Name hash (0x000b + SHA256) of AK Public - used by TPM as name
// Input: TBD - either ASN1.DER encoded public key or x509r3 certificate for the Attestation Key
// Input: Decrypted Credential
// Input: Credential Challenge Blob
// Output: Trusted AK Blob
// Return: Success or Error code.
int ERP_EnrollTPMAK(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)        // SFC = 14
{
    unsigned int err = E_ERP_SUCCESS;
    ERP_AuditID_t auditID = ERP_AUDIT_Failed_TPM_AK_Enrollment;
    unsigned int desiredGeneration = 0;
    SealedBlob_t* pTrustedEKBlob = NULL;
    SealedBlob_t* pChallengeBlob = NULL;
    unsigned int AKPubLength = 0;
    unsigned char* AKPubData = NULL;
    unsigned int plainCredLength = 0;
    unsigned char* plainCredData = NULL;
    unsigned char* nameAK = 0;
    if (0 != check_permission(p_hdl, ERP_SETUP_PERMISSION, 2))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }
    if (err == E_ERP_SUCCESS)
    {
        // To avoid lots of copying and reallocating, the pointers returned by this method are all
        //   referring directly to the elements of the ASN1_ITEM array returned by pItems.
        //   So, to delete them all, we need to call deleteASNItemList with pItems when we are finished.
        err = parseEnrollAKInput(l_cmd, p_cmd,
            &desiredGeneration,
            &pTrustedEKBlob,
            &pChallengeBlob,
            &AKPubLength,
            &AKPubData,
            &nameAK,
            &plainCredLength,
            &plainCredData);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = CheckAvailableGeneration(p_hdl, desiredGeneration);
    }

    // Check AK Public data against NameAK.
    if (err == E_ERP_SUCCESS)
    {
        err = CheckTPMNameHash(p_hdl, AKPubLength, AKPubData, nameAK);
    }

    size_t ANSIAKPublicKeyLen = 0;
    unsigned char* pANSIAKPublicKeyData = NULL;
    size_t ANSIAKCurveLen = 0;
    unsigned char* pANSIAKCurveOID = NULL;
    if (err == E_ERP_SUCCESS)
    { // Check this here and we will need the public key later.
        err = ConvertTPMT_PUBLICToANSI(p_hdl,
            AKPubLength, AKPubData,
            &ANSIAKPublicKeyLen, &pANSIAKPublicKeyData,
            &ANSIAKCurveLen, &pANSIAKCurveOID);
    }

    ClearBlob_t* clearEK = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = UnsealBlobAndCheckType(p_hdl, Trusted_EK, pTrustedEKBlob, &clearEK);
    }
    ClearBlob_t* clearChallenge = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = UnsealBlobAndCheckType(p_hdl, AKChallenge, pChallengeBlob, &clearChallenge);
    }

    // Check the credential challenge against the input AK and decrypted challenge.
    if (err == E_ERP_SUCCESS)
    { // Intentionally do not differentiate the two error cases here.
        AKChallengeBlob_t* challenge = (AKChallengeBlob_t*)clearChallenge->Data;
        // First two bytes of stored challenge are a length field not present in the result.
        if (challenge->DataLength != plainCredLength + 2)
        {
            err = E_ERP_FAIL_AK_CREDENTIAL_MATCH;
        }
        if (0 != os_mem_cmp(&(challenge->Data[2]), plainCredData, plainCredLength))
        {
            err = E_ERP_FAIL_AK_CREDENTIAL_MATCH;
        }
    }

    // Make the TrustedAK Blob.
    //       At the moment this is just a bit of static data...
    ClearBlob_t* clearResponseBlob = NULL;
    if (err == E_ERP_SUCCESS)
    {
        clearResponseBlob = os_mem_new_tag(sizeof(ClearBlob_t) + sizeof(KnownAKBlob_t) + ANSIAKPublicKeyLen, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        if (clearResponseBlob == NULL)
        {
            err = E_ERP_MALLOC;
        }
    }
    KnownAKBlob_t* AKBlob = NULL;
    if (err == E_ERP_SUCCESS)
    { // Create the new known AK Blob
        clearResponseBlob->BlobType = Trusted_AK;
        err = fillGeneric(clearResponseBlob);
    }
    if (err == E_ERP_SUCCESS)
    { // Challenge is unique and tied to AK.
        clearResponseBlob->DataLength = sizeof(KnownAKBlob_t) +ANSIAKPublicKeyLen;
        AKBlob = (KnownAKBlob_t *)&(clearResponseBlob->Data[0]);
        AKBlob->ANSIPubKeyLength = ANSIAKPublicKeyLen;
        os_mem_cpy(&(AKBlob->ANSIPubKeyData[0]), &(pANSIAKPublicKeyData[0]), ANSIAKPublicKeyLen);
        os_mem_cpy(&(AKBlob->AKName[0]), &(nameAK[0]), TPM_NAME_LEN);
    }
    SealedBlob_t* sealedResponseBlob = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = SealBlob(p_hdl, clearResponseBlob, desiredGeneration, &sealedResponseBlob);
    }

    if (err == E_ERP_SUCCESS)
    {
        err = makeSingleSealedBlobOutput(p_hdl,
            sealedResponseBlob);
    }
    FREE_IF_NOT_NULL(pANSIAKCurveOID);
    FREE_IF_NOT_NULL(pANSIAKPublicKeyData);
    FREE_IF_NOT_NULL(pTrustedEKBlob);
    FREE_IF_NOT_NULL(clearEK);
    FREE_IF_NOT_NULL(pChallengeBlob);
    FREE_IF_NOT_NULL(clearChallenge);
    FREE_IF_NOT_NULL(sealedResponseBlob);
    FREE_IF_NOT_NULL(clearResponseBlob);
    if (err == E_ERP_SUCCESS)
    {
        auditErrWithID(err, ERP_AUDIT_TPM_Attestation_Key_Enrolled);
    }
    else {
        auditErrWithID(err, auditID);
    }
    return (int)err;
}

// Externally callable FWAPI Command
// Enroll a VAU Software stack quote.
// Input: TPM Name hash (0x000b + SHA256) of AK Public - used by TPM as name
// Input: Trusted AK Blob
// Input: NONCE Blob
// Input: Quote Data from TPM
//        The quote data will include a NONCE-derived value of HMAC(HSM NONCE,"ERP_ENROLLMENT")
// Input: TPM Signature of quote data and NONCE.
// Output: Trusted Quote Blob
// Return: Success or Error code.
int ERP_EnrollEnclave(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)        // SFC = 15
{
    unsigned int err = E_ERP_SUCCESS;
    ERP_AuditID_t auditID = ERP_AUDIT_Failed_TPM_Quote_Enrollment;
    unsigned int desiredGeneration = 0;
    SealedBlob_t* pTrustedAKBlob = NULL;
    SealedBlob_t* pNONCEBlob = NULL;
    unsigned int QuoteLength = 0;
    unsigned char* QuoteData = NULL;
    unsigned int SignatureLength = 0;
    unsigned char* SignatureData = NULL;
    unsigned char* nameAK = 0;
    if (0 != check_permission(p_hdl, ERP_SETUP_PERMISSION, 2))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }
    if (err == E_ERP_SUCCESS)
    {
        // To avoid lots of copying and reallocating, the pointers returned by this method are all
        //   referring directly to nthe elements of the ASN1_ITEM array returned by pItems.
        //   So, to delete them all, we need to call deleteASNItemList with pItems when we are finished.
        err = parseEnrollEnclaveInput(l_cmd, p_cmd,
            &desiredGeneration,
            &nameAK,
            &pTrustedAKBlob,
            &pNONCEBlob,
            &QuoteLength,
            &QuoteData,
            &SignatureLength,
            &SignatureData);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = CheckAvailableGeneration(p_hdl, desiredGeneration);
    }

    // Unseal the Blobs
    ClearBlob_t* clearAK = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = UnsealBlobAndCheckType(p_hdl, Trusted_AK, pTrustedAKBlob, &clearAK);
    }

    ClearBlob_t* clearNONCE = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = UnsealBlobAndCheckType(p_hdl, NONCE_Blob, pNONCEBlob, &clearNONCE);
    }

    // Check AK Public data from TrustedAKBlob against NameAK.
    KnownAKBlob_t* pAKBlob = NULL;
    if (err == E_ERP_SUCCESS)
    {
        pAKBlob = (KnownAKBlob_t*)clearAK->Data;
        if (0 != os_mem_cmp(&(pAKBlob->AKName[0]), nameAK, TPM_NAME_LEN))
        {
            err = E_ERP_TPM_NAME_MISMATCH;
        }
    }

    // Check the Signature with AK and NONCE.
    if (err == E_ERP_SUCCESS)
    {
        err = verifyECDSAWithTPMTSHA256Signature(p_hdl,
            QuoteLength, QuoteData,
            SignatureLength, SignatureData,
            pAKBlob->ANSIPubKeyLength, pAKBlob->ANSIPubKeyData);       // public key of signer in RFC 5480 format.
    }
    // Other checks for a valid quote:
    //     Check Quote formal validity
    unsigned char* pPCRFlags = NULL;
    unsigned char* pPCRHash = NULL; // This will be an SHA256 Hash.
    unsigned char* pNONCE = NULL;
    unsigned char* pQualifiedSignerName = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = verifyTPMQuote(p_hdl,
            QuoteData, QuoteLength,
            pAKBlob->AKName, // The AKName also needs to be inside the quote...
            &pQualifiedSignerName,
            &pNONCE,
            &pPCRFlags,
            &pPCRHash);
    }
    // Check variation form of random number against Quote.
    if (err == E_ERP_SUCCESS)
    {
        unsigned char variationNONCE[NONCE_LEN];
        NONCEBlob_t* nonceBlob = (NONCEBlob_t*)&(clearNONCE->Data[0]);
        err = varyNONCE("ERP_ENROLLMENT", &(nonceBlob->RNDData[0]), &(variationNONCE[0]));
        if (err == E_ERP_SUCCESS)
        {
            if (0 != os_mem_cmp(pNONCE, &(variationNONCE[0]), NONCE_LEN / 8))
            {
                err = E_ERP_QUOTE_NONCE_MISMATCH;
            }
        }
    }
    // Here we know:
    //        - Signature over quote is valid and calculated with the AK named in the quote and passed in in TrustedAK Blob.
    //        - format and static contents of the quote are ok.
    //        - the quote contains one PCR Set.
    // TODO:   ERP-6201 - identify if there are any other checks that make sense at this point.

    // Make the TrustedQuote Blob.
    //       At the moment this is just a repeat of the Quote Data.
    ClearBlob_t* clearResponseBlob = NULL;
    if (err == E_ERP_SUCCESS)
    {
        clearResponseBlob = os_mem_new_tag(sizeof(ClearBlob_t) + sizeof(KnownQuoteBlob_t) + QuoteLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        if (clearResponseBlob == NULL)
        {
            err = E_ERP_MALLOC;
        }
    }
    KnownQuoteBlob_t* quoteBlob = NULL;
    if (err == E_ERP_SUCCESS)
    { // Create the new Quote Blob
        clearResponseBlob->BlobType = Trusted_Quote;
        err = fillGeneric(clearResponseBlob);
    }
    if (err == E_ERP_SUCCESS)
    { // Data is currently just AK Name and Quote value.
        clearResponseBlob->DataLength = sizeof(KnownQuoteBlob_t) + QuoteLength;
        quoteBlob = (KnownQuoteBlob_t *)&(clearResponseBlob->Data[0]);
        quoteBlob->QuoteLength = QuoteLength;
        os_mem_cpy(&(quoteBlob->QuoteData[0]), &(QuoteData[0]), QuoteLength);
        os_mem_cpy(&(quoteBlob->AKName[0]), &(nameAK[0]), TPM_NAME_LEN);
    }
    SealedBlob_t* sealedResponseBlob = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = SealBlob(p_hdl, clearResponseBlob, desiredGeneration, &sealedResponseBlob);
    }

    if (err == E_ERP_SUCCESS)
    {
        err = makeSingleSealedBlobOutput(p_hdl,
            sealedResponseBlob);
    }
    FREE_IF_NOT_NULL(pTrustedAKBlob);
    FREE_IF_NOT_NULL(clearAK);
    FREE_IF_NOT_NULL(pNONCEBlob);
    FREE_IF_NOT_NULL(clearNONCE);
    FREE_IF_NOT_NULL(sealedResponseBlob);
    FREE_IF_NOT_NULL(clearResponseBlob);
    if (err == E_ERP_SUCCESS)
    {
        auditErrWithID(err, ERP_AUDIT_TPM_Quote_Enrolled);
    }
    else {
        auditErrWithID(err, auditID);
    }
    return (int)err;
}

// Externally callable FWAPI Command
// Get a time limited Token to use the HSM as a VAU
// Input: TPM Name hash (0x000b + SHA256) of AK Public - used by TPM as name
// Input: Trusted AK Blob
// Input: NONCE Blob
// Input: Trusted Quote Blob
// Input: Quoted Data - TBD exact sub-structure here?
// Input: TPM Signature over the quoted data using NONCE and AK
// Output: TEE Token Blob
// Return: Success or Error code.
int ERP_GetTEEToken(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)        // SFC = 16
{
    unsigned int err = E_ERP_SUCCESS;
    ERP_AuditID_t auditID = ERP_AUDIT_Failed_getTEEToken;
    unsigned int desiredGeneration = 0;
    SealedBlob_t* pTrustedAKBlob = NULL;
    SealedBlob_t* pTrustedQuoteBlob = NULL;
    SealedBlob_t* pNONCEBlob = NULL;
    unsigned int QuoteLength = 0;
    unsigned char* QuoteData = NULL;
    unsigned int SignatureLength = 0;
    unsigned char* SignatureData = NULL;
    unsigned char* nameAK = 0;
    if (0 != check_permission(p_hdl, ERP_WORKING_PERMISSION, 2))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }
    if (err == E_ERP_SUCCESS)
    {
        // To avoid lots of copying and reallocating, the pointers returned by this method are all
        //   referring directly to the elements of the ASN1_ITEM array returned by pItems.
        //   So, to delete them all, we need to call deleteASNItemList with pItems when we are finished.
        err = parseGetTEETokenInput(l_cmd, p_cmd,
            &nameAK,
            &pTrustedAKBlob,
            &pTrustedQuoteBlob,
            &pNONCEBlob,
            &QuoteLength,
            &QuoteData,
            &SignatureLength,
            &SignatureData);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = CheckAvailableGeneration(p_hdl, desiredGeneration);
    }

    // Unseal the Blobs.   This involves checking validity and types.
    ClearBlob_t* clearAK = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = UnsealBlobAndCheckType(p_hdl, Trusted_AK, pTrustedAKBlob, &clearAK);
    }
    ClearBlob_t* clearTrustedQuote = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = UnsealBlobAndCheckType(p_hdl, Trusted_Quote, pTrustedQuoteBlob, &clearTrustedQuote);
    }
    ClearBlob_t* clearNONCE = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = UnsealBlobAndCheckType(p_hdl, NONCE_Blob, pNONCEBlob, &clearNONCE);
    }
    // Check AK Public data from TrustedAKBlob against NameAK.
    KnownAKBlob_t* pAKBlob = NULL;
    if (err == E_ERP_SUCCESS)
    {
        pAKBlob = (KnownAKBlob_t*)clearAK->Data;
        if (0 != os_mem_cmp(&(pAKBlob->AKName[0]), nameAK, TPM_NAME_LEN))
        {
            err = E_ERP_TPM_NAME_MISMATCH;
        }
    }
    // Check the Signature with AK.
    if (err == E_ERP_SUCCESS)
    {
        err = verifyECDSAWithTPMTSHA256Signature(p_hdl,
            QuoteLength, QuoteData,
            SignatureLength, SignatureData,
            pAKBlob->ANSIPubKeyLength, pAKBlob->ANSIPubKeyData);       // public key of signer in RFC 5480 format.
    }

    //     Check Quote formal validity
    unsigned char* pPCRFlags = NULL;
    unsigned char* pPCRHash = NULL; // This will be an SHA256 Hash.
    unsigned char* pNONCE = NULL;
    unsigned char* pQualifiedSignerName = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = verifyTPMQuote(p_hdl,
            QuoteData, QuoteLength,
            pAKBlob->AKName, // The AKName also needs to be inside the quote...
            &pQualifiedSignerName,
            &pNONCE,
            &pPCRFlags,
            &pPCRHash);
    }
    if (err == E_ERP_SUCCESS)
    {
        unsigned char variationNONCE[NONCE_LEN];
        NONCEBlob_t* nonceBlob = (NONCEBlob_t*)&(clearNONCE->Data[0]);
        err = varyNONCE("ERP_ATTESTATION", &(nonceBlob->RNDData[0]), &(variationNONCE[0]));
        if (err == E_ERP_SUCCESS)
        {
            if (0 != os_mem_cmp(pNONCE, &(variationNONCE[0]), NONCE_LEN / 8))
            {
                err = E_ERP_QUOTE_NONCE_MISMATCH;
            }
        }
    }    // Compare quote with quote from Trsuted Quote Blob
    unsigned char* pTrustedPCRFlags = NULL;
    unsigned char* pTrustedPCRHash = NULL; // This will be an SHA256 Hash.
    unsigned char* pTrustedNONCE = NULL;
    unsigned char* pTrustedQualifiedSignerName = NULL;
    if (err == E_ERP_SUCCESS)
    {
        KnownQuoteBlob_t* knownQuote = (KnownQuoteBlob_t*)(&(clearTrustedQuote->Data[0]));
        err = verifyTPMQuote(p_hdl,
            knownQuote->QuoteData, knownQuote->QuoteLength,
            pAKBlob->AKName, // The AKName also needs to be inside the quote...
            &pTrustedQualifiedSignerName,
            &pTrustedNONCE,
            &pTrustedPCRFlags,
            &pTrustedPCRHash);
    }
    // ERP-5802 - Check removed -  Check signer name matches.
    if (err == E_ERP_SUCCESS)
    {
        if (0 != os_mem_cmp(pPCRFlags, pTrustedPCRFlags, 3))
        {
            err = E_ERP_QUOTE_PCRSET_MISMATCH;
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        if (0 != os_mem_cmp(pPCRHash, pTrustedPCRHash, SHA_256_LEN/8))
        {
            err = E_ERP_QUOTE_DIGEST_MISMATCH;
        }
    }
    // Make the TEE Token Blob.
    //       At the moment this is just a repeat of the Quote Data.
    ClearBlob_t* clearResponseBlob = NULL;
    if (err == E_ERP_SUCCESS)
    {
        clearResponseBlob = os_mem_new_tag(sizeof(ClearBlob_t) + sizeof(TEETokenBlob_t) + TEE_TOKEN_TEXT_LEN, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        if (clearResponseBlob == NULL)
        {
            err = E_ERP_MALLOC;
        }
    }
    TEETokenBlob_t* tokenBlob = NULL;
    if (err == E_ERP_SUCCESS)
    { // Create the new Token
        clearResponseBlob->BlobType = TEE_Token;
        err = fillGeneric(clearResponseBlob);
    }
    if (err == E_ERP_SUCCESS)
    { // Data is currently just AK Name and a Static String
        clearResponseBlob->DataLength = sizeof(TEETokenBlob_t) + TEE_TOKEN_TEXT_LEN;
        tokenBlob = (TEETokenBlob_t *) &(clearResponseBlob->Data[0]);
        static const char tokenText[] = TEE_TOKEN_TEXT;
        os_mem_cpy(&(tokenBlob->TokenText[0]), &(tokenText[0]), TEE_TOKEN_TEXT_LEN);
        os_mem_cpy(&(tokenBlob->AKName[0]), &(nameAK[0]), TPM_NAME_LEN);
    }
    SealedBlob_t* sealedResponseBlob = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = SealBlob(p_hdl, clearResponseBlob, desiredGeneration, &sealedResponseBlob);
    }

    if (err == E_ERP_SUCCESS)
    {
        err = makeSingleSealedBlobOutput(p_hdl,
            sealedResponseBlob);
    }
    FREE_IF_NOT_NULL(pNONCEBlob);
    FREE_IF_NOT_NULL(clearNONCE);
    FREE_IF_NOT_NULL(pTrustedQuoteBlob);
    FREE_IF_NOT_NULL(clearTrustedQuote);
    FREE_IF_NOT_NULL(pTrustedAKBlob);
    FREE_IF_NOT_NULL(clearAK);
    FREE_IF_NOT_NULL(sealedResponseBlob);
    FREE_IF_NOT_NULL(clearResponseBlob);
    if (err != E_ERP_SUCCESS)
    {
        auditErrWithID(err, auditID);
    }
    return (int)err;
}

// Shared implementation for multiple externally callable FWAPI Commands
// Derive a TASK Persistence symmetric key.
// Input: currently valid TEE Token
// Input: Input Derivation Data
// Input: Initial Derivation 1 is true, 0 is false
//          if Initial Derivation then the HSM will add extra data to the derivation data which must be
//          stored by the application for subsequent derivations of this key.
// Input: Derivation Key Blob
// Input: Key Prefix - will be XOR'd with the start of the key derivation data before derivation.
// Output: Symmetric derived key.
// Output: Used Derivation data - data actually used for the derivation, including any extra added by HSM.
// Return: Success or Error code.
int ERP_DerivePersistenceKey(
    T_CMDS_HANDLE* p_hdl,
    int l_cmd,
    unsigned char* p_cmd,
    char * KeyPrefix)        // SFC = 17
{
    unsigned int err = E_ERP_SUCCESS;
    ERP_AuditID_t auditID = ERP_AUDIT_Failed_Key_Derivation;
    SealedBlob_t* pTEETokenBlob = NULL;
    SealedBlob_t* pDerivationKeyBlob = NULL;
    unsigned char* nameAK = 0;
    unsigned int isInitial = 0;
    unsigned int derivationDataLength = 0;
    unsigned char* derivationData = NULL;

    if (0 != check_permission(p_hdl, ERP_WORKING_PERMISSION, 2))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }
    if (err == E_ERP_SUCCESS)
    {
        // To avoid lots of copying and reallocating, the pointers returned by this method are all
        //   referring directly to the elements of the ASN1_ITEM array returned by pItems.
        //   So, to delete them all, we need to call deleteASNItemList with pItems when we are finished.
        err = parseDeriveKeyInput(l_cmd, p_cmd,
            &nameAK,
            &pTEETokenBlob,
            &pDerivationKeyBlob,
            &isInitial,
            &derivationDataLength,
            &derivationData);
    }

    ClearBlob_t* clearToken = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = UnsealBlobAndCheckType(p_hdl, TEE_Token, pTEETokenBlob, &clearToken);
    }
    ClearBlob_t* clearDerivationKey = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = UnsealBlobAndCheckType(p_hdl, Derivation_Key, pDerivationKeyBlob, &clearDerivationKey);
    }
    // Check Token Times - done in UnsealBlob
    // TODO:   ERP-6201 - check AK in request against Token.
    unsigned int UsedDerivationDataLength = 0;
    unsigned char * UsedDerivationData = NULL;

    if (err == E_ERP_SUCCESS)
    {
        if (isInitial != 0)
        {   // Append ": " + 256 bit RND in hex.
            UsedDerivationDataLength = derivationDataLength + 2 + (256 / 8);
            UsedDerivationData = os_mem_new_tag(UsedDerivationDataLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
            if (UsedDerivationData == NULL)
            {
                err = E_ERP_MALLOC;
            }
            if (err == E_ERP_SUCCESS)
            {
                os_mem_cpy(&(UsedDerivationData[0]), derivationData, derivationDataLength);
                UsedDerivationData[derivationDataLength] = ':';
                UsedDerivationData[derivationDataLength + 1] = ' ';
                err = os_crypt_drbg_rnd(DRBG_PSEUDO, &(UsedDerivationData[derivationDataLength + 2]), 256 / 8);
            }
        }
        else {
            UsedDerivationDataLength = derivationDataLength;
            // Be careful - this does not need to be deleted later.
            UsedDerivationData = &(derivationData[0]);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        if (UsedDerivationDataLength < strlen(KeyPrefix))
        {
            err = E_ERP_DERIVATION_DATA_LENGTH;
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        unsigned int c;
        unsigned int prefixLen = strlen(KeyPrefix);
        for (c = 0; c < prefixLen; c++)
        {
            UsedDerivationData[c] ^= KeyPrefix[c];
        }
    }
    // Derive the key here...
    // The initial value here is to be overwritten with the derived value.
    unsigned char DerivedKey[AES_256_LEN / 8] =
            { 0,1,2,3,4,5,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf,
            0xf,0xe,0xd,0xc,0xb,0xa,9,8,7,6,5,4,3,2,1,0 };
    if (err == E_ERP_SUCCESS)
    {
        AES256KeyBlob_t* Key = (AES256KeyBlob_t *)&(clearDerivationKey->Data[0]);
        size_t outLen = AES_256_LEN / 8;
        err = _DoHKDF(p_hdl,
            &(Key->KeyData[0]),
            UsedDerivationDataLength,
            UsedDerivationData,
            outLen,
            &(DerivedKey[0]) );
    }

    // Now XOR the prefix back to undo the variation before returning the used derivation data.
    if (err == E_ERP_SUCCESS)
    {
        unsigned int c;
        unsigned int prefixLen = strlen(KeyPrefix);
        for (c = 0; c < prefixLen; c++)
        {
            UsedDerivationData[c] ^= KeyPrefix[c];
        }
    }

    if (err == E_ERP_SUCCESS)
    {
        err = makeDerivedKeyOutput(p_hdl,
            DerivedKey,
            UsedDerivationDataLength,
            UsedDerivationData);
    }
    FREE_IF_NOT_NULL(pTEETokenBlob);
    FREE_IF_NOT_NULL(clearToken);
    FREE_IF_NOT_NULL(pDerivationKeyBlob);
    FREE_IF_NOT_NULL(clearDerivationKey);
    if ((isInitial !=0) && (UsedDerivationData != NULL))
    {
        os_mem_del_set(UsedDerivationData, 0);
    }
    if (err != E_ERP_SUCCESS)
    {
        auditErrWithID(err, auditID);
    }
    return (int)err;
}

// Externally callable FWAPI Command
// Derive a TASK Persistence symmetric key.
// Input: currently valid TEE Token
// Input: Input Derivation Data
// Input: Initial Derivation 1 is true, 0 is false
//          if Initial Derivation then the HSM will add extra data to the derivation data which must be
//          stored by the application for subsequent derivations of this key.
// Input: Derivation Key Blob
// Output: Symmetric derived key.
// Output: Used Derivation data - data actually used for the derivation, including any extra added by HSM.
// Return: Success or Error code.
int ERP_DeriveTaskKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)        // SFC = 17
{
    return ERP_DerivePersistenceKey(p_hdl, l_cmd, p_cmd, "ERP_TASK");
}

// Externally callable FWAPI Command
// As ERP_deriveTaskKey, but for Audit persistence keys.
int ERP_DeriveAuditKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)        // SFC = 18
{
    return ERP_DerivePersistenceKey(p_hdl, l_cmd, p_cmd, "ERP_AUDIT");
}

// Externally callable FWAPI Command
// As ERP_deriveTaskKey, but for Communications persistence keys.
int ERP_DeriveCommsKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)        // SFC = 19
{
    return ERP_DerivePersistenceKey(p_hdl, l_cmd, p_cmd, "ERP_COMMS");
}

// Externally callable FWAPI Command
// As ERP_deriveTaskKey, but for ChargeItem persistence keys.
int ERP_DeriveChargeItemKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)        // SFC = 30
{
    return ERP_DerivePersistenceKey(p_hdl, l_cmd, p_cmd, "ERP_CHARGE");
}

// Externally callable FWAPI Command
// Command to generate a Random Data with the HSM hardware RND Generator
// Input: none.
// Output: The requested RND Data
// Return: Success or Error code.
extern int ERP_GetRNDBytes(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)
{
     unsigned int err = E_ERP_SUCCESS;
    ERP_AuditID_t auditID = ERP_AUDIT_Internal_Error;
    unsigned int RequestedBytes = 0;

    if (0 != check_permission(p_hdl, ERP_WORKING_PERMISSION, 2))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }

    if (err == E_ERP_SUCCESS)
    {
        err = parseSingleIntInput(l_cmd, p_cmd, &RequestedBytes);
    }
    if (err == E_ERP_SUCCESS)
    {
        if ((RequestedBytes == 0) || (RequestedBytes > MAX_RND_BYTES))
        { // Maximum RND Bytes.
            err = E_ERP_PARAM;
        }
    }
    unsigned char* RNDData = NULL;
    if (err == E_ERP_SUCCESS)
    {
        RNDData = os_mem_new_tag(RequestedBytes, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, RNDData, 0x39);
    }

    if (err == E_ERP_SUCCESS)
    { // This is real hardware RND!
        err = os_crypt_drbg_rnd(DRBG_REAL, &(RNDData[0]), RequestedBytes);
    }
    // This method will do all the work of building and allocating the firmware
    //   response containing the integer.
    if (err == E_ERP_SUCCESS)
    {
        err = makeSimpleOctetStringOutput(p_hdl, RequestedBytes, &(RNDData[0]));
    }

    FREE_IF_NOT_NULL(RNDData);
    if (err != E_ERP_SUCCESS)
    {
        auditErrWithID(err, auditID);
    }
    return (int)err;
}

// Externally callable FWAPI Command
// ERP-9411 - allowed for ERP_SETUP, ERP_WORKING or ERP_UPDATE userpermissions.
// return public key for keypair.
// input: ECIES KeyPair Blob
// output: ASN1.DER encoded public key from the blob.
// Return: Success or Error code.
extern int ERP_GetECPublicKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)
{
     unsigned int err = E_ERP_SUCCESS;
    ERP_AuditID_t auditID = ERP_AUDIT_Failed_EC_Get_Public_Key;
    SealedBlob_t* pKeyPairBlob = NULL;
    if ((0 != check_permission(p_hdl, ERP_SETUP_PERMISSION, 2)) &&
        (0 != check_permission(p_hdl, ERP_WORKING_PERMISSION, 2)) &&
        (0 != check_permission(p_hdl, ERP_UPDATE_PERMISSION, 2)))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }
    if (err == E_ERP_SUCCESS)
    {
        // To avoid lots of copying and reallocating, the pointers returned by this method are all
        //   referring directly to the elements of the ASN1_ITEM array returned by pItems.
        //   So, to delete them all, we need to call deleteASNItemList with pItems when we are finished.
        err = parseSingleBlobInput(l_cmd, p_cmd, &pKeyPairBlob);
    }

    ClearBlob_t* clearKeyPair = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = UnsealBlob(p_hdl, pKeyPairBlob, &clearKeyPair);
    }
    if (err == E_ERP_SUCCESS)
    {
        if ((clearKeyPair->BlobType != ECIES_KeyPair) &&
            (clearKeyPair->BlobType != VAUSIG_KeyPair))
        {
            err = E_ERP_KEY_USAGE_ERROR;
        }
    }
    unsigned int pubKeyLen = 0;
    unsigned char* pPubKeyData = NULL;

    if (err == E_ERP_SUCCESS)
    {
        err = GetASN1PublicKeyFromBlob(clearKeyPair,
            &pubKeyLen,
            &pPubKeyData);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = makePublicKeyOutput(p_hdl, pubKeyLen, pPubKeyData);
    }
    FREE_IF_NOT_NULL(pKeyPairBlob);
    FREE_IF_NOT_NULL(clearKeyPair);
    FREE_IF_NOT_NULL(pPubKeyData);
    if (err != E_ERP_SUCCESS)
    {
        auditErrWithID(err, auditID);
    }
    return (int)err;
}

// Externally callable FWAPI Command
// Command to Do ECIES KEy Derivation for VAU Protocol
// input: TEE Token
// input: ECIES KeyPair Blob
// input: Client ECIES Public key
// output: AES128 vau protocol key.
// Return: Success or Error code.
extern int ERP_DoECIES128(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)
{
     unsigned int err = E_ERP_SUCCESS;
    ERP_AuditID_t auditID = ERP_AUDIT_Failed_ECIES_DO_VAUECIES;
    SealedBlob_t* pTEETokenBlob = NULL;
    SealedBlob_t* pKeyPairBlob = NULL;
    if (0 != check_permission(p_hdl, ERP_WORKING_PERMISSION, 2))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }
    size_t clientPubKeyLength = 0;
    unsigned char* pClientPubKeyData = NULL;
    if (err == E_ERP_SUCCESS)
    {
        // To avoid lots of copying and reallocating, the pointers returned by this method are all
        //   referring directly to the elements of the ASN1_ITEM array returned by pItems.
        //   So, to delete them all, we need to call deleteASNItemList with pItems when we are finished.
        err = parseDoECIESAES128Request(l_cmd, p_cmd,
            &pTEETokenBlob,
            &pKeyPairBlob,
            &clientPubKeyLength,
            &pClientPubKeyData );
    }

    ClearBlob_t* clearTEEToken = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = UnsealBlobAndCheckType(p_hdl, TEE_Token, pTEETokenBlob, &clearTEEToken);
    }
    ClearBlob_t* clearKeyPair = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = UnsealBlobAndCheckType(p_hdl, ECIES_KeyPair, pKeyPairBlob, &clearKeyPair);
    }
    unsigned int AESKeyLen = 0;
    unsigned char* pAESKeyData = NULL;

    if (err == E_ERP_SUCCESS)
    {
        err = DoVAUECIES(p_hdl,
            clearKeyPair,
            clientPubKeyLength, pClientPubKeyData,
            &AESKeyLen,
            &pAESKeyData);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = makeSimpleOctetStringOutput(p_hdl, AESKeyLen, pAESKeyData);
    }
    FREE_IF_NOT_NULL(pKeyPairBlob);
    FREE_IF_NOT_NULL(clearKeyPair);
    FREE_IF_NOT_NULL(pTEETokenBlob);
    FREE_IF_NOT_NULL(clearTEEToken);
    FREE_IF_NOT_NULL(pAESKeyData);
    if (err != E_ERP_SUCCESS)
    {
        auditErrWithID(err, auditID);
    }
    return (int)err;
}

// Externally callable FWAPI Command
// Command to Get VAUSIG Private Key
// input: TEE Token
// input: ECSIG KeyPair Blob
// output: VAUSIG Private key in PKCS#8 /RFC5208/5915/5240 format.
// Return: Success or Error code.
extern int ERP_GetVAUSIGPrivateKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)
{
     unsigned int err = E_ERP_SUCCESS;
    ERP_AuditID_t auditID = ERP_AUDIT_Failed_VAUSIG_Get_Private_Key;
    SealedBlob_t* pTEETokenBlob = NULL;
    SealedBlob_t* pKeyPairBlob = NULL;
    if (0 != check_permission(p_hdl, ERP_WORKING_PERMISSION, 2))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }
    if (err == E_ERP_SUCCESS)
    {
        // To avoid lots of copying and reallocating, the pointers returned by this method are all
        //   referring directly to the elements of the ASN1_ITEM array returned by pItems.
        //   So, to delete them all, we need to call deleteASNItemList with pItems when we are finished.
        // Exception to the above:   Any SealedBlobs returned by this method will be in newly allocated
        //   buffers and must be freed by the caller.
        err = parseTwoBlobInputRequest(l_cmd, p_cmd,
            &pTEETokenBlob,
            &pKeyPairBlob);
    }

    ClearBlob_t* clearTEEToken = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = UnsealBlobAndCheckType(p_hdl, TEE_Token, pTEETokenBlob, &clearTEEToken);
    }
    ClearBlob_t* clearKeyPair = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = UnsealBlobAndCheckType(p_hdl, VAUSIG_KeyPair, pKeyPairBlob, &clearKeyPair);
    }
    unsigned int privateKeyLen = 0;
    unsigned char* pPrivateKeyData = NULL;

    if (err == E_ERP_SUCCESS)
    {
        err = GetPKCS8PrivateKey(p_hdl,
            clearKeyPair,
            &privateKeyLen,
            &pPrivateKeyData);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = makeSimpleOctetStringOutput(p_hdl, privateKeyLen, pPrivateKeyData);
    }
    FREE_IF_NOT_NULL(pKeyPairBlob);
    FREE_IF_NOT_NULL(clearKeyPair);
    FREE_IF_NOT_NULL(pTEETokenBlob);
    FREE_IF_NOT_NULL(clearTEEToken);
    FREE_IF_NOT_NULL(pPrivateKeyData);
    if (err != E_ERP_SUCCESS)
    {
        auditErrWithID(err, auditID);
    }
    return (int)err;
}

// Externally callable FWAPI Command
// Extract AES 256 Hash key
// Input: currently valid TEE Token
// Input: Hash Key Blob
// Output: Symmetric AES256 hash key.
// Return: Success or Error code.
extern int ERP_UnwrapHashKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)
{
     unsigned int err = E_ERP_SUCCESS;
    ERP_AuditID_t auditID = ERP_AUDIT_Failed_Unwrap_Hash_Key;
    SealedBlob_t* pTEETokenBlob = NULL;
    SealedBlob_t* pKeyBlob = NULL;
    if (0 != check_permission(p_hdl, ERP_WORKING_PERMISSION, 2))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }
    if (err == E_ERP_SUCCESS)
    {
        // To avoid lots of copying and reallocating, the pointers returned by this method are all
        //   referring directly to the elements of the ASN1_ITEM array returned by pItems.
        //   So, to delete them all, we need to call deleteASNItemList with pItems when we are finished.
        // Exception to the above:   Any SealedBlobs returned by this method will be in newly allocated
        //   buffers and must be freed by the caller.
        err = parseTwoBlobInputRequest(l_cmd, p_cmd,
            &pTEETokenBlob,
            &pKeyBlob);
    }

    ClearBlob_t* clearTEEToken = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = UnsealBlobAndCheckType(p_hdl, TEE_Token, pTEETokenBlob, &clearTEEToken);
    }
    ClearBlob_t* clearKey = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = UnsealBlobAndCheckType(p_hdl, Hash_Key, pKeyBlob, &clearKey);
    }
    AES256KeyBlob_t* keyBlob = NULL;
    if (err == E_ERP_SUCCESS)
    {
        keyBlob = (AES256KeyBlob_t*)&(clearKey->Data[0]);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = makeSimpleOctetStringOutput(p_hdl, AES_256_LEN / 8, &(keyBlob->KeyData[0]));
    }
    FREE_IF_NOT_NULL(pKeyBlob);
    FREE_IF_NOT_NULL(clearKey);
    FREE_IF_NOT_NULL(pTEETokenBlob);
    FREE_IF_NOT_NULL(clearTEEToken);
    if (err != E_ERP_SUCCESS)
    {
        auditErrWithID(err, auditID);
    }
    return (int)err;
}

// Externally callable FWAPI Command
// Extract AES 256 Pseudoname key
// Required Permission: Working
// Input: currently valid TEE Token
// Input: Hash Key Blob
// Output: Symmetric AES256 hash key.
// Return: Success or Error code.
extern int ERP_UnwrapPseudonameKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)
{
    unsigned int err = E_ERP_SUCCESS;
    ERP_AuditID_t auditID = ERP_AUDIT_Failed_Unwrap_Pseudoname_Key;
    SealedBlob_t* pTEETokenBlob = NULL;
    SealedBlob_t* pKeyBlob = NULL;
    if (0 != check_permission(p_hdl, ERP_WORKING_PERMISSION, 2))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }
    if (err == E_ERP_SUCCESS)
    {
        // To avoid lots of copying and reallocating, the pointers returned by this method are all
        //   referring directly to the elements of the ASN1_ITEM array returned by pItems.
        //   So, to delete them all, we need to call deleteASNItemList with pItems when we are finished.
        // Exception to the above:   Any SealedBlobs returned by this method will be in newly allocated
        //   buffers and must be freed by the caller.
        err = parseTwoBlobInputRequest(l_cmd, p_cmd,
            &pTEETokenBlob,
            &pKeyBlob);
    }

    ClearBlob_t* clearTEEToken = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = UnsealBlobAndCheckType(p_hdl, TEE_Token, pTEETokenBlob, &clearTEEToken);
    }
    ClearBlob_t* clearKey = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = UnsealBlobAndCheckType(p_hdl, Pseudoname_Key, pKeyBlob, &clearKey);
    }
    AES256KeyBlob_t* keyBlob = NULL;
    if (err == E_ERP_SUCCESS)
    {
        keyBlob = (AES256KeyBlob_t*)&(clearKey->Data[0]);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = makeSimpleOctetStringOutput(p_hdl, AES_256_LEN / 8, &(keyBlob->KeyData[0]));
    }
    FREE_IF_NOT_NULL(pKeyBlob);
    FREE_IF_NOT_NULL(clearKey);
    FREE_IF_NOT_NULL(pTEETokenBlob);
    FREE_IF_NOT_NULL(clearTEEToken);
    if (err != E_ERP_SUCCESS)
    {
        auditErrWithID(err, auditID);
    }
    return (int)err;
}


// Externally callable FWAPI Command
// Extract rawPayload
// Required Permission: Working
// Input: currently valid TEE Token
// Input: Payload Blob
// Output: rawPayload
// Return: Success or Error code.
extern int ERP_UnwrapRawPayload(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)
{
    unsigned int err = E_ERP_SUCCESS;
    ERP_AuditID_t auditID = ERP_AUDIT_Failed_Unwrap_Raw_Payload;
    SealedBlob_t* pTEETokenBlob = NULL;
    SealedBlob_t* pPayloadBlob = NULL;
    if (0 != check_permission(p_hdl, ERP_WORKING_PERMISSION, 2))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }
    if (err == E_ERP_SUCCESS)
    {
        // To avoid lots of copying and reallocating, the pointers returned by this method are all
        //   referring directly to the elements of the ASN1_ITEM array returned by pItems.
        //   So, to delete them all, we need to call deleteASNItemList with pItems when we are finished.
        // Exception to the above:   Any SealedBlobs returned by this method will be in newly allocated
        //   buffers and must be freed by the caller.
        err = parseUnwrapRawPayloadRequest(l_cmd, p_cmd,
                                        &pTEETokenBlob,
                                        &pPayloadBlob);
    }

    ClearBlob_t* clearTEEToken = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = UnsealBlobAndCheckType(p_hdl, TEE_Token, pTEETokenBlob, &clearTEEToken);
    }
    ClearBlob_t* clearPayload = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = UnsealBlobAndCheckType(p_hdl, RawPayload, pPayloadBlob, &clearPayload);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = makeSimpleOctetStringOutput(p_hdl, clearPayload->DataLength, &(clearPayload->Data[0]));
    }
    FREE_IF_NOT_NULL(pPayloadBlob);
    FREE_IF_NOT_NULL(clearPayload);
    FREE_IF_NOT_NULL(pTEETokenBlob);
    FREE_IF_NOT_NULL(clearTEEToken);
    if (err != E_ERP_SUCCESS)
    {
        auditErrWithID(err, auditID);
    }
    return (int)err;
}

// Externally callable FWAPI Command
// Extract rawPayload
// Required Permission: allowed for ERP_SETUP or ERP_UPDATE
// Input: cleartext Payload
// Output: wrapped rawPayload blob
// Return: Success or Error code.
extern int ERP_WrapRawPayload(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)
{
    unsigned int err = E_ERP_SUCCESS;
    unsigned int desiredGeneration = 0;
    ERP_AuditID_t auditID = ERP_AUDIT_Failed_Wrap_Raw_Payload;
    unsigned int payloadLength = 0;
    unsigned char* pPayloadData = NULL;
    if ((0 != check_permission(p_hdl, ERP_SETUP_PERMISSION, 2)) &&
        (0 != check_permission(p_hdl, ERP_UPDATE_PERMISSION, 2)))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }
    if (err == E_ERP_SUCCESS)
    {
        err = parseWrapRawPayloadRequest(l_cmd, p_cmd, &desiredGeneration, &payloadLength, &pPayloadData);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = CheckAvailableGeneration(p_hdl, desiredGeneration);
    }
    ClearBlob_t* clear = NULL;
    if (err == E_ERP_SUCCESS)
    {
        clear = os_mem_new_tag(sizeof(ClearBlob_t) + payloadLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        if (clear == NULL)
        {
            err = E_ERP_MALLOC;
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        clear->BlobType = RawPayload;
        err = fillGeneric(clear);
    }
    if (err == E_ERP_SUCCESS)
    {
        os_mem_cpy(&(clear->Data[0]), pPayloadData, payloadLength);
        clear->DataLength = payloadLength;
    }
    SealedBlob_t* sealed = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = SealBlob(p_hdl, clear, desiredGeneration, &sealed);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = makeSingleSealedBlobOutput(p_hdl, sealed);
    }
    FREE_IF_NOT_NULL(sealed);
    FREE_IF_NOT_NULL(clear);

    if (err == E_ERP_SUCCESS)
    {
        auditErrWithID(err, ERP_AUDIT_Wrap_Raw_Payload);
    }
    else
    {
        auditErrWithID(err, auditID);
    }
    return (int)err;
}

// Externally callable FWAPI Command
// Extract rawPayload
// Required Permission: allowed for ERP_SETUP or ERP_UPDATE
// Input: cleartext Payload
// Output: wrapped rawPayload blob
// Return: Success or Error code.
extern int ERP_WrapRawPayloadWithToken(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)
{
    unsigned int err = E_ERP_SUCCESS;
    ERP_AuditID_t auditID = ERP_AUDIT_Failed_Wrap_Raw_Payload;
    unsigned int desiredGeneration = 0;
    SealedBlob_t* pTEETokenBlob = NULL;
    unsigned int payloadLength = 0;
    unsigned char* pPayloadData = NULL;
    if (0 != check_permission(p_hdl, ERP_WORKING_PERMISSION, 2))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }
    if (err == E_ERP_SUCCESS)
    {
        err = parseWrapRawPayloadWithTokenRequest(l_cmd, p_cmd, &pTEETokenBlob, &desiredGeneration, &payloadLength, &pPayloadData);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = CheckAvailableGeneration(p_hdl, desiredGeneration);
    }
    ClearBlob_t* clearTEEToken = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = UnsealBlobAndCheckType(p_hdl, TEE_Token, pTEETokenBlob, &clearTEEToken);
    }
    ClearBlob_t* clear = NULL;
    if (err == E_ERP_SUCCESS)
    {
        clear = os_mem_new_tag(sizeof(ClearBlob_t) + payloadLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        if (clear == NULL)
        {
            err = E_ERP_MALLOC;
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        clear->BlobType = RawPayload;
        err = fillGeneric(clear);
    }
    if (err == E_ERP_SUCCESS)
    {
        os_mem_cpy(&(clear->Data[0]), pPayloadData, payloadLength);
        clear->DataLength = payloadLength;
    }
    SealedBlob_t* sealed = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = SealBlob(p_hdl, clear, desiredGeneration, &sealed);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = makeSingleSealedBlobOutput(p_hdl, sealed);
    }
    FREE_IF_NOT_NULL(sealed);
    FREE_IF_NOT_NULL(clear);
    FREE_IF_NOT_NULL(pTEETokenBlob);
    FREE_IF_NOT_NULL(clearTEEToken);

    if (err == E_ERP_SUCCESS)
    {
        auditErrWithID(err, ERP_AUDIT_Wrap_Raw_Payload);
    }
    else
    {
        auditErrWithID(err, auditID);
    }
    return (int)err;
}

// Export a single Blob Generation using the AES256 MBK.
// Requires: 20000000 - Administrator permission.
// Blob Generation must exist in the HSM
// input: Blob Generation
// output: BUBlob Structure
extern int ERP_ExportSingleBlobKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)
{
    unsigned int err = E_ERP_SUCCESS;
    ERP_AuditID_t auditID = ERP_AUDIT_Failed_Export_Single_Blob_Generation;
    unsigned int Generation = 0;

    // This operation requires ERP Setup or ERP Update Rights.
    if ((0 != check_permission(p_hdl, ERP_SETUP_PERMISSION, 2)) &&
        (0 != check_permission(p_hdl, ERP_UPDATE_PERMISSION, 2)))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }
    if (err == E_ERP_SUCCESS)
    {
        err = parseSingleIntInput(l_cmd, p_cmd, &Generation);
    }
    if (err == E_ERP_SUCCESS)
    {
        if (Generation == 0)
        {
            err = E_ERP_BAD_BLOB_GENERATION;
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        if (NULL == getSingleBlobKey(p_hdl, Generation))
        { // Key is not present!
            err = E_ERP_BAD_BLOB_GENERATION;
            INDEX_ERR(err, 0x06);
        }
    }

    // Now get the BackupBlob.
    BackupBlob_t* pOutBlob = NULL;
    if (err == E_ERP_SUCCESS)
    { // Create the new key
        err = backupBlobGeneration(p_hdl, Generation, &pOutBlob);
    }

    // This method will do all the work of building and allocating the firmware
    //   response containing the integer.
    if (err == E_ERP_SUCCESS)
    {
        err = makeBackupBlobOutput(p_hdl, pOutBlob);
    }

    if (err == E_ERP_SUCCESS)
    {
        auditErrWithID(err, ERP_AUDIT_Exported_Single_Blob_Generation);
    }
    else {
        auditErrWithID(err, auditID);
    }
    FREE_IF_NOT_NULL(pOutBlob);
    return (int)err;
}

// Import a single Blob Generation using the AES256 MBK.
// Requires: 20000000 - Administrator permission.
// The MBK loaded in the HSM must match that in the BUBlob
// The Generation in the BUBlob must not already be present in the HSM, neither with the same key value, nor a different one.
// input: BUBlob Structure
// output: None.
extern int ERP_ImportSingleBlobKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)
{
    unsigned int err = E_ERP_SUCCESS;
    ERP_AuditID_t auditID = ERP_AUDIT_Failed_Import_Single_Blob_Generation;
    BackupBlob_t* pBackupBlob = NULL;

    // This operation requires ERP Setup or ERP Update Rights.
    if ((0 != check_permission(p_hdl, ERP_SETUP_PERMISSION, 2)) &&
        (0 != check_permission(p_hdl, ERP_UPDATE_PERMISSION, 2)))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }
    if (err == E_ERP_SUCCESS)
    {
        // The BackupBlob returned by this method will be in newly allocated
        //   buffers and must be freed by the caller.
        err = parseBackupBlobInputRequest(l_cmd, p_cmd,
            &pBackupBlob);
    }

    if (err == E_ERP_SUCCESS)
    {
        if ((pBackupBlob->Generation == 0) ||
            (NULL != getSingleBlobKey(p_hdl, pBackupBlob->Generation)))
        { // A Key is already present or gen == 0
            err = E_ERP_BAD_BLOB_GENERATION;
            INDEX_ERR(err, 0x07);
        }
    }

    if (err == E_ERP_SUCCESS)
    {
        err = restoreBlobGeneration(p_hdl, pBackupBlob);
    }

    // No Output to command.

    FREE_IF_NOT_NULL(pBackupBlob);

    if (err == E_ERP_SUCCESS)
    {
        auditErrWithID(err, ERP_AUDIT_Imported_Single_Blob_Generation);
    }
    else {
        auditErrWithID(err, auditID);
    }
    return (int)err;
}

// Create a new Blob containing the contents of an existing blob but reencoded with a different Generation.
// The intention here is to allow preservation of blob contents when the blob generation of the original blob is to be deleted.   The
//   intention is that only special cases will require this treatment, e.g. Security reasons mandate hard retiral of some keys
// There is a guarantee that the new blob and the old blob will return the same Check Value in calls to GetBlobContentHash()
// Requires: 00000200 ERP Setup or 00002000 ERP Update Permission
// The Generation of the blob must be present in the HSM.
// input:  newBlobGeneration               an integer Blob Generation for the new Blob.   This must be present in the HSM.
// input:  blobIn                          The blob that is to be migrated.   The Blob generation for this blob must be present in the HSM.
// output: new migrated blob.
extern int ERP_MigrateBlob(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)
{
    int err = E_ERP_SUCCESS;
    ERP_AuditID_t auditID = ERP_AUDIT_Failed_Migrate_Blob;
    SealedBlob_t* pInputBlob = NULL;
    unsigned int newGeneration = 0;
    if ((0 != check_permission(p_hdl, ERP_SETUP_PERMISSION, 2)) &&
        (0 != check_permission(p_hdl, ERP_UPDATE_PERMISSION, 2)))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }
    if (err == E_ERP_SUCCESS)
    {
        // To avoid lots of copying and reallocating, the pointers returned by this method are all
        //   referring directly to the elements of the ASN1_ITEM array returned by pItems.
        //   So, to delete them all, we need to call deleteASNItemList with pItems when we are finished.
        err = parseMigrateBlobInput(l_cmd, p_cmd, &newGeneration, &pInputBlob);
    }

    if (err == E_ERP_SUCCESS)
    {
        err = CheckAvailableGeneration(p_hdl, newGeneration);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = CheckAvailableGeneration(p_hdl, pInputBlob->Generation);
    }
    ClearBlob_t* pClearInput = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = UnsealBlob(p_hdl, pInputBlob, &pClearInput);
    }
    SealedBlob_t* pResealedBlob = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = SealBlob(p_hdl, pClearInput, newGeneration, &pResealedBlob);
    }

    if (err == E_ERP_SUCCESS)
    {
        err = makeSingleSealedBlobOutput(p_hdl, pResealedBlob);
    }

    FREE_IF_NOT_NULL(pInputBlob);
    FREE_IF_NOT_NULL(pClearInput);
    FREE_IF_NOT_NULL(pResealedBlob);
    if (err != E_ERP_SUCCESS)
    {
        auditErrWithID(err, auditID);
    }
    return err;
}

// For Setup or Update users: Calculate and return the SHA256 hash of the contents of a blob.
// Requires: 00000200 ERP Setup or 00002000 ERP Update Permission
// Working users should use GetBlobContentHashWithToken
// The Generation of the blob must be present in the HSM.
// The intention here is to allow identification of a key that may be stored in multiple blobs with different generations.
// The only guarantee is that multiple calls to this method with blobs containing the same contents will return the same hash.
// "The same contents" implies that the blobs were related through use of ERP_MigrateBlob.
// input: Blob to be hashed.
// output: hash
extern int ERP_GetBlobContentHash(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)
{
    int err = E_ERP_SUCCESS;
    ERP_AuditID_t auditID = ERP_AUDIT_Failed_Get_Blob_Content_Hash;
    SealedBlob_t* pInputBlob = NULL;
    if ((0 != check_permission(p_hdl, ERP_SETUP_PERMISSION, 2)) &&
        (0 != check_permission(p_hdl, ERP_UPDATE_PERMISSION, 2)))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }
    if (err == E_ERP_SUCCESS)
    {
        // To avoid lots of copying and reallocating, the pointers returned by this method are all
        //   referring directly to the elements of the ASN1_ITEM array returned by pItems.
        //   So, to delete them all, we need to call deleteASNItemList with pItems when we are finished.
        err = parseSingleBlobInput(l_cmd, p_cmd, &pInputBlob);
    }

    ClearBlob_t* clearInput = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = UnsealBlob(p_hdl, pInputBlob, &clearInput);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = hashAndReturnBlobContents(p_hdl, clearInput);
    }

    FREE_IF_NOT_NULL(pInputBlob);
    FREE_IF_NOT_NULL(clearInput);
    if (err != E_ERP_SUCCESS)
    {
        auditErrWithID(err, auditID);
    }
    return err;
}

// For Working users with a TEE Token: Calculate and return the SHA256 hash of the contents of a blob.
// Requires: 00000020 ERP Working permission with a valid TEE Token.
// Setup or Update users should use ERP_GetBlobContentHash
// The Generation of the blob must be present in the HSM.
// The intention here is to allow identification of a derivation key that may be stored in multiple blobs with different generations.
// The only guarantee is that multiple calls to this method with blobs containing the same contents will return the same hash.
// "The same contents" implies that the blobs were related through use of ERP_MigrateBlob.
// input: Derivation key Blob.
// input: ECSIG KeyPair Blob
// input: Data to be signed
// output: Signature
extern int ERP_GetBlobContentHashWithToken(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd)
{
    int err = E_ERP_SUCCESS;
    ERP_AuditID_t auditID = ERP_AUDIT_Failed_Get_Blob_Content_Hash;
    SealedBlob_t* pTEETokenBlob = NULL;
    SealedBlob_t* pInputBlob = NULL;
    if (0 != check_permission(p_hdl, ERP_WORKING_PERMISSION, 2))
    {
        err = E_ERP_PERMISSION_DENIED;
        auditID = ERP_AUDIT_Permission_Failure;
    }
    if (err == E_ERP_SUCCESS)
    {
        // To avoid lots of copying and reallocating, the pointers returned by this method are all
        //   referring directly to the elements of the ASN1_ITEM array returned by pItems.
        //   So, to delete them all, we need to call deleteASNItemList with pItems when we are finished.
        // Exception to the above:   Any SealedBlobs returned by this method will be in newly allocated
        //   buffers and must be freed by the caller.
        err = parseTwoBlobInputRequest(l_cmd, p_cmd,
            &pTEETokenBlob,
            &pInputBlob);
    }

    ClearBlob_t* clearTEEToken = NULL;
    if (err == E_ERP_SUCCESS)
    { // Note that this method will check expiry of the token.
        err = UnsealBlobAndCheckType(p_hdl, TEE_Token, pTEETokenBlob, &clearTEEToken);
    }
    ClearBlob_t* clearInput = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = UnsealBlob(p_hdl, pInputBlob, &clearInput);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = hashAndReturnBlobContents(p_hdl, clearInput);
    }

    FREE_IF_NOT_NULL(pTEETokenBlob);
    FREE_IF_NOT_NULL(clearTEEToken);
    FREE_IF_NOT_NULL(pInputBlob);
    FREE_IF_NOT_NULL(clearInput);
    if (err != E_ERP_SUCCESS)
    {
        auditErrWithID(err, auditID);
    }
    return err;
}
