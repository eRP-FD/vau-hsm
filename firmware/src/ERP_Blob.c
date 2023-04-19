/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021
 * (C) Copyright IBM Corp. 2021
 * SPDX-License-Identifier: CC BY-NC-ND 3.0 DE
 **************************************************************************************************/

// Needed to avoid bug warning in winnt.h
#define no_init_all

#include <cryptoserversdk/stype.h>
#include <cryptoserversdk/memutil.h>
#include <cryptoserversdk/os_mem.h>
#include <cryptoserversdk/os_str.h>
#include <cryptoserversdk/os_crypt.h>
#include <cryptoserversdk/cmds.h>
#include <cryptoserversdk/util.h>
#include <cryptoserversdk/db.h>
#include <cryptoserversdk/aes.h>
#include <cryptoserversdk/hash.h>
#include <cryptoserversdk/mbk.h>

#include "ERP_InternalGlue.h"
#include "ERP_Blob.h"
#include "ERP_MDLError.h"
#include "ERP_CryptoUtils.h"

// Length of Blob Keys in Bits, i.e. AES256.
FILE_CONST int BlobKeyLength = 256;

MDL_GLOBAL T_BLOBK** LoadedBlobKeyList = NULL;
MDL_GLOBAL unsigned int HighestLoadedBlobGeneration = 0;
MDL_GLOBAL unsigned int NumLoadedBlobGenerations = 0;

extern MDL_GLOBAL void* p_BlobSemaphore;

// May only be called from countLoadedBlobKeys due to semaphore ownership.
// Semaphore object is NOT owner-counted, i.e. if the caller owns the semaphore, it would fail to claim it here.
void freeLoadedBlobKeyList()
{
    if (LoadedBlobKeyList != NULL)
    {
        unsigned int i = 0;
        while (LoadedBlobKeyList[i] != NULL)
        {
            os_mem_del_set(LoadedBlobKeyList[i], 0);
            i++;
        }
        os_mem_del_set(LoadedBlobKeyList, 0);
        LoadedBlobKeyList = NULL;
        HighestLoadedBlobGeneration = 0;
        NumLoadedBlobGenerations = 0;
    }
    return;
}

// Reads all Blob Keys from DB and stores them in LoadedBlobKeyList.
// The list will be sorted by Blob Generation.
unsigned int countLoadedBlobKeys(T_CMDS_HANDLE* p_hdl)
{
    unsigned int err = E_ERP_SUCCESS;
    char keyName[40];
    os_str_snprintf(keyName, 40, "%08x", 0);
    if (err == E_ERP_SUCCESS)
    {
        freeLoadedBlobKeyList();
    }
    unsigned int blobCount = 0;
    while (err == E_ERP_SUCCESS)
    {
        size_t secretLen;
        void* foundSecretData;
        err = db_find(p_BlobKDB, DB_GREATER, keyName, 0, NULL, (unsigned int*) &secretLen, &foundSecretData);
        if (err == E_ERP_SUCCESS)
        {
            blobCount++;
        }
    }
    if (blobCount == 0)
    { // Empty DB.
        LoadedBlobKeyList = os_mem_new_tag(sizeof(T_BLOBK*) *  1, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, LoadedBlobKeyList, 0x20)
        else {
            err = E_ERP_SUCCESS;
        }
        if (err == E_ERP_SUCCESS)
        {
            LoadedBlobKeyList[0] = NULL;
        }
        return err;
    }
    else {
        // Allocate the list for the blob pointers.
        LoadedBlobKeyList = os_mem_new_tag(sizeof(T_BLOBK*) * (blobCount + 1), OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, LoadedBlobKeyList, 0x21)
        else {
            err = E_ERP_SUCCESS;
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        os_str_snprintf(keyName, 40, "%8x", 0);
        unsigned int index = 0;
        while ((err == E_ERP_SUCCESS) && (index < blobCount))
        {
            size_t secretLen;
            void* foundSecretData;
            err = db_find(p_BlobKDB, DB_GREATER, keyName, 0, NULL, (unsigned int*) &secretLen, &foundSecretData);
            if (err == E_ERP_SUCCESS)
            {
                LoadedBlobKeyList[index] = os_mem_new_tag((unsigned int) (sizeof(T_BLOBK) + secretLen), OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
                if (LoadedBlobKeyList[index] == NULL)
                {
                    err = E_ERP_MALLOC;
                }
                else {
                    T_BLOBK* foundBlob = (T_BLOBK*)foundSecretData;
                    LoadedBlobKeyList[index]->Generation = foundBlob->Generation;
                    // These should have been sorted by Generation anyway by the DB search, but
                    //   check anyway.
                    if (foundBlob->Generation > HighestLoadedBlobGeneration)
                    {
                        HighestLoadedBlobGeneration = foundBlob->Generation;
                    }
                    LoadedBlobKeyList[index]->KeyLength = foundBlob->KeyLength;
                    os_mem_cpy(LoadedBlobKeyList[index]->KeyData, foundBlob->KeyData, foundBlob->KeyLength);
                    index++;
                }
            }
        }
        NumLoadedBlobGenerations = blobCount;
        // Null terminate the list.
        LoadedBlobKeyList[index] = NULL;
    }
    if (err != E_ERP_SUCCESS)
    {   // This can only be caused by a DB or malloc error - either way the firmware is dead until it can complete a successful
        // loading of the blob keys.
        // Set the firmware state to no loaded blob keys so a future attempt may try this agin.
        freeLoadedBlobKeyList();
    }
    return err;
}

// Retrieve all blob keys - caller may not change result.
// The list will be sorted by Blob Generation.
// Be careful, the list can be overwritten by other tasks in parallel.
unsigned int getLoadedBlobKeys(T_CMDS_HANDLE* p_hdl, T_BLOBK* const** pppOutList)
{
    unsigned int err = E_ERP_SUCCESS;

    if (LoadedBlobKeyList == NULL)
    {
        err = countLoadedBlobKeys(p_hdl);
    }
    if (err == E_ERP_SUCCESS)
    {
        *pppOutList = LoadedBlobKeyList;
    }
    return err;
}

unsigned int getHighestBlobGeneration(T_CMDS_HANDLE* p_hdl)
{
    if (LoadedBlobKeyList == NULL)
    {
        countLoadedBlobKeys(p_hdl);
    }
    return HighestLoadedBlobGeneration;
}

// Returns the total number of currently loaded Blob Generations.
unsigned int getNumLoadedBlobGenerations(T_CMDS_HANDLE* p_hdl)
{
    if (LoadedBlobKeyList == NULL)
    {
        countLoadedBlobKeys(p_hdl);
    }
    return NumLoadedBlobGenerations;
}

// Return a single blob key - caller may not change result structure.
// Returns null if no blob key for that generation.
// Generation 0 means return the highest currently supported.
T_BLOBK* getSingleBlobKey(T_CMDS_HANDLE* p_hdl, unsigned int Generation)
{
    unsigned int err = E_ERP_SUCCESS;
    // Warning - multiple returns in this method
    T_BLOBK* const* keyList = NULL;
    // We don't actually need the key list here, we jsut call it to
    //   force an initial load if it has not yet been loaded.
    if (err == E_ERP_SUCCESS)
    {
        err = getLoadedBlobKeys(p_hdl, &keyList);
    }
    if (err == E_ERP_SUCCESS)
    {
        if (Generation == 0)
        {
            Generation = getHighestBlobGeneration(p_hdl);
        }

        int i = 0;
        while (keyList[i] != NULL)
        {
            if (keyList[i]->Generation == Generation)
            { // Found the Blob key.
                return keyList[i];
            }
            i++;
        }
    }
    // Not found.
    return NULL;
}

// Add a new blob to the DB.   Returns E_ERP_SUCCESS (0) if ok.
// Returns an error otherwise.
int addNewBlobKey(T_CMDS_HANDLE* p_hdl, const T_BLOBK* newBlob)
{
    unsigned int err = E_ERP_SUCCESS;
    char keyName[40];
    os_str_snprintf(keyName, 40, "%08x",newBlob->Generation);
    err = db_insert(p_BlobKDB, keyName, 0, NULL, sizeof(T_BLOBK) + newBlob->KeyLength, newBlob);
    // the case (err == E_DB_EXISTS):
    // This should have been caught earlier in the call tree.
    // The key is already there, so do NOT update it.

    if (err == E_ERP_SUCCESS)
    {
        // Now update the cached list of keys:
        err = countLoadedBlobKeys(p_hdl);
    }
    return err;
}

// Creates a new Blob Key for the requested Generation.
//   Input:Generation = 0 means one more than the current highest one.
//   Returns E_ERP_SUCCESS (0) if ok.
//   Returns an error otherwise.
//   Output: Value of Generation actually added is written to the Generation Argument.
int createNewBlobKey(T_CMDS_HANDLE* p_hdl, unsigned int * pGeneration)
{
    int           err = E_ERP_SUCCESS;
    T_BLOBK * pNewBlobKey = NULL;

    // allocate secure memory for key to be generated
    if ((pNewBlobKey = os_mem_new_tag(sizeof(T_BLOBK) + (BlobKeyLength/8), OS_MEM_TYPE_SECURE, __FILE__, __LINE__)) == NULL)
    {
        err = E_ERP_MALLOC;
    }

    // generate key
    if (err == E_ERP_SUCCESS)
    {
        if (*pGeneration == 0)
        {
            T_BLOBK* const* keyList = NULL;
            // We don't actually need the key list here, we just call it to
            //   force an initial load if it has not yet been loaded.
            err = getLoadedBlobKeys(p_hdl, &keyList);
            pNewBlobKey->Generation = getHighestBlobGeneration(p_hdl) + 1;
        }
        else {
            // Check generation is not already present has been done by the caller.
            if (NULL != getSingleBlobKey(p_hdl, *pGeneration))
            { // Key is already present!   Do not replace it.
                err = E_ERP_BAD_BLOB_GENERATION;
                INDEX_ERR(err, 0x01);
            }
            else {
                pNewBlobKey->Generation = *pGeneration;
            }
        }

        pNewBlobKey->KeyLength = BlobKeyLength / 8;

        err = aes_gen_key(pNewBlobKey->KeyLength, &(pNewBlobKey->KeyData[0]));
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x01);
        }
    }

    if (err != E_ERP_SUCCESS)
    {
        cmds_audit_write(
            ERP_AUDIT_CLASS,
            p_hdl,
            (unsigned char*)"%s Blob Key Creation for Generation %i failed [%08x]",
            ERP_AUDIT_LOG_TAG,
            *pGeneration,
            err);
    }

    // store key in database
    if (err == E_ERP_SUCCESS)
    {
        err = addNewBlobKey(p_hdl,pNewBlobKey);
    }

    if (err != E_ERP_SUCCESS)
    {
        cmds_audit_write(
            ERP_AUDIT_CLASS,
            p_hdl,
            (unsigned char*)"%s New Blob Key for Generation %i storage failed [%08x]",
            ERP_AUDIT_LOG_TAG,
            *pGeneration,
            err);
    }
    else {
        cmds_audit_write(
            ERP_AUDIT_CLASS,
            p_hdl,
            (unsigned char*)"%s New Blob Key for Generation %i Created ok.",
            ERP_AUDIT_LOG_TAG,
            pNewBlobKey->Generation);
        *pGeneration = pNewBlobKey->Generation;
    }

    // erase and free memory
    FREE_IF_NOT_NULL(pNewBlobKey);

    return err;
}

// Removes a Blob Key from the Database.
//   Returns E_ERP_SUCCESS (0) if ok.
//   Returns an error otherwise.
int deleteBlobKey(T_CMDS_HANDLE* p_hdl, unsigned int Generation)
{
    int err = E_ERP_SUCCESS;
    char keyName[40];
    if (NULL == getSingleBlobKey(p_hdl, Generation))
    {
        err = E_ERP_UNKNOWN_BLOB_GENERATION;
        INDEX_ERR(err, 0x01);
    }
    os_str_snprintf(keyName, 40, "%08x", Generation);
    err = db_delete(p_BlobKDB, keyName);

    if (err == E_ERP_SUCCESS)
    {
        // Now update the cached list of keys:
        err = countLoadedBlobKeys(p_hdl);
    }
    return err;
}

size_t SizeofClearBlobData(ClearBlob_t* blob)
{
    size_t result = sizeof(ERPBlobType_t) +
                    sizeof(unsigned int) +
                    sizeof(blob->DataLength) +
                    blob->DataLength;
    return result;
}

// Returns the Blob Domain for which this firmware has been built.
// Return data is read only.
FILE_CONST char BlobDomain[5] = BLOB_DOMAIN; // null terminated "DVLP", "REFZ", "TEST" or "PROD"
const char* getBlobDomain()
{
    return BlobDomain;
}

// Helper method to return the IV used for AES GCM Encryption and Decryption of Blobs.
// Has the value blob Domain padded with 0x00 to 16 bytes.
// Input: pLen - length of input buffer.   Minimum BLOB_IV_LEN
// Input: pOutBuff - Buffer to hold RND.
// Output: *pLen - the length of the IV created.
// Output: pOutBuff - filled with the data of the IV.
unsigned int getNewBlobIV(unsigned int * pLen, unsigned char *pOutBuff)
{
    int err = E_ERP_SUCCESS;
    if (*pLen < BLOB_IV_LEN)
    {
        err = E_ERP_MALLOC;
    }
    else {
        *pLen = BLOB_IV_LEN;
        err = os_crypt_drbg_rnd(DRBG_PSEUDO, pOutBuff, *pLen);
    }
    return err;
}

unsigned int CheckAvailableGeneration(T_CMDS_HANDLE* p_hdl, unsigned int Generation)
{
    unsigned int err = E_ERP_SUCCESS;
    if  (NULL == getSingleBlobKey(p_hdl, Generation))
    {
        err = E_ERP_BAD_BLOB_GENERATION;
        INDEX_ERR(err, 0x02);
    }
    return err;
}

unsigned int checkBlobExpiry(ClearBlob_t* aBlob)
{
    // All times in this method are in seconds after 2020.01.01 0:00:00.0
    unsigned int err = E_ERP_SUCCESS;
    unsigned int now = 0;
    unsigned int ms = 0;
    // ERP-8927 - "Lets do the Time Slip agaaaainnnn..."   This is a tolerance built into time checking
    //   to deal with imperfect clock synchronisation between the HSM which issued a blob and the HSM currently
    //   checking it.   Units are seconds.   Current HSM NTP setup should correct after 500ms slippage so
    //   1 second is the theoretical maximum difference not allowing for non-zero NTP polling intervals.
    // Empirical observations showed up to 600ms before corrections.   So, 2 seconds should be enough.
    static const int TIME_SLIP = 2; // two second time slip.
    // Don't actually care about milliseconds.
    err = util_get_time(&now, &ms);
    if (err == E_ERP_SUCCESS)
    {
        // ERP-8927 - Take 2: allow slippage to account for imperfect HSM Clock Sync in hardware HSM clusters.
        if (aBlob->IssueTime > (now + TIME_SLIP))
        {
            err = E_ERP_BAD_BLOB_TIME;
        }
    }
    // How long the blob is valid after issue.
    // Use zero to signify that blob does not expire.
    unsigned int Validity = 0;
    if (err == E_ERP_SUCCESS)
    {
        switch (aBlob->BlobType)
        {
        default:
        case Reserved: // = 0 // RFU
         // Long Lived Blobs:
        case TPM_Mfr_RootCert: // = 1 // Issued by the TPM Manufacturerand used to sign TPM Endorsement Key(EK) Certificates.Trusted by us to genuinely come from the manufacturer..
        case Trusted_EK: // = 2 // Known and Trusted EK public key.   Installed by Manufacturer in TPM and verified against the TPM Manufacturer root key.Trusted by us to be for a TPM belonging to part of our VAU.   (Actually, EKs are not installed directly in the TPM, but rather the TPM comes with a Seed value used to derive the EK and other keys - the derivation data used for the EK ensures that this seed will always produce the same EK.)
        case Trusted_AK: // = 4 // Knownand Trusted AK.   Attestation Key generated by a TPM.Trusted by us to be present in a TPM containing a trusted EK.Trust is established through the enrollment process.
        case Trusted_Quote: // = 5 // Known and trusted Attestation Quote Data.TPM PCR Hash values relating to a secure boot of a system setupand SGX Enclave.   Trusted by us during the enrollment process to match a trusted software and hardware stack allowed to run our VAU.
        case Derivation_Key: // = 6 // A symmetric key used to derive Persistence Keys.
        case Hash_Key: // = 7 // A symmetric key used to calculate keyed hashes.
        case ECIES_KeyPair: // = 8
        case RawPayload:
            Validity = 0;
            break;
            // Transient Blobs:
        case NONCE_Blob: // = 9 // A NONCE to be used to prevent replay attacks.
        case AKChallenge: // = 3 // A credential that must be decrypted during the AK attestation.
//        case TPM_Challenge: // = 10 // A Credential Challenge to be cross checked against
            Validity = 300; // 5 minutes
            break;
        case TEE_Token: // = 11  // A time limited Token allowing access tothe VAU HSM functions.
            Validity = 1800; // 30 minutes.
            break;
        case Pseudoname_Key: // = 12 // time limited unwrappable AES key.    See PSEUDONAME_BLOB_EXPIRY
            Validity = PSEUDONAME_BLOB_EXPIRY;
            break;
        }
        // ERP-6199   !!!  THIS Must definitely be enabled for final version!!!!
        // Leaving the blob expiry disabled enables replay attacks - we use
        //   this for testing, but it must be removed for final versions and
        //   the removal needs to be confirmed by test cases.
// Force this for now:
#ifndef DISABLE_BLOB_EXPIRY
        if ((Validity != 0) && ((now - aBlob->IssueTime) > (Validity + TIME_SLIP)))
        {
            err = E_ERP_BLOB_EXPIRED;
        }
#else
        (void) Validity;
#endif
    }
    return err;
}
// Seal a Blob with the requested Generation, where 0 means the latest available.
// Memory for the Blob is allocated by this method and must be freed by os_mem_del_set
unsigned int SealBlob(T_CMDS_HANDLE* p_hdl, ClearBlob_t* pInBlob, unsigned int Generation, SealedBlob_t** ppOutBlob)
{
    unsigned int err = E_ERP_SUCCESS;

    T_BLOBK * key = getSingleBlobKey(p_hdl, Generation);

    if (key == NULL)
    {
        err = E_ERP_BAD_BLOB_GENERATION;
        INDEX_ERR(err, 0x03);
    }
    AES_KEY* encKey = NULL;
    if (err == E_ERP_SUCCESS)
    {
        encKey = aes_pkey(key->KeyLength, key->KeyData, AES_ENC, NULL);
        if (encKey == NULL)
        {
            err = E_ERP_AES_KEY_ERROR;
            INDEX_ERR(err, 0x03);
        }
    }
    unsigned int plainLen = 0;
    if (err == E_ERP_SUCCESS)
    {
        plainLen = (unsigned int) SizeofClearBlobData(pInBlob);
        // Allocate the output blob slightly too large to cope with at least one additional block.
        *ppOutBlob = os_mem_new_tag((unsigned int) (sizeof(SealedBlob_t) + plainLen + 16), OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        if (*ppOutBlob == NULL)
        {
            err = E_ERP_MALLOC;
        }
    }
    unsigned int IVLen = BLOB_IV_LEN;
    unsigned char GCMCounter[BLOB_COUNTER_LEN] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
    unsigned char GCMADHash[BLOB_AD_HASH_LEN] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
    if (err == E_ERP_SUCCESS)
    {
        err = getNewBlobIV(&IVLen, &((*ppOutBlob)->ICV[0]));
    }
    if (err == E_ERP_SUCCESS)
    {
        err = aes_gcm_init(encKey, IVLen, &((*ppOutBlob)->ICV[0]), &(GCMCounter[0]));
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x04);
        }
    }
    unsigned int ADLen = BLOB_AD_LEN;
    if (err == E_ERP_SUCCESS)
    {
        (*ppOutBlob)->Generation = key->Generation;
        os_mem_cpy(&((*ppOutBlob)->Domain[0]), getBlobDomain(), BLOB_DOMAIN_LEN);
        // Be careful that the order of AD fields in BLOB Structure does not change too much.
        err = aes_gcm_ad(encKey, ADLen, (const unsigned char *) &((*ppOutBlob)->Generation), &(GCMADHash[0]));
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x05);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        err = aes_gcm_data(
            encKey,
            AES_ENC,
            plainLen,
            (const unsigned char *)&(pInBlob->BlobType),
            &(GCMCounter[0]),
            &(GCMADHash[0]),
            &((*ppOutBlob)->EncodedData[0]) );
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x06);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        err = aes_gcm_final(
            encKey,
            AES_ENC,
            ADLen,
            plainLen,
            &(GCMCounter[0]),
            &(GCMADHash[0]),
            BLOB_COUNTER_LEN * 8,
            &((*ppOutBlob)->AuthTag[0]) );
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x07);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        (*ppOutBlob)->EncodedDataLength = plainLen;
     }
    if (err == E_ERP_SUCCESS)
    { // Now set the BlobID to be an SHA256 hash over the encrypted Data.
        err = hash_sha256(
            0, // Start a new hash...
            (*ppOutBlob)->EncodedDataLength,
            &((*ppOutBlob)->EncodedData[0]),
            NULL, // Means that this is a single hash operation, not a chained one.
            &((*ppOutBlob)->BlobID[0]));
    }
    FREE_IF_NOT_NULL(encKey);
    return err;
}

// Unseals a sealed blob using the generation contained in the Blob.
// The memory for the ClearBlob is allocated by this method and must be freed by os_mem_del_set
// Use UnsealBlobAndCheckType whenever the blob has a single allowed type, otherwise
//   the caller must check the blob type manually after this call has returned.
// The Generation of the sealed blob must match a blob key present in the HSM.
unsigned int UnsealBlob(T_CMDS_HANDLE* p_hdl, SealedBlob_t* pInBlob, ClearBlob_t** ppOutBlob)
{
    unsigned int err = E_ERP_SUCCESS;

    if (0 != os_mem_cmp(pInBlob->Domain, getBlobDomain(), BLOB_DOMAIN_LEN))
    {
        err = E_ERP_BAD_BLOB_DOMAIN;
    }
    T_BLOBK* key = NULL;
    if (err == E_ERP_SUCCESS)
    {
        if (pInBlob->Generation == 0)
        {   // ERP-6543 MTG review - Issue #72 in the Github Repo.
            // The case of a sealed blob with generation == 0 can only happen with manipulated data, but we should check it and return ER_ERR_BAD_BLOB_GENERATION.
            err = E_ERP_BAD_BLOB_GENERATION;
            INDEX_ERR(err, 0x04);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        key = getSingleBlobKey(p_hdl, pInBlob->Generation);
        if (key == NULL)
        {
            err = E_ERP_BAD_BLOB_GENERATION;
            INDEX_ERR(err, 0x06);
        }
    }

    AES_KEY* encKey = NULL;
    if (err == E_ERP_SUCCESS)
    {
        encKey = aes_pkey(key->KeyLength, key->KeyData, AES_ENC, NULL);
        if (encKey == NULL)
        {
            err = E_ERP_AES_KEY_ERROR;
            INDEX_ERR(err, 0x08);
        }
    }
    unsigned int cryptLen = 0;
    if (err == E_ERP_SUCCESS)
    {
        cryptLen = pInBlob->EncodedDataLength;
        // Allocate the output blob slightly too large to cope with at least one additional block.
        *ppOutBlob = os_mem_new_tag(sizeof(ClearBlob_t) + cryptLen + 16, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        if (*ppOutBlob == NULL)
        {
            err = E_ERP_MALLOC;
        }
    }
    unsigned int IVLen = BLOB_IV_LEN;
    unsigned char GCMCounter[BLOB_COUNTER_LEN] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
    unsigned char GCMADHash[BLOB_AD_HASH_LEN] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
    if (err == E_ERP_SUCCESS)
    {
        err = aes_gcm_init(encKey, IVLen, &(pInBlob->ICV[0]), &(GCMCounter[0]));
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x09);
        }
    }
    unsigned int ADLen = BLOB_AD_LEN;
    if (err == E_ERP_SUCCESS)
    {
        // Be careful that the order of AD fields in BLOB Structure does not change too much.
        err = aes_gcm_ad(encKey, ADLen, (const unsigned char *)&(pInBlob->Generation), &(GCMADHash[0]));
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x0a);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        err = aes_gcm_data(
            encKey,
            AES_DEC,
            cryptLen,
            &(pInBlob->EncodedData[0]),
            &(GCMCounter[0]),
            &(GCMADHash[0]),
            (unsigned char *)&((*ppOutBlob)->BlobType));
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x0b);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        err = aes_gcm_final(
            encKey,
            AES_DEC,
            ADLen,
            cryptLen,
            &(GCMCounter[0]),
            &(GCMADHash[0]),
            BLOB_COUNTER_LEN * 8,
            &(pInBlob->AuthTag[0]) );
        if (err != E_ERP_SUCCESS)
        {
            err = E_ERP_BAD_BLOB_AD;
            INDEX_ERR(err, 0x0c);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        (*ppOutBlob)->DataLength = cryptLen - sizeof(ClearBlob_t);
    }
    // Now check the Blob expiry if appplicable.
    if (err == E_ERP_SUCCESS)
    {
        err = checkBlobExpiry(*ppOutBlob);
    }
    FREE_IF_NOT_NULL(encKey);
    return err;
}

// Calls UnsealBlob but checks type of Blob.
extern unsigned int UnsealBlobAndCheckType(T_CMDS_HANDLE* p_hdl, ERPBlobType_t expectedType, SealedBlob_t* pInBlob, ClearBlob_t** ppOutBlob)
{
    unsigned int err = UnsealBlob(p_hdl, pInBlob, ppOutBlob);

    if (err == E_ERP_SUCCESS)
    {
        if ((*ppOutBlob)->BlobType != expectedType)
        {
            err = E_ERP_WRONG_BLOB_TYPE;
            INDEX_ERR(err, 0x02);
            os_mem_del_set(*ppOutBlob, 0);
            *ppOutBlob = NULL;
        }
    }
    return err;
}

// Helper method to fill fields common to all Blobs:
//   Generation - left at 0 for default.
//   issue - time set to current HSM time.
//   DataLength - set to initial 0 value.
unsigned int fillGeneric(ClearBlob_t* pOutBlob)
{
    unsigned int err = E_ERP_SUCCESS;
    pOutBlob->DataLength = 0;
    unsigned int ms = 0;
    // Don't actually care about milliseconds.
    err = util_get_time(&pOutBlob->IssueTime, &ms);

    return err;
}
// Allocates and fills a NONCE Blob with a new RND value.
// The time is set to the current HSM time.
// The memory for the Blob is allocated by this method and must be freed by os_mem_del_set.
unsigned int getNONCEBlob(T_CMDS_HANDLE* p_hdl, ClearBlob_t** ppOutBlob)
{
    unsigned int err = E_ERP_SUCCESS;
    *ppOutBlob = os_mem_new_tag(sizeof(ClearBlob_t) + sizeof(NONCEBlob_t) + 1, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
    (*ppOutBlob)->BlobType = NONCE_Blob;
    err = fillGeneric(*ppOutBlob);
    if (err == E_ERP_SUCCESS)
    {
        (*ppOutBlob)->DataLength = sizeof(NONCEBlob_t);
        NONCEBlob_t* noncy = (NONCEBlob_t *)&((*ppOutBlob)->Data[0]);
        err = os_crypt_drbg_rnd(DRBG_PSEUDO, &(noncy->RNDData[0]), NONCE_LEN / 8);
    }
    return err;
}

// Allocates and fills a Derivation Key Blob with a newly generated Derivation Key.
// The time is set to the current HSM time.
// The memory for the Blob is allocated by this method and must be freed by os_mem_del_set.
unsigned int getAES256KeyBlob(T_CMDS_HANDLE* p_hdl, ClearBlob_t** ppOutBlob,ERPBlobType_t blobType)
{
    unsigned int err = E_ERP_SUCCESS;
    *ppOutBlob = os_mem_new_tag(sizeof(ClearBlob_t) + sizeof(AES256KeyBlob_t) + 1, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
    (*ppOutBlob)->BlobType = blobType;
    err = fillGeneric(*ppOutBlob);
    // Psuedoname Expiry is defined and enforced in the UnsealAndCheckBlob method.
    AES256KeyBlob_t* pKeyBlob = NULL;
    {
        (*ppOutBlob)->DataLength = sizeof(AES256KeyBlob_t);
        pKeyBlob = (AES256KeyBlob_t *)&((*ppOutBlob)->Data[0]);
        err = aes_gen_key(AES_256_LEN/8, &(pKeyBlob->KeyData[0]));
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x0d);
        }
    }

    unsigned int KeyChecksum = 0;
    if (err == E_ERP_SUCCESS)
    {
        // ERP-6226 - calculate a genuine key checksum.
        // This will be an integer from a big endian interpretation of the first four bytes of the result
        //   of encrypting 32 bytes of zero with the key.
        // This will be tested during the existing Derive Key tests.
        err = GenerateAES256CheckSum(&(pKeyBlob->KeyData[0]), (unsigned long *)&KeyChecksum);
    }
    if (err == E_ERP_SUCCESS)
    {
        cmds_audit_write(
            ERP_AUDIT_CLASS,
            p_hdl,
            (unsigned char*)"%s New Key Derivation Key generated. KCV: [%08x]",
            ERP_AUDIT_LOG_TAG,
            KeyChecksum);
    }
    else {
        cmds_audit_write(
            ERP_AUDIT_CLASS,
            p_hdl,
            (unsigned char*)"%s New Key Derivation Key Failed.   Error: [%08x]",
            ERP_AUDIT_LOG_TAG,
            err);

    }
    return err;
}

// Allocates and fills a Derivation Key Blob with a newly generated Derivation Key.
// The time is set to the current HSM time.
// The memory for the Blob is allocated by this method and must be freed by os_mem_del_set.
unsigned int getDerivationKeyBlob(T_CMDS_HANDLE* p_hdl, ClearBlob_t** ppOutBlob)
{
    return getAES256KeyBlob(p_hdl, ppOutBlob, Derivation_Key);
}
// Allocates and fills a HashKey clear Blob with a new RND value.
// The time is set to the current HSM time.
// The memory for the Blob is allocted by this method and must be freed by os_mem_del_set.
unsigned int getHashKeyBlob(T_CMDS_HANDLE* p_hdl, ClearBlob_t** ppOutBlob)
{
    return getAES256KeyBlob(p_hdl, ppOutBlob, Hash_Key);
}

// Allocates and fills a Pseudoname Key clear Blob with a new RND value.
// The time is set to the current HSM time.
// The blob is given an expiry period of 8 months, but this is enforced in the UnsealAndCheckBlob method.
// The memory for the Blob is allocted by this method and must be freed by os_mem_del_set.
unsigned int getPseudonameKeyBlob(T_CMDS_HANDLE* p_hdl, ClearBlob_t** ppOutBlob)
{
    return getAES256KeyBlob(p_hdl, ppOutBlob, Pseudoname_Key);
}

// Utility method to return KCV of a BLob Key.
// This is currently an SHA256 hash of the key
// pLen input is size of buffer passed in for output.   Must be at least SHA_256_LEN/8 bytes.
unsigned int getBlobKeyKCV(T_BLOBK* pBlobKey, size_t * pLen, unsigned char* pOutput)
{
    unsigned int err = E_ERP_SUCCESS;

    if (*pLen < (SHA_256_LEN / 8))
    {
        err = E_ERP_INTERNAL_BUFFER_ERROR;
    }
    if (err == E_ERP_SUCCESS)
    {
        *pLen = SHA_256_LEN / 8;
        err = hash_sha256(
            0, // Start a new hash...
            pBlobKey->KeyLength,
            &(pBlobKey->KeyData[0]),
            NULL, // Means that this is a single hash operation, not a chained one.
            pOutput);
    }
    return err;
}
// This is set to 3 for AES keys in the UTimaco headers.

const unsigned int AES_MBK_Number = MBK_EI_KEY_NO_AES;

// Utility method wrapping access to the backup key used to backup and restore single blob generations.
// This method returns an AES_256 key in raw form derived from the AES_256 Utimaco MBK and using a
//    key derivation unique to all eRP Firmware versions plus the BLOB_DOMAIN identifier for the Blobs.
// input:   length of and pointer to buffer to hold the resulting AES_KEY.   This must be at least AES_256_LEN/8
// output:    length and content of the AES key
// return:  result of the operation.
unsigned int getBlobBackupKey(size_t len, unsigned char* pKeyData)
{
    unsigned int err = E_ERP_SUCCESS;
    if (len < AES_256_LEN / 8)
    {
        err = E_ERP_INTERNAL_BUFFER_ERROR;
    }
    // Cannot be static const because I change it at runtime.
    unsigned char pFixData[] = "ERP Blob Backup Feedback Variation Data.   DOMAIN: NNNN";
    if (err == E_ERP_SUCCESS)
    {
        // Vary the derivation data with BLOB_DOMAIN
        os_mem_cpy(&(pFixData[sizeof(pFixData) - sizeof(BLOB_DOMAIN)]), BLOB_DOMAIN, sizeof(BLOB_DOMAIN));
    }
    // Then derive the key.
    if (err == E_ERP_SUCCESS)
    {
        err = mbk_derive_key_sp800108(AES_MBK_Number, KDF_MOD_FEEDBACK, KDF_PRF_HMAC, HASH_SHA256,
            NULL, 0, // No IV
            pFixData, sizeof(pFixData),
            len, pKeyData); // The output Key.
    }
    return err;
}

// Allocates and fills a BackupBlob_t with a backup of the blob key with the input generation.
// The caller must free the returned BackupBlob_t.
// The current AES 256 Master Backup Key in the HSM is used to create the backup.
// Information about the MBK used is stored in the Backup�Blob.
// Metadata in clear is only provided as information.   The same values are stored in the encrypted
//   data which is AES_GCM encoded to protect against manipulation.
// In the event of failure, *ppBackupBlob will be returned NULL and there will be no memory to free.
unsigned int backupBlobGeneration(T_CMDS_HANDLE* p_hdl, unsigned int Generation, BackupBlob_t** ppBackupBlob)
{
    unsigned int err = E_ERP_SUCCESS;

    // First of all, check we have a key to backup.
    T_BLOBK* pKey = getSingleBlobKey(p_hdl, Generation);
    if (pKey == NULL)
    {
        err = E_ERP_BAD_BLOB_GENERATION;
        INDEX_ERR(err, 0x03);
    }

    *ppBackupBlob = NULL;

    // Precalculate encDataSize to get idea of how much to allocate:
    size_t encDataSize = 0;
    if (err == E_ERP_SUCCESS)
    {
        encDataSize = BLOB_IV_LEN + pKey->KeyLength + BLOB_COUNTER_LEN;
    }
    unsigned int keyLen = AES_256_LEN/8;
    unsigned char keyData[AES_256_LEN/8] = "";
    AES_KEY* pEncryptKeyToken = NULL;

    // First get the backup key derived from the MBK and its' metadata from the HSM.
    // Note that for AES_GCM both encryption and decryption are actually AES Encryption operations
    //   on the keystream
    if (err == E_ERP_SUCCESS)
    {
        // ERP-7954 - do not use the MBK Directly, instead use a derived key
        err = getBlobBackupKey(keyLen, &(keyData[0]));
    }
    if (err == E_ERP_SUCCESS)
    {
        // The key tokens are what are needed to do enc/dec operations.
        pEncryptKeyToken = aes_pkey(keyLen, &(keyData[0]),AES_ENC,NULL);
        if (pEncryptKeyToken->error != 0)
        {
            err = pEncryptKeyToken->error;
        }
    }
    if (err == E_ERP_SUCCESS)
    { // overwrite the derived key to make sure a caller cannot get it from the stack.
        os_mem_set(&(keyData[0]), 0, sizeof(keyData));
    }

    T_MBK_KEY_INFO keyInfo;

    if (err == E_ERP_SUCCESS)
    {
        err = mbk_get_key_info(AES_MBK_Number, &keyInfo);
    }

    if (err == E_ERP_SUCCESS)
    {
        // Build the response
        *ppBackupBlob = os_mem_new_tag(sizeof(BackupBlob_t) + encDataSize, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, *ppBackupBlob, 0x3b);
    }

    if (err == E_ERP_SUCCESS)
    {    // Fill the backup blob Metadata.
        (*ppBackupBlob)->Generation = Generation;
        os_mem_cpy((*ppBackupBlob)->MBKName, keyInfo.name, MBK_NAME_LEN);
        os_mem_cpy((*ppBackupBlob)->MBKKCV, keyInfo.hash, MBK_KCV_LEN);
        os_mem_cpy((*ppBackupBlob)->BlobKeyKCV, "BlobKeyKCVabcdef0123456789abcdef\0", SHA_256_LEN / 8);
        os_mem_cpy((*ppBackupBlob)->Domain, getBlobDomain(), BLOB_DOMAIN_LEN);
        (*ppBackupBlob)->encDataLength = encDataSize; // Not the final value...
        memset(&((*ppBackupBlob)->encData[0]), 0, encDataSize);
        // Now get the BlobKeyKCV - the SHA256 hash of the key data.
        size_t kcvLen = SHA_256_LEN;
        err = getBlobKeyKCV(pKey, &kcvLen, &((*ppBackupBlob)->BlobKeyKCV[0]));
    }

    unsigned int IVLen = BLOB_IV_LEN;
    unsigned char GCMCounter[BLOB_COUNTER_LEN] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
    unsigned char GCMADHash[BLOB_AD_HASH_LEN] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
    if (err == E_ERP_SUCCESS)
    {    // Put the IV at the start of our encoded data buffer.
        err = getNewBlobIV(&IVLen, &((*ppBackupBlob)->encData[0]));
    }
    if (err == E_ERP_SUCCESS)
    {
        err = aes_gcm_init(pEncryptKeyToken, IVLen, &((*ppBackupBlob)->encData[0]), &(GCMCounter[0]));
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x050);
        }
    }
    // Endian issues mean we must take end of domain rather than address of encDataLength.
    // Apologies for pointer arithmetic, but structure alignment means adding sizeof() for each of the items would not be safe.
    // This calculation gives the size of the AES-GCM additional Data in bytes (unsigned char) as stored in the Backup Blob object.
    unsigned int ADLen = 0;
    if (err == E_ERP_SUCCESS)
    {
        ADLen = (unsigned int)(((unsigned char*)&((*ppBackupBlob)->Domain[BLOB_DOMAIN_LEN])) - ((unsigned char*)(&((*ppBackupBlob)->Generation))));
        // Be careful that the order of AD fields in BLOB Structure does not change too much.
        err = aes_gcm_ad(pEncryptKeyToken, ADLen, (unsigned char *)(*ppBackupBlob), &(GCMADHash[0]));
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x51);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        err = aes_gcm_data(
            pEncryptKeyToken,
            AES_ENC,
            pKey->KeyLength,
            pKey->KeyData,
            &(GCMCounter[0]),
            &(GCMADHash[0]),
            &((*ppBackupBlob)->encData[BLOB_IV_LEN]));
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x52);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        err = aes_gcm_final(
            pEncryptKeyToken,
            AES_ENC,
            ADLen,
            pKey->KeyLength,
            &(GCMCounter[0]),
            &(GCMADHash[0]),
            BLOB_AD_HASH_LEN * 8, // Use the full counter length (16) as the tag size.   i.e. use all of the tag.
            &((*ppBackupBlob)->encData[BLOB_IV_LEN + pKey->KeyLength]));
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x52);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        (*ppBackupBlob)->encDataLength = BLOB_IV_LEN + pKey->KeyLength + BLOB_COUNTER_LEN;
    }
    if (pEncryptKeyToken != NULL)
    {
        aes_free(pEncryptKeyToken);
    }
    return err;
}

// Restore a Blob Key Generation from a backup blob.
// There may not be a blob key already present for that generation.
// The current AES 256 MBK in the HSM must match that used to create the BackupBlob_t
// The Generation, key and MBK values in clear will be checked against those in the encrypted Data.
// Ownership of the input BackupBlob_t remains with the caller.
unsigned int restoreBlobGeneration(T_CMDS_HANDLE* p_hdl, BackupBlob_t* pBackupBlob)
{
    unsigned int err = E_ERP_SUCCESS;

    // Is this for the correct domain, i.e. "SIML", "TEST", "DVLP" or "PROD"?
    if (0 != os_mem_cmp(pBackupBlob->Domain, getBlobDomain(), BLOB_DOMAIN_LEN))
    {
        err = E_ERP_BAD_BLOB_DOMAIN;
    }

    //Do we already have a Blob Key under that Generation?
    if (err == E_ERP_SUCCESS)
    { // Actually, this should have been checked by the caller, but check again here since we don't trust them.
        if (NULL != getSingleBlobKey(p_hdl, pBackupBlob->Generation))
        { // A Key is already present!
            err = E_ERP_BAD_BLOB_GENERATION;
            INDEX_ERR(err, 0x08);
        }
    }

    // First get the backup key derived from the MBK and its' metadata from the HSM.
    // Note that for AES_GCM both encryption and decryption are actually AES Encryption operations
    //   on the keystream
    unsigned int keyLen = AES_256_LEN / 8;
    unsigned char keyData[AES_256_LEN / 8] = "";
    AES_KEY * pEncryptKeyToken = NULL;
    if (err == E_ERP_SUCCESS)
    {
        // ERP-7954 - do not use the MBK Directly, instead use a derived key
        err = getBlobBackupKey(keyLen, &(keyData[0]));
    }
    if (err == E_ERP_SUCCESS)
    {
        // The key tokens are what are needed to do enc/dec operations.
        pEncryptKeyToken = aes_pkey(keyLen, &(keyData[0]), AES_ENC, NULL);
        if (pEncryptKeyToken->error != 0)
        {
            err = pEncryptKeyToken->error;
        }
    }
    if (err == E_ERP_SUCCESS)
    { // overwrite the derived key to make sure a caller cannot get it from the stack.
        os_mem_set(&(keyData[0]), 0, sizeof(keyData));
    }
    T_MBK_KEY_INFO keyInfo;

    if (err == E_ERP_SUCCESS)
    { // And get the MBK Metadata to check the MBK identity.
        err = mbk_get_key_info(AES_MBK_Number, &keyInfo);
    }

    // Now check if this is the MBK that we want.
    if (err == E_ERP_SUCCESS)
    {
        if (0 != os_mem_cmp(keyInfo.name, pBackupBlob->MBKName, MBK_NAME_LEN))
        {
            err = E_ERP_BACKUP_WRONG_MBK_NAME;
            INDEX_ERR(err, 0x00);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        if (0 != os_mem_cmp(keyInfo.hash, pBackupBlob->MBKKCV, MBK_KCV_LEN))
        {
            err = E_ERP_BACKUP_WRONG_MBK_KCV;
            INDEX_ERR(err, 0x00);
        }
    }

    // Now Decryt the Blob.
    unsigned char* pICV = NULL;     // AES-GCM ICV
    unsigned int ADLen = 0;
    unsigned char* pAD = NULL;        // AES-GCM Associated Data.
    unsigned int cryptLen = 0;
    unsigned char* pCryptoData = NULL;
    unsigned char* pTag = NULL;
    // Find our encrypted Data.
    if (err == E_ERP_SUCCESS)
    { // This must be IV length plus tag length plus key size.
        if (pBackupBlob->encDataLength != (BLOB_IV_LEN + BLOB_AD_HASH_LEN + (AES_256_LEN/8)))
        {
            err = E_ERP_BACKUP_WRONG_DATA_LEN;
            INDEX_ERR(err, 0x00);
        }
    }

    if (err == E_ERP_SUCCESS)
    {
        pICV = &(pBackupBlob->encData[0]);
        pCryptoData = &(pBackupBlob->encData[BLOB_IV_LEN]);
        cryptLen = pBackupBlob->encDataLength - BLOB_IV_LEN - BLOB_AD_HASH_LEN;
        pTag = &(pBackupBlob->encData[BLOB_IV_LEN + cryptLen]);
        pAD = (unsigned char*)(&(pBackupBlob->Generation));
        ADLen = (unsigned int)(((unsigned char*)&(pBackupBlob->Domain[BLOB_DOMAIN_LEN])) - ((unsigned char*)(&(pBackupBlob->Generation))));
    }

    // Now decrpyt the data.
    unsigned char GCMCounter[BLOB_COUNTER_LEN] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
    unsigned char GCMADHash[BLOB_AD_HASH_LEN] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
    if (err == E_ERP_SUCCESS)
    {
        err = aes_gcm_init(pEncryptKeyToken, BLOB_IV_LEN, pICV, &(GCMCounter[0]));
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x53);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        // Be careful that the order of AD fields in BLOB Structure does not change too much.
        err = aes_gcm_ad(pEncryptKeyToken, ADLen, pAD, &(GCMADHash[0]));
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x54);
        }
    }
    T_BLOBK* pNewKey = NULL;
    if (err == E_ERP_SUCCESS)
    {
        pNewKey = os_mem_new_tag(sizeof(T_BLOBK) + (AES_256_LEN / 8), OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, pNewKey, 0x3b);
    }

    if (err == E_ERP_SUCCESS)
    {
        pNewKey->Generation = pBackupBlob->Generation;
        pNewKey->KeyLength = AES_256_LEN/8;
    }

    if (err == E_ERP_SUCCESS)
    {
        err = aes_gcm_data(
            pEncryptKeyToken,
            AES_DEC,
            cryptLen,
            pCryptoData,
            &(GCMCounter[0]),
            &(GCMADHash[0]),
            (unsigned char*)&(pNewKey->KeyData[0]));
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x55);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        err = aes_gcm_final(
            pEncryptKeyToken,
            AES_DEC,
            ADLen,
            cryptLen,
            &(GCMCounter[0]),
            &(GCMADHash[0]),
            BLOB_COUNTER_LEN * 8,
            pTag);
        if (err != E_ERP_SUCCESS)
        {
            err = E_ERP_BAD_BLOB_AD;
            INDEX_ERR(err, 0x56);
        }
    }
    // Check the new key's KCV against the metadata:
    if (err == E_ERP_SUCCESS)
    {
        // Get the BlobKeyKCV - the SHA256 hash of the key data.
        unsigned char calculatedKCV[SHA_256_LEN/8];
        size_t kcvLen = SHA_256_LEN/8;
        err = getBlobKeyKCV(pNewKey, &kcvLen, &(calculatedKCV[0]));
        if (err == E_ERP_SUCCESS)
        { // And check it against the metadata in the backup blob, which has been authenticated by now (AES-GCM AD).
            if (0 != os_mem_cmp(&(calculatedKCV[0]), &(pBackupBlob->BlobKeyKCV[0]), SHA_256_LEN/8))
            {
                err = E_ERP_BACKUP_WRONG_BLOB_KEY_KCV;
                INDEX_ERR(err, 0x01);
            }
        }
    }

    // Now try to add the new key:
    if (err == E_ERP_SUCCESS)
    {
        err = addNewBlobKey(p_hdl,pNewKey);
    }
    FREE_IF_NOT_NULL(pNewKey);
    if (pEncryptKeyToken != NULL)
    {
        aes_free(pEncryptKeyToken);
    }
    return err;
}
// Calculate an SHA256 hash if the contents of a clear blob and write them to the command output
//   buffer as an OCTET String.
unsigned int hashAndReturnBlobContents(T_CMDS_HANDLE* p_hdl, ClearBlob_t* input)
{
    unsigned int err = E_ERP_SUCCESS;
    unsigned int hashLen = SHA_256_LEN / 8;
    unsigned char hash[SHA_256_LEN / 8] = { 0 };
    if (err == E_ERP_SUCCESS)
    {
        err = hash_hash(HASH_SHA256,
            input->DataLength,
            &(input->Data[0]),
            NULL, // Do whole hash in one operation.
            &(hash[0]),
            &hashLen);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = makeSimpleOctetStringOutput(p_hdl, SHA_256_LEN / 8, &(hash[0]));
    }
    return err;
}