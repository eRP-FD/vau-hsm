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
#include <cryptoserversdk/asn1.h>
#include <cryptoserversdk/hash.h>

#include "ERP_ASNUtils.h"
#include "ERP_MDLError.h"
#include "ERP_CryptoUtils.h"

// Utility method to set initial NULL values of ASN1_ITEMS arrays
unsigned int initASN1Items(ASN1_ITEM* Items, unsigned int TableLength)
{
    unsigned int i = 0;
    for (i = 0; i < TableLength; i++)
    {
        Items[i].len = 0;
        Items[i].p_data = NULL;
        Items[i].raw_off = 0;
        Items[i].tag = 0;
    }
    return E_ERP_SUCCESS;
}

// Returns how many bytes are needed to encode the length as an ASN1 length field.
unsigned int getASN1Length(unsigned int len)
{
    unsigned int val = len;
    unsigned int intLen = 1;
    while ((val >>= 8) > 0)
    {
        intLen++;
    }
    // Only lengths less without bit 7 set go into one byte.
    if ((intLen > 1) || (len > 0x7f))
    { // If more than one byte add byte for length of length field.
        intLen++;
    }
    return intLen;
}

// This method assumes a well-formed item list.
size_t getEncodedSize(ASN1_ITEM* pItem, unsigned int NItems,ASN1_ITEM **ppNextItem) 
{
    size_t len = 0;
    unsigned int i;
    *ppNextItem = pItem + 1; // step one past this item.

    for (i = 0; i < NItems; i++)
    {   // There are different possibilities for structured tags - use the Utimaco Macro to detect them.
        //    ASN_SEQUENCE, ASN_SET, ASN_SE(0) - is ok for x509, but not general.
        if (ASN_IS_STRUCT(pItem->tag))
        {
            len++; // for the sequence tag
            unsigned int seqLen = 0; // Length of this sequence.
            // is sum of lengths of subsidiary items
            int j;
            for (j = 0; j < pItem->nitems; j++)
            { // Intended recursion.
                unsigned int addLen = getEncodedSize(*ppNextItem,1,ppNextItem);
                seqLen += addLen; // The content.
            }
            len += getASN1Length(seqLen);
            len += seqLen;
        }
        else {
            len += getASN1Length(pItem->len); //The length field
            len++; // The tag
            len += pItem->len; // The content.
        }
    }
    return len;
}

unsigned int checkASNBufferLength(unsigned int len, ASN1_ITEM* firstItem)
{
    unsigned int err = E_ERP_SUCCESS;
    ASN1_ITEM* pItem = NULL;
    if (len != getEncodedSize(firstItem, 1, &pItem))
    {
        err = E_ERP_PARAM_LEN;
        INDEX_ERR(err, 0x01);
    }
    return err;
}

// Utility method to parse and check a buffer into an Item list.
// The Item List must be deleted by the caller once they are finished with it.
extern unsigned int decodeASNList(int l_cmd, const unsigned char* p_cmd, ASN1_ITEM** pItems, unsigned int expectedItems, unsigned int expectedTopLevelNItems)
{
    unsigned int err = E_ERP_SUCCESS;
    unsigned int TableLength = 0;
    *pItems = NULL;  // In case the caller hasn't enforced this.

    // First call will tell us how big our table structure needs to be.
    err = asn1_decode((unsigned char*)p_cmd, // input Data
        l_cmd, // Length of input Data
        0,    // Flags
        NULL,
        &TableLength);

    if (err != E_ERP_SUCCESS)
    {
        INDEX_ERR(err, 0x05);
    }

    if (err == E_ERP_SUCCESS)
    {
        if (TableLength != expectedItems)
        {
            err = E_ERP_ASN1_CONTENT_ERROR;
            INDEX_ERR(err, 0x01);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        *pItems = os_mem_new_tag(sizeof(ASN1_ITEM) * TableLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, *pItems, 0x01);
    }
 
    if (err == E_ERP_SUCCESS)
    {
        err = asn1_decode((unsigned char *)p_cmd, // input Data
            l_cmd, // Length of input Data
            0,    // Flags
            *pItems,
            &TableLength);
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x06);
        }
    }

    if (err != E_ERP_SUCCESS)
    {
        INDEX_ERR(err, 0x01);
    }

    if (err == E_ERP_SUCCESS)
    {
        if ((TableLength != expectedItems) ||
            ((*pItems)[0].tag != ASN_SEQUENCE) ||
            ((*pItems)[0].nitems != expectedTopLevelNItems))
        {
            err = E_ERP_ASN1_CONTENT_ERROR;
            INDEX_ERR(err, 0x02);
        }
    }

    if (err == E_ERP_SUCCESS)
    {
        err = checkASNBufferLength(l_cmd, &((*pItems)[0]));
    }

    if ((err != E_ERP_SUCCESS) && ((*pItems) != NULL))
    {
        os_mem_del_set(*pItems, 0);
        *pItems = NULL;
    }
    return err;
}
// This writes an unsigned integer by, if neccesary, prepending an extra 0.
unsigned int setASNIntegerItem(ASN1_ITEM* item, unsigned int value)
{
    unsigned int err = E_ERP_SUCCESS;
    unsigned int intLen = 1;
    unsigned int val = value;
    if (item == NULL)
    { // Really shouldn't happen, but code defensively.
        err = E_ERP_MALLOC;
    }
    if (err == E_ERP_SUCCESS)
    {
        int negInt = ((val & 0x00000080) > 0); // Actually a bool.
        while ((val >>= 8) > 0)
        { // Only the last write to negInt will count and that will be for the MSB.
            negInt = ((val & 0x00000080) > 0);
            intLen++;
        }
        if (negInt > 0)
        {
            intLen++;
        }
        item->tag = ASN_INTEGER;
        item->len = intLen;
        item->p_data = os_mem_new_tag(intLen, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, item->p_data, 0x02);
    }
    if (err == E_ERP_SUCCESS)
    {
        item->nitems = 0;
        val = value;
        while (intLen > 0)
        { // If negInt then the last iteration will be with val == 0...
            item->p_data[--intLen] = val % 0x100;
            val >>= 8;
        }
    }
    return err;
}

unsigned int getASN1Integer(ASN1_ITEM* pItem, unsigned int* pOut)
{
    if (pItem->tag != ASN_INTEGER)
    {
        unsigned int err = E_ERP_ASN1_CONTENT_ERROR;
        INDEX_ERR(err, 0x02);
        return err;
    }
    unsigned int index = 0;
    unsigned int retVal = 0;
    while (index < pItem->len)
    {
        retVal <<= 8;
        retVal += pItem->p_data[index++];
    }
    *pOut = retVal;
    return 0;
}

// pOut must point to an integer variable.
// Out value is left as value from the ASN Data, i.e. 0 or FF
unsigned int getASN1Boolean(ASN1_ITEM* pItem, unsigned int* pOut)
{
    if (pItem->tag != ASN_BOOLEAN)
    {
        unsigned int err =  E_ERP_ASN1_CONTENT_ERROR;
        INDEX_ERR(err, 0x03);
        return err;
    }
    unsigned int index = 0;
    unsigned int retVal = 0;
    while (index < pItem->len)
    {
        retVal <<= 8;
        retVal += pItem->p_data[index++];
    }
    *pOut = retVal;
    return 0;
}

// This method does not allocate memory for the output buffer, but provides a pointer
//   into the ASM1_ITEM array to return the OCTET STRING Data. 
// Length is returned in pOutLen.
unsigned int getASN1OCTETSTRING(ASN1_ITEM* pItems, unsigned int* pOutLen, unsigned char** pOut)
{
    unsigned int err = E_ERP_SUCCESS;
    if ((pItems[0].tag != ASN_OCTET_STRING) || (pItems[0].len == 0) || (pItems[0].p_data == NULL))
    {
        err = E_ERP_ASN1_CONTENT_ERROR;
        INDEX_ERR(err, 0x04);
    }
    else {
        *pOutLen = pItems[0].len;
        *pOut = pItems[0].p_data;
    }
    return err;
}

// This method does not allocate memory for the outpu buffer, but provides a pointer
//   into the ASM1_ITEM array to return the NONCE Data. 
unsigned int getASN1NONCE(ASN1_ITEM* pItems, unsigned char** pOut)
{
    unsigned int err = E_ERP_SUCCESS;
    if ((pItems[0].tag != ASN_OCTET_STRING) || (pItems[0].len != (NONCE_LEN / 8)) || (pItems[0].p_data == NULL))
    {
        err = E_ERP_ASN1_CONTENT_ERROR;
        INDEX_ERR(err, 0x05);
    }
    else {
        *pOut = pItems[0].p_data;
    }
    return err;
}

// This method does allocate memory for the output buffer, which must be deleted by the caller. 
unsigned int getASN1SealedBlob(ASN1_ITEM* pItems, SealedBlob_t ** ppOut)
{
    unsigned int err = E_ERP_SUCCESS;
    if ((pItems[0].tag != ASN_SEQUENCE) ||
        (pItems[1].tag != ASN_INTEGER) ||
        (pItems[2].tag != ASN_OCTET_STRING))
    {
        err = E_ERP_ASN1_CONTENT_ERROR;
        INDEX_ERR(err, 0x06);
    }
    int BlobGeneration = 0;
    if (err == E_ERP_SUCCESS)
    {
        err = getASN1Integer(&pItems[1], &BlobGeneration);
    }
    if (err == E_ERP_SUCCESS)
    {
        if (pItems[2].len <= sizeof(SealedBlob_t))
        {
            err = E_ERP_ASN1_CONTENT_ERROR;
            INDEX_ERR(err, 0x07);
        }
    }
    // Nasty compiler byte alignment issue means that simply casting the p_data pointer and assigning to the *pOut
    //   changes the value of the pointer to the enarest 32 bit boundary.
    // To fix this we need to create a new buffer for the output blob (Creation will align it on a boundary) and
    //   copy the data of the sealed Blob into it.
    // A side effect of this is that the blobs must be deleted by the caller.
    unsigned char* outBuff = NULL;
    if (err == E_ERP_SUCCESS)
    {
        outBuff = os_mem_new_tag(pItems[2].len, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, outBuff, 0x03);
    }
    if (err == E_ERP_SUCCESS)
    {
        os_mem_cpy(outBuff,&(pItems[2].p_data[0]),pItems[2].len);
    }
    if (err == E_ERP_SUCCESS)
    {
        *ppOut = (SealedBlob_t *)outBuff;
        if (pItems[2].len != ((*ppOut)->EncodedDataLength + sizeof(SealedBlob_t)))
        {
            err = E_ERP_ASN1_CONTENT_ERROR;
            INDEX_ERR(err, 0x08);
        }
    }
    
    return err;
}

// This method does allocate memory for the output buffer, which must be deleted by the caller. 
unsigned int getASN1BackupBlob(ASN1_ITEM* pItems, BackupBlob_t** ppOut)
{
    unsigned int err = E_ERP_SUCCESS;
    if ((pItems[0].tag != ASN_SEQUENCE) ||
        (pItems[1].tag != ASN_INTEGER) ||
        (pItems[2].tag != ASN_OCTET_STRING) ||
        (pItems[3].tag != ASN_OCTET_STRING) ||
        (pItems[4].tag != ASN_OCTET_STRING) ||
        (pItems[5].tag != ASN_OCTET_STRING) ||
        (pItems[6].tag != ASN_OCTET_STRING) )
    {
        err = E_ERP_ASN1_CONTENT_ERROR;
        INDEX_ERR(err, 0x13);
    }

    if (err == E_ERP_SUCCESS)
    {
        // Size of Backup Blob is extended by size of encrypted Data in Items [5]
        *ppOut = os_mem_new_tag(sizeof (BackupBlob_t) + pItems[6].len, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, *ppOut, 0x40);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = getASN1Integer(&pItems[1], &((*ppOut)->Generation));
    }
    unsigned char* pCopy = NULL;
    if (err == E_ERP_SUCCESS)
    {
        size_t domainLen = 0;
        err = getASN1OCTETSTRING(&pItems[2], &domainLen, &pCopy);
        if ((err == E_ERP_SUCCESS) && (domainLen != BLOB_DOMAIN_LEN))
        {
            err = E_ERP_ASN1_CONTENT_ERROR;
            INDEX_ERR(err, 0x17);
        }
        if (err == E_ERP_SUCCESS)
        {
            os_mem_cpy(&((*ppOut)->Domain[0]), pCopy, domainLen);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        size_t mbkNameLen = 0;
        err = getASN1OCTETSTRING(&pItems[3], &mbkNameLen, &pCopy);
        if ((err == E_ERP_SUCCESS) && (mbkNameLen != MBK_NAME_LEN))
        {
            err = E_ERP_ASN1_CONTENT_ERROR;
            INDEX_ERR(err, 0x14);
        }
        if (err == E_ERP_SUCCESS)
        {
            os_mem_cpy(&((*ppOut)->MBKName[0]), pCopy, mbkNameLen);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        size_t mbkKCVLen = 0;
        err = getASN1OCTETSTRING(&pItems[4], &mbkKCVLen, &pCopy);
        if ((err == E_ERP_SUCCESS) && (mbkKCVLen != MBK_KCV_LEN))
        {
            err = E_ERP_ASN1_CONTENT_ERROR;
            INDEX_ERR(err, 0x15);
        }
        if (err == E_ERP_SUCCESS)
        {
            os_mem_cpy(&((*ppOut)->MBKKCV[0]), pCopy, mbkKCVLen);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        size_t blobKeyKCVLen = 0;
        err = getASN1OCTETSTRING(&pItems[5], &blobKeyKCVLen, &pCopy);
        if ((err == E_ERP_SUCCESS) && (blobKeyKCVLen != SHA_256_LEN/8))
        {
            err = E_ERP_ASN1_CONTENT_ERROR;
            INDEX_ERR(err, 0x16);
        }
        if (err == E_ERP_SUCCESS)
        {
            os_mem_cpy(&((*ppOut)->BlobKeyKCV[0]), pCopy, blobKeyKCVLen);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        size_t encDataLen = 0;
        err = getASN1OCTETSTRING(&pItems[6], &encDataLen, &pCopy);
        if (err == E_ERP_SUCCESS)
        {
            os_mem_cpy(&((*ppOut)->encData[0]), pCopy, encDataLen);
            (*ppOut)->encDataLength = encDataLen;
        }
    }

    return err;
}

// Creates a new ASN1_ITEM array containing the blob key.
// If a null pointer is passed in for pItem then a new array of 4 
//    ASN1_ITEMS items will be allocted.
// The returned ASN1_ITEMs must be deleted using deleteASN1Item.
// SHA256Hash ::= SEQUENCE {
//  hashValue OCTET STRING(64)
//  }
//  BlobKeyInfo :: = SEQUENCE{
//  generation INTEGER,
//  keyHash SHA256Hash -- hex encoded SHA256 hash of key.
//  }
unsigned int makeBlobKeyInfoItem(ASN1_ITEM** pItem, const T_BLOBK* blobKey)
{
    unsigned int err = E_ERP_SUCCESS;
    // SEQUENCE, INTEGER, SEQUENCE, OCTET STRING (64)
    // There does not seem to be any way to check the size of the memory allocation.
    if (*pItem == NULL)
    {
        *pItem = os_mem_new_tag(sizeof(ASN1_ITEM) * 4, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, *pItem, 0x04);
    }
    unsigned char HashBuffer[SHA256_DIGESTSIZE];
    if (err == E_ERP_SUCCESS)
    { // Start at the end:
        err = hash_sha256(0, blobKey->KeyLength, (unsigned char*)blobKey->KeyData, NULL, &(HashBuffer[0]));
    }
    if (err == E_ERP_SUCCESS)
    {
        (*pItem)[3].len = SHA256_DIGESTSIZE;
        (*pItem)[3].tag = ASN_OCTET_STRING;
        (*pItem)[3].p_data = os_mem_new_tag(SHA256_DIGESTSIZE, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err,(*pItem)[3].p_data, 0x05)
    }
    if (err == E_ERP_SUCCESS)
    {
        os_mem_cpy((*pItem)[3].p_data, HashBuffer, SHA256_DIGESTSIZE);
        (*pItem)[2].tag = ASN_SEQUENCE;
        (*pItem)[2].len = SHA256_DIGESTSIZE + 2;
        (*pItem)[2].nitems = 1;
        (*pItem)[2].p_data = NULL;
        (*pItem)[1].tag = ASN_INTEGER;
        err = setASNIntegerItem(&(*pItem)[1], blobKey->Generation);
    }
    if (err == E_ERP_SUCCESS)
    {
        (*pItem)[0].tag = ASN_SEQUENCE;
        (*pItem)[0].len = (*pItem)[1].len + (*pItem)[2].len + 4;
        (*pItem)[0].p_data = NULL;
        (*pItem)[0].nitems = 2;
    }
    return err;
}

// Deletes an ASN1 Item list, assuming that all the items in the list are part of a 
//   single allocation in an array.
// It also assumes that p_data (if not NULL) is allocated separately from the Itemlist itself.
// The size of the list passed in is used to walk the array checking the p_data values.
unsigned int deleteASNItemList(ASN1_ITEM* pItems, unsigned int nItems)
{
    unsigned int i = 0;
    while (i < nItems)
    {
        if (pItems[i].p_data != NULL)
        {
            os_mem_del_set(pItems[i].p_data, 0);
        }
        i++;
    }
    os_mem_del_set(pItems, 0);
    return 0;
}

// Utility method to parse an ASN input to extract a single integer input argument.
unsigned int parseSingleIntInput(int l_cmd, unsigned char* p_cmd, unsigned int* pOut)
{
    unsigned int err = E_ERP_SUCCESS;
    unsigned int TableLength = 2;
    ASN1_ITEM* Items = NULL;

    err = decodeASNList(l_cmd, p_cmd, &Items, TableLength, 1);

    if (err == E_ERP_SUCCESS)
    {
        // Extract the requested integer
        err = getASN1Integer(&Items[1], pOut);
    }
    // Subsidiary structures in Itemlist from der_decode point into the original buffer 
    //   and should not be deleted here.
    FREE_IF_NOT_NULL(Items);
    return err;
}

// Utility method to parse an ASN input to extract a Single Blob input argument.
// To avoid lots of copying and reallocating, the pointers returned by this method are all
//   pointing into the original data buffer so do not delete the input buffer until you are 
//   finished with the output pointers.
// Exception to the above:   Any SealedBlobs returned by this method will be in newly allocated 
//   buffers and must be freed by the caller. 
unsigned int parseSingleBlobInput(
    int l_cmd,
    unsigned char* p_cmd,
    // All Parameters from here are output:
    SealedBlob_t** ppOutBlob)
{
    unsigned int err = E_ERP_SUCCESS;
    unsigned int TableLength = 4;
    ASN1_ITEM* Items = NULL;

    err = decodeASNList(l_cmd, p_cmd, &Items, TableLength, 1);

    if (err == E_ERP_SUCCESS)
    {
        err = getASN1SealedBlob(&Items[1], ppOutBlob);
    }

    // Subsidiary structures in Itemlist from der_decode point into the original buffer 
    //   and should not be deleted here.
    FREE_IF_NOT_NULL(Items);
    return err;
}

// Utility method to parse an ASN input to extract a Migrate Blob input argument.
// To avoid lots of copying and reallocating, the pointers returned by this method are all
//   pointing into the original data buffer so do not delete the input buffer until you are 
//   finished with the output pointers.
// Exception to the above:   Any SealedBlobs returned by this method will be in newly allocated 
//   buffers and must be freed by the caller. 
unsigned int parseMigrateBlobInput(
    int l_cmd,
    unsigned char* p_cmd,
    // All Parameters from here are output:
    unsigned int* pNewGeneration,
    SealedBlob_t** ppOutBlob)
{
    unsigned int err = E_ERP_SUCCESS;
    unsigned int TableLength = 5;
    ASN1_ITEM* Items = NULL;

    err = decodeASNList(l_cmd, p_cmd, &Items, TableLength, 2);

    if (err == E_ERP_SUCCESS)
    {
        // Extract the requested integer
        err = getASN1Integer(&Items[1], pNewGeneration);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = getASN1SealedBlob(&Items[2], ppOutBlob);
    }

    // Subsidiary structures in Itemlist from der_decode point into the original buffer 
    //   and should not be deleted here.
    FREE_IF_NOT_NULL(Items);
    return err;
}

// To avoid lots of copying and reallocating, the pointers returned by this method are all
//   referring directly to nthe elements of the ASN1_ITEM array returned by pItems.
//   So, to delete them all, we need to call deleteASNItemList with pItems when we are finished.
unsigned int parseTrustTPMMfrInput(
    int l_cmd,
    unsigned char* p_cmd,
    // All Parameters from here are output:
    unsigned int* pDesiredGeneration,
    unsigned int* pOutLen,
    unsigned char** ppOutData)
{
    unsigned int err = E_ERP_SUCCESS;
    unsigned int TableLength = 3;
    ASN1_ITEM* Items = NULL;

    err = decodeASNList(l_cmd, p_cmd, &Items, TableLength, 2);

    if (err == E_ERP_SUCCESS)
    {
        // Extract the generation.
        err = getASN1Integer(&Items[1], pDesiredGeneration);
    }
    if (err == E_ERP_SUCCESS)
    {
        *pOutLen = 0;
        err = getASN1OCTETSTRING(&Items[2], pOutLen, ppOutData);
    }

    // Subsidiary structures in Itemlist from der_decode point into the original buffer 
    //   and should not be deleted here.
    FREE_IF_NOT_NULL(Items);
    return err;
}


// To avoid lots of copying and reallocating, the pointers returned by this method are all
//   pointing into the original data buffer so do not delete the input buffer until you are 
//   finished with the output pointers.
// Exception to the above:   Any SealedBlobs returned by this method will be in newly allocated 
//   buffers and must be freed by the caller. 
unsigned int parseEnrollTPMEKInput(
    int l_cmd,
    unsigned char* p_cmd,
    // All Parameters from here are output:
    unsigned int* pDesiredGeneration,
    SealedBlob_t** ppTrustedTPMMfrRootBlob,
    unsigned int* pEKCertLength,
    unsigned char** ppEKCertData)
{
    unsigned int err = E_ERP_SUCCESS;
    unsigned int TableLength = 6;
    ASN1_ITEM* Items = NULL;

    err = decodeASNList(l_cmd, p_cmd, &Items, TableLength, 3);

    if (err == E_ERP_SUCCESS)
    {
        // Extract the generation
        err = getASN1Integer(&Items[1], pDesiredGeneration);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = getASN1SealedBlob(&Items[2], ppTrustedTPMMfrRootBlob);
    }
    if (err == E_ERP_SUCCESS)
    {
       *pEKCertLength = 0;
        err = getASN1OCTETSTRING(&Items[5], pEKCertLength, ppEKCertData);
    }

    // Subsidiary structures in Itemlist from der_decode point into the original buffer 
    //   and should not be deleted here.
    FREE_IF_NOT_NULL(Items);
    return err;
}

// To avoid lots of copying and reallocating, the pointers returned by this method are all
//   pointing into the original data buffer so do not delete the input buffer until you are 
//   finished with the output pointers.
// Exception to the above:   Any SealedBlobs returned by this method will be in newly allocated 
//   buffers and must be freed by the caller. 
unsigned int parseGetAKChallengeInput(
    int l_cmd,
    unsigned char* p_cmd,
    // All Parameters from here are output:
    unsigned int* pDesiredGeneration,
    SealedBlob_t** ppTrustedEKBlob,
    unsigned int* pAKPubLength,
    unsigned char** ppAKPubData,
    unsigned char** ppAKName)
{
    //  GetAKChallenge :: = SEQUENCE{
    //          desiredGeneration INTEGER,
    //          trustedEKBlob SingleBlob,
    //          nameAK OCTET STRING(34), -- 0x000b plus SHA256 hash of AK Public - used by TPM as name
    //          certAK OCTET STRING -- Decision: ASN1.DER encoded public key or x509v3 Certificate ?    }
    unsigned int err = E_ERP_SUCCESS;
    unsigned int TableLength = 7;
    ASN1_ITEM* Items = NULL;

    err = decodeASNList(l_cmd, p_cmd, &Items, TableLength, 4);

    if (err == E_ERP_SUCCESS)
    {
        // Extract the generation
        err = getASN1Integer(&Items[1], pDesiredGeneration);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = getASN1SealedBlob(&Items[2], ppTrustedEKBlob);
    }
    if (err == E_ERP_SUCCESS)
    {
        if (Items[5].len != TPM_NAME_LEN)
        {
            err = E_ERP_ASN1_CONTENT_ERROR;
            INDEX_ERR(err, 0x09);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        unsigned int dontCareInt = 0;
        err = getASN1OCTETSTRING(&Items[5], &dontCareInt, ppAKName);
    }
    if (err == E_ERP_SUCCESS)
    {
        *pAKPubLength = 0;
        err = getASN1OCTETSTRING(&Items[6], pAKPubLength, ppAKPubData);
    }

    // Subsidiary structures in Itemlist from der_decode point into the original buffer 
    //   and should not be deleted here.
    FREE_IF_NOT_NULL(Items);
    return err;
}

// To avoid lots of copying and reallocating, the pointers returned by this method are all
//   pointing into the original data buffer so do not delete the input buffer until you are 
//   finished with the output pointers.
// Exception to the above:   Any SealedBlobs returned by this method will be in newly allocated 
//   buffers and must be freed by the caller. 
unsigned int parseEnrollAKInput(
    int l_cmd,
    unsigned char* p_cmd,
    // All Parameters from here are output:
    unsigned int* pDesiredGeneration,
    SealedBlob_t** ppTrustedEKBlob,
    SealedBlob_t** ppChallengeBlob,
    unsigned int* pAKPubLength,
    unsigned char** ppAKPubData,
    unsigned char** ppAKName,
    unsigned int* pPlainCredLength,
    unsigned char** ppPlainCredData )
{
    //  EnrollAKRequest :: = SEQUENCE{
    //        desiredGeneration INTEGER,
    //        nameAK OCTET STRING(34), --TPM Name hash (0x000b + SHA256) of AK Public - used by TPM as name
    //        certAK OCTET STRING, --Decision: ASN1.DER encoded public key or x509v3 Certificate ?
    //        decryptedCredential OCTET STRING, --decrypted credential from theAK Challenge
    //        challengeBlob SingleBlob, --Blob returned from the getAKChallenge call.
    //        trustedEKBlob SingleBlob    }
    unsigned int err = E_ERP_SUCCESS;
    unsigned int TableLength = 11;
    ASN1_ITEM* Items = NULL;

    err = decodeASNList(l_cmd, p_cmd, &Items, TableLength, 6);

    if (err == E_ERP_SUCCESS)
    {
        // Extract the generation
        err = getASN1Integer(&Items[1], pDesiredGeneration);
    }
    if (err == E_ERP_SUCCESS)
    {
        if (Items[2].len != TPM_NAME_LEN)
        {
            err = E_ERP_ASN1_CONTENT_ERROR;
            INDEX_ERR(err, 0x0a);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        unsigned int dontCareInt = 0; // Has to be TPM_NAME_LEN/8
        err = getASN1OCTETSTRING(&Items[2], &dontCareInt, ppAKName);
    }
    if (err == E_ERP_SUCCESS)
    {
        *pAKPubLength = 0;
        err = getASN1OCTETSTRING(&Items[3], pAKPubLength, ppAKPubData);
    }
    if (err == E_ERP_SUCCESS)
    {
        *pPlainCredLength = 0;
        err = getASN1OCTETSTRING(&Items[4], pPlainCredLength, ppPlainCredData);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = getASN1SealedBlob(&Items[5], ppChallengeBlob);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = getASN1SealedBlob(&Items[8], ppTrustedEKBlob);
    }

    // Subsidiary structures in Itemlist from der_decode point into the original buffer 
    //   and should not be deleted here.
    FREE_IF_NOT_NULL(Items);
    return err;
}

// To avoid lots of copying and reallocating, the pointers returned by this method are all
//   pointing into the original data buffer so do not delete the input buffer until you are 
//   finished with the output pointers.
// Exception to the above:   Any SealedBlobs returned by this method will be in newly allocated 
//   buffers and must be freed by the caller. 
unsigned int parseEnrollEnclaveInput(
    int l_cmd,
    unsigned char* p_cmd,
    // All Parameters from here are output:
    unsigned int* pDesiredGeneration,
    unsigned char** ppAKName,
    SealedBlob_t** ppTrustedAKBlob,
    SealedBlob_t** ppNONCEBlob,
    unsigned int* pQuoteLength,
    unsigned char** ppQuoteData,
    unsigned int* pSignatureLength,
    unsigned char** ppSignatureData)
{
    //  EnrollEnclaveRequest :: = SEQUENCE{
    //          desiredGeneration INTEGER,
    //          nameAK OCTET STRING(34), --TPM Name hash (0x000b + SHA256) of AK Public - used by TPM as name
    //          trustedAKBlob SingleBlob,
    //          aNONCEBlob SingleBlob,
    //          quotedData OCTET STRING, --Data of the TPM Quote
    //          signature OCTET STRING -- Signature by the TPM using AK over Quoted Data including NONE.    }
    unsigned int err = E_ERP_SUCCESS;
    unsigned int TableLength = 11;
    ASN1_ITEM* Items = NULL;

    err = decodeASNList(l_cmd, p_cmd, &Items, TableLength, 6);

    if (err == E_ERP_SUCCESS)
    {
        // Extract the generation
        err = getASN1Integer(&Items[1], pDesiredGeneration);
    }
    if (err == E_ERP_SUCCESS)
    {
        if (Items[2].len != TPM_NAME_LEN)
        {
            err = E_ERP_ASN1_CONTENT_ERROR;
            INDEX_ERR(err, 0x0b);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        unsigned int dontCareInt = 0; // Has to be TPM_NAME_LEN
        err = getASN1OCTETSTRING(&Items[2], &dontCareInt, ppAKName);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = getASN1SealedBlob(&Items[3], ppTrustedAKBlob);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = getASN1SealedBlob(&Items[6], ppNONCEBlob);
    }
    if (err == E_ERP_SUCCESS)
    {
        *pQuoteLength = 0;
        err = getASN1OCTETSTRING(&Items[9], pQuoteLength, ppQuoteData);
    }
    if (err == E_ERP_SUCCESS)
    {
        *pSignatureLength = 0;
        err = getASN1OCTETSTRING(&Items[10], pSignatureLength, ppSignatureData);
    }

    // Subsidiary structures in Itemlist from der_decode point into the original buffer 
    //   and should not be deleted here.
    FREE_IF_NOT_NULL(Items);
    return err;
}

// To avoid lots of copying and reallocating, the pointers returned by this method are all
//   pointing into the original data buffer so do not delete the input buffer until you are 
//   finished with the output pointers.
// Exception to the above:   Any SealedBlobs returned by this method will be in newly allocated 
//   buffers and must be freed by the caller. 
unsigned int parseGetTEETokenInput(
    int l_cmd,
    unsigned char* p_cmd,
    // All Parameters from here are output:
    unsigned char** ppAKName,
    SealedBlob_t** ppTrustedAKBlob,
    SealedBlob_t** ppTrustedQuoteBlob,
    SealedBlob_t** ppNONCEBlob,
    unsigned int* pQuoteLength,
    unsigned char** ppQuoteData,
    unsigned int* pSignatureLength,
    unsigned char** ppSignatureData)
{
    //  TEETokenRequest :: = SEQUENCE{ --TEEToken is always newest Generation.
    //          nameAK OCTET STRING(34), --TPM Name hash (0x000b + SHA256) of AK Public - used by TPM as name
    //          knownAKBlob SingleBlob,
    //          knownQuoteBlob SingleBlob,
    //          aNONCEBlob SingleBlob,
    //          quoteData OCTET STRING, --Can we impose any more structure on this ?
    //          quoteSignature OCTET STRING -- Can we impose any more structure on this ?    }
    unsigned int err = E_ERP_SUCCESS;
    unsigned int TableLength = 13;
    ASN1_ITEM* Items = NULL;

    err = decodeASNList(l_cmd, p_cmd, &Items, TableLength, 6);

    if (err == E_ERP_SUCCESS)
    {
        if (Items[1].len != TPM_NAME_LEN)
        {
            err = E_ERP_ASN1_CONTENT_ERROR;
            INDEX_ERR(err, 0x0c);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        unsigned int dontCareInt = 0; // Has to be SHA_1_LEN/8
        err = getASN1OCTETSTRING(&Items[1], &dontCareInt, ppAKName);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = getASN1SealedBlob(&Items[2], ppTrustedAKBlob);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = getASN1SealedBlob(&Items[5], ppTrustedQuoteBlob);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = getASN1SealedBlob(&Items[8], ppNONCEBlob);
    }
    if (err == E_ERP_SUCCESS)
    {
        *pQuoteLength = 0;
        err = getASN1OCTETSTRING(&Items[11], pQuoteLength, ppQuoteData);
    }
    if (err == E_ERP_SUCCESS)
    {
        *pSignatureLength = 0;
        err = getASN1OCTETSTRING(&Items[12], pSignatureLength, ppSignatureData);
    }

    // Subsidiary structures in Itemlist from der_decode point into the original buffer 
    //   and should not be deleted here.
    FREE_IF_NOT_NULL(Items);
    return err;
}


// To avoid lots of copying and reallocating, the pointers returned by this method are all
//   pointing into the original data buffer so do not delete the input buffer until you are 
//   finished with the output pointers.
// Exception to the above:   Any SealedBlobs returned by this method will be in newly allocated 
//   buffers and must be freed by the caller. 
unsigned int parseDeriveKeyInput(
    int l_cmd,
    unsigned char* p_cmd,
    // All Parameters from here are output:
    unsigned char** ppAKName,
    SealedBlob_t** ppTEETokenBlob,
    SealedBlob_t** ppDerivationKeyBlob,
    unsigned int* pIsInitial, // Boolean 1 == TRUE...
    unsigned int* pDerivationDataLength,
    unsigned char** ppDerivationData)
{
    //  DeriveKeyRequest :: = SEQUENCE{
    //          nameAK OCTET STRING (34), -- TPM Name hash (0x000b + SHA256) of AK Public - used by TPM as name
    //          tokenTEE SingleBlob, --Currently valid TEEToken Blob
    //          derivationData OCTET STRING, --Derivation data to be used.Possibly to be extended if InitialDerivation is true
    //          initialDerivation BOOLEAN, -- if TRUE then derivation data will be extended by HSM.
    //          derivationKeyBlob SingleBlob -- Blob containing the derivation key to be used.    }
    unsigned int err = E_ERP_SUCCESS;
    unsigned int TableLength = 10;
    ASN1_ITEM* Items = NULL;

    err = decodeASNList(l_cmd, p_cmd, &Items, TableLength, 5);

    if (err == E_ERP_SUCCESS)
    {
        if (Items[1].len != TPM_NAME_LEN)
        {
            err = E_ERP_ASN1_CONTENT_ERROR;
            INDEX_ERR(err, 0x0d);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        unsigned int dontCareInt = 0; // Has to be SHA_1_LEN/8
        err = getASN1OCTETSTRING(&Items[1], &dontCareInt, ppAKName);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = getASN1SealedBlob(&Items[2], ppTEETokenBlob);
    }
    if (err == E_ERP_SUCCESS)
    {
        *pDerivationDataLength = 0;
        err = getASN1OCTETSTRING(&Items[5], pDerivationDataLength, ppDerivationData);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = getASN1Boolean(&Items[6], pIsInitial);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = getASN1SealedBlob(&Items[7], ppDerivationKeyBlob);
    }

    // Subsidiary structures in Itemlist from der_decode point into the original buffer 
    //   and should not be deleted here.
    FREE_IF_NOT_NULL(Items);
    return err;
}

// Method to validate an x509 ANSI X9.62 encoded public key.
// To avoid lots of copying and reallocating, the pointers returned by this method are all
//   pointing into the original data buffer so do not delete the input buffer until you are 
//   finished with the output pointers.
extern unsigned int parseASN1PublicKey(
    size_t keyLength,
    const unsigned char* pKeyData,
    size_t* pCurveOIDLen, unsigned char** ppCurveOID,
    size_t* pCoordinateSize, // in bytes.   Output,
    unsigned char** ppXCoord, unsigned char** ppYCoord)

{
    //    ECParams :: = SEQUENCE{
    //    algID OBJECT IDENTIFIER, --must be id_ecPublicKey 1,2,840,10045,2,1
    //    curveID OBJECT IDENTIFIER },
    //        ECCPublicKey :: = SEQUENCE{ --actually same as x.509
    //        params ECParams,
    //        value BIT STRING -- curve - dependent encoding of ECC public key. }
    unsigned int err = E_ERP_SUCCESS;
    unsigned int TableLength = 5;
    ASN1_ITEM* Items = NULL;

    err = decodeASNList(keyLength, pKeyData, &Items, TableLength, 2);

    if (err == E_ERP_SUCCESS)
    {
        if ((Items[1].tag != ASN_SEQUENCE) ||
            (Items[1].nitems != 2) ||
            (Items[2].tag != ASN_OBJECT_ID) ||
            (Items[3].tag != ASN_OBJECT_ID) ||
            (Items[4].tag != ASN_BIT_STRING) ||
            (Items[4].len != 0x42))
        {
            err = E_ERP_ASN1_CONTENT_ERROR;
            INDEX_ERR(err, 0x0e);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        if (Items[2].len != ID_EC_PUBLICKEY_ANSI_OID_LEN)
        {
            err = E_ERP_ASN1_CONTENT_ERROR;
            INDEX_ERR(err, 0x0f);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        if (0 != os_mem_cmp(ID_EC_PUBLICKEY_ANSI_OID, &(Items[2].p_data[0]), Items[2].len))
        {
            err = E_ERP_ASN1_CONTENT_ERROR;
            INDEX_ERR(err, 0x10);
        }
    }
    if (err == E_ERP_SUCCESS)
    { // Second oid is curve ID for a curve that we support.
        if (0 == isSupportedCurveID(&(Items[3])))
        {
            err = E_ERP_CERT_UNSUPPORTED_CURVE;
        }
    }
    if (err == E_ERP_SUCCESS)
    { // If we get here then we can pick out the values for the return data.
        
        // For now, both curves that we support have 256 bit coordinates.
        *pCoordinateSize = 0x20;
        *pCurveOIDLen = Items[3].len;
        *ppCurveOID = &(Items[3].p_data[0]);
        *ppXCoord = &(Items[4].p_data[0x2]);
        *ppYCoord = &(Items[4].p_data[0x22]);
    }

    // Subsidiary structures in Itemlist from der_decode point into the original buffer 
    //   and should not be deleted here.
    FREE_IF_NOT_NULL(Items);
    return err;
}

// To avoid lots of copying and reallocating, the pointers returned by this method are all
//   pointing into the original data buffer so do not delete the input buffer until you are 
//   finished with the output pointers.
// Exception to the above:   Any SealedBlobs returned by this method will be in newly allocated 
//   buffers and must be freed by the caller. 
unsigned int parseTwoBlobInputRequest(
    int l_cmd,
    unsigned char* p_cmd,
    // All Parameters from here are output:
    SealedBlob_t** ppBlob1,
    SealedBlob_t** ppBlob2)
{
    //  GetPublicKeyRequest :: = SEQUENCE{
    //      teeToken SingleBlob,
    //      keyPair SingleBlob }
    unsigned int err = E_ERP_SUCCESS;
    unsigned int TableLength = 7;
    ASN1_ITEM* Items = NULL;

    err = decodeASNList(l_cmd, p_cmd, &Items, TableLength, 2);
 
    if (err == E_ERP_SUCCESS)
    {
        err = getASN1SealedBlob(&Items[1], ppBlob1);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = getASN1SealedBlob(&Items[4], ppBlob2);
    }

    // Subsidiary structures in Itemlist from der_decode point into the original buffer 
    //   and should not be deleted here.
    FREE_IF_NOT_NULL(Items);
    return err;
}

// To avoid lots of copying and reallocating, the pointers returned by this method are all
//   pointing into the original data buffer so do not delete the input buffer until you are 
//   finished with the output pointers.
// Exception to the above:   Any SealedBlobs returned by this method will be in newly allocated 
//   buffers and must be freed by the caller. 
unsigned int parseGenerateCSRInput(int l_cmd,
    unsigned char* p_cmd,
    // All Parameters from here are output:
    SealedBlob_t** ppKeyPairBlob,
    size_t* pCandidateCSRLength,
    unsigned char** ppCandidateCSRData)
{
    //  GetVAUCSRRequest :: = SEQUENCE{
    //      keyPair SingleBlob,
    //      candidateCSR OCTET STRING }
    unsigned int err = E_ERP_SUCCESS;
    unsigned int TableLength = 5;
    ASN1_ITEM* Items = NULL;

    err = decodeASNList(l_cmd, p_cmd, &Items, TableLength, 2);

    if (err == E_ERP_SUCCESS)
    {
        err = getASN1SealedBlob(&Items[1], ppKeyPairBlob);
    }
    if (err == E_ERP_SUCCESS)
    {
        *pCandidateCSRLength = 0;
        err = getASN1OCTETSTRING(&Items[4], pCandidateCSRLength, ppCandidateCSRData);
    }

    // Subsidiary structures in Itemlist from der_decode point into the original buffer 
    //   and should not be deleted here.
    FREE_IF_NOT_NULL(Items);
    return err;
}

// To avoid lots of copying and reallocating, the pointers returned by this method are all
//   pointing into the original data buffer so do not delete the input buffer until you are 
//   finished with the output pointers.
// Exception to the above:   Any SealedBlobs returned by this method will be in newly allocated 
//   buffers and must be freed by the caller. 
extern unsigned int parseDoECIESAES128Request(
    int l_cmd,
    unsigned char* p_cmd,
    // All Parameters from here are output:
    SealedBlob_t** ppTEETokenBlob,
    SealedBlob_t** ppKeyPairBlob,
    unsigned int* pClientPubKeyLength,
    unsigned char** ppClientPubKeyData)
{
    //  GetPublicKeyRequest :: = SEQUENCE{
    //      teeToken SingleBlob,
    //      eciesKeyPair SingleBlob }
    unsigned int err = E_ERP_SUCCESS;
    unsigned int TableLength = 8;
    ASN1_ITEM* Items = NULL;

    err = decodeASNList(l_cmd, p_cmd, &Items, TableLength, 3);

    if (err == E_ERP_SUCCESS)
    {
        err = getASN1SealedBlob(&Items[1], ppTEETokenBlob);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = getASN1SealedBlob(&Items[4], ppKeyPairBlob);
    }

    if (err == E_ERP_SUCCESS)
    {
        *pClientPubKeyLength = 0;
        err = getASN1OCTETSTRING(&Items[7], pClientPubKeyLength, ppClientPubKeyData);
    }

    // Subsidiary structures in Itemlist from der_decode point into the original buffer 
    //   and should not be deleted here.
    FREE_IF_NOT_NULL(Items);
    return err;
}

unsigned int buildOutputBuffer(T_CMDS_HANDLE* p_hdl, ASN1_ITEM * itemList, unsigned int numItems)
{
    unsigned int err = E_ERP_SUCCESS;
    ASN1_ITEM* offEnd = NULL;   // Not used here, but it is required 
                            // by the recursive sub calls in the length measurement.
    unsigned int OutputLength = getEncodedSize(itemList, 1, &offEnd);
    unsigned char* pBuff = os_mem_new_tag(OutputLength, OS_MEM_TYPE_SECURE,__FILE__,__LINE__);
    CHECK_NOT_NULL(err, pBuff, 0x06);

    // Build the ASN1 DER buffer for returning to the caller.
    if (err == E_ERP_SUCCESS)
    { // First call works out size of output buffer.
        err = asn1_encode(itemList, // input Items
                        numItems, // size of item table
                        0,    // Flags
                        &pBuff, // This gets written by method.
                        &OutputLength);
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x01);
        }
    }


    unsigned char* pOutputData = NULL;
    // Allocate the output buffer:
    if (err == E_ERP_SUCCESS)
    {
        err = cmds_alloc_answ(p_hdl, OutputLength, &pOutputData);
    }

    if (err == E_ERP_SUCCESS)
    { // First call works out size of output buffer.
        os_mem_cpy(pOutputData, pBuff, OutputLength);
    }
    FREE_IF_NOT_NULL(pBuff);
    return err;
}
// Utility Method to build an ASN Output containing a single integer value.
// The result is automatically packed into an HSM response using cds_alloc_answ
// input: Commands handle for the command
// input: the integer value
unsigned int makeSingleIntOutput(T_CMDS_HANDLE* p_hdl, unsigned int input)
{
    unsigned int err = E_ERP_SUCCESS;
    unsigned int TableLength = 2;
    
    ASN1_ITEM* Items = os_mem_new_tag(sizeof(ASN1_ITEM) * TableLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
    CHECK_NOT_NULL(err, Items, 0x07);
    if (err == E_ERP_SUCCESS)
    {
        err = initASN1Items(Items, TableLength);
    }
    if (err == E_ERP_SUCCESS)
    {
        Items[0].tag = ASN_SEQUENCE;
        Items[0].p_data = NULL;
        Items[0].len = 0;
        Items[0].nitems = 1;

        // Set up the return value with the actual generation used.
        err = setASNIntegerItem(&Items[1], (long)input);
    }

    if (err == E_ERP_SUCCESS)
    {
        err = buildOutputBuffer(p_hdl,
            Items, // input Items
            TableLength);
    }

    if (Items != NULL)
    {
        deleteASNItemList(Items, TableLength);
    }
    return err;
}

// Utility Method to build an ASN Output containing a single sealed Blob.
// The result is automatically packed into an HSM response using cds_alloc_answ
// input: Commands handle for the command
// input: the integer value
// Output: the length of the data created.
// Output: The data buffer for the command response
unsigned int makeSingleSealedBlobOutput(
    T_CMDS_HANDLE* p_hdl,
    SealedBlob_t* input)
{
//    SingleBlob :: = SEQUENCE{
//              blobGeneration INTEGER,
//              aBlob OCTET STRING   }
    unsigned int err = E_ERP_SUCCESS;
    unsigned int TableLength = 3;

    ASN1_ITEM* Items = os_mem_new_tag(sizeof(ASN1_ITEM) * TableLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
    CHECK_NOT_NULL(err, Items, 0x08);

    if (err == E_ERP_SUCCESS)
    {
        err = initASN1Items(Items, TableLength);
    }
    if (err == E_ERP_SUCCESS)
    {
        Items[0].tag = ASN_SEQUENCE;
        Items[0].p_data = NULL;
        Items[0].len = 0;
        Items[0].nitems = 2;
        // Set up the return value with the actual generation used.
        err = setASNIntegerItem(&Items[1],input->Generation);
    }
    if (err == E_ERP_SUCCESS)
    { // Set up the return value with the actual generation used.
        Items[2].tag = ASN_OCTET_STRING;
        Items[2].len = sizeof(SealedBlob_t) + input->EncodedDataLength;
        Items[2].p_data = os_mem_new_tag(Items[2].len, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, Items[2].p_data, 0x09);
    }
    if (err == E_ERP_SUCCESS)
    { 
        // We do not need to make streaming of blob structure endian independent since the blob is 
        //    meant to be opaque to the client.   And blobs cannot be shared between architectures anyway.
        os_mem_cpy(Items[2].p_data, input, Items[2].len);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = buildOutputBuffer(p_hdl,
            Items, // input Items
            TableLength);
    }
    if (Items != NULL)
    {
        deleteASNItemList(Items, TableLength);
    }
    return err;
}

// Utility Method to build an ASN Output containing a NONCE Value and related BLOB.
// The result is automatically packed into an HSM response using cds_alloc_answ
// input: Commands handle for the command
// input: the various Data fields for the NONCE And Blob
// Output: the length of the data created.
// Output: The data buffer for the command response
unsigned int makeNONCEAndBlobOutput(
    T_CMDS_HANDLE* p_hdl,
    NONCEBlob_t* aNONCEBlob,
    SealedBlob_t* input)
{
    //   NONCEAndBlob :: = SEQUENCE{
    //                  aNONCE OCTET STRING(32),
    //                  aNONCEBlob SingleBlob     }
    unsigned int err = E_ERP_SUCCESS;
    unsigned int TableLength = 5;

    ASN1_ITEM* Items = os_mem_new_tag(sizeof(ASN1_ITEM) * TableLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
    CHECK_NOT_NULL(err, Items, 0x0a);
    if (err == E_ERP_SUCCESS)
    {
        err = initASN1Items(Items, TableLength);
    }
    if (err == E_ERP_SUCCESS)
    {
        Items[0].tag = ASN_SEQUENCE;
        Items[0].p_data = NULL;
        Items[0].len = 0;
        Items[0].nitems = 2;

        // Set up the return value with the actual generation used.
        Items[1].tag = ASN_OCTET_STRING;
        Items[1].len = NONCE_LEN / 8; // NONCE_LEN here is in bits.
        Items[1].nitems = 0;
        Items[1].p_data = os_mem_new_tag(Items[1].len, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, Items[1].p_data, 0x0b)
    }
    if (err == E_ERP_SUCCESS)
    {
         os_mem_cpy(&(Items[1].p_data[0]), &(aNONCEBlob->RNDData[0]), Items[1].len);
    }

    if (err == E_ERP_SUCCESS)
    {
        Items[2].tag = ASN_SEQUENCE;
        Items[2].p_data = NULL;
        Items[2].len = 0;
        Items[2].nitems = 2;
    }
    if (err == E_ERP_SUCCESS)
    { // Set up the return value with the actual generation used.
        err = setASNIntegerItem(&Items[3], input->Generation);
    }

    if (err == E_ERP_SUCCESS)
    {
        Items[4].tag = ASN_OCTET_STRING;
        Items[4].len = sizeof(SealedBlob_t) + input->EncodedDataLength;
        Items[4].p_data = os_mem_new_tag(Items[4].len, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
    }
    if (err == E_ERP_SUCCESS)
    {
        os_mem_cpy(Items[4].p_data, input, Items[4].len);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = buildOutputBuffer(p_hdl,
            Items, // input Items
            TableLength);
    }

    if (Items != NULL)
    {
        deleteASNItemList(Items, TableLength);
    }
    return err;
}

// Utility Method to build an ASN Output containing the Output of a GetAKChallenge
// The result is automatically packed into an HSM response using cds_alloc_answ
// input: Commands handle for the command
// input: the various Data fields for the AK Challenge response
// Output: the length of the data created.
// Output: The data buffer for the command response
unsigned int makeAKChallengeOutput(
    T_CMDS_HANDLE* p_hdl,
    SealedBlob_t* pSealedChallengeBlob,
    unsigned int credentialLength,
    unsigned char* pCredentialData,
    unsigned int secretLength,
    unsigned char* pSecretData)
 {
    //   --This is the response to the get AK challenge command to the HSM, not the response to the challenge.
    //    AKChallengeResponse :: = SEQUENCE{
    //          secret OCTET STRING, --TPM2 Secret to decrpyt credential
    //          credential OCTET STRING, --TPM2 encrypted Credential
    //          challengeBlob SingleBlob -- Blob to allow HSM to verify credential decryption.    }
    unsigned int err = E_ERP_SUCCESS;
    unsigned int TableLength = 6;

    ASN1_ITEM* Items = os_mem_new_tag(sizeof(ASN1_ITEM) * TableLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
    CHECK_NOT_NULL(err, Items, 0x0c);
    if (err == E_ERP_SUCCESS)
    {
        err = initASN1Items(Items, TableLength);
    }
    if (err == E_ERP_SUCCESS)
    {
        Items[0].tag = ASN_SEQUENCE;
        Items[0].p_data = NULL;
        Items[0].len = 0;
        Items[0].nitems = 3;
        // Set up the return value with the actual generation used.
        Items[1].tag = ASN_OCTET_STRING;
        Items[1].len = secretLength; // NONCE_LEN here is in bits.
        Items[1].nitems = 0;
        Items[1].p_data = os_mem_new_tag   (Items[1].len, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, Items[1].p_data, 0x0d);
    }
    if (err == E_ERP_SUCCESS)
    {
        os_mem_cpy(&(Items[1].p_data[0]), &(pSecretData[0]), Items[1].len);
    }
    if (err == E_ERP_SUCCESS)
    { // Set up the return value with the actual generation used.
        Items[2].tag = ASN_OCTET_STRING;
        Items[2].len = credentialLength; // NONCE_LEN here is in bits.
        Items[2].nitems = 0;
        Items[2].p_data = os_mem_new_tag(Items[2].len, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, Items[2].p_data, 0x0e);
    }
    if (err == E_ERP_SUCCESS)
    {
        os_mem_cpy(&(Items[2].p_data[0]), &(pCredentialData[0]), Items[2].len);
    }
    if (err == E_ERP_SUCCESS)
    {
        Items[3].tag = ASN_SEQUENCE;
        Items[3].p_data = NULL;
        Items[3].len = 0;
        Items[3].nitems = 2;
        // Set up the return value with the actual generation used.
        err = setASNIntegerItem(&Items[4], pSealedChallengeBlob->Generation);
    }
    if (err == E_ERP_SUCCESS)
    {
        Items[5].tag = ASN_OCTET_STRING;
        Items[5].len = sizeof(SealedBlob_t) + pSealedChallengeBlob->EncodedDataLength;
        Items[5].p_data = os_mem_new_tag(Items[5].len, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, Items[5].p_data, 0x0f);
    }
    if (err == E_ERP_SUCCESS)
    {
        os_mem_cpy(Items[5].p_data, pSealedChallengeBlob, Items[5].len);
    }

    if (err == E_ERP_SUCCESS)
    {
        err = buildOutputBuffer(p_hdl,
            Items, // input Items
            TableLength);
    }

    if (Items != NULL)
    {
        deleteASNItemList(Items, TableLength);
    }
    return err;
}

// Utility Method to build an ASN Output containing a DerivedKey Output.
// The result is automatically packed into an HSM response using cds_alloc_answ
// input: Commands handle for the command
// input: the various Data fields for the Key and Derivation data.
// Output: the length of the data created.
// Output: The data buffer for the command response
unsigned int makeDerivedKeyOutput(
    T_CMDS_HANDLE* p_hdl,
    unsigned char * pKey, // AES_256_LEN / 8
    unsigned int derivationDataLength,
    unsigned char *pDerivationData)
{
    //  DerivedKey :: = SEQUENCE{
    //          derivedKey OCTET STRING(32), --AES 256 Symmetric key.
    //          usedDerivationData OCTET STRING -- derivation data actually used by HSM.For an initial derivation, this will
    //                                         -- differ from the derivation data passed in the request.    }
    unsigned int err = E_ERP_SUCCESS;
    unsigned int TableLength = 3;

    ASN1_ITEM* Items = os_mem_new_tag(sizeof(ASN1_ITEM) * TableLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
    CHECK_NOT_NULL(err, Items, 0x10);
    if (err == E_ERP_SUCCESS)
    {
        err = initASN1Items(Items, TableLength);
    }

    if (err == E_ERP_SUCCESS)
    {
        Items[0].tag = ASN_SEQUENCE;
        Items[0].p_data = NULL;
        Items[0].len = 0;
        Items[0].nitems = 2;
        // Set up the return value with the actual generation used.
        Items[1].tag = ASN_OCTET_STRING;
        Items[1].len = AES_256_LEN / 8; // AES_256_LEN here is in bits.
        Items[1].nitems = 0;
        Items[1].p_data = os_mem_new_tag(Items[1].len, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, Items[1].p_data, 0x11);
    }
    if (err == E_ERP_SUCCESS)
    {
        os_mem_cpy(&(Items[1].p_data[0]), pKey, Items[1].len);
    }

    if (err == E_ERP_SUCCESS)
    { // Set up the return value with the actual generation used.
        Items[2].tag = ASN_OCTET_STRING;
        Items[2].len = derivationDataLength; // NONCE_LEN here is in bits.
        Items[2].nitems = 0;
        Items[2].p_data = os_mem_new_tag(Items[2].len, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, Items[2].p_data, 0x12);
    }
    if (err == E_ERP_SUCCESS)
    {
        os_mem_cpy(&(Items[2].p_data[0]), pDerivationData, Items[2].len);
    }

    if (err == E_ERP_SUCCESS)
    {
        err = buildOutputBuffer(p_hdl,
            Items, // input Items
            TableLength);
    }

    if (Items != NULL)
    {
        deleteASNItemList(Items, TableLength);
    }
    return err;
}

// Utility Method to build an ASN Output containing an ASN1 encoded CSR
// The result is automatically packed into an HSM response using cds_alloc_answ
// input: Commands handle for the command
// input: length and data for thw ASN1 encoded CSR.
unsigned int makeSimpleOctetStringOutput(
    T_CMDS_HANDLE* p_hdl,
    unsigned int inLen,
    unsigned char* inData)
{
    // X509CSR :: = SEQUENCE{
    //                  csrData OCTET STRING }

    unsigned int err = E_ERP_SUCCESS;
    unsigned int TableLength = 2;

    ASN1_ITEM* Items = os_mem_new_tag(sizeof(ASN1_ITEM) * TableLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
    CHECK_NOT_NULL(err, Items, 0x13);
    if (err == E_ERP_SUCCESS)
    {
        err = initASN1Items(Items, TableLength);
    }

    if (err == E_ERP_SUCCESS)
    {
        Items[0].tag = ASN_SEQUENCE;
        Items[0].p_data = NULL;
        Items[0].len = 0;
        Items[0].nitems = 1;
        // Set up the return value with the actual generation used.
        Items[1].tag = ASN_OCTET_STRING;
        Items[1].len = inLen; // AES_256_LEN here is in bits.
        Items[1].nitems = 0;
        Items[1].p_data = os_mem_new_tag(Items[1].len, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, Items[1].p_data, 0x14);
    }
    if (err == E_ERP_SUCCESS)
    {
        os_mem_cpy(&(Items[1].p_data[0]), inData, Items[1].len);
    }

    if (err == E_ERP_SUCCESS)
    {
        err = buildOutputBuffer(p_hdl,
            Items, // input Items
            TableLength);
    }

    if (Items != NULL)
    {
        deleteASNItemList(Items, TableLength);
    }
    return err;
}

// Utility Method to build an ASN Output containing already formed ASN1 response
// The result is automatically packed into an HSM response using cds_alloc_answ
// input: Commands handle for the command
// input: length and data for the ASN1 encoded return data.
unsigned int makeDirectASN1Output(
    T_CMDS_HANDLE* p_hdl,
    unsigned int dataLen,
    unsigned char* pData)
{
    unsigned int err = E_ERP_SUCCESS;
  
    unsigned char* pOutputData = NULL;
    // Allocate the output buffer:
    if (err == E_ERP_SUCCESS)
    {
        err = cmds_alloc_answ(p_hdl, dataLen, &pOutputData);
        CHECK_NOT_NULL(err, pOutputData, 0x15);
    }
    if (err == E_ERP_SUCCESS)
    {
        os_mem_cpy(pOutputData, pData, dataLen);
    }
    return err;
}

// Utility Method to build an ASN Output containing an ASN1 encoded CSR
// The result is automatically packed into an HSM response using cds_alloc_answ
// input: Commands handle for the command
// input: length and data for the ASN1 encoded CSR.
extern unsigned int makex509CSROutput(
    T_CMDS_HANDLE* p_hdl,
    unsigned int csrLen,
    unsigned char* pCsrData)
{
    return makeSimpleOctetStringOutput(p_hdl, csrLen, pCsrData);
}

// Utility Method to build an ASN Output containing an ECC Public key
// The result is automatically packed into an HSM response using cds_alloc_answ
// input: Commands handle for the command
// input: EC Public key in RFC 5480 / ANSI X9.62 format.
extern unsigned int makePublicKeyOutput(
    T_CMDS_HANDLE* p_hdl,
    unsigned int keyLen,
    unsigned char* pKeyData)
{
    return makeSimpleOctetStringOutput(p_hdl, keyLen, pKeyData);
}

// Utility method to parse a BasicConstraints octet string, usually from an x509 Certificate.
// input:   inputLength and pInputData of the basic constraints octet string value to be parsed.
// output:  boolean isCA - 0 == FALSE, (!0) == true
// output:  path length constraint.   0 if no constraint is present.
// return:  error status.
unsigned int parseBasicConstraints(
    size_t inputLength,
    unsigned char* pInputData,
    unsigned int* pBIsCA,
    unsigned int* pPathLengthConstraint
)
{
    unsigned int err = E_ERP_SUCCESS;
    unsigned int TableLength = 0;
    ASN1_ITEM* Items = NULL;

    // First call will tell us how big our table structure needs to be.
    err = asn1_decode(pInputData, // input Data
        (unsigned int)inputLength, // Length of input Data
        0,    // Flags
        NULL,
        &TableLength);

    if (err != E_ERP_SUCCESS)
    {
        INDEX_ERR(err, 0x0d);
    }

    // TableLength will be variable.
    if (err == E_ERP_SUCCESS)
    {
        Items = os_mem_new_tag(sizeof(ASN1_ITEM) * TableLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, Items, 0x16);
    }

    if (err == E_ERP_SUCCESS)
    {
        err = asn1_decode(pInputData, // input Data
            (unsigned int)inputLength, // Length of input Data
            ASN_RAW_OFFSET,    // Flags
            Items,
            &TableLength);
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x0e);
        }
    }

    if (err == E_ERP_SUCCESS)
    {
// ERP-10331 - TPM EK Certificates fail to pass parse checks.
// Some TPM EK certificates pass in an empty ASN1 Sequence at this point
        if ((Items[0].tag != ASN_SEQUENCE) ||
            (Items[0].nitems > 2))
#           // Items[0].nitems can be 1 for no path constraint, just an isCA,
            //    2 if isCA and path constraint are both present and
            //    0 if neither is present which is non standard, but does actually happen in the wild (Nuvoton)
        {
            err = E_ERP_ASN1_CONTENT_ERROR;
            INDEX_ERR(err, 0x12);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        // ERP-10331 - TPM EK Certificates fail to pass parse checks.
        // Some TPM EK certificates pass in an empty ASN1 Sequence at this point
        if ((Items[0].nitems > 0) && (Items[1].tag != ASN_BOOLEAN) )
        {
            err = E_ERP_ASN1_CONTENT_ERROR;
            INDEX_ERR(err, 0x14);
        }
    }

    if (err == E_ERP_SUCCESS)
    {
        if (Items[0].nitems > 0)
        {
            err = getASN1Boolean(&(Items[1]), pBIsCA);
        }
        else { // ERP-10331 default FALSE
            *pBIsCA = 0;
        }
    }

    if (err == E_ERP_SUCCESS)
    {
        if (Items[0].nitems == 2)
        {
            err = getASN1Integer(&(Items[2]), pPathLengthConstraint);
        }
        else {
            *pPathLengthConstraint = 0;
        }
    }
    return err;
}

// Utility method to extract an EC public key from an x509 certificate.
// The output pointers are to the correct places in the original data so do not delete them
//    separately.
// input:   The certificate.
// output:   The signable part of the certificate
// output:   The Signature.   This is the content of an ASN1 DER BIT STRING, i.e the first byte
//             is the number of unused bits at the end of the string.
// output:   The EC Subject Public key in x509 format
// output:   The EC Subject Public key in HSM-useable 0x41 byte format
// output:   The Subject Public Key curve OID.
// output:   Is the certificate a CA?   !0 == TRUE, 0 == FALSE
unsigned int parsex509ECCertificate(
    size_t certLength,
    unsigned char* pCertData,
    size_t* pSignableLength,
    unsigned char** ppSignableData,
    size_t* pSignatureLength,
    unsigned char** ppSignatureData,
    size_t* px509ECKeyLength,
    unsigned char** ppx509ECKeyData,
    size_t* pECPointLength,
    unsigned char** ppECPointData,
    size_t * pCurveIDLen, // OID of curve.
    unsigned char **ppCurveID,
    unsigned int * pbIsCA
) 
{
    unsigned int err = E_ERP_SUCCESS;
    unsigned int TableLength = 0;
    ASN1_ITEM* Items = NULL;

    // First call will tell us how big our table structure needs to be.
    err = asn1_decode(pCertData, // input Data
        (unsigned int) certLength, // Length of input Data
        0,    // Flags
        NULL,
        &TableLength);

    if (err != E_ERP_SUCCESS)
    {
        INDEX_ERR(err, 0x07);
    }

    // TableLength will be variable.
    if (err == E_ERP_SUCCESS)
    {
        Items = os_mem_new_tag(sizeof(ASN1_ITEM) * TableLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, Items, 0x16);
    }

    if (err == E_ERP_SUCCESS)
    {
        err = asn1_decode(pCertData, // input Data
            (unsigned int) certLength, // Length of input Data
            ASN_RAW_OFFSET,    // Flags
            Items,
            &TableLength);
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x08);
        }
    }

    if (err == E_ERP_SUCCESS)
    {
        if ((Items[0].tag != ASN_SEQUENCE) ||
            (Items[0].nitems != 3) || // Cert, SigAlg, Sig.
            (Items[1].tag != ASN_SEQUENCE))
        {
            err = E_ERP_ASN1_CONTENT_ERROR;
            INDEX_ERR(err, 0x11);
        }
    }

    ASN1_ITEM* pSubjectKeyAlgID = NULL;
    if (err == E_ERP_SUCCESS)
    { // Check the subject public key algorithm
        err = asn1_find_object((unsigned char *)&(ID_ECDSA_WITH_SHA256_ANSI_OID[0]),ID_ECDSA_WITH_SHA256_ANSI_OID_LEN,&(Items[1]), &pSubjectKeyAlgID);
        if (err != E_ERP_SUCCESS)
        {
            err = E_ERP_CERT_BAD_SUBJECT_ALG;
        }
    }

    ASN1_ITEM* pPublicKey = NULL;
    if (err == E_ERP_SUCCESS)
    { // Check the signature public key algorithm
        err = asn1_find_object((unsigned char*)&(ID_EC_PUBLICKEY_ANSI_OID[0]), ID_EC_PUBLICKEY_ANSI_OID_LEN, &(Items[1]), &pPublicKey);
        if (err != E_ERP_SUCCESS)
        {
            err = E_ERP_CERT_BAD_SUBJECT_ALG;
        }
    }

    if (err == E_ERP_SUCCESS)
    {   // Start of public key sequence should be two items before oid_ecPublicKey.
        // Call to find object returns ITEM AFTER the object id...
        pPublicKey -= 3;
        if ((pPublicKey->tag != ASN_SEQUENCE) ||
            (pPublicKey->nitems != 2) ||
            ((pPublicKey + 1)->tag != ASN_SEQUENCE) ||
            ((pPublicKey + 1)->nitems != 2))
        {
            err = E_ERP_CERT_BAD_SUBJECT_ENCODING;
        }
    }
    ASN1_ITEM* pCurveID = NULL;
    if (err == E_ERP_SUCCESS)
    { // Check the curve
        pCurveID = pPublicKey + 3;
        if (pCurveID->tag != ASN_OBJECT_ID)
        {
            err = E_ERP_CERT_BAD_SUBJECT_ENCODING;
        }
        else {
            if (0 == isSupportedCurveID(pCurveID))
            {
                err = E_ERP_CERT_UNSUPPORTED_CURVE;
            }
        }
    }

    if (err == E_ERP_SUCCESS)
    {
        *ppCurveID = pCurveID->p_data;
        *pCurveIDLen = pCurveID->len;
    }
    // Set PublicKey Return values the first is the whole c509 public key structure
    if (err == E_ERP_SUCCESS)
    {
        *ppx509ECKeyData = pPublicKey->p_data - pPublicKey->raw_off;
        *px509ECKeyLength = pPublicKey->len + pPublicKey->raw_off;
    }
    // Set PublicKey Return values the second is the 0x41 bytes of the public point 
    //   representation starting with 0x04
    if (err == E_ERP_SUCCESS)
    {
        if ((pPublicKey + 4)->tag != ASN_BIT_STRING)
        {
            err = E_ERP_CERT_BAD_SUBJECT_ENCODING;
        }
        *ppECPointData = (pPublicKey + 4)->p_data+1;
        *pECPointLength = (pPublicKey + 4)->len-1;
    }

    // Now find basic constraints and identify the isCA value.
    ASN1_ITEM* pIsCANode = NULL;
    if (err == E_ERP_SUCCESS)
    { // Find location of start of Signature.
        err = asn1_find_object((unsigned char*)&(ID_BASIC_CONSTRAINTS_OID[0]), ID_BASIC_CONSTRAINTS_OID_LEN, &(Items[1]), &pIsCANode);
        if (err == E_ASN1_NOT_FOUND)
        {
            // There are no basic constraints in this certificate.
            *pbIsCA = 0;
            err = E_ERP_SUCCESS;
        }
        else {
            // The data following the tag is:
            //   BOOLEAN isCritical - optional
            //   OCTET_STRING containing an ASN Sequence of:
            //     BOOLEAN isCA   ERP-10331 - Not Optional, but may be missing.
            //     integer pathLengthConstraint.   Optional.
            if (pIsCANode->tag == ASN_BOOLEAN)
            { // We are not interested in the isCritical value because it is not used consistently in the Certs that we deal with.
                pIsCANode++;
            }
            if ((pIsCANode->tag == ASN_OCTET_STRING) &&
                (pIsCANode->nitems == 0))
            {
                // We don't actually use the isCritical or path length constraint here and it may or may not be present.
                // We are only parsing here to check formal correctness and ensure that parsing from this point on is still valid.
                unsigned int pathLengthConstraint = 0;
                err = parseBasicConstraints(pIsCANode->len, pIsCANode->p_data, pbIsCA, &pathLengthConstraint);
            }
            else {
                err = E_ERP_CERT_BAD_BASIC_CONSTRAINTS;
                INDEX_ERR(err, 0x01);
            }
        }
    }

    ASN1_ITEM* pSignatureAlg = NULL;
    if (err == E_ERP_SUCCESS)
    { // Find location of start of Signature.
        LOCAL_STAT char searchPath[] = { 2,0 };
        err = asn1_find_item(&(Items[0]), &(searchPath[0]),NULL, &pSignatureAlg);
    }
    if (err == E_ERP_SUCCESS)
    {
        if ((pSignatureAlg->tag != ASN_SEQUENCE) ||
            (pSignatureAlg->nitems != 1) ||
            ((pSignatureAlg+1)->tag != ASN_OBJECT_ID) ||
            ((pSignatureAlg+1)->len != ID_ECDSA_WITH_SHA256_ANSI_OID_LEN) ||
            (0 != os_mem_cmp((pSignatureAlg+1)->p_data,&(ID_ECDSA_WITH_SHA256_ANSI_OID[0]),ID_ECDSA_WITH_SHA256_ANSI_OID_LEN)))
        {
            err = E_ERP_CERT_BAD_SIGNATURE_ALG;
        }
    }
    ASN1_ITEM* pSignatureBody = NULL;
    if (err == E_ERP_SUCCESS)
    { // Check the signature public key algorithm
        LOCAL_STAT char searchPath[] = { 3,0 };
        err = asn1_find_item(&(Items[0]), &(searchPath[0]),NULL,&pSignatureBody);
        if (err != E_ERP_SUCCESS)
        {
            err = E_ERP_CERT_BAD_SIGNATURE_FORMAT;
        }
    }

    // Set SignableData Return values
    if (err == E_ERP_SUCCESS)
    {
        *ppSignableData = &(Items[1].p_data[0]) - Items[1].raw_off;
         *pSignableLength = Items[1].len + Items[1].raw_off;
    }

    // Set Signature Return values
    if (err == E_ERP_SUCCESS)
    {
        *ppSignatureData = &((pSignatureAlg+2)->p_data[0]) + 1;
        *pSignatureLength = (pSignatureAlg+2)->len - 1;
    }

    // Subsidiary structures in ASN1_ITEMs point to the original data stream.
    FREE_IF_NOT_NULL(Items);
 
    return err;
}

// Utility method to check an admissions x590 extension against allowed value for the keypair
unsigned int checkX509Admissions(ASN1_ITEM* pAdmissionsItem, ClearBlob_t* keyPair)
{
    unsigned int err = E_ERP_SUCCESS;

    if (err == E_ERP_SUCCESS)
    {
        if ((pAdmissionsItem[0].tag != ASN_OCTET_STRING) ||
            (pAdmissionsItem[0].nitems != 0))
        {
            err = E_ERP_ASN1_PARSE_ERROR;
        }
    }
    int TableLength = 0;
    ASN1_ITEM* pItems = NULL;
    if (err == E_ERP_SUCCESS)
    {
        // First call will tell us how big our table structure needs to be.
        err = asn1_decode(pAdmissionsItem->p_data, // input Data
            pAdmissionsItem->len, // Length of input Data
            0,    // Flags
            NULL,
            &TableLength);
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x09);
        }
    }

    if (err == E_ERP_SUCCESS)
    {
        if (TableLength != 9)
        {
            err = E_ERP_ASN1_PARSE_ERROR;
        }
    }

    if (err == E_ERP_SUCCESS)
    {
        pItems = os_mem_new_tag(sizeof(ASN1_ITEM) * TableLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, pItems, 0x17);
    }

    if (err == E_ERP_SUCCESS)
    {
        err = asn1_decode(pAdmissionsItem->p_data, // input Data
            pAdmissionsItem->len, // Length of input Data
            ASN_RAW_OFFSET,    // Flags
            pItems,
            &TableLength);
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x0a);
        }
    }

    if (err == E_ERP_SUCCESS)
    {
        // We must Drill down to get to actual useful data:
    // Yes, really, I mean this...
        if ((pItems[0].tag != ASN_SEQUENCE) ||
            (pItems[0].nitems != 1) ||
            (pItems[1].tag != ASN_SEQUENCE) ||
            (pItems[1].nitems != 1) ||
            (pItems[2].tag != ASN_SEQUENCE) ||
            (pItems[2].nitems != 1) ||
            (pItems[3].tag != ASN_SEQUENCE) ||
            (pItems[3].nitems != 1) ||
            (pItems[4].tag != ASN_SEQUENCE) ||
            (pItems[4].nitems != 2) ||
            (pItems[5].tag != ASN_SEQUENCE) ||
            (pItems[5].nitems != 1) ||
            (pItems[6].tag != ASN_UTF8STRING) ||
            (pItems[6].nitems != 0) ||
            (pItems[7].tag != ASN_SEQUENCE) ||
            (pItems[7].nitems != 1) ||
            (pItems[8].tag != ASN_OBJECT_ID) ||
            (pItems[8].nitems != 0))
        {
            err = E_ERP_ASN1_PARSE_ERROR;
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        switch (keyPair->BlobType)
        {
        case ECIES_KeyPair:
        {
            // "E-Rezept vertrauenswürdige Ausführungsumgebung and oid_erezept" in UTF8.
            const unsigned char erpVAU[] = // "E-Rezept vertrauenswürdige Ausführungsumgebung";
            {   0x45, 0x2D, 0x52, 0x65, 0x7A, 0x65, 0x70, 0x74,
                0x20, 0x76, 0x65, 0x72, 0x74, 0x72, 0x61, 0x75,
                0x65, 0x6E, 0x73, 0x77, 0x75, 0xCC, 0x88, 0x72,
                0x64, 0x69, 0x67, 0x65, 0x20, 0x41, 0x75, 0x73,
                0x66, 0x75, 0xCC, 0x88, 0x68, 0x72, 0x75, 0x6E,
                0x67, 0x73, 0x75, 0x6D, 0x67, 0x65, 0x62, 0x75,
                0x6E, 0x67 };

            const size_t erpVAULen = sizeof(erpVAU);
            if ((pItems[6].len != erpVAULen) ||
                (0 != os_mem_cmp(pItems[6].p_data, &(erpVAU[0]), erpVAULen)) ||
                (pItems[8].len != ID_EREZEPT_ANSI_OID_LEN) ||
                (0 != os_mem_cmp(pItems[8].p_data, ID_EREZEPT_ANSI_OID, ID_EREZEPT_ANSI_OID_LEN)))
            {
                err = E_ERP_CSR_ADMISSIONS_MISMATCH;
            }
        }
        break;
        case VAUSIG_KeyPair:
        {
            // "E-Rezept" and oid_erp_vau
            const char eRezept[] = "E-Rezept";
            const size_t eRezeptLen = sizeof(eRezept) - 1;
            if ((pItems[6].len != eRezeptLen) ||
                (0 != os_mem_cmp(pItems[6].p_data, &(eRezept[0]), eRezeptLen)) ||
                (pItems[8].len != ID_ERP_VAU_ANSI_OID_LEN) ||
                (0 != os_mem_cmp(pItems[8].p_data, ID_ERP_VAU_ANSI_OID, ID_ERP_VAU_ANSI_OID_LEN)))
            {
                err = E_ERP_CSR_ADMISSIONS_MISMATCH;
            }
        }
        break;
        default:
            err = E_ERP_WRONG_BLOB_TYPE;
            INDEX_ERR(err, 0x01);
            break;
        }
    }
    FREE_IF_NOT_NULL(pItems);
    return err;
}
// This method will parse and verify the candidate CSR and then replace the contained public key
//   with the public key from the keypair and resign with the private key from the keypair.
// The candidate CSR must be complete with a public key and signature, though the content of 
//    the public ky and the validity of the signature do not matter.
// Admission Extensions will be checkd for VAUSIG and ECIES keypairs
// A new buffer will be allocated for the modified CSR which must be freed by the caller.
unsigned int x509ECCSRReplacePublicKeyAndSign(
    T_CMDS_HANDLE* p_hdl,
    size_t candidateCSRLength, unsigned char* pCandidateCSRData,
    ClearBlob_t* keyPair,
    size_t* pModifiedCSRLength, unsigned char** ppModifiedCSRData)
{
    unsigned int err = E_ERP_SUCCESS;
    unsigned int TableLength = 0;
    ASN1_ITEM* Items = NULL;

    // First call will tell us how big our table structure needs to be.
    err = asn1_decode(pCandidateCSRData, // input Data
        (unsigned int)candidateCSRLength, // Length of input Data
        0,    // Flags
        NULL,
        &TableLength);

    if (err != E_ERP_SUCCESS)
    {
        INDEX_ERR(err, 0x0b);
    }

    // TableLength will be variable.
    if (err == E_ERP_SUCCESS)
    {
        Items = os_mem_new_tag(sizeof(ASN1_ITEM) * TableLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, Items, 0x18);
    }

    if (err == E_ERP_SUCCESS)
    {
        err = asn1_decode(pCandidateCSRData, // input Data
            (unsigned int)candidateCSRLength, // Length of input Data
            ASN_RAW_OFFSET,    // Flags
            Items,
            &TableLength);
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x0c);
        }
    }

    if (err == E_ERP_SUCCESS)
    {
        if ((Items[0].tag != ASN_SEQUENCE) ||
            (Items[0].nitems != 3) || // Cert, SigAlg, Sig.
            (Items[1].tag != ASN_SEQUENCE))
        {
            err = E_ERP_ASN1_CONTENT_ERROR;
            INDEX_ERR(err, 0x13);
        }
    }

    // Check Admissions:
    ASN1_ITEM* pAdmissions = NULL;
    if (err == E_ERP_SUCCESS)
    { // Find location of Admissions Extension.   (1 3 36 8 3 3)
        err = asn1_find_object(
            (unsigned char*)&(ID_X509_ADMISSIONS_ANSI_OID[0]), ID_X509_ADMISSIONS_ANSI_OID_LEN,
            &(Items[1]), &pAdmissions);
    }

    if (err == E_ERP_SUCCESS)
    {   // Check that the admissions are correct for 
        err = checkX509Admissions(pAdmissions, keyPair);
    }

    ASN1_ITEM* pPublicKey = NULL;
    if (err == E_ERP_SUCCESS)
    {   // Find and Check the subject public key algorithm
        err = asn1_find_object((unsigned char*)&(ID_EC_PUBLICKEY_ANSI_OID[0]), ID_EC_PUBLICKEY_ANSI_OID_LEN, &(Items[1]), &pPublicKey);
        if (err != E_ERP_SUCCESS)
        {
            err = E_ERP_CERT_BAD_SUBJECT_ALG;
        }
    }

    if (err == E_ERP_SUCCESS)
    {   // Start of public key sequence should be two items before oid_ecPublicKey.
        // Call to find object returns ITEM AFTER the object id...
        pPublicKey -= 3;
        if ((pPublicKey->tag != ASN_SEQUENCE) ||
            (pPublicKey->nitems != 2) ||
            ((pPublicKey + 1)->tag != ASN_SEQUENCE) ||
            ((pPublicKey + 1)->nitems != 2))
        {
            err = E_ERP_CERT_BAD_SUBJECT_ENCODING;
        }
    }
    ASN1_ITEM* pCurveID = NULL;
    if (err == E_ERP_SUCCESS)
    { // Check the curve
        pCurveID = pPublicKey + 3;
        if (pCurveID->tag != ASN_OBJECT_ID)
        {
            err = E_ERP_CERT_BAD_SUBJECT_ENCODING;
        }
        else {
            if (0 == isSupportedCurveID(pCurveID))
            {
                err = E_ERP_CERT_UNSUPPORTED_CURVE;
            }
        }
    }

    size_t newPublicKeyLength = 0;
    unsigned char* pNewPublicKey = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = GetASN1PublicKeyFromBlob(keyPair, &newPublicKeyLength, &pNewPublicKey);
    }

    ASN1_ITEM* pRecurseItem = NULL;
    if (err == E_ERP_SUCCESS)
    {
        size_t existingPublicKeyLength = getEncodedSize(pPublicKey, 1, &pRecurseItem);
        if (existingPublicKeyLength != newPublicKeyLength)
        {
            err = E_ERP_BAD_ANSIX9_62_LENGTH;
        }
    }

    size_t x509ECKeyLength = 0;
    unsigned char* px509ECKeyData = NULL;
    // Set PublicKey Return values the first is the whole c509 public key structure
    if (err == E_ERP_SUCCESS)
    {   // pPublicKey is a SEQUENCE
        px509ECKeyData = pPublicKey->p_data - pPublicKey->raw_off;
        x509ECKeyLength = pPublicKey->len + pPublicKey->raw_off;
        if (x509ECKeyLength != newPublicKeyLength)
        {
            err = E_ERP_BAD_ANSIX9_62_LENGTH;
        }
    }

    if (err == E_ERP_SUCCESS)
    {   // Now actually copy the new public key over the top of the old.
        os_mem_cpy(px509ECKeyData, pNewPublicKey, newPublicKeyLength);
    }

    ASN1_ITEM* pSignatureAlg = NULL;
    if (err == E_ERP_SUCCESS)
    { // Find location of start of Signature.
        static char searchPath[] = { 2,0 };
        err = asn1_find_item(&(Items[0]), &(searchPath[0]), NULL, &pSignatureAlg);
    }
    if (err == E_ERP_SUCCESS)
    {
        if ((pSignatureAlg->tag != ASN_SEQUENCE) ||
            (pSignatureAlg->nitems != 1) ||
            ((pSignatureAlg + 1)->tag != ASN_OBJECT_ID) ||
            ((pSignatureAlg + 1)->len != ID_ECDSA_WITH_SHA256_ANSI_OID_LEN) ||
            (0 != os_mem_cmp((pSignatureAlg + 1)->p_data, &(ID_ECDSA_WITH_SHA256_ANSI_OID[0]), ID_ECDSA_WITH_SHA256_ANSI_OID_LEN)))
        {
            err = E_ERP_CERT_BAD_SIGNATURE_ALG;
        }
    }
    ASN1_ITEM* pSignatureBody = NULL;
    if (err == E_ERP_SUCCESS)
    { // Check the signature public key algorithm
        static char searchPath[] = { 3,0 };
        err = asn1_find_item(&(Items[0]), &(searchPath[0]), NULL, &pSignatureBody);
        if (err != E_ERP_SUCCESS)
        {
            err = E_ERP_CERT_BAD_SIGNATURE_FORMAT;
        }
    }

    // Calculate the SignableData buffer and calculate the Signature
    size_t signatureLength = 0;
    unsigned char* pSignatureData = NULL;
    if (err == E_ERP_SUCCESS)
    {
        unsigned char* pSignableData = &(Items[1].p_data[0]) - Items[1].raw_off;
        size_t signableLength = Items[1].len + Items[1].raw_off;
        err = x509ECDSASign(p_hdl,
                    keyPair,
                    signableLength, pSignableData,
                    &signatureLength, &pSignatureData);
    }

    // Put the signature into the Items List.
    if (err == E_ERP_SUCCESS)
    {   // Pointer arithmetic should work in intervals of sizeof(pointer).
        TableLength = 1 + (pSignatureBody - &(Items[0]));
        pSignatureBody->len = signatureLength;
        pSignatureBody->p_data = pSignatureData;
        pSignatureBody->nitems = 0;
    }

    // We need this extra stp of encoding to a larger buffer because sometimes the Utimaco method 
    //   requires an extra byte of data, but if it does then it does not encode the data to the start 
    //   of the buffer which breaks the code that later frees that buffer.
    size_t encodedLength = 0;
    unsigned char* pEncodedDataBuffer = NULL;
    unsigned char* pEncodedData = NULL;
    if (err == E_ERP_SUCCESS)
    {
        ASN1_ITEM* offEnd = NULL;  // start of recursion level uses NULL.
        encodedLength = getEncodedSize(&(Items[0]), 1, &offEnd) + 4;
        pEncodedDataBuffer = os_mem_new_tag(encodedLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, pEncodedDataBuffer, 0x19);
    }
    if (err == E_ERP_SUCCESS)
    {   // The asn1_encode starts at the end of the buffer, so the start of the encoded data may not be the 
        //   start of the buffer.
        pEncodedData = pEncodedDataBuffer;
        err = asn1_encode(Items, // input Items
            TableLength, // size of item table
            0,    // Flags
            &pEncodedData, // This gets written by method.
            &encodedLength); // Also gets written by method.
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x02);
        }
    }
    if (err == E_ERP_SUCCESS)
    { // Now allocate a new buffer which can have the encoded data at the start.
        *pModifiedCSRLength = encodedLength;
        *ppModifiedCSRData = os_mem_new_tag(encodedLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, *ppModifiedCSRData, 0x1a);
    }
    if (err == E_ERP_SUCCESS)
    {
        os_mem_cpy(*ppModifiedCSRData, pEncodedData, encodedLength);
    }

    // Subsidiary structures in ASN1_ITEMs point to the original data stream.
    FREE_IF_NOT_NULL(Items);
    FREE_IF_NOT_NULL(pNewPublicKey);
    FREE_IF_NOT_NULL(pSignatureData);
    FREE_IF_NOT_NULL(pEncodedDataBuffer);
    if ((err != E_ERP_SUCCESS) && (*ppModifiedCSRData != NULL))
    {
        os_mem_del_set(*ppModifiedCSRData, 0);
        *ppModifiedCSRData = NULL;
        *pModifiedCSRLength = 0;
    }

    return err;
}


// Utility Method to build an ASN public key with idECPublicKey.
// The result is returned in allocated memory that the caller must delete.
// input: curveID object id length and value
// input: X and Y Coordinates for oublic key
// Output: The public key data buffer - must be deleted by caller.
extern unsigned int makeAsn1PublicKey(
    size_t curveIDLen, unsigned char* pCurveID,
    unsigned char* pXCoord, unsigned char* pYCoord,
    size_t* pOutLen, unsigned char** ppPubOut)
{
    //   NONCEAndBlob :: = SEQUENCE{
    //                          SEQUENCE {
    //                              OBJECT_ID,
    //                              OBJECT_ID }
    //                          BIT STRING }
    unsigned int err = E_ERP_SUCCESS;
    unsigned int TableLength = 5;

    ASN1_ITEM* Items = os_mem_new_tag(sizeof(ASN1_ITEM) * TableLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
    CHECK_NOT_NULL(err, Items, 0x1b);
    if (err == E_ERP_SUCCESS)
    {
        err = initASN1Items(Items, TableLength);
    }
    if (err == E_ERP_SUCCESS)
    {
        Items[0].tag = ASN_SEQUENCE;
        Items[0].p_data = NULL;
        Items[0].len = 0;
        Items[0].nitems = 2;

        Items[1].tag = ASN_SEQUENCE;
        Items[1].p_data = NULL;
        Items[1].len = 0;
        Items[1].nitems = 2;
    }
    if (err == E_ERP_SUCCESS)
    {
        Items[2].tag = ASN_OBJECT_ID;
        Items[2].len = ID_EC_PUBLICKEY_ANSI_OID_LEN;
        Items[2].nitems = 0;
        Items[2].p_data = os_mem_new_tag(Items[2].len, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, Items[2].p_data, 0x1c);
    }
    if (err == E_ERP_SUCCESS)
    {
        os_mem_cpy(Items[2].p_data, ID_EC_PUBLICKEY_ANSI_OID, ID_EC_PUBLICKEY_ANSI_OID_LEN);
        Items[3].tag = ASN_OBJECT_ID;
        Items[3].len = curveIDLen;
        Items[3].nitems = 0;
        Items[3].p_data = os_mem_new_tag(Items[3].len, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, Items[3].p_data, 0x1d);
    }

    // At the moment both our supported curves are 256 bit.
    // If this changes then we will need to derive coordinate size from curve ID.   
    const size_t coordSize = EC_COORD_SIZE / 8;
    if (err == E_ERP_SUCCESS)
    {
        os_mem_cpy(Items[3].p_data, pCurveID,curveIDLen);
        Items[4].tag = ASN_BIT_STRING;
        Items[4].nitems = 0;
        Items[4].len = 2+ (coordSize * 2);
        Items[4].p_data = os_mem_new_tag(Items[4].len, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, Items[4].p_data, 0x1e);
    }
    if (err == E_ERP_SUCCESS)
    {
        Items[4].p_data[0] = 0x00; // Number of remainder bits at end of bit string.
        Items[4].p_data[1] = 0x04; // Tag for public key.
        os_mem_cpy(&(Items[4].p_data[2]), pXCoord, coordSize);
        os_mem_cpy(&(Items[4].p_data[2 + coordSize]), pYCoord, coordSize);
    }
    if (err == E_ERP_SUCCESS)
    {
        ASN1_ITEM* offEnd = NULL;   // Not used here, but it is required 
                        // by the recursive sub calls in the length measurement.
        *pOutLen = getEncodedSize(Items, 1, &offEnd);
        *ppPubOut = os_mem_new_tag(*pOutLen, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, *ppPubOut, 0x1f);
    }
    if (err == E_ERP_SUCCESS)
    {
        // Build the ASN1 DER buffer for retuirning to the caller.
            err = asn1_encode(Items, // input Items
            (unsigned int)5, // size of item table
            0,    // Flags
            ppPubOut, // This gets written by method
            pOutLen);
            if (err != E_ERP_SUCCESS)
            {
                INDEX_ERR(err, 0x03);
            }
    }

    if (Items != NULL)
    {
        deleteASNItemList(Items, TableLength);
    }
    return err;
}

// Utility Method to build an ASN Output containing a BackupBlob.
// The result is automatically packed into an HSM response using cds_alloc_answ
// input: Commands handle for the command
// input: the BackupBlob to be encoded.
extern unsigned int makeBackupBlobOutput(
    T_CMDS_HANDLE* p_hdl,
    BackupBlob_t* pBackupBlob)
{
    //   BackupBlob :: = BackupBlob ::= SEQUENCE {
    //                  generation INTEGER,
    //                  domain OCTET STRING(5), -- assigns the blob generation to a domain, one of "DVLP", "TEST", "PROD"
    //                  mbkName OCTET STRING(8), --Utimaco 8 byte name of Master Backup Key used to generate Blob.
    //                  mbkKCV OCTET STRING(16), --MDC2 hash as KCV for Master backup Key used to creat BUBlob.
    //                  blobKeyKCV OCTET STRING(32), --SHA256 hash as KCV of Blob Key contained in BUBlob
    //                  blobEncData OCTET STRING -- Encrypted Data of BUBlob }
    unsigned int err = E_ERP_SUCCESS;
    unsigned int TableLength = 7;

    ASN1_ITEM* Items = os_mem_new_tag(sizeof(ASN1_ITEM) * TableLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
    CHECK_NOT_NULL(err, Items, 0x3b);
    if (err == E_ERP_SUCCESS)
    {
        err = initASN1Items(Items, TableLength);
    }
    if (err == E_ERP_SUCCESS)
    {
        Items[0].tag = ASN_SEQUENCE;
        Items[0].p_data = NULL;
        Items[0].len = 0;
        Items[0].nitems = 6;
    }
    if (err == E_ERP_SUCCESS)
    { // Set up the return value with the actual generation used.
        err = setASNIntegerItem(&Items[1], pBackupBlob->Generation);
    }
    if (err == E_ERP_SUCCESS)
    {
        Items[2].tag = ASN_OCTET_STRING;
        Items[2].len = BLOB_DOMAIN_LEN;
        Items[2].nitems = 0;
        Items[2].p_data = os_mem_new_tag(Items[2].len, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, Items[2].p_data, 0x3c)
    }
    if (err == E_ERP_SUCCESS)
    {
        memcpy(Items[2].p_data, pBackupBlob->Domain, BLOB_DOMAIN_LEN);
        Items[3].tag = ASN_OCTET_STRING;
        Items[3].len = MBK_NAME_LEN;
        Items[3].nitems = 0;
        Items[3].p_data = os_mem_new_tag(Items[3].len, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, Items[3].p_data, 0x3d)
    }
    if (err == E_ERP_SUCCESS)
    {
        memcpy(Items[3].p_data, pBackupBlob->MBKName, MBK_NAME_LEN);
        Items[4].tag = ASN_OCTET_STRING;
        Items[4].len = MBK_KCV_LEN;
        Items[4].nitems = 0;
        Items[4].p_data = os_mem_new_tag(Items[4].len, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, Items[4].p_data, 0x3d)
    }
    if (err == E_ERP_SUCCESS)
    {
        memcpy(Items[4].p_data, pBackupBlob->MBKKCV, MBK_KCV_LEN);
        Items[5].tag = ASN_OCTET_STRING;
        Items[5].len = SHA_256_LEN/8;
        Items[5].nitems = 0;
        Items[5].p_data = os_mem_new_tag(Items[5].len, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, Items[5].p_data, 0x3e)
    }
    if (err == E_ERP_SUCCESS)
    {
        memcpy(Items[5].p_data, pBackupBlob->BlobKeyKCV, SHA_256_LEN/8);
        Items[6].tag = ASN_OCTET_STRING;
        Items[6].len = pBackupBlob->encDataLength;
        Items[6].nitems = 0;
        Items[6].p_data = os_mem_new_tag(Items[6].len, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, Items[6].p_data, 0x3f)
    }
    if (err == E_ERP_SUCCESS)
    {
        os_mem_cpy(Items[6].p_data, pBackupBlob->encData, pBackupBlob->encDataLength);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = buildOutputBuffer(p_hdl,
            Items, // input Items
            TableLength);
    }

    if (Items != NULL)
    {
        deleteASNItemList(Items, TableLength);
    }
    return err;
}

// The returned Backup Blobs will be in newly allocated buffers and must be freed by the caller. 
extern unsigned int parseBackupBlobInputRequest(
    int l_cmd,
    unsigned char* p_cmd,
    // All Parameters from here are output:
    BackupBlob_t** ppBackupBlob)
{
    //   BackupBlob :: = BackupBlob ::= SEQUENCE {
   //                  generation INTEGER,
    //                  domain OCTET STRING(5), -- assigns the blob generation to a domain, one of "DVLP", "TEST", "PROD"
    //                  mbkName OCTET STRING(8), --Utimaco 8 byte name of Master Backup Key used to generate Blob.
    //                  mbkKCV OCTET STRING(16), --MDC2 hash as KCV for Master backup Key used to creat BUBlob.
    //                  blobKeyKCV OCTET STRING(32), --SHA256 hash as KCV of Blob Key contained in BUBlob
    //                  blobEncData OCTET STRING -- Encrypted Data of BUBlob }
    unsigned int err = E_ERP_SUCCESS;
    unsigned int TableLength = 8;
    ASN1_ITEM* Items = NULL;

    err = decodeASNList(l_cmd, p_cmd, &Items, TableLength, 1);

    if (err == E_ERP_SUCCESS)
    {
        err = getASN1BackupBlob(&Items[1], ppBackupBlob);
    }

    // Subsidiary structures in Itemlist from der_decode point into the original buffer 
    //   and should not be deleted here.   i.e. we have taken a copy of what we want to keep.
    FREE_IF_NOT_NULL(Items);
    return err;
}
