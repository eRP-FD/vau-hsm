/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021
 * (C) Copyright IBM Corp. 2021
 * SPDX-License-Identifier: CC BY-NC-ND 3.0 DE
 **************************************************************************************************/

#include <cryptoserversdk/stype.h>
#include <cryptoserversdk/memutil.h>
#include <cryptoserversdk/os_mem.h>
#include <cryptoserversdk/asn1.h>
#include <cryptoserversdk/cmds.h>
#include <cryptoserversdk/aes.h>
#include <cryptoserversdk/eca.h>
#include <cryptoserversdk/ecdsa.h>
#include <cryptoserversdk/hash.h>

#include "ERP_CryptoUtils.h"
#include "ERP_MDLError.h"
#include "ERP_ASNUtils.h"

MDL_CONST unsigned char NIST_P256_ANSI_OID[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
MDL_CONST size_t NIST_P256_ANSI_OID_LEN = sizeof(NIST_P256_ANSI_OID);
MDL_CONST unsigned char BRAINPOOL_P256R1_ANSI_OID[] = { 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07 };
MDL_CONST size_t BRAINPOOL_P256R1_ANSI_OID_LEN = sizeof(BRAINPOOL_P256R1_ANSI_OID);
MDL_CONST unsigned char ID_EC_PUBLICKEY_ANSI_OID[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
MDL_CONST size_t ID_EC_PUBLICKEY_ANSI_OID_LEN = sizeof(ID_EC_PUBLICKEY_ANSI_OID);
MDL_CONST unsigned char ID_ECDSA_WITH_SHA256_ANSI_OID[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
MDL_CONST size_t ID_ECDSA_WITH_SHA256_ANSI_OID_LEN = sizeof(ID_ECDSA_WITH_SHA256_ANSI_OID);
MDL_CONST unsigned char ID_X509_ADMISSIONS_ANSI_OID[] = { 0x2B, 0x24, 0x08, 0x03, 0x03 };
MDL_CONST size_t ID_X509_ADMISSIONS_ANSI_OID_LEN = sizeof(ID_X509_ADMISSIONS_ANSI_OID);
MDL_CONST unsigned char ID_ERP_VAU_ANSI_OID[] = { 0x2A, 0x82, 0x14, 0x00, 0x4C, 0x04, 0x82, 0x03 }; // 1.2.276.0.76.4.259
MDL_CONST size_t ID_ERP_VAU_ANSI_OID_LEN = sizeof(ID_ERP_VAU_ANSI_OID);
MDL_CONST unsigned char ID_EREZEPT_ANSI_OID[] = { 0x2A, 0x82, 0x14, 0x00, 0x4C, 0x04, 0x82, 0x02 }; // 1.2.276.0.76.4.258
MDL_CONST size_t ID_EREZEPT_ANSI_OID_LEN = sizeof(ID_EREZEPT_ANSI_OID);
MDL_CONST unsigned char ID_BASIC_CONSTRAINTS_OID[] = { 0x55, 0x1D, 0x13 }; // (2 5 29 19)
MDL_CONST size_t ID_BASIC_CONSTRAINTS_OID_LEN = sizeof(ID_BASIC_CONSTRAINTS_OID);
MDL_CONST size_t BASIC_CONSTRAINTS_LEN = 5; // Number of bytes in basic constraints octet string.

unsigned int AES_BLOCK(AES_KEY* p_key_buff,
    size_t blockSize,
    unsigned char* p_data_in,
    unsigned char* p_data_out);

char HexChar(unsigned char nibble)
{
    char retVal = '\0';
    switch (nibble)
    {
    case 0: retVal = '0'; break;
    case 1: retVal = '1'; break;
    case 2: retVal = '2'; break;
    case 3: retVal = '3'; break;
    case 4: retVal = '4'; break;
    case 5: retVal = '5'; break;
    case 6: retVal = '6'; break;
    case 7: retVal = '7'; break;
    case 8: retVal = '8'; break;
    case 9: retVal = '9'; break;
    case 10: retVal = 'a'; break;
    case 11: retVal = 'b'; break;
    case 12: retVal = 'c'; break;
    case 13: retVal = 'd'; break;
    case 14: retVal = 'e'; break;
    case 15: retVal = 'f'; break;
    default: break;
    }
    return retVal;
}
int _Bin2Hex(unsigned char* binIn, unsigned int inLen, char* hexOut, unsigned int bufLen)
{
    int err = E_ERP_SUCCESS;
    if (bufLen < ((((unsigned int)inLen) * 2) + 1))
    {
        err = E_ERP_INTERNAL_BUFFER_ERROR;
    }
    if (err == E_ERP_SUCCESS)
    {
        unsigned int i;
        for (i = 0; i < inLen; i++)
        {
            hexOut[i * 2] = HexChar(binIn[i] >> 4);
            hexOut[(i * 2) + 1] = HexChar(binIn[i] & 0x0F);
        }
    }
    return err;
}

// Utility method to return >0 if the curve OBJECT IDENTIFIER in item is one that we support.
extern int isSupportedCurveID(ASN1_ITEM* pItem)
{   // Currently only support NIST Prime256 or BrainpoolP256R1
    int retVal = 0;
    if (pItem->len == NIST_P256_ANSI_OID_LEN)
    {
        if (0 == os_mem_cmp(NIST_P256_ANSI_OID, &(pItem->p_data[0]), NIST_P256_ANSI_OID_LEN))
        {
            retVal = 1;
        }
    }
    else {
        if (pItem->len == BRAINPOOL_P256R1_ANSI_OID_LEN)
        {
            if (0 == os_mem_cmp(BRAINPOOL_P256R1_ANSI_OID, &(pItem->p_data[0]), BRAINPOOL_P256R1_ANSI_OID_LEN))
            {
                retVal = 1;
            }
        }
    }
    return retVal;
}

// This functions treats the key data as an AES 256 key and encrypts the value 32bytes*0x00 and returns the first 
//   four bytes as a big endian integer in pChecksum.
// If pKeyData or pChecksum are NULL then an E_ERP_INTERNAL_BUFFER_ERROR is returned.
// This method may also return the error codes of the Utimaco AES module.
// The return value is an error or E_ERP_SUCCESS
unsigned int GenerateAES256CheckSum(unsigned char* pKeyData, unsigned long* pCheckSum)
{
    unsigned int err = E_ERP_SUCCESS;
    if ((pKeyData == NULL) || (pCheckSum == NULL))
    {
        err = E_ERP_INTERNAL_BUFFER_ERROR;
    } else 
    {
        *pCheckSum = 0;   // Don't leave it uninitialised.
    }
    // 32 bytes of zero data used as plain text for KCV
    unsigned char zeroData[] = { 
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
    // An array to hold the raw encrypted block.
    unsigned char encZero[32] = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
    AES_KEY* pEncKey = NULL;
    if (err == E_ERP_SUCCESS)
    {
        pEncKey = aes_pkey(AES_256_LEN/8, pKeyData, AES_ENC, NULL);
        if (pEncKey == NULL)
        {
            err = E_ERP_AES_KEY_ERROR;
            INDEX_ERR(err, 0x11);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        err = AES_BLOCK(pEncKey, AES_256_LEN / 8, &(zeroData[0]), &(encZero[0]));
    }
    if (err == E_ERP_SUCCESS)
    {
        err = readBELongInt(&(encZero[0]), pCheckSum);
    }
    if (pEncKey != NULL)
    {
        os_mem_del_set(pEncKey,0);
    }
    return err;
}

extern unsigned int _DoHMAC(
    T_CMDS_HANDLE* p_hdl,
    unsigned char* pKDK,
    unsigned char* InputData,
    size_t InputLength,
    unsigned char* pOut,
    size_t* pOutputLength) //in: size of buffer must be greater than hash length, out: size written.
{
    int err = E_ERP_SUCCESS;
    err = hash_hmac(
        HASH_SHA256,                    // int algorithm/MODE,
        32,                                // unsigned int l_key,
        (unsigned char*)pKDK,            // unsigned char *p_key,
        InputLength,                    // unsigned int l_data,
        InputData,                        // unsigned char *p_data,
        NULL,                            // HASH_HMAC_INFO - only used for HASH_CONT
        pOut,                            // pointer to get the output hash.
        (unsigned int *)pOutputLength);    // Integer to hold length of output data)
    return err;
}

// This function will produce a one way variation of the NONCE value using a variation parameter to
//   enforce a purpose restriction on the NONCE.
// The variation function is out = HMAC_SHA256(nonceIn,variation data) where nonceIn is used as the HMAC key.
// This function does not do error checking on its' input - it is assumed that the caller did that.
extern unsigned int varyNONCE(const char* variation, unsigned char* nonceDataIn, unsigned char* variedNONCEOut)
{
    int err = E_ERP_SUCCESS;
    size_t outputLength = NONCE_LEN;
    err = hash_hmac(
        HASH_SHA256,                    // int algorithm/MODE,
        32,                                // unsigned int l_key,
        (unsigned char*)nonceDataIn,            // unsigned char *p_key,
        strlen(variation),                    // unsigned int l_data,
        (char *)variation,                        // unsigned char *p_data,
        NULL,                            // HASH_HMAC_INFO - only used for HASH_CONT
        variedNONCEOut,                            // pointer to get the output hash.
        &outputLength);    // Integer to hold length of output data)
    return err;
}

extern unsigned int _DoHKDF(
    T_CMDS_HANDLE* p_hdl,
    unsigned char* pKDK,
    size_t inputLength,
    unsigned char* inputData,
    size_t outputLength,
    unsigned char* pOut) //in: size of buffer must be greater than hash length, out: size written.
{
    unsigned int err = E_ERP_SUCCESS;
    unsigned char allZero[] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
    size_t prkLen = SHA_256_LEN/8;
    unsigned char pPrkData[32] = { 0 };
    err = _DoHMAC(p_hdl, allZero, pKDK, SHA_256_LEN / 8, &(pPrkData[0]), &prkLen);
    size_t outLen = 0;
    unsigned char T[SHA_256_LEN / 8] = { 0 };
    unsigned char* inData = NULL;
    unsigned int N = outputLength / (SHA_256_LEN / 8);
    if (err == E_ERP_SUCCESS)
    {
        if (N * (SHA_256_LEN / 8) < outputLength)
        {
            N++;
        }
        // input length + one hash length + one byte tag + one byte extra to be sure.
        inData = os_mem_new_tag(inputLength + (SHA_256_LEN / 8) + 2, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, inData, 0x22);
    }
    if (err == E_ERP_SUCCESS)
    {
        unsigned char i;
        for (i = 0; (i < N) && (err == E_ERP_SUCCESS); i++)
        { // outLen on first iteration is 0.
            os_mem_cpy(&(inData[0]), &(T[0]), outLen);
            os_mem_cpy(&(inData[outLen]), &(inputData[0]), inputLength);
            inData[outLen + inputLength] = i+1;
            size_t newOutLen = SHA_256_LEN / 8;
            err = _DoHMAC(p_hdl, pPrkData, &(inData[0]), outLen + inputLength + 1, &(T[0]), &newOutLen);
            outLen = newOutLen;
            if (err == E_ERP_SUCCESS)
            {
                os_mem_cpy(&(pOut[(SHA_256_LEN / 8) * i]), &(T[0]), SHA_256_LEN / 8);
            }
        }
    }
    FREE_IF_NOT_NULL(inData);
    return err;
}
// Allocates and fills an ECIES or ECSIG KeyPair Blob with a newly generated ECIES KeyPair.
// The time is set to the current HSM time.
// The memory for the Blob is allocated by this method and must be freed by os_mem_del_set.
unsigned int getECKeyPairBlob(T_CMDS_HANDLE* p_hdl, ClearBlob_t** ppOutBlob, ERPBlobType_t blobType)
{
    unsigned int err = E_ERP_SUCCESS;

    ECDP* pCurve = NULL;
    // oid for brainpoolP256r1 : 1.3.36.3.3.2.8.1.1.7
    // Badly Documented - curve is not to be deleted...
    err = eca_dp_find_name("brainpoolP256r1", &pCurve);
    if (pCurve == NULL)
    {
        err = E_ERP_NO_ECC_DOMAIN_PARAMETERS;
    }
    if (err != E_ERP_SUCCESS)
    { // Index here in case curve is not null but err was set by eca_dp_find_name.
        INDEX_ERR(err, 0x01);
    }
    // 20 bytes should be more than enough to encode any oid.
    unsigned int oidLen = 0;
    unsigned char* pOidData = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = eca_dp_get_info(pCurve, ECA_DP_OID, &oidLen, &pOidData);
        if (err != E_ERP_SUCCESS)
        { 
            INDEX_ERR(err, 0x02);
        }
    }
    unsigned int privKeyLen = 0;
    unsigned char* privKeyData = NULL;
    unsigned int pubKeyLen = 0;
    unsigned char* pubKeyData = NULL;
    if (err == E_ERP_SUCCESS)
    { // Note - output data here is the caller's responsibility to free.
        err = ecdsa_keygen(pCurve,
            ECDSA_MODE_REAL_RND | ECDSA_FMT_UNCOMP,
            &privKeyLen,
            &privKeyData,
            &pubKeyLen,
            &pubKeyData);
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x01);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        if ((privKeyLen == 0) ||
            (pubKeyLen == 0) ||
            (pubKeyData == NULL) ||
            (privKeyData == NULL))
        {
            err = E_ERP_FAILED_ECC_KEYPAIR_GENERATION;
        }
    }
    // There is no way to interrogate the length of the required buffer, so just use a large one and treat an overflow as an error,
    unsigned int outLen = ERP_BIG_BUFFER;
    unsigned char outData[ERP_BIG_BUFFER] = "";
    if (err == E_ERP_SUCCESS)
    {
        err = ecdsa_key_encode(privKeyLen, privKeyData,
            pubKeyLen, pubKeyData,
            oidLen, pOidData,
            NULL,
            &outLen,
            &(outData[0]));
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x02);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        *ppOutBlob = os_mem_new_tag(sizeof(ClearBlob_t) + sizeof(ECKeyPairBlob_t) + outLen, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, *ppOutBlob, 0x23)
    }
    if (err == E_ERP_SUCCESS)
    { // blobType can be ECIES or ECSIG.
        (*ppOutBlob)->BlobType = blobType;
        err = fillGeneric(*ppOutBlob);
    }
    if (err == E_ERP_SUCCESS)
    {
        (*ppOutBlob)->DataLength = sizeof(ECKeyPairBlob_t) + outLen;
        ECKeyPairBlob_t* pKeyBlob = (ECKeyPairBlob_t*)&((*ppOutBlob)->Data[0]);
        pKeyBlob->keyLength = outLen;
        os_mem_cpy(pKeyBlob->keyData, outData, outLen);
    }

    // Do not Delete pCurve or pOidData;
    FREE_IF_NOT_NULL(pubKeyData);
    FREE_IF_NOT_NULL(privKeyData);
    return err;
}

// Method to return a Private key for a VAUSIG EC KeyPair.
// Memory returned in *ppPrivateKeyData must be released by the caller.
// input: VAUSIG Keypair Blob containing the VAU ID.FD.SIG Key.
// output: The private key in binary PKCS#8 (RFC/5208/5915/5480) format.
unsigned int GetPKCS8PrivateKey(T_CMDS_HANDLE* p_hdl,
    const ClearBlob_t* keyPair,
    size_t* pPrivateKeyLen, unsigned char** ppPrivateKeyData)
{
    unsigned int err = E_ERP_SUCCESS;
    if (keyPair->BlobType != VAUSIG_KeyPair)
    { // May be VAUSIG_KeyPair
        err = E_ERP_WRONG_BLOB_TYPE;
        INDEX_ERR(err, 0x03);
    }
    ECKeyPairBlob_t* keyBlob = (ECKeyPairBlob_t*)keyPair->Data;

    // Data stored in keyBlob->KeyData is RFC5915 encoded private key.
    // We just need to add a static wrapper to this to get the PKCS 
    // We parse the key structure mainly to get the curve IDs.
    size_t privKeyLength = 0;
    unsigned char* pPrivKeyData = NULL;
    size_t pubKeyLength = 0;
    unsigned char* pPubKeyData = NULL;
    size_t oidLength = 0;
    unsigned char* pOidData = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = ecdsa_key_decode(keyBlob->keyLength,
            keyBlob->keyData,
            NULL, // void* p_rfu,
            &privKeyLength, // unsigned int* p_l_x,
            &pPrivKeyData, // unsigned char** pp_x,
            &pubKeyLength, // unsigned int* p_l_y,
            &pPubKeyData, // unsigned char** pp_y,
            &oidLength, // unsigned int* p_l_oid,
            &pOidData); // unsigned char* pp_oid)
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x03);
        }
    }

    // If we ever move to supporting more than one curve then we should think about some refactoring of the 
    //    curve operations.
    if ((oidLength != BRAINPOOL_P256R1_ANSI_OID_LEN) || 
        (0 != os_mem_cmp(BRAINPOOL_P256R1_ANSI_OID, &(pOidData[0]), BRAINPOOL_P256R1_ANSI_OID_LEN)))
    {
        err = E_ERP_CERT_UNSUPPORTED_CURVE;
    }

    // Static PKCS8 header.   Constant for our choice of curve.
    unsigned char PKCSHeader[] = { 0x30, 0x81, 0x95
            , 0x02, 0x01, 0x00
            , 0x30, 0x14
        // Note that object ID ECPublicKey means "EC public key cryptography", not "this is an EC public key."...
            , 0x06, 0x07, 0x2a, 0x86, 0x48 , 0xce, 0x3d, 0x02, 0x01 // 1.2.840.10045.2.1 - ECPublicKey
            , 0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07 // 1.3.36.3.3.2.8.1.1.7 // BrainpoolP256R1
            , 0x04, 0x7a };
    size_t pkcs8HeaderLength = sizeof(PKCSHeader);
    if (err == E_ERP_SUCCESS)
    {
        *pPrivateKeyLen = pkcs8HeaderLength + keyBlob->keyLength;
        *ppPrivateKeyData = os_mem_new((*pPrivateKeyLen) + 1, OS_MEM_TYPE_SECURE);
        CHECK_NOT_NULL(err,*ppPrivateKeyData, 0x24)
    }
    if (err == E_ERP_SUCCESS)
    {
        os_mem_cpy(&((*ppPrivateKeyData)[0]), &(PKCSHeader[0]), pkcs8HeaderLength);
        os_mem_cpy(&((*ppPrivateKeyData)[pkcs8HeaderLength]), &(keyBlob->keyData[0]),keyBlob->keyLength);
    }
    if ((err != E_ERP_SUCCESS) && (*ppPrivateKeyData != NULL))
    {
        os_mem_del_set(*ppPrivateKeyData, 0);
        *ppPrivateKeyData = NULL;
        *pPrivateKeyLen = 0;
    }
    return err;

}

// input: clear ECIES or ECSIG Keypair Blob containing the keypair to be extracted.
// output: public and private keys + domain params in format required by HSM internally.
// output: Object ID for the ECC Curve.
// Pointers returned are to within the original key blob object.
extern unsigned int ECKeysFromBlob(
    const ClearBlob_t* blob,
    size_t* pPrivKeyLength, unsigned char** ppPrivKeyData,
    size_t* pPubKeyLength, unsigned char** ppPubKeyData,
    size_t * pOidLength, unsigned char** ppOidData,
    ECDP ** ppDomainParams ) // Read only output.
{
    unsigned int err = E_ERP_SUCCESS;
    if ((blob->BlobType != ECIES_KeyPair) && (blob->BlobType != VAUSIG_KeyPair))
    { // May be ECIES_KeyPair or ECSIG_KeyPair
        err = E_ERP_WRONG_BLOB_TYPE;
        INDEX_ERR(err, 0x04);
    }
    ECKeyPairBlob_t * keyBlob = (ECKeyPairBlob_t*)blob->Data;

    if (err == E_ERP_SUCCESS)
    {
        err = ecdsa_key_decode(keyBlob->keyLength,
            keyBlob->keyData,
            NULL, // void* p_rfu,
            pPrivKeyLength, // unsigned int* p_l_x,
            ppPrivKeyData, // unsigned char** pp_x,
            pPubKeyLength, // unsigned int* p_l_y,
            ppPubKeyData, // unsigned char** pp_y,
            pOidLength, // unsigned int* p_l_oid,
            // Readonly output!
            ppOidData); // unsigned char* pp_oid)
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x04);
        }
    }
    if (err == E_ERP_SUCCESS)
    { // Get the Domain Params to match the curve OID.
        err = eca_dp_find_oid(*pOidLength, *ppOidData, ppDomainParams);
        if (err != E_ERP_SUCCESS)
        { 
            INDEX_ERR(err, 0x03);
        }
    }
    return err;
}

// Method to return an externl RFC 5480 / ANSI X9.62 encoding of an ECIES public key.
// Memory returned in pKeyData must be released by the caller.
// output: EC Public key in RFC 5480 / ANSI X9.62 format.
extern unsigned int GetASN1PublicKeyFromBlob(const ClearBlob_t* blob,
    unsigned int* pKeyLength,
    unsigned char** ppKeyData)
{
    unsigned int err = E_ERP_SUCCESS;

    size_t privKeyLength = 0;
    unsigned char* pPrivKeyData = NULL;
    size_t pubKeyLength = 0;
    unsigned char* pPubKeyData = NULL;
    ECDP* pDomainParams = NULL;
    size_t oidLength = 0;
    unsigned char* pOidData = NULL;
    err = ECKeysFromBlob(blob,
        &privKeyLength, &pPrivKeyData,
        &pubKeyLength, &pPubKeyData,
        &oidLength, &pOidData,
        &pDomainParams);

    // Exchange format is:
    //        ECCPublicKey ::= SEQUENCE { -- actually same as x.509
    //            SEQUENCE{
    //            algID OBJECT IDENTIFIER, --must be id_ecPublicKey 1,2,840,10045,2,1
    //            curveID OBJECT IDENTIFIER },
    //            value BIT STRING  }-- curve - dependent encoding of ECC public key.
    //        

    ASN1_ITEM* pItemTable = NULL;
    if (err == E_ERP_SUCCESS)
    {
        pItemTable = os_mem_new_tag(5 * sizeof(ASN1_ITEM), OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, pItemTable, 0x25);
    }
    unsigned char* pBitString = NULL;
    if (err == E_ERP_SUCCESS)
    {
        pItemTable->tag = ASN_SEQUENCE;
        pItemTable->nitems = 2;
        (pItemTable + 1)->tag = ASN_SEQUENCE;
        (pItemTable + 1)->nitems = 2;
        (pItemTable + 2)->tag = ASN_OBJECT_ID;
        // OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1)
        // Can't use const because of Utimaco API.
        (pItemTable + 2)->len = ID_EC_PUBLICKEY_ANSI_OID_LEN;
        (pItemTable + 2)->p_data =  &(((unsigned char*)ID_EC_PUBLICKEY_ANSI_OID)[0]); /* cast from const */
        (pItemTable + 3)->tag = ASN_OBJECT_ID;
        (pItemTable + 3)->p_data = pOidData;
        (pItemTable + 3)->len = oidLength;
        (pItemTable + 4)->tag = ASN_BIT_STRING;
        // One extra byte for BIT STRING leading zero for unused bits.
        (pItemTable + 4)->len = pubKeyLength + 1;
        pBitString = os_mem_new_tag(pubKeyLength + 1, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, pBitString, 0x26);
    }
    if (err == E_ERP_SUCCESS)
    {
        (pItemTable + 4)->p_data = pBitString;
        pBitString[0] = 0;
        os_mem_cpy(&(pBitString[1]), pPubKeyData, pubKeyLength);
    }
    if (err == E_ERP_SUCCESS)
    {
        ASN1_ITEM* offEnd = NULL;   // Not used here, but it is required 
                                // by the recursive sub calls in the length measurement.
        *pKeyLength = getEncodedSize(pItemTable, 1, &offEnd);
        *ppKeyData = os_mem_new_tag(*pKeyLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err,*ppKeyData, 0x27)
        // Build the ASN1 DER buffer for retuirning to the caller.
        if (err == E_ERP_SUCCESS)
        { // First call works out size of output buffer.
            err = asn1_encode(pItemTable, // input Items
                5, // size of item table
                0,    // Flags
                ppKeyData, // This gets written by method.
                pKeyLength);
            if (err != E_ERP_SUCCESS)
            {
                INDEX_ERR(err, 0x04);
            }
        }
    }

    FREE_IF_NOT_NULL(pBitString);
    FREE_IF_NOT_NULL(pItemTable);
    return err;
}

// Method to return an AES 128 Key following the ERP VAU ECDH process.
// Memory returned in *ppAESKeyData must be released by the caller.
// input: ECIES Keypair Blob containing the VAU ECDH Key.
// input: Client public key in ANSI X9.62 format.
// output: 16 bytes of AES128 key value.
unsigned int DoVAUECIES(T_CMDS_HANDLE* p_hdl,
    const ClearBlob_t* keyPair,
    size_t clientPubKeyLength, unsigned char* pClientPubKeyData,
    size_t* pAESKeyLen, unsigned char** ppAESKeyData)
{
    unsigned int err = E_ERP_SUCCESS;
    *ppAESKeyData = NULL;   // Make sure in case caller passed in a bad pointer.
    if (keyPair->BlobType != ECIES_KeyPair)
    {
        err = E_ERP_WRONG_BLOB_TYPE;
        INDEX_ERR(err, 0x05);
    }
    // Convert the client public key to useful internal format.
    unsigned int oidClientLength = 0;
    unsigned char* pOidClientData = NULL;
    size_t clientCoordinateSize = 0;
    unsigned char* pClientXCoord = NULL;
    unsigned char* pClientYCoord = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = parseASN1PublicKey(clientPubKeyLength, pClientPubKeyData,
            &oidClientLength, &pOidClientData,
            &clientCoordinateSize,
            &pClientXCoord, &pClientYCoord);
    }

    // Extract our key pair from the blob.
    ECKeyPairBlob_t* keyBlob = (ECKeyPairBlob_t*)keyPair->Data;
    size_t privKeyLength = 0;
    unsigned char* pPrivKeyData = NULL;
    size_t pubKeyLength = 0;
    unsigned char* pPubKeyData = NULL;
    size_t oidLength = 0;
    unsigned char* pOidData = NULL;
    ECDP* pDomainParams = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = ecdsa_key_decode(keyBlob->keyLength,
            keyBlob->keyData,
            NULL, // void* p_rfu,
            &privKeyLength, // unsigned int* p_l_x,
            &pPrivKeyData, // unsigned char** pp_x,
            &pubKeyLength, // unsigned int* p_l_y,
            &pPubKeyData, // unsigned char** pp_y,
            &oidLength, // unsigned int* p_l_oid,
            // Readonly output!
            &pOidData); // unsigned char* pp_oid)
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x05);
        }
    }
    if (err == E_ERP_SUCCESS)
    { // Get the Domain Params to match the curve OID.
        err = eca_dp_find_oid(oidLength, pOidData, &pDomainParams);
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x04);
        }
    }
    // Both keysets must use the same curve.
    if (err == E_ERP_SUCCESS)
    {
        if (oidClientLength != oidLength)
        {
            err = E_ERP_ECIES_CURVE_MISMATCH;
            INDEX_ERR(err, 0x01);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        if (0 != os_mem_cmp(&(pOidData[0]), &(pOidClientData[0]), oidLength))
        {
            err = E_ERP_ECIES_CURVE_MISMATCH;
            INDEX_ERR(err, 0x02);
        }
    }
    // Do the ECDH.   From the Gematik Spec description of the client side:
    // gemSpec_Krypt_V2.18.0 Übergreifende Spezifikation Seite 95 von 118
    // 1. Client MUSS ein ephemeres ECDH-Schlüsselpaar erzeugen und mit diesem und 
    //    dem VAU - Schlüssel aus A_20160 - ein ECDH gemäß[NIST - 800 - 56 - A] durchführen.
    //    Das somit erzeugte gemeinsame Geheimnis ist Grundlage für die folgende Schlüsselableitung.
    // 2. Als Schlüsselableitungsfunktion MUSS er die HKDF nach[RFC - 5869] auf Basis von SHA - 256 verwenden.
    // 3. Dabei MUSS er den Ableitungsvektor "ecies-vau-transport" verwenden, d.h.in
    //    der Formulierung von[RFC - 5869] info = "ecies-vau-transport" .
    // 4. Er MUSS mit dieser Schlüsselableitung einen AES - 128 - Bit Content - Encryption Key 
    //    für die Verwendung von AES / GCM abgeleiten
    *pAESKeyLen = AES_128_LEN/8;
    if (err == E_ERP_SUCCESS)
    { // Output buffer for hkdf must be at least one hash block long.
        *ppAESKeyData = os_mem_new_tag(SHA_256_LEN + 1, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, *ppAESKeyData, 0x28);
    }
    unsigned char derivationVector[] = "ecies-vau-transport";

    if (err == E_ERP_SUCCESS)
    {
        // Format required for ecdsa_dh_ex is 0x04<xCoord><yCoord>
        // We can take this from the ANSI key since we know it will start at pXCoord-1 and be 1 + 2*coordinateSize
        // It would be cleaner to make a new buffer here and copy the data in, but it is unnecessary processing.
//        unsigned char GemPrivate[] = { 0x5b, 0xbb, 0xa3, 0x4d, 0x47, 0x50, 0x2b, 0xd5, 0x88, 0xed, 0x68, 0x0d, 0xfa,
//            0x23, 0x09, 0xca, 0x37, 0x5e, 0xb7, 0xa3, 0x5d, 0xdb, 0xbd, 0x67, 0xcc, 0x7f, 0x8b,  0x6b, 0x68, 0x7a, 0x1c, 0x1d };
        unsigned char secret[(SHA_256_LEN / 8) +1];
        err = ecdsa_dh(pDomainParams,
            (2 * clientCoordinateSize) + 1, pClientXCoord - 1,
            privKeyLength, pPrivKeyData,
            0, NULL,
            ECDSA_KDF_RAW,
            SHA_256_LEN/8,
            &(secret[0]));
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x06);
        }
        if (err == E_ERP_SUCCESS)
        {
            err = _DoHKDF(p_hdl,
                &(secret[0]),
                strlen(derivationVector),
                &(derivationVector[0]),
                *pAESKeyLen,
                *ppAESKeyData);
            if (err != E_ERP_SUCCESS)
            {
                INDEX_ERR(err, 0x05);
            }
        }
    }
    if ((err != E_ERP_SUCCESS) && (*ppAESKeyData != NULL))
    {
        os_mem_del_set(*ppAESKeyData, 0);
        *ppAESKeyData = NULL;
    }
    return err;
}

extern unsigned int verifyECDSAWithSRValSHA256Signature(T_CMDS_HANDLE* p_hdl,
    size_t signableLength, unsigned char* pSignableData,    // The signed data
    size_t sigRLength, unsigned char* pSigRData,   // Signature R value
    size_t sigSLength, unsigned char* pSigSData,   // Signature S value
    size_t ECKeyLength, unsigned char* pECKeyData)      // public key of signer in RFC 5480 format.
{
    unsigned int err = E_ERP_SUCCESS;
    size_t curveOIDLen = 0;
    size_t coordinateSize = 0;
    unsigned char* pCurveOID = NULL;
    unsigned char* pXCoord = NULL;
    unsigned char* pYCoord = NULL;

    err = parseASN1PublicKey(
        ECKeyLength, pECKeyData,
        &curveOIDLen, &pCurveOID,
        &coordinateSize,
        &pXCoord, &pYCoord);
    ECDP* pCurve = NULL;
    if (err == E_ERP_SUCCESS)
    {
        err = eca_dp_find_oid(curveOIDLen, pCurveOID, &pCurve);
        INDEX_ERR(err, 0x01);
    }
    unsigned int hashSize = SHA_256_LEN / 8;
    unsigned char hashValue[SHA_256_LEN / 8];
    // Do the sha256 hash.
    if (err == E_ERP_SUCCESS)
    {
        err = hash_hash(HASH_SHA256,
            signableLength, pSignableData,
            NULL,
            &(hashValue[0]),
            &hashSize);
    }

    if (err == E_ERP_SUCCESS)
    { // Format required for ecdsa_verify is 0x04<xCoord><yCoord>
        // We can take this from the ANSI key since we know it will start at pXCoord-1 and be 1 + 2*coordinateSize
        // It would be cleaner to make a new buffer here and copy the data in, but it is unnecessary processing.
        // err == E_ERP_SUCCESS from this call is a good signature check.
        // err = 0xb09c0007 is an ecdsa signature verification failed.
        err = ecdsa_verify(pCurve,
            1+(2*coordinateSize), pXCoord-1,
            NULL,
            hashSize, &(hashValue[0]),
            sigRLength,pSigRData,
            sigSLength, pSigSData);
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x07);
        }
    }
    return err;
}

// Calculates a signature over the signable data using the private key of the keypair.
// The compressed raw format for the signature (defined by Utimaco)is R and the S concatenated.
// after a successful call, the caller must delete *ppRawSigData when finished with it.
extern unsigned int signECDSAWithRawSigSHA256Signature(T_CMDS_HANDLE* p_hdl,
    size_t signableLength, unsigned char* pSignableData,    // The signed data
    size_t* pRawSigLength, unsigned char** ppRawSigData,   // output: Signature Raw value - r | s
    ClearBlob_t* keyPair)      // Keypair of Signer..
{
    unsigned int err = E_ERP_SUCCESS;
    size_t privKeyLength = 0;
    unsigned char* pPrivKeyData = NULL;
    size_t pubKeyLength = 0;
    unsigned char* pPubKeyData = NULL;
    size_t oidLength = 0;
    unsigned char* pOidData;
    ECDP* pCurve;

    err = ECKeysFromBlob( keyPair,
        &privKeyLength, &pPrivKeyData,
        &pubKeyLength, &pPubKeyData,
        &oidLength, &pOidData,
        &pCurve); // Read only output.

    size_t hashSize = SHA_256_LEN / 8;
    unsigned char hashValue[SHA_256_LEN / 8];
    // Do the sha256 hash.
    if (err == E_ERP_SUCCESS)
    {
        err = hash_hash(HASH_SHA256,
            signableLength, pSignableData,
            NULL,
            &(hashValue[0]),
            &hashSize);
    }

     if (err == E_ERP_SUCCESS)
    {
        *pRawSigLength = (2 * eca_int_get_blen(pCurve)) + 1;
        *ppRawSigData = os_mem_new_tag(*pRawSigLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, *ppRawSigData, 0x29);
    }
    if (err == E_ERP_SUCCESS)
    { // Format required for ecdsa_sign is 0x04<xCoord><yCoord>
        // We can take this from the ANSI key since we know it will start at pXCoord-1 and be 1 + 2*coordinateSize
        // It would be cleaner to make a new buffer here and copy the data in, but it is unnecessary processing.
        err = ecdsa_sign(pCurve,
            ECDSA_MODE_PSEUDO_RND,
            privKeyLength, pPrivKeyData,
            hashSize, &(hashValue[0]),
            pRawSigLength, *ppRawSigData);
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x08);
        }
    }
    if ((err != E_ERP_SUCCESS) && (*ppRawSigData != NULL))
    {
        *pRawSigLength = 0;
        os_mem_del_set(*ppRawSigData, 0);
        *ppRawSigData = NULL;
    }
    return err;
}

extern unsigned int verifyECDSAWithANSISHA256Signature(T_CMDS_HANDLE* p_hdl,
    size_t signableLength, unsigned char* pSignableData,    // The signed data
    size_t signatureLength, unsigned char* pSignatureData,   // Signature Body, as in x509 certificate
    size_t ECKeyLength, unsigned char* pECKeyData)       // public key of signer in RFC 5480 format.
{
    unsigned int err = E_ERP_SUCCESS;

    unsigned int len_r = 0;
    unsigned char* p_r = NULL;
    unsigned int len_s = 0;
    unsigned char* p_s = NULL;
    // Convert the signature to the HSM format.
    if (err == E_ERP_SUCCESS)
    {
        err = ecdsa_sign_decode(
            signatureLength, pSignatureData,
            &len_r, &p_r,
            &len_s, &p_s);
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x09);
        }
    }

    if (err == E_ERP_SUCCESS)
    { 
        err = verifyECDSAWithSRValSHA256Signature(p_hdl,
            signableLength, pSignableData,
            len_r, p_r,
            len_s, p_s,
            ECKeyLength, pECKeyData);
    }

    return err;
}

extern unsigned int verifyECDSAWithTPMTSHA256Signature(T_CMDS_HANDLE* p_hdl,
    size_t signableLength, unsigned char* pSignableData,    // The signed data
    size_t signatureLength, unsigned char* pSignatureData,   // Signature Body, TPM format
    size_t ECKeyLength, unsigned char* pECKeyData)       // public key of signer in RFC 5480 format.
{
    unsigned int err = E_ERP_SUCCESS;

    unsigned int len_r = EC_COORD_SIZE / 8;
    unsigned char* p_r = NULL;
    unsigned int len_s = EC_COORD_SIZE / 8;
    unsigned char* p_s = NULL;
    // Convert the signature to the HSM format.
    if (err == E_ERP_SUCCESS)
    {
        err = parseTPMT_Signature(signatureLength, pSignatureData, &p_r, &p_s);
    }

    if (err == E_ERP_SUCCESS)
    {
        err = verifyECDSAWithSRValSHA256Signature(p_hdl,
            signableLength, pSignableData,
            len_r, p_r,
            len_s, p_s,
            ECKeyLength, pECKeyData);
    }
    return err;
}

// Check whether a TPM name hash matches the public key data
// input: public key length and data in ANSI X9.62   LEngth must be 0x5b.
// input: key name including 2 byte hash algorithm identifier - must be 0x000b
unsigned int CheckTPMNameHash(T_CMDS_HANDLE* p_hdl, size_t pubLength, unsigned char* pubData, unsigned char* nameAK)
{
    unsigned int err = E_ERP_SUCCESS;

    if (pubLength != 0x78)
    {
        err = E_ERP_BAD_TPMT_PUBLIC_LENGTH;
    }
    // First check hash algorithm - must be SHA_256
    if (err == E_ERP_SUCCESS)
    {
        if ((nameAK[0] != 0) || (nameAK[1] != 0x0b))
        {
            err = E_ERP_BAD_TPM_NAME_ALGORITHM;
        }
    }
    unsigned char hashOut[SHA_256_LEN / 8];
    size_t hashLen = SHA_256_LEN / 8;
    if (err == E_ERP_SUCCESS)
    {
        err = hash_hash(HASH_SHA256, pubLength, pubData, NULL, &(hashOut[0]), &hashLen);
    }
    if (err == E_ERP_SUCCESS)
    {
        if (hashLen != (SHA_256_LEN / 8))
        {
            err = E_ERP_INTERNAL_BUFFER_ERROR;
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        if (0 != os_mem_cmp(&(nameAK[2]), &(hashOut[0]), SHA_256_LEN / 8))
        {
            err = E_ERP_TPM_NAME_MISMATCH;
        }
    }
    return err;
}

// Convert a TPMT_PUBLIC public key into an ANSI X9.62 format public key including parsing for correctness.
// input: public key length and data in TPMT_PUBLIC
// input: key name including 2 byte hash algorithm identifier - must be 0x000b
// output: public key length and data in ANSI X9.62 Must be freed by caller.
// output: x509 OID for Public key curve.   Must be freed by caller.
unsigned int ConvertTPMT_PUBLICToANSI(T_CMDS_HANDLE* p_hdl,
    size_t pubLength, unsigned char* pubData,
    size_t* pOutLen, unsigned char** ppPubOut,
    size_t* pCurveOIDLen, unsigned char** ppCurveOID)
{
    // ("int bn..." comments are from IBM Attestation server code for validating an AK.)
    unsigned int err = E_ERP_SUCCESS;

    // Sample TPMT_PUBLIC:
    //        Defined in TPM2.0 sepcification Part 2 - Data Structures. 
    //--------------
    //  00 23 // TPMI_ALG_PUBLIC - TPM_ALG_ECC
    //    00 0B // TPMI_ALG_HASH - name hash algorithm - SHA_256
    //    00 05 04 72 // TPMA_OBJECT - object attributes - uint32 - flags
    //    // TPMI_DIGEST - optional policy.
    //    00 20 E5 87 C1 1A B5 0F 9D 87 30 F7 21 E3 FE A4 2B 46 C0 45 5B 24 6F 96 AE E8 5D 18 EB 3B E6 4D 66 6A
    //    // TPMU_PUBLIC_PARMS - algorithm or structure details, e.g. curve ID.
    //    // Because of TPMI_ALG_PUBLIC this will be a TPMS_ECC_PARMS
    //        TPMT_SYM_DEF_OBJECT - TPM_ALG_NULL - 0x0010
    //     TPMT_ECC_SCHEME - TPM_ALG_ECDSA - 0x0018   TPM_ALG_SHA256 - 0x000B
    //        TPMI_ECC_CURVE
    //        TPMT_KDF_SCHEME - TPM_ALG_NULL - 0x0010
    //    00 10 00 18    00 0B 00 03    00 10
    //     // TPMU_PUBLIC_ID
    //    // XCoord
    //    00 20 1C C6 75 88 66 B0 B4 48 BC AB E8 65 1B 0F CE 75 0E 92 79 17 9A 52 CD 08 CA 58 FE EB C4 9F 70 38
    //    // YCoord
    //    00 20 33 2D 1C A2 75 1D 59 60 47 BA 1D C2 50 6A E5 C8 A4 A4 77 36 FF A3 DC F0 36 44 3E 5F 71 DB 92 51
    if (pubLength != 0x78)
    {
        err = E_ERP_BAD_TPMT_PUBLIC_LENGTH;
    }
    size_t offset = 0;
    // First check the data structure tag TPMI_ALG_ECC 0x0023 - don't accept rsa.
    //        int b1 = ((attestPub->type != TPM_ALG_RSA) && (attestPub->type != TPM_ALG_ECC));
    if (err == E_ERP_SUCCESS)
    {
        if ((pubData[0] != 0x00) ||
            (pubData[1] != 0x23))
        {
            err = E_ERP_BAD_TPMT_PUBLIC_ALGORITHM;
        }
        offset += 2;
    }
    // First check hash algorithm - must be SHA_256 - 0x000B
    //        int b2 = (attestPub->nameAlg != TPM_ALG_SHA256);
    if (err == E_ERP_SUCCESS)
    {
        if ((pubData[offset] != 0x00) ||
            (pubData[offset + 1] != 0x0b))
        {
            err = E_ERP_BAD_TPM_NAME_ALGORITHM;
        }
        offset += 2;
    }
    if (err == E_ERP_SUCCESS)
    {
        // TPMA_OBJECT
        // Validate the attributes for an attestation key.
        err = validateAKAttributes(&(pubData[offset]));
        offset += 4;
    }
    if (err == E_ERP_SUCCESS)
    {
        // TPMI_DIGEST - optional policy - compulsory for us.
        if ((pubData[offset] != 0x00) ||
            (pubData[offset + 1] != 0x20))
        { // Bad length
            err = E_ERP_BAD_TPMT_PUBLIC_FORMAT;
        }
        // TODO:   ERP-6201 check if there are any sensible checks we can do to the policy?
        offset += 0x22;
    }
    if (err == E_ERP_SUCCESS)
    {
        // TPMU_PUBLIC_PARMS - TPMS_ECC_PARMS - don't accept RSA
        // The values below are taken with permission from the source code of the IBM Attestation 
        // Server demo code written by Ken Goldman of IBM.   #L https://sourceforge.net/projects/ibmtpm20acs/
//        if (attestPub->type == TPM_ALG_ECC) {
//            b9 = attestPub->parameters.eccDetail.scheme.details.ecdsa.hashAlg != TPM_ALG_SHA256;
//            b10 = attestPub->parameters.eccDetail.scheme.scheme != TPM_ALG_ECDSA;
//            b11 = attestPub->parameters.eccDetail.curveID != TPM_ECC_NIST_P256;
//            b12 = attestPub->parameters.eccDetail.kdf.scheme != TPM_ALG_NULL;
        if ((pubData[offset] != 0x00) ||
            (pubData[offset + 1] != 0x10) || // TPM_ALG_NULL
            (pubData[offset + 2] != 0x00) ||
            (pubData[offset + 3] != 0x18) || // TPM_ALG_ECDSA
            (pubData[offset + 4] != 0x00) ||
            (pubData[offset + 5] != 0x0B) || // TPM_ALG_SHA256
            (pubData[offset + 6] != 0x00) || // depends on curve
            (pubData[offset + 8] != 0x00) ||
            (pubData[offset + 9] != 0x10))    // TPM_ALG_NULL
        {
            err = E_ERP_BAD_TPMT_PUBLIC_ALGORITHM;
        }
    }
    if (err == E_ERP_SUCCESS)
    { // Accept NISTP256 (0x03) or Brainpool P256 (0x30)
        switch (pubData[offset + 7])
        {
        case (unsigned char)TPM_ECC_NIST_P256: 
            *pCurveOIDLen = NIST_P256_ANSI_OID_LEN;
            *ppCurveOID = os_mem_new_tag(NIST_P256_ANSI_OID_LEN, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
            CHECK_NOT_NULL(err, ppCurveOID, 0x2a);
            if (err == E_ERP_SUCCESS)
            {
                os_mem_cpy(*ppCurveOID, NIST_P256_ANSI_OID, NIST_P256_ANSI_OID_LEN);
            }
            break;
        case (unsigned char)TPM_ECC_BP_P256_R1:
            *pCurveOIDLen = BRAINPOOL_P256R1_ANSI_OID_LEN;
            *ppCurveOID = os_mem_new_tag(BRAINPOOL_P256R1_ANSI_OID_LEN, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
            CHECK_NOT_NULL(err, ppCurveOID, 0x2b);
            if (err == E_ERP_SUCCESS)
            {
                os_mem_cpy(*ppCurveOID, BRAINPOOL_P256R1_ANSI_OID, BRAINPOOL_P256R1_ANSI_OID_LEN);
            }
            break;
        default:
            err = E_ERP_TPM_UNSUPPORTED_CURVE;
            break;
        }
        offset += 10;
    }
    if (err == E_ERP_SUCCESS)
    { // XCoordinate with length prefix
        if ((pubData[offset] != 0x00) ||
            (pubData[offset + 1] != 0x20))
        { // Bad length
            err = E_ERP_BAD_TPMT_PUBLIC_FORMAT;
        }
        offset += 2;
    }
    unsigned char* xCoord = NULL;
    if (err == E_ERP_SUCCESS)
    { // XCoord
        xCoord = &(pubData[offset]);
        offset += 0x20;
        if ((pubData[offset] != 0x00) ||
            (pubData[offset + 1] != 0x20))
        { // Bad length
            err = E_ERP_BAD_TPMT_PUBLIC_FORMAT;
        }
        offset += 2;
    }
    unsigned char* yCoord = NULL;
    if (err == E_ERP_SUCCESS)
    { // Y Coord
        yCoord = &(pubData[offset]);
        offset += 0x20;
    }
    if (err == E_ERP_SUCCESS)
    {
        err = makeAsn1PublicKey(*pCurveOIDLen, *ppCurveOID,
            xCoord, yCoord,
            pOutLen, ppPubOut);
    }
    return err;
}

// This method checks whether a buffer containing bit flags has the bit at position bitFlagindex
//   counting from LSB, set.   If set then the method returns 0, otherwise it returns 1.
// flagBufferSize is the size of the flag word in bytes.
// LSB is bitFlagIndex == 0
// If there is an error then it will return -1
int checkBitFlagSet(unsigned char* flagBuffer, size_t flagBufferSize, unsigned int bitFlagIndex)
{
    if ((bitFlagIndex/8) >= flagBufferSize)
    {
        return -1;
    }
    if (((flagBuffer[flagBufferSize - ((bitFlagIndex / 8) + 1)] >> (bitFlagIndex % 8)) & 0x01) > 0)
    {
        return 0;
    }
    return 1;
}
// Method to check that the attributes of a TPMT_PUBLIC key are suitable for use as an 
//   attestation Key.
unsigned int validateAKAttributes(unsigned char attributes[4])
{
    unsigned int err = E_ERP_SUCCESS;
    // Need to be careful with bit endianness and checking the bitmap.

    // If checkBitFlagSet returns -1 it will result in the same error code anyway, so we don't
    //   explicitly check whether 1 or -1.
    if ((checkBitFlagSet(&(attributes[0]), 4, TPMA_OBJECT_FIXEDTPM) != 0) ||
        (checkBitFlagSet(&(attributes[0]), 4, TPMA_OBJECT_FIXEDPARENT) != 0) ||
        (checkBitFlagSet(&(attributes[0]), 4, TPMA_OBJECT_SENSITIVEDATAORIGIN) != 0) ||
        (checkBitFlagSet(&(attributes[0]), 4, TPMA_OBJECT_SIGN) != 0) ||
        (checkBitFlagSet(&(attributes[0]), 4, TPMA_OBJECT_RESTRICTED) != 0) ||
        (checkBitFlagSet(&(attributes[0]), 4, TPMA_OBJECT_DECRYPT) == 0)) // Note NOT DECRPYT
    {
        err = E_ERP_BAD_TPMT_PUBLIC_ATTRIBUTES;
    }
    return err;
 }

// This method will verify all aspects of a TPM Quote except the signature and 
//   the contents of the PCR set and hash.   The NONCE, PCR Set and hash are returned.
// The AKName in the quote is checked against the one passed in.
// Output pointers refer to original input data.   Do not delete.
unsigned int verifyTPMQuote(T_CMDS_HANDLE* p_hdl,
    unsigned char* pQuoteData, size_t quoteLength,
    unsigned char* pAKName,
    unsigned char** ppQualifiedSignerName,
    unsigned char** ppNONCE,
    unsigned char** ppPCRFlags,
    unsigned char** ppPCRHash)
{

    unsigned int err = E_ERP_SUCCESS;
    if (quoteLength != 0x91)
    {
        err = E_ERP_BAD_QUOTE_LENGTH;
    }
    size_t offset = 0;
    // Sample parsing for a simulated TPM Quote:
    // ------------------------------------------
    //    TPM Magic Number
    //        FF 54 43 47 // TPM_GENERATED_VALUE - Always 0xff"TCG"
//        80 18 // TPMI_ST_ATTEST - TPMI_ST_ATTEST_QUOTE 0x8018
    if (err == E_ERP_SUCCESS)
    {
        if ((pQuoteData[offset] != 0xff) ||
            (pQuoteData[offset + 1] != 0x54) ||
            (pQuoteData[offset + 2] != 0x43) ||
            (pQuoteData[offset + 3] != 0x47) ||
            (pQuoteData[offset + 4] != 0x80) ||
            (pQuoteData[offset + 5] != 0x18))
        {
            err = E_ERP_BAD_QUOTE_HEADER;
        }
        offset += 6;
    }
    //        Signing key qualified name TPM2B_NAME
    //        00 22 // size 2 bytes
    //        // TPMU_NAME - 
    //        00 0B // TPMI_ALG_HASH - TPM_ALG_SHA256 - 0x000B
    //        9A 9D 5C 78 E6 F2 9B 6A DB 8D 9F C0 16 4E B3 C4 92 0A 7C C3 FB 74 82 59 E7 06 74 40 FB E4 8E 3C
    if (err == E_ERP_SUCCESS)
    {
        if ((pQuoteData[offset] != 0x00) ||
            (pQuoteData[offset + 1] != 0x22))
        {
            err = E_ERP_BAD_QUOTE_FORMAT;
        }
        offset += 2;
    }
    if (err == E_ERP_SUCCESS)
    {
        if ((pQuoteData[offset] != 0x00) ||
            (pQuoteData[offset + 1] != 0x0B))
        {
            err = E_ERP_BAD_TPM_NAME_ALGORITHM;
        }
        offset += 2;
    }
    if (err == E_ERP_SUCCESS)
    {
        // TODO:   ERP-6201 - workout how and if we can use the qualified name for anything.
        *ppQualifiedSignerName = &(pQuoteData[offset]);
        offset += TPM_NAME_LEN; // This actually jumps us past the initial 0x00 0x20 of the following NONCE information.
    }
    //    Qualifying Data(NONCE) - comes from me.
    //        00 20 35 6F 9C 3A 24 8D 82 A9 76 9D 27 EF 6F 08 A3 C5 4D FE 40 82 FC C9 C1 04 71 80 F3 6B 40 F3 97 B2
    if (err == E_ERP_SUCCESS)
    {
        *ppNONCE = &(pQuoteData[offset]);
        offset += NONCE_LEN / 8;   // The Initial 2 bytes were already bypassed by the previous step.
    }
    //    TPMS_CLOCK_INFO
    //        00 00 00 00 01 F1 4D 6B // uint64 clock.
    //        00 00 00 09 // UINT32 reset count
    //        00 00 00 00 // unint32 Restart Count
    //        01 // Safe - TPMI_YES_NO - TRUE = 1
    //        20 19 10 23 00 16 36 36 // uint64 Firmware Version
    if (err == E_ERP_SUCCESS)
    {
        offset += 8; // Clock - nothing sensible to check here.
        offset += 4; // Reset Count - nothing sensible to check here.
        offset += 4; // Restart Count - nothing sensible to check here.
        offset += 1; // Safe = TRUE?   Is this relevant?
        offset += 8; // TPM Firmware version, also nothing to check here.
    }
    //  TPMS_QUOTE_INFO(
    //    TPML_PCR_SELECTION
    //        00 00 00 01 // Count - we only accept one digest.
    if (err == E_ERP_SUCCESS)
    {
        if ((pQuoteData[offset] != 0x00)||
            (pQuoteData[offset + 1] != 0x00) ||
            (pQuoteData[offset + 2] != 0x00) ||
            (pQuoteData[offset + 3] != 0x01))
        {
            err = E_ERP_BAD_QUOTE_FORMAT;
        }
        offset += 4;
    }
//        // TPMS_PCR_SELECTION
//        00 0B // TPMI_ALG_HASH - TPM_ALG_SHA256 - 0x000B
    if (err == E_ERP_SUCCESS)
    {
        if ((pQuoteData[offset] != 0x00) ||
            (pQuoteData[offset + 1] != 0x0B))
        {
            err = E_ERP_BAD_QUOTE_HASH_FORMAT;
        }
        offset += 2;
    }
    //        03 // Size of select array
    if (err == E_ERP_SUCCESS)
    { // Selection array is always 3 bytes.
        if (pQuoteData[offset] != 0x03)
        {
            err = E_ERP_BAD_QUOTE_FORMAT;
        }
        offset += 1;
    }
    //        01 00 00 // Bitmap of selected PCRs.    Example is for PCR 0 only.
    if (err == E_ERP_SUCCESS)
    {
        *ppPCRFlags = &(pQuoteData[offset]);
        offset += 3;
    }
    //    Digest of hashes in quote.
    //        00 20 66 68 7A AD F8 62 BD 77 6C 8F C1 8B 8E 9F 8E 20 08 97 14 85 6E E2 33 B3 90 2A 59 1D 0D 5F 29 25
    if (err == E_ERP_SUCCESS)
    {
        if ((pQuoteData[offset] != 0x00) ||
            (pQuoteData[offset + 1] != 0x20))
        {
            err = E_ERP_BAD_QUOTE_FORMAT;
        }
        offset += 2;
        *ppPCRHash = &(pQuoteData[offset]);
    }
// Alternative example for more PCRs:
//        00 00 00 01
//        00 0B
//        03
//        0F 00 00 // Flags of PCRs. <--- Here there are more bits set.   i.e.PCRs 0,1,2,3.
//        00 20 38 72 3A 2E 5E 8A 17 AA 79 50 DC 00 82 09 94 4E 89 8F 69 A7 BD 10 A2 3C 83 9D 34 1E 93 5F D5 CA

    return err;
}

// Utility method to parse a TPMT_SIGNATURE structure and extract the R and S values from it.
// It enforces an algorithm of TPMI_ALG_ECDSA and a hash of SHA256.
// output: *ppSigR and *ppSigS are pointers into the original buffer.
unsigned int parseTPMT_Signature(size_t sigLength, unsigned char* pSig, unsigned char ** ppSigR, unsigned char **ppSigS)
{
// Sample TPMS Signature of correct format.
//  quotesig: TPMT_SIGNATURE
//    // TPMI_ALG_ECDSA 2 bytes 0018
//    00 18
//    // TPMS_SIGNATURE_ECC since the above is ECDSA...
//    // TPMI_ALG_SHA256
//    00 0B
//    // signatureR
//    00 20 BE B8 40 0C B0 BD 6B 60 C0 0E 77 7D 7C 7A F5 E3 07 C4 30 1E 65 CE 1B D9 A1 93 A9 C5 1A AA 57 F8
//    // signatureS
//    00 20 91 E3 57 2E 6D CD E1 EF 32 7B EE E4 DD 46 C0 6D 51 68 BF 54 BA C9 5D 02 06 CF 69 4B 49 AA E6 EC
    unsigned int err = E_ERP_SUCCESS;
    const size_t expectedLength = 0x48;
    if (sigLength != expectedLength)
    {
        err = E_ERP_BAD_TPMT_SIGNATURE_FORMAT;
    }
    size_t offset = 0;
    if (err == E_ERP_SUCCESS)
    { // first part is all constant.
        if ((pSig[offset] != 0x00) ||
            (pSig[offset + 1] != 0x18) ||
            (pSig[offset + 2] != 0x00) ||
            (pSig[offset + 3] != 0x0B) ||
            (pSig[offset + 4] != 0x00) ||
            (pSig[offset + 5] != 0x20))
        {
            err = E_ERP_BAD_TPMT_SIGNATURE_FORMAT;
        }
        offset += 6;
    }
    if (err == E_ERP_SUCCESS)
    {
        *ppSigR = pSig + offset;
        offset += EC_COORD_SIZE/8;
        if ((pSig[offset] != 0x00) ||
            (pSig[offset + 1] != 0x20))
        {
            err = E_ERP_BAD_TPMT_SIGNATURE_FORMAT;
        }
        offset += 2;
    }
    if (err == E_ERP_SUCCESS)
    {
        *ppSigS = pSig + offset;
        offset += EC_COORD_SIZE / 8; // Should take us to end of data.   (This line left in for future parsing to be added below, someday.)
    }
    return err;
}
// Writes a big endian long (32 bit) integer to a buffer - works on any endian machine.
int writeBELongInt(unsigned char* buffer, unsigned long input)
{
    // Yes, this could be more efficiently coded.
    buffer[3] = (unsigned char)(input);
    buffer[2] = (unsigned char)(input >>= 8);
    buffer[1] = (unsigned char)(input >>= 8);
    buffer[0] = (unsigned char)(input >>= 8);
    return 0;
}

// Reads a big endian long (32 bit) integer to a buffer - works on any endian machine.
int readBELongInt(unsigned char* buffer, unsigned long* output)
{
    // Yes, this could be more efficiently coded.
    *output = buffer[3];
    *output += buffer[2] * 0x100;
    *output += buffer[1] * 0x10000;
    *output += buffer[0] * 0x1000000;
    return 0;
}

unsigned int DoKDFa(T_CMDS_HANDLE* p_hdl, 
    const char* label,
    const unsigned char* key, size_t keyLength,
    const unsigned char* inData, size_t inDataLength,
    unsigned int outputKeyBits,
    unsigned char* pOutputData, size_t* pOutputLength)
{
    unsigned int err = E_ERP_SUCCESS; 
    // Do KDF to get symmetric key
    unsigned long Counter = 1;
    size_t labelLength = strlen(label);
    int offset = 0;
    unsigned char* pHMACInput = os_mem_new_tag((sizeof(unsigned long)*2) + inDataLength + labelLength + 1, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
    CHECK_NOT_NULL(err, pHMACInput, 0x2c);
    if (err == E_ERP_SUCCESS)
    {
        writeBELongInt(pHMACInput + offset, Counter);
        offset += 4;
        // Copy this with a terminating null...   To match SW TPM code.
        os_mem_cpy(pHMACInput + offset, label, labelLength + 1);
        offset += labelLength + 1;
        if (inDataLength > 0)
        {
            os_mem_cpy(pHMACInput + offset, inData, inDataLength);
            offset += inDataLength;
        }
        writeBELongInt(pHMACInput + offset, outputKeyBits);
        offset += 4;
        err = _DoHMAC(p_hdl, (unsigned char *)key, pHMACInput, offset, pOutputData, pOutputLength);
    }
    FREE_IF_NOT_NULL(pHMACInput);
    return err;
}

unsigned int AES_BLOCK(AES_KEY* p_key_buff,
    size_t blockSize,
    unsigned char* p_data_in,
    unsigned char* p_data_out)
{
    unsigned int err =  aes_ecb(p_key_buff, AES_ENC, blockSize, p_data_in, p_data_out);
    INDEX_ERR(err, 0x0e);
    return err;
}

// AES full block CFB chaining.
unsigned int AES_CFB_BLOCK(AES_KEY* p_key_buff,
    size_t blockSize,
    unsigned char* p_iv_in,
    size_t len,
    unsigned char* p_data_in,
    unsigned char* p_data_out)
{
    unsigned int err = E_ERP_SUCCESS;

    unsigned int numBlocks = len / blockSize;
    if (len % blockSize > 0)
    {
        numBlocks++;
    }
    unsigned char IVData[(AES_256_LEN / 8) * 2] = { 0 };
    if (p_iv_in != NULL)
    { 
        os_mem_cpy(&(IVData[0]), p_iv_in, blockSize);
    }
    else {
        os_mem_set(&(IVData[0]), 0, (AES_256_LEN / 8) * 2);
    }
    unsigned int i;
    for (i = 0; (i < numBlocks) && (err == E_ERP_SUCCESS) ; i++)
    {
        err = AES_BLOCK(p_key_buff,  blockSize, &(IVData[0]), &(IVData[0]));
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x0f);
        }
        if (err == E_ERP_SUCCESS)
        {
            // XOR input with result.
            size_t blockStart = i * blockSize;
            size_t j;
            for (j = 0; ((j < blockSize) && ((blockStart + j) < len)); j++)
            {
                IVData[j] ^= p_data_in[blockStart + j];
                p_data_out[blockStart + j] = IVData[j];
            }
        }
    }

    return err;
}

unsigned int DoKDFe(T_CMDS_HANDLE* p_hdl, 
    const char* label, // Input: "IDENTITY", "STORAGE" or "INTEGRITY"
    const unsigned char* Z_ECDHSharedSecret, size_t Z_ECDHSharedSecretLength, // Input: Buffer and length for Z, the ECDH-derived  X coordinate
    unsigned char * xEphem, // input: X affine coordinate of ephemeral public key
    unsigned char * xEKPub, // input: X affine coordinate of EK public key.
    size_t coordSize, // input: Size of a point coordinate in bytes.
    unsigned int KeyBits, // input: The size (in bits) of the desired key.
    unsigned char* pOutputData, size_t* pOutputLength) // Buffer and Length for output from KDF.
{
    unsigned int err = E_ERP_SUCCESS;
    unsigned long Counter = 1;
    size_t labelLength = strlen(label);
    unsigned char * pHMACInput = os_mem_new_tag(sizeof(unsigned long) + (coordSize*3) + labelLength + 1, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
    CHECK_NOT_NULL(err, pHMACInput, 0x2d);
    
    int offset = 0;
    if (err == E_ERP_SUCCESS)
    {
        writeBELongInt(pHMACInput + offset, Counter);
        offset += 4;
        os_mem_cpy(pHMACInput + offset, Z_ECDHSharedSecret, Z_ECDHSharedSecretLength);
        offset += Z_ECDHSharedSecretLength;
        // Copy the Lable with a terminating null...   To match SW TPM code.
        os_mem_cpy(pHMACInput + offset, label, labelLength + 1);
        offset += labelLength + 1;
        os_mem_cpy(pHMACInput + offset, xEphem, coordSize);
        offset += coordSize;
        os_mem_cpy(pHMACInput + offset, xEKPub, coordSize);
        offset += coordSize;
        HASH_INFO info;
        err = hash_hash(HASH_SHA256,
            offset, pHMACInput,
            &info,
            pOutputData, (unsigned int *)pOutputLength);
    }

    FREE_IF_NOT_NULL(pHMACInput);
    return err;
}

// Method to calculate the TPM credential challenge.   The challenge Data is passed in in plaintext and 
//    the credential and secret data is calculated for the TPM to be able to decrypt it.
// input: clear response blob containing an AKChallenge with the plaintext credential
// input: clear trusted EK Certificate Blob containing the EK public key.
// input: AK Name hash for the AK Key to be attested.
// input: AK Public key in ANSI X9.62 format.
// *** Credential and secret if allocated by this method must be deleted by the caller. ***
//
// Annoyingly this method uses the name "secret" twice.   Once for the buffer that is returned to the TPM and 
//   once for the ECDH shared secret.   They are two different entities!
extern unsigned int makeAKChallenge(T_CMDS_HANDLE* p_hdl,
    const ClearBlob_t* responseBlob,
    const ClearBlob_t* pEKCertBlob,
    const size_t AKPubLen, const unsigned char* pAKPub,
    const unsigned char* pAKName, // Length is always SHA_256_LEN + 2 bytes.
    size_t* pCredentialLength, unsigned char** ppCredentialData,
    size_t* pSecretLength, unsigned char** ppSecretData)
{
    unsigned int err = E_ERP_SUCCESS;

    // Extract EK Public Key in HSM useable form.
    KnownEKBlob_t* pEKBlob = (KnownEKBlob_t*)&(pEKCertBlob->Data[0]);
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
    unsigned int pBIsCA = 0;
    if (err == E_ERP_SUCCESS)
    {
        err = parsex509ECCertificate(
            pEKBlob->CertificateLength, pEKBlob->CertificateData,
            &EKSignableLength, &pEKSignableData,
            &EKSignatureLength, &pEKSignatureData,
            &EKx509ECKeyLength, &pEKx509ECKeyData,
            &EKECPointLength, &pEKECPointData,
            &EKCurveIDLen, &pEKCurveID,
            &pBIsCA);
    }
    // Get Ephemeral public key X and Y affine
    // Format of pubKeyData is 0x04 - 0x20 byte X, 0x20 byte Y
    unsigned char* pEKPubX = NULL;
    if (err == E_ERP_SUCCESS)
    {
        pEKPubX = &(pEKECPointData[0x1]);
    }

    // AK Public key in TPMT_PUBLIC has already been formally checked in caller method, including 
    // Relation between AK Public and AKName.

    // Generate ephemeral ECC Keypair.
    unsigned int privKeyLen = 0;
    unsigned char* privKeyData = NULL;
    unsigned int pubKeyLen = 0;
    unsigned char* pubKeyData = NULL;
    ECDP* pCurve = NULL;
    if (err == E_ERP_SUCCESS)
    { // Note - output data here is the caller's responsibility to free.
        // oid for brainpoolP256r1 : 1.3.36.3.3.2.8.1.1.7
        // Badly Documented - curve is not to be deleted...
        err = eca_dp_find_oid(EKCurveIDLen, pEKCurveID, &pCurve);
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x05);
        }
    }
    if (err == E_ERP_SUCCESS)
    {
        err = ecdsa_keygen(pCurve,
            ECDSA_MODE_REAL_RND | ECDSA_FMT_UNCOMP,
            &privKeyLen,
            &privKeyData,
            &pubKeyLen,
            &pubKeyData);
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x0a);
        }
    }
    // Get Ephemeral public key X and Y affine
    // Format of pubKeyData is 0x04 - 0x20 byte X, 0x20 byte Y
    unsigned char* ephX = NULL;
    unsigned char* ephY = NULL;
    if (err == E_ERP_SUCCESS)
    {
        ephX = &(pubKeyData[0x1]);
        ephY = &(pubKeyData[(EC_COORD_SIZE/8) + 0x1]);
    }
    // Marshal Ephemeral key to secret buffer.   (Not the ECDH Shared secret)
    // 00 44 - 00 20 - 0x20 bytes X binary - 00 20 - 0x20 bytes Y binary.
    if (err == E_ERP_SUCCESS)
    {
        *pSecretLength = ((EC_COORD_SIZE/8) * 2) + 0x6;
        *ppSecretData = os_mem_new_tag(*pSecretLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, *ppSecretData, 0x2e);
    }
    if (err == E_ERP_SUCCESS)
    {
        (*ppSecretData)[0x0] = 0x00;
        (*ppSecretData)[0x1] = 0x44;
        (*ppSecretData)[0x2] = 0x00;
        (*ppSecretData)[0x3] = 0x20;
        (*ppSecretData)[0x24] = 0x00;
        (*ppSecretData)[0x25] = 0x20;
        os_mem_cpy(&((*ppSecretData)[0x4]), ephX, EC_COORD_SIZE/8);
        os_mem_cpy(&((*ppSecretData)[(EC_COORD_SIZE/8) + 0x6]), ephY, EC_COORD_SIZE/8);
    }
    size_t ECDHSecretLength = 0;
    unsigned char* pECDHSecretData = NULL;
    // Do ECDH to get shared secret (Not the secret buffer...)
    if (err == E_ERP_SUCCESS)
    {
        ECDHSecretLength = EC_COORD_SIZE/8;
        pECDHSecretData = os_mem_new_tag(ECDHSecretLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, pECDHSecretData, 0x2f);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = ecdsa_dh(pCurve,
            EKECPointLength, pEKECPointData,
            privKeyLen, privKeyData,
            0, NULL,
            ECDSA_KDF_RAW,
            ECDHSecretLength,
            pECDHSecretData);
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x0b);
        }
    }
    // Do KDFe ("IDENTITY") on shared secret to get the AES key ("Seed")
    size_t seedLength = EC_COORD_SIZE/8;
    unsigned char seedData[EC_COORD_SIZE/8];
    if (err == E_ERP_SUCCESS)
    {
        unsigned int outputKeyLenBits = 0x100;
        err = DoKDFe(p_hdl,"IDENTITY", pECDHSecretData, ECDHSecretLength, ephX, pEKPubX, EC_COORD_SIZE/8,
            outputKeyLenBits, &(seedData[0]), &seedLength);
    }
    // Do KDFa ("STORAGE") to get the AES 128 key.   Used to encrypt the credential.
    size_t AES128KeyLength = SHA_256_LEN/8;
    unsigned char AES128Key[SHA_256_LEN / 8];
    if (err == E_ERP_SUCCESS)
    {
        unsigned int outputKeyLenBits = 0x80;
        err = DoKDFa(p_hdl,
            "STORAGE",
            &(seedData[0]), seedLength,
            pAKName, TPM_NAME_LEN, 
            outputKeyLenBits,
            &(AES128Key[0]), &AES128KeyLength);
        // We only want the first half of this,
        AES128KeyLength = AES_128_LEN / 8;
    }

    // Encrypt plaintext Credential with "STORAGE" AES 128 key
    // Plaintext credential comes from the response Blob and already has the 2 byte length field prepended.
    size_t encCredLength = 0;
    unsigned char* pEncCredData = NULL;
    if (err == E_ERP_SUCCESS)
    {
        AES_KEY* encKey = NULL;
        if (err == E_ERP_SUCCESS)
        {
            encKey = aes_pkey(AES128KeyLength,&(AES128Key[0]), AES_ENC, NULL);
            if (encKey == NULL)
            {
                err = E_ERP_AES_KEY_ERROR;
                INDEX_ERR(err, 0x10);
            }
        }
        AKChallengeBlob_t* challenge = NULL;
        if (err == E_ERP_SUCCESS)
        {
            challenge = (AKChallengeBlob_t*)responseBlob->Data;
            encCredLength = challenge->DataLength;   
            // At least enough for result in complete blocks.
            pEncCredData = os_mem_new_tag(encCredLength + (AES_128_LEN/8), OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
            CHECK_NOT_NULL(err, pEncCredData, 0x30);
        }
        if (err == E_ERP_SUCCESS)
        {
            err = AES_CFB_BLOCK(encKey,
                AES_128_LEN/8,
                NULL, // Use default all 0 IV
                challenge->DataLength,
                challenge->Data,
                pEncCredData);
        }
        FREE_IF_NOT_NULL(encKey);
    }
    // Do KDFa ("INTEGRITY") on Seed to get HMAC Key
    size_t HMACIntegrityKeyLength = SHA_256_LEN/8;
    unsigned char* pHMACIntegrityKey = NULL;
    if (err == E_ERP_SUCCESS)
    {
        pHMACIntegrityKey = os_mem_new_tag(HMACIntegrityKeyLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, pHMACIntegrityKey, 0x31);
    }
    if (err == E_ERP_SUCCESS)
    {
        err = DoKDFa(p_hdl,
            "INTEGRITY",
            &(seedData[0]), seedLength,
            NULL,0,
            SHA_256_LEN,
            pHMACIntegrityKey, &HMACIntegrityKeyLength);
    }
    unsigned char integrityHMAC[SHA_256_LEN / 8] = {0};
    size_t integrityHMACLen = SHA_256_LEN / 8;
    // Calculate HMAC Integrity hash.
    if (err == E_ERP_SUCCESS)
    {
        unsigned char *pIntegrityInput= os_mem_new_tag(encCredLength + TPM_NAME_LEN,OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, pIntegrityInput, 0x32);
        if (err == E_ERP_SUCCESS)
        {
            
            int offset = 0;
            os_mem_cpy(pIntegrityInput + offset, pEncCredData, encCredLength);
            offset += encCredLength;
            os_mem_cpy(pIntegrityInput+ offset, pAKName, TPM_NAME_LEN);
            offset += TPM_NAME_LEN;
            err = _DoHMAC(p_hdl,pHMACIntegrityKey, pIntegrityInput, offset, &(integrityHMAC[0]), &integrityHMACLen);
        }
        FREE_IF_NOT_NULL(pIntegrityInput);
    }
    // Build Credential Data structure.
    if (err == E_ERP_SUCCESS)
    {
        // Wrap blob.
        // Following logic should do its word-> byte[] conversions better than this...
       // <length>(length<IV><IV><credEnc>)
        unsigned int innerLength = encCredLength + integrityHMACLen + 2;
        *pCredentialLength = innerLength + 2;
        *ppCredentialData = os_mem_new_tag(*pCredentialLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, *ppCredentialData, 0x33);
        if (err == E_ERP_SUCCESS)
        {
            (*ppCredentialData)[0] = (unsigned char)(innerLength >> 8);
            (*ppCredentialData)[1] = (unsigned char)(innerLength % 0x100);
            (*ppCredentialData)[2] = (unsigned char)(integrityHMACLen >> 8);
            (*ppCredentialData)[3] = (unsigned char)(integrityHMACLen % 0x100);
            os_mem_cpy(&((*ppCredentialData)[4]), integrityHMAC, integrityHMACLen);
            os_mem_cpy(&((*ppCredentialData)[4 + integrityHMACLen]), pEncCredData, encCredLength);
        }
    }

    FREE_IF_NOT_NULL(pECDHSecretData);
    FREE_IF_NOT_NULL(pHMACIntegrityKey);
    FREE_IF_NOT_NULL(pEncCredData);
    FREE_IF_NOT_NULL(pubKeyData);
    FREE_IF_NOT_NULL(privKeyData);
    return err;
}

// Sign a buffer and encode the signature in the x509 Certificate and CSR format.
// A Buffer will be allocated to hold the signature that will have to be freed by the caller.
// The signature will be padded with a single 0 in front so that it can be used as the
//    content of a BIT STRING
unsigned int x509ECDSASign(T_CMDS_HANDLE* p_hdl,
    ClearBlob_t* clearKeyPair,
    size_t signableLength, unsigned char* pSignableData,
    size_t* pSignatureLength, unsigned char** ppSignatureData)
{
    unsigned int err = E_ERP_SUCCESS;

    size_t rawSigLength = 0;
    unsigned char* pRawSigData = NULL;

    if (err == E_ERP_SUCCESS)
    {
        err = signECDSAWithRawSigSHA256Signature(p_hdl,
            signableLength, pSignableData,
            &rawSigLength, &pRawSigData,
            clearKeyPair);
    }
    // Convert the signature to the x509 format.
    // The compressed raw signature has the problem that it may or may not have leading zeroes added to the data.
    if (err == E_ERP_SUCCESS)
    {
        // 9 bytes allows for possible leading zeroes on both R and S.
        *pSignatureLength = 9 + rawSigLength;
        *ppSignatureData = os_mem_new_tag(*pSignatureLength, OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
        CHECK_NOT_NULL(err, *ppSignatureData, 0x34);
    }
    if (err == E_ERP_SUCCESS)
    {
        (*ppSignatureData)[0] = 0x00;
        size_t writtenLength = *pSignatureLength - 1;
        err = ecdsa_sign_encode(
            rawSigLength / 2, &(pRawSigData[0]), // SIG R Value
            rawSigLength / 2, &(pRawSigData[rawSigLength / 2]), // SIG R Value
            &writtenLength, (*ppSignatureData) + 1);
        if (err != E_ERP_SUCCESS)
        {
            INDEX_ERR(err, 0x0c);
        }
        if (err == E_ERP_SUCCESS)
        {
            *pSignatureLength = writtenLength + 1; // for the initial zero.
        }
    }

    FREE_IF_NOT_NULL(pRawSigData);
    if ((err != E_ERP_SUCCESS) && ((*ppSignatureData) != NULL))
    {
        os_mem_del_set(*ppSignatureData, 0);
        *ppSignatureData = NULL;
        *pSignatureLength = 0;
    }
    return err;
}
