/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021
 * (C) Copyright IBM Corp. 2021
 * SPDX-License-Identifier: CC BY-NC-ND 3.0 DE
 **************************************************************************************************/

#ifndef ERP_ASN_UTILS_H
#define ERP_ASN_UTILS_H

#include <cryptoserversdk/asn1.h>

#include "ERP_Blob.h"

// Header file for IBM ERP HSM Firmware Module ASN support Utils.

extern size_t getEncodedSize(ASN1_ITEM* pItem, unsigned int NItems, ASN1_ITEM** ppNextItem);

// Utility method to parse and check a buffer into an Item list.
// The Item List must be deleted by the caller once they are finished with it.
extern unsigned int decodeASNList(int l_cmd, const unsigned char * p_cmd, ASN1_ITEM * *pItems, unsigned int expectedItems, unsigned int expectedTopLevelNItems);

// This writes an unsigned integer by, if neccesary, prepending an extra 0.
extern unsigned int setASNIntegerItem(ASN1_ITEM * pItem, unsigned int value);

// pOut must point to an integer variable.
extern unsigned int getASN1Integer(ASN1_ITEM* pItem, unsigned int* pOut);
// pOut must point to an integer variable.
// Out value is left as value from the ASN Data, i.e. 0 or FF
extern unsigned int getASN1Boolean(ASN1_ITEM* pItem, unsigned int* pOut);
// This method does not allocate memory for the output buffer, but provides a pointer
//   into the ASN1_ITEM array to return the NONCE Data. 
extern unsigned int getASN1NONCE(ASN1_ITEM* pItems, unsigned char ** pOut);
// This method does not allocate memory for the output buffer, but provides a pointer
//   into the ASN1_ITEM array to return the OCTET STRING Data. 
// Length is returned in pOutLen.
extern unsigned int getASN1OCTETSTRING(ASN1_ITEM* pItems, unsigned int * pOutLen, unsigned char** pOut);
// This method does not allocate memory for the output buffer, but provides a pointer
//   into the ASN1_ITEM array to return the SealedBlob structure. 
extern unsigned int getASN1SealedBlob(ASN1_ITEM* pItems, SealedBlob_t** ppOut);
// This method does not allocate memory for the output buffer, but provides a pointer
//   into the ASN1_ITEM array to return the SealedBlob structure. 
extern unsigned int getASN1BackupBlob(ASN1_ITEM* pItems, BackupBlob_t** ppOut);

// Creates a new ASN1_ITEM containing the blob key.
// The returned ASN1_ITEM must be deleted using deleteASN1ItemList.
// SHA256Hash ::= SEQUENCE {
//  hashValue OCTET STRING(64)
//  }
//  BlobKeyInfo :: = SEQUENCE{
//  generation INTEGER,
//  keyHash SHA256Hash -- hex encoded SHA256 hash of key.
//  }
extern unsigned int makeBlobKeyInfoItem(ASN1_ITEM** pItem, const T_BLOBK* blobKey);
// Deletes an ASN1 Item list, assuming that all the items in the list are part of a 
//   single allocation in an array.
// It also assumes that p_data (if not NULL) is allocated separately from the Itemlist itself.
// The size of the list passed in is used to walk the array checking the p_data values.
extern unsigned int deleteASNItemList(ASN1_ITEM* pItem, unsigned int nItems);

// Utility method to parse an ASN input to extract a single integer input argument.
extern unsigned int parseSingleIntInput(int l_cmd, unsigned char* p_cmd, unsigned int* pOut);

// Utility method to parse an ASN input to extract a Single Blob input argument.
// To avoid lots of copying and reallocating, the pointers returned by this method are all
//   pointing into the original data buffer so do not delete the input buffer until you are 
//   finished with the output pointers.
// Exception to the above:   Any SealedBlobs returned by this method will be in newly allocated 
//   buffers and must be freed by the caller. 
extern unsigned int parseSingleBlobInput(
    int l_cmd,
    unsigned char* p_cmd,
    // All Parameters from here are output:
    SealedBlob_t** ppOutBlob);

// Utility method to parse an ASN input to extract a Migrate Blob input argument.
// To avoid lots of copying and reallocating, the pointers returned by this method are all
//   pointing into the original data buffer so do not delete the input buffer until you are 
//   finished with the output pointers.
// Exception to the above:   Any SealedBlobs returned by this method will be in newly allocated 
//   buffers and must be freed by the caller. 
extern unsigned int parseMigrateBlobInput(
    int l_cmd,
    unsigned char* p_cmd,
    // All Parameters from here are output:
    unsigned int* pNewGeneration,
    SealedBlob_t** ppOutBlob);

// To avoid lots of copying and reallocating, the pointers returned by this method are all
//   pointing into the original data buffer so do not delete the input buffer until you are 
//   finished with the output pointers.
extern unsigned int parseTrustTPMMfrInput(
    int l_cmd,
    unsigned char* p_cmd, 
    // All Parameters from here are output:
    unsigned int * pDesiredGeneration,
    unsigned int * pOutLen, 
    unsigned char ** ppOutData);

// To avoid lots of copying and reallocating, the pointers returned by this method are all
//   pointing into the original data buffer so do not delete the input buffer until you are 
//   finished with the output pointers.
// Exception to the above:   Any SealedBlobs returned by this method will be in newly allocated 
//   buffers and must be freed by the caller. 
extern unsigned int parseEnrollTPMEKInput(
    int l_cmd, 
    unsigned char * p_cmd,
    // All Parameters from here are output:
    unsigned int * pDesiredGeneration,
    SealedBlob_t ** pTrustedTPMMfrRootBlob,
    unsigned int * pEKCertLength,
    unsigned char ** ppEKCertData);

// To avoid lots of copying and reallocating, the pointers returned by this method are all
//   pointing into the original data buffer so do not delete the input buffer until you are 
//   finished with the output pointers.
// Exception to the above:   Any SealedBlobs returned by this method will be in newly allocated 
//   buffers and must be freed by the caller. 
extern unsigned int parseGetAKChallengeInput(
    int l_cmd,
    unsigned char* p_cmd,
    // All Parameters from here are output:
    unsigned int* pDesiredGeneration,
    SealedBlob_t** pTrustedEKBlob,
    unsigned int* pAKPubLength,
    unsigned char** ppAKPubData,
    unsigned char** ppAKName);

// To avoid lots of copying and reallocating, the pointers returned by this method are all
//   pointing into the original data buffer so do not delete the input buffer until you are 
//   finished with the output pointers.
// Exception to the above:   Any SealedBlobs returned by this method will be in newly allocated 
//   buffers and must be freed by the caller. 
extern unsigned int parseEnrollAKInput(
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
    unsigned char** ppPlainCredData);

// To avoid lots of copying and reallocating, the pointers returned by this method are all
//   pointing into the original data buffer so do not delete the input buffer until you are 
//   finished with the output pointers.
// Exception to the above:   Any SealedBlobs returned by this method will be in newly allocated 
//   buffers and must be freed by the caller. 
extern unsigned int parseEnrollEnclaveInput(
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
    unsigned char** ppSignatureData);

// To avoid lots of copying and reallocating, the pointers returned by this method are all
//   pointing into the original data buffer so do not delete the input buffer until you are 
//   finished with the output pointers.
// Exception to the above:   Any SealedBlobs returned by this method will be in newly allocated 
//   buffers and must be freed by the caller. 
extern unsigned int parseGetTEETokenInput(
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
    unsigned char** ppSignatureData);

// To avoid lots of copying and reallocating, the pointers returned by this method are all
//   pointing into the original data buffer so do not delete the input buffer until you are 
//   finished with the output pointers.
// Exception to the above:   Any SealedBlobs returned by this method will be in newly allocated 
//   buffers and must be freed by the caller. 
extern unsigned int parseDeriveKeyInput(
    int l_cmd,
    unsigned char* p_cmd,
    // All Parameters from here are output:
    unsigned char** ppAKName,
    SealedBlob_t** ppTEETokenBlob,
    SealedBlob_t** ppDerivationKeyBlob,
    unsigned int* pIsInitial, // Boolean 1 == TRUE...
    unsigned int* pDerivationDataLength,
    unsigned char** ppDerivationData);

// To avoid lots of copying and reallocating, the pointers returned by this method are all
//   pointing into the original data buffer so do not delete the input buffer until you are 
//   finished with the output pointers.
// Exception to the above:   Any SealedBlobs returned by this method will be in newly allocated 
//   buffers and must be freed by the caller. 
extern unsigned int parseTwoBlobInputRequest(
    int l_cmd,
    unsigned char* p_cmd,
    // All Parameters from here are output:
    SealedBlob_t** ppBlob1,
    SealedBlob_t** ppBlob2);

// The returned Backup Blobs will be in newly allocated buffers and must be freed by the caller. 
extern unsigned int parseBackupBlobInputRequest(
    int l_cmd,
    unsigned char* p_cmd,
    // All Parameters from here are output:
    BackupBlob_t** ppBackupBlob);

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
    unsigned char** ppCandidateCSRData);

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
    unsigned char** ppClientPubKeyData);

// Method to validate an x509 ANSI X9.62 encoded public key.
// To avoid lots of copying and reallocating, the pointers returned by this method are all
//   pointing into the original data buffer so do not delete the input buffer until you are 
//   finished with the output pointers.
extern unsigned int parseASN1PublicKey(
    size_t keyLength, const unsigned char* pKeyData,
    size_t * pCurveOIDLen, unsigned char ** ppCurveOID,
    size_t * pCoordinateSize, // in bytes.
    unsigned char ** ppXCoord, unsigned char ** ppYCoord);

// Utility method to encode the output in an adequately large buffer, generate the response
//   and then clean up the intermediate buffers.
// deletion of itemList remains the responsibility of the caller.
extern unsigned int buildOutputBuffer(T_CMDS_HANDLE* p_hdl, ASN1_ITEM* itemList, unsigned int numItems);

// Utility Method to build an ASN Output containing a single integer value.
// The result is automatically packed into an HSM response using cds_alloc_answ
// input: Commands handle for the command
// input: the integer value
extern unsigned int makeSingleIntOutput(
    T_CMDS_HANDLE* p_hdl,
    unsigned int input);

// Utility Method to build an ASN Output containing a single sealed Blob.
// The result is automatically packed into an HSM response using cds_alloc_answ
// input: Commands handle for the command
// input: the integer value
extern unsigned int makeSingleSealedBlobOutput(
    T_CMDS_HANDLE* p_hdl,
    SealedBlob_t * input);

// Utility Method to build an ASN Output containing a NONCE Value and related BLOB.
// The result is automatically packed into an HSM response using cds_alloc_answ
// input: Commands handle for the command
// input: the various Data fields for the NONCE And Blob
extern unsigned int makeNONCEAndBlobOutput(
    T_CMDS_HANDLE* p_hdl,
    NONCEBlob_t * aNONCEBlob,
    SealedBlob_t* input);

// Utility Method to build an ASN Output containing the Output of a GetAKChallenge
// The result is automatically packed into an HSM response using cds_alloc_answ
// input: Commands handle for the command
// input: the various Data fields for the AK Challenge response
extern unsigned int makeAKChallengeOutput(
    T_CMDS_HANDLE * p_hdl,
    SealedBlob_t  * pSealedChallengeBlob,
    unsigned int credentialLength,
    unsigned char * pCredentialData,
    unsigned int secretLength,
    unsigned char * pSecretData);

// Utility Method to build an ASN Output containing a DerivedKey Output.
// The result is automatically packed into an HSM response using cds_alloc_answ
// input: Commands handle for the command
// input: the various Data fields for the Key and Derivation data.
extern unsigned int makeDerivedKeyOutput(
    T_CMDS_HANDLE* p_hdl,
    unsigned char* pKey, // AES_256_LEN / 8
    unsigned int derivationDataLength,
    unsigned char* pDerivationData);

// Utility Method to build an ASN Output containing an OCTET STRING
// The result is automatically packed into an HSM response using cds_alloc_answ
// input: Commands handle for the command
// input: length and data for thw ASN1 encoded CSR.
extern unsigned int makeSimpleOctetStringOutput(
    T_CMDS_HANDLE* p_hdl,
    unsigned int inLen,
    unsigned char* inData);

// Utility Method to build an ASN Output containing an ASN1 encoded CSR
// The result is automatically packed into an HSM response using cds_alloc_answ
// input: Commands handle for the command
// input: length and data for thw ASN1 encoded CSR.
extern unsigned int makex509CSROutput(
    T_CMDS_HANDLE* p_hdl,
    unsigned int csrLen,
    unsigned char* pCsrData);

// Utility Method to build an ASN Output containing an ECC Public key
// The result is automatically packed into an HSM response using cds_alloc_answ
// input: Commands handle for the command
// input: EC Public key in RFC 5480 / ANSI X9.62 format.
extern unsigned int makePublicKeyOutput(
    T_CMDS_HANDLE* p_hdl,
    unsigned int keyLen,
    unsigned char* pKeyData);

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
);

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
// return:  error status.
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
    size_t* pCurveIDLen, // OID of curve.
    unsigned char** ppCurveID,
    unsigned int * pbIsCA
);

// Utility method to check an admissions x590 extension against allowed value for the keypair
// return:  error status.
unsigned int checkX509Admissions(ASN1_ITEM* pAdmissionsItem, ClearBlob_t* keyPair);

// This method will parse and verify the candidate CSR and then replace the contained public key
//   with the public key from the keypair and resign with the private key from the keypair.
// The candidate CSR must be complete with a public key and signature, though the content of 
//    the public ky and the validity of the signature do not matter.
// Admission Extensions will be checkd for VAUSIG and ECIES keypairs
// A new buffer will be allocated for the modified CSR which must be freed by the caller.
// return:  error status.
unsigned int x509ECCSRReplacePublicKeyAndSign(
    T_CMDS_HANDLE* p_hdl,
    size_t candidateCSRLength, unsigned char* pCandidateCSRData,
    ClearBlob_t* keyPair,
    size_t* pModifiedCSRLength, unsigned char** ppModifiedCSRData);

// Utility Method to build an ASN public key with idECPublicKey.
// The result is returned in allocated memory that the caller must delete.
// input: curveID object id length and value
// input: X and Y Coordinates for oublic key
// Output: The public key data buffer - must be deleted by caller.
// return:  error status.
unsigned int makeAsn1PublicKey(
    size_t curveIDLen, unsigned char* pCurveID,
    unsigned char* pXCoord, unsigned char* pYCoord,
    size_t* pOutLen, unsigned char** ppPubOut);

// Utility Method to build an ASN Output containing a BackupBlob.
// The result is automatically packed into an HSM response using cds_alloc_answ
// input: Commands handle for the command
// input: the BackupBlob to be encoded.
extern unsigned int makeBackupBlobOutput(
    T_CMDS_HANDLE* p_hdl,
    BackupBlob_t* pBackupBlob);

#endif
