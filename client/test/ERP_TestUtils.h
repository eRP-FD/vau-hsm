#ifndef ERP_TEST_UTILS_H
#define ERP_TEST_UTILS_H

#include "ERP_Client.h"
#include <vector>
#include <fstream>
#include <memory>
#include <cstddef>

// Utility method to create and initialise an empty ERPBlob as a unique_ptr.
std::unique_ptr<ERPBlob> getEmptyBlob(unsigned int Gen = 0);

// Utility method to read a file form the resources directory, allocates a pointer to a buffer to it and return that pointer 
// for the caller to own and be responsible for deletion.
std::vector<char> readERPResourceFile(const std::string& filename,bool bMustExist = true);
// Caller must delete returned object.
ERPBlob* readBlobResourceFile(const std::string& filename,bool bMustExist = true);
unsigned int writeERPResourceFile(const std::string& filename, const std::vector<char>& data);
unsigned int writeBlobResourceFile(const std::string& filename, const ERPBlob * blob);

// Method to either read a blob from filename or to create a new derivation key and write it to filename.
// pOutBlob must point to an empty blob which can receive the result.
unsigned int deriveOrRetrieveDerivationKey(HSMSession sesh,
    unsigned int generation,
    const char* filename,
    ERPBlob* pOutBlob );

void printHex(const std::string& message, const std::vector<char>& data);

unsigned int teststep_DumpHSMMemory(HSMSession sesh);
unsigned int teststep_GenerateBlobKey(HSMSession sesh, unsigned int gen);
unsigned int teststep_ListLoadedBlobKeys(HSMSession sesh);
unsigned int teststep_DeleteBlobKey(HSMSession sesh, unsigned int gen);
unsigned int teststep_GenerateNONCE(HSMSession sesh, unsigned int gen);

unsigned int teststep_TrustTPMMfr(HSMSession sesh, unsigned int generation, ERPBlob* pOutBlob, const std::vector<char>& certFile);
unsigned int teststep_EnrollTPMEK(
    HSMSession sesh,
    unsigned int generation,
    ERPBlob* pTrustedRoot,
    ERPBlob* pTrustedEK, // Output
    size_t EKCertLen,
    unsigned char* pEKCertData);
unsigned int teststep_GetAKChallenge(
    HSMSession sesh,
    // Input
    unsigned int desiredGeneration,
    ERPBlob* pTrustedEK,
    unsigned char* pAKName, // SHA_1_LEN...
    size_t AKCertLength,
    unsigned char* AKCertData,
    // output
    ERPBlob* pCredChallengeBlob,
    size_t* pEncCredentialLength,
    unsigned char* pEncCredentialData, // MAX_BUFFER
    size_t* pSecretLength,
    unsigned char* pSecretData); // MAX_BUFFER
unsigned int teststep_EnrollAK(
    HSMSession sesh,
    unsigned int desiredGeneration,
    ERPBlob* pTrustedEK,
    ERPBlob* pChallengeBlob,
    unsigned char* pAKName, // SHA_1_LEN
    size_t AKCertLength,
    unsigned char* AKCertData,
    size_t decCredLength,
    unsigned char* decCredData,
    ERPBlob* pOutBlob);
unsigned int teststep_TrustQuote(
    HSMSession sesh,
    unsigned int desiredGeneration,
    ERPBlob* pTrustedAK,
    ERPBlob* pNONCEBlob,
    unsigned char* pAKName, // SHA_1_LEN
    size_t quoteLength,
    unsigned char* quoteData,
    size_t sigLength,
    unsigned char* sigData,
    ERPBlob* pOutBlob);
unsigned int teststep_getTEEToken(
    HSMSession sesh,
    ERPBlob* pTrustedAK,
    ERPBlob* pTrustedQuote,
    ERPBlob* pNONCEBlob,
    unsigned char* pAKName, // SHA_1_LEN
    size_t quoteLength,
    unsigned char* quoteData,
    size_t sigLength,
    unsigned char* sigData,
    ERPBlob* pOutBlob);
unsigned int teststep_GenerateDerivationKey(HSMSession sesh, unsigned int desiredGeneration, ERPBlob* pOutBlob);
unsigned int teststep_deriveTaskPersistenceKey(
    HSMSession sesh,
    unsigned char* pAKName, // SHA_1_LEN
    ERPBlob* pTEEToken,
    ERPBlob* pDerivationKey,
    size_t derivationDataLength,
    unsigned char* derivationData,
    unsigned int isInitial, // 1 => Initial Derivation, 0 => subsequent Derivation. 
    // Output
    size_t* pUsedDerivationDataLength,
    unsigned char* usedDerivationData, // MAX_BUFFER
    unsigned char* derivedKey); // AES_256_LEN
unsigned int teststep_deriveAuditKey(
        HSMSession sesh,
        unsigned char* pAKName, // TPM_NAME_LEN
        ERPBlob* pTEEToken,
        ERPBlob* pDerivationKey,
        size_t derivationDataLength,
        unsigned char* derivationData,
        unsigned int isInitial, // 1 => Initial Derivation, 0 => subsequent Derivation.
        // Output
        size_t* pUsedDerivationDataLength,
        unsigned char* usedDerivationData, // MAX_BUFFER
        unsigned char* derivedKey); // AES_256_LEN
unsigned int teststep_deriveCommsKey(
        HSMSession sesh,
        unsigned char* pAKName, // TPM_NAME_LEN
        ERPBlob* pTEEToken,
        ERPBlob* pDerivationKey,
        size_t derivationDataLength,
        unsigned char* derivationData,
        unsigned int isInitial, // 1 => Initial Derivation, 0 => subsequent Derivation.
        // Output
        size_t* pUsedDerivationDataLength,
        unsigned char* usedDerivationData, // MAX_BUFFER
        unsigned char* derivedKey); // AES_256_LEN

void teststep_ASN1IntegerInput(HSMSession sesh, unsigned int SFCCode, bool bZeroOk = true);

// This function will produce a one way variation of the NONCE value using a variation parameter to
//   enforce a purpose restriction on the NONCE.
// The variation function is out = HMAC_SHA256(nonceIn,variation data) where nonceIn is used as the HMAC key.
// This function does not do error checking on its' input - it is assumed that the caller did that.
// Both Buffers must be NOCEN_LEN long.
extern unsigned int varyNONCE(const char* variation, unsigned char* nonceDataIn, unsigned char* variedNONCEOut);

#endif