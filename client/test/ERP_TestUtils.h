/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021, 2023
 * (C) Copyright IBM Corp. 2021, 2023
 *
 * non-exclusively licensed to gematik GmbH
 **************************************************************************************************/

#ifndef ERP_TEST_UTILS_H
#define ERP_TEST_UTILS_H

#include "ERP_Client.h"

#include <vector>
#include <fstream>
#include <memory>
#include <cstddef>

#define TEST_CONNECT_TIMEOUT_MS 5000
#define TEST_READ_TIMEOUT_MS   1800000
#define TEST_RECONNECT_INTERVAL_MS 300
// Wherever a single byte magic number is needed.
#define THE_ANSWER 0x42
// Generation for tests changing blob keys.
#define TEST_BLOB_GEN 0x55

// Iterations for loop tests.
#define SMALL_LOOP 10
#define MEDIUM_LOOP 100
#define BIG_LOOP 1000

#define TEST_ABSENT_GEN 0x10000000
#define TEST_MAX_UNSIGNED_GEN 0xffffffff
#define TEST_MAX_SIGNED_GEN 0x7fffffff
#define TEST_HIGH_VALID_GENERATION 0x1fff
#define TEST_LEN_CURTAILMENT 7
#define NIBBLE_SIZE 16
#define BAD_BYTE 0xFE
#define XOR_CHANGE_BYTE (uint8_t)0xaa

// Utility method to create and initialise an empty ERPBlob as a unique_ptr.
std::unique_ptr<ERPBlob> getEmptyBlob(unsigned int Gen = 0);

// Utility Method for byte arrays initialised from strings.
std::vector<std::uint8_t> asciiToBuffer(std::string_view in );

// Utility method to read a file form the resources directory, allocates a pointer to a buffer to it and return that pointer
// for the caller to own and be responsible for deletion.
std::vector<uint8_t> readERPResourceFile(const std::string& filename,bool bMustExist = true);

// Caller must delete returned object.
std::unique_ptr<ERPBlob> readBlobResourceFile(const std::string& filename,bool bMustExist = true);
unsigned int writeERPResourceFile(const std::string& filename, const std::vector<uint8_t>& data);
unsigned int writeBlobResourceFile(const std::string& filename, const ERPBlob * blob);

// Method to either read a blob from filename or to create a new derivation key and write it to filename.
// pOutBlob must point to an empty blob which can receive the result.
unsigned int deriveOrRetrieveDerivationKey(HSMSession sesh,
    unsigned int generation,
    const char* filename,
    ERPBlob* pOutBlob );

void printHex(const std::string& message, const std::vector<uint8_t>& data);

unsigned int teststep_DumpHSMMemory(HSMSession sesh);
unsigned int teststep_GenerateBlobKey(HSMSession sesh, unsigned int gen);
unsigned int teststep_ListLoadedBlobKeys(HSMSession sesh);
unsigned int teststep_DeleteBlobKey(HSMSession sesh, unsigned int gen);
unsigned int teststep_GenerateNONCE(HSMSession sesh, unsigned int gen);

unsigned int teststep_TrustTPMMfr(HSMSession sesh, unsigned int generation, ERPBlob* pOutBlob, const std::vector<uint8_t>& certFile);
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

typedef unsigned int (deriveFunc_t)(
    HSMSession,
    unsigned char*,
    ERPBlob*,
    ERPBlob*,
    size_t,
    unsigned char* a,
    unsigned int, // 1 => Initial Derivation, 0 => subsequent Derivation.
    // Output
    size_t*,
    unsigned char*, // MAX_BUFFER
    unsigned char*); // AES_256_LEN;

deriveFunc_t teststep_deriveTaskPersistenceKey;
deriveFunc_t teststep_deriveAuditKey;
deriveFunc_t teststep_deriveCommsKey;
deriveFunc_t teststep_deriveChargeItemKey;

// The pGoodTestFunc is one of the teststep_DeriveXXXXPersistenceKey Methods which will
//   be checked that it produces a consistent derived key for initial and subsequent derivations.
// The pOtherTestFunc is another test function for a DIFFERENT class of derivation
//   key which should NOT produce the same derived key as the first.
extern unsigned int teststep_GoodKeyDerivation(HSMSession sesh,
    ERPBlob* pTEEToken, unsigned char* pAKName,
    deriveFunc_t *pGoodTestFunc, // Will be checked for consistent derivation
    deriveFunc_t *pOtherTestFunc // Will be checked that it DOES NOT prpoduce the same result.
);

void teststep_ASN1IntegerInput(HSMSession sesh, unsigned int SFCCode, bool bZeroOk = true);

// This function will produce a one way variation of the NONCE value using a variation parameter to
//   enforce a purpose restriction on the NONCE.
// The variation function is out = HMAC_SHA256(nonceIn,variation data) where nonceIn is used as the HMAC key.
// This function does not do error checking on its' input - it is assumed that the caller did that.
// Both Buffers must be NOCEN_LEN long.
extern unsigned int varyNONCE(const char* variation, unsigned char* nonceDataIn, unsigned char* variedNONCEOut);

extern unsigned int teststep_GenerateHashKey(HSMSession sesh, unsigned int Generation, SingleBlobOutput* pHashBlobOut);
extern unsigned int teststep_GeneratePseudonameKey(HSMSession sesh, unsigned int Generation, SingleBlobOutput* pPseudonameBlobOut);

extern unsigned int teststep_UnwrapHashKey(HSMSession sesh, ERPBlob* hashBlob, AES256KeyOutput* pKeyOut);
extern unsigned int teststep_UnwrapPseudonameKey(HSMSession sesh, ERPBlob* PseudonameBlob, AES256KeyOutput* pKeyOut);
unsigned int teststep_WrapRawPayload(HSMSession sesh, unsigned int Generation, size_t payloadLength,
                                     const unsigned char *rawPayload, SingleBlobOutput *payloadBlob);
unsigned int teststep_WrapRawPayloadWithToken(HSMSession sesh, unsigned int Generation, size_t payloadLength,
                                           const unsigned char *rawPayload, SingleBlobOutput *payloadBlob);
unsigned int teststep_UnwrapRawPayload(HSMSession sesh, ERPBlob *payloadBlob, RawPayloadOutput *payloadOut);

#endif
