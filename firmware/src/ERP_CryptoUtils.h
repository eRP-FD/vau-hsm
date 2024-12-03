/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021, 2024
 * (C) Copyright IBM Corp. 2021, 2024
 *
 * non-exclusively licensed to gematik GmbH
 *
 * Description: Header file for cryptographic utility methods.
 **************************************************************************************************/

#ifndef ERP_CRYPTO_UTILS_H
#define ERP_CRYPTO_UTILS_H

#include <cryptoserversdk/cmds.h>
#include <cryptoserversdk/eca.h>

#include "ERP_Blob.h"

extern MDL_CONST unsigned char NIST_P256_ANSI_OID[];
extern MDL_CONST size_t NIST_P256_ANSI_OID_LEN;
extern MDL_CONST unsigned char BRAINPOOL_P256R1_ANSI_OID[];
extern MDL_CONST size_t BRAINPOOL_P256R1_ANSI_OID_LEN;
extern MDL_CONST unsigned char SECP384R1_ANSI_OID[];
extern MDL_CONST size_t SECP384R1_ANSI_OID_LEN;
extern MDL_CONST unsigned char SECP521R1_ANSI_OID[];
extern MDL_CONST size_t SECP521R1_ANSI_OID_LEN;
extern MDL_CONST unsigned char ID_EC_PUBLICKEY_ANSI_OID[];
extern MDL_CONST size_t ID_EC_PUBLICKEY_ANSI_OID_LEN;
extern MDL_CONST unsigned char ID_ECDSA_WITH_SHA256_ANSI_OID[];
extern MDL_CONST size_t ID_ECDSA_WITH_SHA256_ANSI_OID_LEN;
extern MDL_CONST unsigned char ID_ECDSA_WITH_SHA384_ANSI_OID[];
extern MDL_CONST size_t ID_ECDSA_WITH_SHA384_ANSI_OID_LEN;
extern MDL_CONST unsigned char ID_ECDSA_WITH_SHA512_ANSI_OID[];
extern MDL_CONST size_t ID_ECDSA_WITH_SHA512_ANSI_OID_LEN;
extern MDL_CONST unsigned char ID_X509_ADMISSIONS_ANSI_OID[];
extern MDL_CONST size_t ID_X509_ADMISSIONS_ANSI_OID_LEN;
extern MDL_CONST unsigned char ID_ERP_VAU_ANSI_OID[];
extern MDL_CONST size_t ID_ERP_VAU_ANSI_OID_LEN;
extern MDL_CONST unsigned char ID_EREZEPT_ANSI_OID[];
extern MDL_CONST size_t ID_EREZEPT_ANSI_OID_LEN;
extern MDL_CONST unsigned char ID_BASIC_CONSTRAINTS_OID[];
extern MDL_CONST size_t ID_BASIC_CONSTRAINTS_OID_LEN;
extern MDL_CONST size_t BASIC_CONSTRAINTS_LEN;

// Utility method to return the curveId>0 if the curve OBJECT IDENTIFIER in item is one that we support.
extern CurveId_t getCurveID(ASN1_ITEM* pItem);
extern SignatureAlgorithm_t getSignatureAlgorithm(ASN1_ITEM* pItem);

extern char HexChar(unsigned char nibble);
extern int _Bin2Hex(unsigned char* binIn, unsigned int inLen, char* hexOut, unsigned int bufLen);

// Writes a big endian long (32 bit) integer to a buffer - works on any endian machine.
int writeBELongInt(unsigned char* buffer, unsigned long input);
// Reads a big endian long (32 bit) integer to a buffer - works on any endian machine.
int readBELongInt(unsigned char* buffer, unsigned long * output);

extern unsigned int _DoHMAC(
    T_CMDS_HANDLE* p_hdl,
    unsigned char* pKDK,
    unsigned char* InputData,    size_t InputLength,
    unsigned char* pOut,
    size_t * pOutputLength); //in: size of buffer, out: size written.

extern unsigned int _DoHKDF(
    T_CMDS_HANDLE* p_hdl,
    unsigned char* pKDK,
    size_t inputLength,
    unsigned char* inputData,
    size_t outputLength,
    unsigned char* pOut); //in: size of buffer must be greater than hash length, out: size written.

// Allocates and fills an ECIES or ECSIG KeyPair Blob with a newly generated ECIES KeyPair.
// The time is set to the current HSM time.
// The memory for the Blob is allocated by this method and must be freed by os_mem_del_set.
extern unsigned int getECKeyPairBlob(T_CMDS_HANDLE* p_hdl, ClearBlob_t** ppOutBlob, ERPBlobType_t blobType);

// input: clear ECIES or ECSIG Keypair Blob containing the keypair to be extracted.
// output: public and private keys + domain params in format required by HSM internally.
// output: Object ID for the ECC Curve.
// Pointers returned are to within the original key blob object.
extern unsigned int ECKeysFromBlob(
    const ClearBlob_t* blob,
    size_t* pPrivKeyLength, unsigned char** ppPrivKeyData,
    size_t* pPubKeyLength, unsigned char** ppPubKeyData,
    size_t* pOidLength, unsigned char** ppOidData,
    ECDP** ppDomainParams ); // Read only output.

// Method to return an externl RFC 5480 / ANSI X9.62 encoding of an ECIES public key.
// Memory returned in *ppKeyData must be released by the caller.
// input: ECIES Keypair Blob containing the key to be returned.
// output: EC Public key in RFC 5480 / ANSI X9.62 format.
extern unsigned int GetASN1PublicKeyFromBlob(const ClearBlob_t* blob,
    unsigned int* pKeyLength,
    unsigned char** ppKeyData);

// Method to return an AES 128 Key following the ERP VAU ECDH process.
// Memory returned in *ppAESKeyData must be released by the caller.
// input: ECIES Keypair Blob containing the VAU ECDH ID.FD.AUT Key.
// input: Client public key in ANSI X9.62 format.
// output: 16 bytes of AES128 key value.
unsigned int DoVAUECIES(T_CMDS_HANDLE* p_hdl,
    const ClearBlob_t* keyPair,
    size_t clientPubKeyLength, unsigned char* pClientPubKeyData,
    size_t* pAESKeyLen, unsigned char** ppAESKeyData);

// Method to return a Private key for a VAUSIG EC KeyPair.
// Memory returned in *ppPrivateKeyData must be released by the caller.
// input: VAUSIG Keypair Blob containing the VAU ID.FD.SIG Key.
// output: The private key in binary PKCS#8 (RFC/5208/5915/5480) format.
unsigned int GetPKCS8PrivateKey(T_CMDS_HANDLE* p_hdl,
    const ClearBlob_t* keyPair,
    size_t* pPrivateKeyLen, unsigned char** ppPrivateKeyData);

// Verify a signature with explicitly known S and R values.
extern unsigned int verifyECDSAWithSRValSHA2Signature(T_CMDS_HANDLE* p_hdl,
    size_t signableLength, unsigned char* pSignableData,    // The signed data
    size_t sigRLength, unsigned char* pSigRData,   // Signature R value
    size_t sigSLength, unsigned char* pSigSData,   // Signature S value
    SignatureAlgorithm_t signatureAlgorithm,
    size_t ECKeyLength, unsigned char* pECKeyData);       // public key of signer in RFC 5480 format.

// Verify a signature in the format used by x509 Certificates.
extern unsigned int verifyECDSAWithANSISHA2Signature(T_CMDS_HANDLE* p_hdl,
    size_t signableLength, unsigned char* pSignableData,    // The signed data
    size_t SignatureLength, unsigned char* pSignatureData,   // Signature Body, as in x509 certificate
    SignatureAlgorithm_t signatureAlgorithm,
    size_t ECKeyLength, unsigned char* pECKeyData);       // public key of signer in RFC 5480 format.

// Verify a signature in the format used by the TPM.
extern unsigned int verifyECDSAWithTPMTSHA256Signature(T_CMDS_HANDLE* p_hdl,
    size_t signableLength, unsigned char* pSignableData,    // The signed data
    size_t SignatureLength, unsigned char* pSignatureData,   // Signature Body, TPM format
    size_t ECKeyLength, unsigned char* pECKeyData);       // public key of signer in RFC 5480 format.

// Check whether a TPM name hash matches the public key data
// input: public key length and data in ANSI X9.62
// input: key name including 2 byte hash algorithm identifier - must be 0x000b
unsigned int CheckTPMNameHash(T_CMDS_HANDLE * p_hdl, size_t pubLength, unsigned char * pubData, unsigned char * nameAK);

// Method to calculate the TPM credential challenge.   The challenge Data is passed in in plaintext and
//    the credential and secret data is calculated for the TPM to be able to decrypt it.
// input: clear response blob containing an AKChallenge with the plaintext credential
// input: clear trusted EK Certificate Blob containing the EK public key.
// input: AK Name hash for the AK Key to be attested.
// input: AK Public key in ANSI X9.62 format.
// *** Credential and secret if allocated by this method must be deleted by the caller. ***
extern unsigned int makeAKChallenge(T_CMDS_HANDLE * p_hdl,
        const ClearBlob_t * responseBlob,
        const ClearBlob_t * pEKCertBlob,
        const size_t AKPubLen, const unsigned char* pAKPub,
        const unsigned char* pAKName, // Length is always SHA_256_LEN + 2 bytes.
        size_t * pCredentialLength,    unsigned char ** ppCredentialData,
        size_t * pSecretLength, unsigned char ** ppSecretData);

// Check whether a TPM name hash matches the public key data
// input: public key length and data in ANSI X9.62
// input: key name including 2 byte hash algorithm identifier - must be 0x000b
unsigned int CheckTPMNameHash(T_CMDS_HANDLE * p_hdl, size_t pubLength, unsigned char * pubData, unsigned char * nameAK);

// Convert a TPMT_PUBLIC public key into an ANSI X9.62 format public key including parsing for correctness.
// input: public key length and data in TPMT_PUBLIC
// input: key name including 2 byte hash algorithm identifier - must be 0x000b
// output: public key length and data in ANSI X9.62 Must be freed by caller.
// output: x509 OID for Public key curve.   Must be freed by caller.
unsigned int ConvertTPMT_PUBLICToANSI(T_CMDS_HANDLE* p_hdl,
    size_t pubLength, unsigned char* pubData,
    size_t* pOutLen, unsigned char** ppPubOut,
    size_t* pCurveOIDLen, unsigned char** ppCurveOID);

// This method checks whether a buffer containing bit flags has the bit at position bitFlagindex
//   counting from LSB, set.   If set then the method returns 0, otherwise it returns 1.
// flagBufferSize is the size of the flag word in bytes.
// LSB is bitFlagIndex == 0
// If there is an error then it will return -1
int checkBitFlagSet(unsigned char* flagBuffer, size_t flagBufferSize, unsigned int bitFlagIndex);

// Method to check that the attributes of a TPMT_PUBLIC key are suitable for use as an
//   attestation Key.
unsigned int validateAKAttributes(unsigned char attributes[4]);

// This method will verify all aspects of a TPM Quote except the signature and
//   the contents of the PCR set and hash.   The NONCE, PCR Set and hash are returned.
// The AKName in the quote is checked against the one passed in.
// Output pointers refer to original input data.   Do not delete.
unsigned int verifyTPMQuote(T_CMDS_HANDLE*  p_hdl,
    unsigned char* pQuoteData, size_t quoteLength,
    unsigned char* pAKName,
    unsigned char** ppQualifiedSignerName,
    unsigned char** ppNONCE,
    unsigned char** ppPCRFlags,
    unsigned char** ppPCRHash);

// Utility method to parse a TPMT_SIGNATURE structure and extract the R and S values from it.
// It enforces an algorithm of TPMI_ALG_ECDSA and a hash of SHA256.
// output: *ppSigR and *ppSigS are pointers into the original buffer.
unsigned int parseTPMT_Signature(size_t sigLength, unsigned char* pSig, unsigned char** ppSigR, unsigned char** ppSigS);

unsigned int DoKDFa(T_CMDS_HANDLE* p_hdl,
    const char* label,
    const unsigned char* key, size_t keyLength,
    const unsigned char* inData, size_t inDataLength,
    unsigned int outputKeyBits,
    unsigned char* pOutputData, size_t* pOutputLength);

unsigned int DoKDFe(T_CMDS_HANDLE* p_hdl,
    const char* label, // Input: "IDENTITY", "STORAGE" or "INTEGRITY"
    const unsigned char* Z_ECDHSharedSecret, size_t Z_ECDHSharedSecretLength, // Input: Buffer and length for Z, the ECDH-derived  X coordinate
    unsigned char* xEphem, // input: X affine coordinate of ephemeral public key
    unsigned char* xEKPub, // input: X affine coordinate of EK public key.
    size_t coordSize, // input: Size of a point coordinate in bytes.
    unsigned int KeyBits, // input: The size (in bits) of the desired key.
    unsigned char* pOutputData, size_t* pOutputLength); // Buffer and Length for output from KDF.

// Calculates a signature over the signable datausing the private key of the keypair.
// The compressed raw format for the signature (defined by Utimaco)is R and the S concatenated.
// after a successful call, the caller must delete *ppRawSigData when finished with it.
unsigned int signECDSAWithRawSigSHA256Signature(T_CMDS_HANDLE* p_hdl,
    size_t signableLength, unsigned char* pSignableData,    // The signed data
    size_t* pRawSigLength, unsigned char** ppRawSigData,   // output: Signature Raw value - r | s
    ClearBlob_t* keyPair);      // Keypair of Signer..

// Sign a buffer and encode the signature in the x509 Certificate and CSR format.
// A Buffer will be allocated to hold the signature that will have to be freed by the caller.
// The signature will be padded with a single 0x00 in front so that it can be used as the
//    content of a BIT STRING
unsigned int x509ECDSASign(T_CMDS_HANDLE *p_hdl,
    ClearBlob_t* clearKeyPair,
    size_t signableLength, unsigned char* pSignableData,
    size_t* pSignatureLength, unsigned char** ppSignatureData);

// This function will produce a one way variation of the NONCE value using a variation parameter to
//   enforce a purpose restriction on the NONCE.
// The variation function is out = HMAC_SHA256(nonceIn,variation data) where nonceIn is used as the HMAC key.
// This function does not do error checking on its' input - it is assumed that the caller did that.
unsigned int varyNONCE(const char * variation, unsigned char * nonceDataIn, unsigned char * variedNONCEOut);

// This function treats the key data as an AES 256 key and encrypts the value 32bytes*0x00 and returns the first
//   four bytes as a big endian integer in pChecksum.
// If pKeyData or pChecksum are NULL then an E_ERP_INTERNAL_BUFFER_ERROR is returned.
// This method may also return the error codes of the Utimaco AES module.
// The return value is an error or E_ERP_SUCCESS
unsigned int GenerateAES256CheckSum(unsigned char*pKeyData, unsigned long* pCheckSum);
#endif
