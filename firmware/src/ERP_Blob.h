/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021
 * (C) Copyright IBM Corp. 2021
 * SPDX-License-Identifier: CC BY-NC-ND 3.0 DE
 *
 * Description: Header file for Blob support Utils.
 **************************************************************************************************/

#ifndef ERP_BLOB_H
#define ERP_BLOB_H

#include <cryptoserversdk/cmds.h>

#include "ERP_Defs.h"

//----------------------------------------------------------------
// Blob Key Declarations and Definitions.
//----------------------------------------------------------------
// We use arrays of undefined size to indicate open ended structures,
//   i.e. the structure contains data beyond the end, but it is not
//   defined at the level of this struct.
#ifdef _MSC_VER
#pragma warning (push)
#pragma warning (disable : 4200)
#elif __GNUC__
#endif

// Blob Strutural constants
#define BLOB_IV_LEN 12
#define BLOB_COUNTER_LEN 16
#define BLOB_AD_HASH_LEN 16
#define BLOB_DOMAIN_LEN 5
#define BLOB_AD_LEN sizeof(unsigned int) + BLOB_DOMAIN_LEN

// Master Backup Key strutural constants.
#define MBK_NAME_LEN 8
#define MBK_KCV_LEN 16

// Note there is NO Blob Generation 0 - it is used to conventionally represent the latest Generation present.

typedef struct {
    unsigned int Generation;
    unsigned int KeyLength;
    unsigned char KeyData[]; // open ended array...
} T_BLOBK;

// Retrieve list containing all blob keys - caller may not change result
// The list will be sorted by Blob Generation.
unsigned int getLoadedBlobKeys(T_CMDS_HANDLE* p_hdl, T_BLOBK* const** pppOutList);

// Returns the highest currently known Blob Generation.
unsigned int getHighestBlobGeneration(T_CMDS_HANDLE* p_hdl);

// Returns the total number of currently loaded Blob Generations.
unsigned int getNumLoadedBlobGenerations(T_CMDS_HANDLE* p_hdl);

// Return a single blob key - caller may not change result
// Returns null if no blob key for that generation.
// Generation 0 means return the highest currently supported.
T_BLOBK* getSingleBlobKey(T_CMDS_HANDLE* p_hdl, unsigned int Generation);

// Add a new blob to the DB.   Returns E_ERP_SUCCESS (0) if ok.
// Returns an error otherwise.
int addNewBlobKey(T_CMDS_HANDLE* p_hdl, const T_BLOBK* newBlob);

// creates a new Blob Key for the requested Generation.
//   Generation = 0 means one more than the current highest one.
//   Returns E_ERP_SUCCESS (0) if ok.
//   Returns an error otherwise.
int createNewBlobKey(T_CMDS_HANDLE* p_hdl, unsigned int *pGeneration);

// Removes a Blob Key from the Database.
//   Returns E_ERP_SUCCESS (0) if ok.
//   Returns an error otherwise.
int deleteBlobKey(T_CMDS_HANDLE* p_hdl, unsigned int Generation);

// Individual Blob Key Backup and Restore
typedef struct {
    // Start of AES-GCM AD.
    unsigned int Generation;
    unsigned char MBKName[MBK_NAME_LEN];    // Utimaco 8 byte name of Master Backup Key used to generate Blob.
    unsigned char MBKKCV[MBK_KCV_LEN];      // MDC2 hash as KCV for Master backup Key used to creat BUBlob.
    unsigned char BlobKeyKCV[SHA_256_LEN/8];  // SHA256 hash as KCV of Blob Key contained in BUBlob
    unsigned char Domain[BLOB_DOMAIN_LEN]; // null terminated "SIML", "DVLP", "REFZ", "TEST" or "PROD".
    // End of AES-GCM AD.
    size_t encDataLength;                   // Length of follwoing encrypted Data of BUBlob.
    // encData will be: < AES GCM 96 bits ICV | encoded Data | AES GCM 128 bits Authorisation Tag>
    unsigned char encData[];                // Intentional Open Ended Array.   Encrypted Data of BUBlob
} BackupBlob_t;

//----------------------------------------------------------------
// Blob Declarations and Definitions
//----------------------------------------------------------------

typedef enum ERPBlobType {
    Reserved            = 0 // RFU
    // Long Lived Blobs:
    , TPM_Mfr_RootCert  = 1 // Issued by the TPM Manufacturerand used to sign TPM Endorsement Key(EK) Certificates.Trusted by us to genuinely come from the manufacturer..
    , Trusted_EK        = 2 // Known and Trusted EK public key.   Installed by Manufacturer in TPM and verified against the TPM Manufacturer root key.Trusted by us to be for a TPM belonging to part of our VAU.   (Actually, EKs are not installed directly in the TPM, but rather the TPM comes with a Seed value used to derive the EK and other keys - the derivation data used for the EK ensures that this seed will always produce the same EK.)
    , Trusted_AK        = 4 // Knownand Trusted AK.   Attestation Key generated by a TPM.Trusted by us to be present in a TPM containing a trusted EK.Trust is established through the enrollment process.
    , Trusted_Quote     = 5 // Known and trusted Attestation Quote Data.TPM PCR Hash values relating to a secure boot of a system setupand SGX Enclave.   Trusted by us during the enrollment process to match a trusted software and hardware stack allowed to run our VAU.
    , Derivation_Key    = 6 // A symmetric key used to derive Persistence Keys.
    , Hash_Key          = 7 // A symmetric key used to calculate keyed hashes.
    , ECIES_KeyPair     = 8 // EC Keypair used for ECIES VAU communications encryption
    , VAUSIG_KeyPair    = 10 // EC Keypair used for VAU Signature operations.
    // Transient Blobs:
    , NONCE_Blob        = 9 // A NONCE to be used to prevent replay attacks.
    , AKChallenge       = 3 // A credential that must be decrypted during the AK attestation.
//    , TPM_Challenge = 10 // A Credential Challenge to be cross checked against
    , TEE_Token         = 11  // A time limited Token allowing access to the VAU HSM functions.
    , Pseudoname_Key    = 12 // time limited unwrappable AES key.    See PSEUDONAME_BLOB_EXPIRY
    , RawPayload        = 13 // arbitrary Payload
} ERPBlobType_t;


typedef struct {
    // This is generated from the encoded data and is reproduced here as a convenience.
    unsigned char BlobID[SHA_256_LEN / 8]; // SHA256 hash of encoded part - usable as ID.
    // Following is AD for AES_GCM
    unsigned int Generation; // The Generation of the BlobKey to be used for unwrapping.
    unsigned char Domain[BLOB_DOMAIN_LEN]; // null terminated "SIML", "DVLP", "REFZ", "TEST" or "PROD".
    // End of AES-GCM AD.
    unsigned char ICV[BLOB_IV_LEN]; // AES GCM 96 bits ICV
    unsigned char AuthTag[BLOB_AD_HASH_LEN]; // AES GCM 128 bits Authorisation Tag.
    unsigned int EncodedDataLength; //
    unsigned char EncodedData[]; // Open ended array.
} SealedBlob_t;

// Time format in string: "YYYY.MM.DD HH:MM:SS.mmm"   Length 24 including null.
#define TIME_SIZE 24
typedef struct {
    // Encoded Data is everything after this.
    ERPBlobType_t BlobType;
    unsigned int IssueTime; // Seconds after 2020.01.01 0:00:00.0
    // Question - should we put a RND padding in here?
    unsigned int DataLength;
    unsigned char Data[]; // open ended array - dependent on type.
} ClearBlob_t;

typedef struct {
    unsigned char KeyData[AES_256_LEN / 8];
} AES256KeyBlob_t;

typedef struct {
    unsigned char RNDData[NONCE_LEN / 8];
} NONCEBlob_t;

typedef struct {
    unsigned int keyLength;
    unsigned char keyData[]; // ASN1.DER encoded ECDSA private and public key according to SEC1
} ECKeyPairBlob_t;

typedef struct {
    unsigned char EKName[TPM_NAME_LEN]; // This is TPM Name hash (0x000b + SHA256) of AK Public - used by TPM as name
    unsigned int CertificateLength;
    unsigned char CertificateData[]; // Open ended ASN1.DER x509 Certificate.
} KnownEKBlob_t;

// This may change depending on whether we use an AK Certificate to wrap the AK public key or not.
typedef struct {
    unsigned char AKName[TPM_NAME_LEN]; // This is TPM Name hash (0x000b + SHA256) of AK Public - used by TPM as name
    unsigned int DataLength;
    unsigned char Data[]; // plaintext Data of the credential challenge.
} AKChallengeBlob_t;

// This may change depending on whether we use an AK Certificate to wrap the AK public key or not.
typedef struct {
    unsigned char AKName[TPM_NAME_LEN]; // This is an TPM Name hash (0x000b + SHA256) of AK Public - used by TPM as name
    unsigned int ANSIPubKeyLength;
    unsigned char ANSIPubKeyData[]; // Open ended ASN1.DER x509 Certificate.
} KnownAKBlob_t;

// This may change depending on whether we have some flexibility in the PCR selection set..
typedef struct {
    unsigned char AKName[TPM_NAME_LEN]; // This is TPM Name hash (0x000b + SHA256) of AK Public - used by TPM as name
    unsigned int QuoteLength;
    unsigned char QuoteData[]; // Open ended - May become a TPMQuote_t
} KnownQuoteBlob_t;

typedef struct {
    unsigned int CertificateLength;
    unsigned char CertificateData[]; // Open ended ASN1.DER x509 Certificate.
} TPMMfrRootCertBlob_t;

// At the moment, I can't think of anything else to put in a TEE Token - time, type and so on are
//   already define at the generic blob level.
#define TEE_TOKEN_TEXT "*x* This is a VAU/TEE HSM Token for the IBM eRP Project. *x*"
#define TEE_TOKEN_TEXT_LEN 51
typedef struct {
    unsigned char AKName[TPM_NAME_LEN]; // This is TPM Name hash (0x000b + SHA256) of AK Public - used by TPM as name
    char TokenText[TEE_TOKEN_TEXT_LEN];
} TEETokenBlob_t;

#define TPM_PCR_COUNT 16
typedef struct {
    unsigned int numPCRsUsed;
    unsigned char PCR[TPM_PCR_COUNT][SHA_256_LEN/8];
} TPMQuote_t;

#ifdef _MSC_VER
#pragma warning (pop)
#elif __GNUC__
#endif

// Helper method to fill fields common to all Blobs:
//   Generation - left at 0 for default.
//   issue - time set to current HSM time.
//   DataLength - set to initial 0 value.
unsigned int fillGeneric(ClearBlob_t* pOutBlob);

// Quick method to return E_ERP_BAD_BLOB_GENERATION if a generation cannot be found.
unsigned int CheckAvailableGeneration(T_CMDS_HANDLE* p_hdl, unsigned int Generation);

// Seal a Blob with the requested Generation, where 0 means the latest available.
// Memory for the Blob is allocated by this method and must be freed by os_mem_del_set
extern unsigned int SealBlob(T_CMDS_HANDLE* p_hdl, ClearBlob_t* pInBlob, unsigned int Generation, SealedBlob_t** ppOutBlob);

// Unseals a sealed blob using the generation contained in the Blob.
// The memory for the ClearBlob is allocated by this method and must be freed by os_mem_del_set
// Use UnsealBlobAndCheckType whenever the blob has a single allowed type, otherwise
//   the caller must check the blob type manually after this call has returned.
// The Generation of the sealed blob must match a blob key present in the HSM.
unsigned int UnsealBlob(T_CMDS_HANDLE* p_hdl, SealedBlob_t* pInBlob, ClearBlob_t** ppOutBlob);

// Unseals a sealed blob using the generation contained in the Blob.
// The memory for the ClearBlob is allocated by this method and must be freed by os_mem_del_set
// Checks type of unsealed Blob against expectedType.
// Checks temporal validity of Blob depending on type of Blob.
extern unsigned int UnsealBlobAndCheckType(T_CMDS_HANDLE* p_hdl, ERPBlobType_t expectedType, SealedBlob_t* pInBlob, ClearBlob_t** ppOutBlob);

// Allocates and fills a NONCE Blob with a new RND value.
// The time is set to the current HSM time.
// The memory for the Blob is allocated by this method and must be freed by os_mem_del_set.
extern unsigned int getNONCEBlob(T_CMDS_HANDLE* p_hdl, ClearBlob_t** ppOutBlob);

// Allocates and fills a HashKey clear Blob with a new RND value.
// The time is set to the current HSM time.
// The memory for the Blob is allocated by this method and must be freed by os_mem_del_set.
extern unsigned int getHashKeyBlob(T_CMDS_HANDLE* p_hdl, ClearBlob_t** ppOutBlob);

// Allocates and fills a HashKey clear Blob with a new RND value.
// The time is set to the current HSM time.
// The blob is given an expiry period of 8 months, but this is enforced in the UnsealAndCheckBlob method.
// The memory for the Blob is allocated by this method and must be freed by os_mem_del_set.
extern unsigned int getPseudonameKeyBlob(T_CMDS_HANDLE* p_hdl, ClearBlob_t** ppOutBlob);

// Allocates and fills a Derivation Key Blob with a newly generated Derivation Key.
// The time is set to the current HSM time.
// The memory for the Blob is allocated by this method and must be freed by os_mem_del_set.
unsigned int getDerivationKeyBlob(T_CMDS_HANDLE* p_hdl, ClearBlob_t** ppOutBlob);

// Allocates and fills a BackupBlob_t with a backup of the blob key with the input generation.
// The caller must free the returned BackupBlob_t.
// The current AES 256 Master Backup Key in the HSM is used to create the backup.
// Information about the MBK used is stored in the Backup�Blob.
// Metadata in clear is only provided as information.   The same values are stored in the encrypted
//   data which is AES_GCM encoded to protect against manipulation.
// In the event of failure, *ppBackupBlob will be returned == NULL and there will be no memory to free.
unsigned int backupBlobGeneration(T_CMDS_HANDLE* p_hdl, unsigned int Generation, BackupBlob_t** ppBackupBlob);

// Restore a Blob Key Generation from a backup blob.
// There may not be a blob key already present for that generation.
// The current AES 256 MBK in the HSM must match that used to create the BackupBlob_t
// The Generation, key and MBK values in clear will be checked against those in the encrypted Data.
// Ownership of the input BackupBlob_t remains with the caller.
unsigned int restoreBlobGeneration(T_CMDS_HANDLE* p_hdl, BackupBlob_t* pBackupBlob);

// Calculate an SHA256 hash if the contents of a clear blob and write them to the command output
//   buffer as an OCTET String.
unsigned int hashAndReturnBlobContents(T_CMDS_HANDLE* p_hdl, ClearBlob_t* input);
#endif
