/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021, 2024
 * (C) Copyright IBM Corp. 2021, 2024
 *
 * non-exclusively licensed to gematik GmbH
 *
 * Description: Implementation of extern Functions (called by the host application).
 *              This module implements the IBM eRezept custom HSM firmware.
 **************************************************************************************************/

#ifndef ERP_EXTERNAL_API_H
#define ERP_EXTERNAL_API_H

#include <cryptoserversdk/db.h>

/******************************************************************************
 * Function Prototypes
 ******************************************************************************/
/** @addtogroup ERP_ext
  * @{
  */

// Externally callable FWAPI Command
// Method to carry out a dump of currently allocated HSM Heap.
// Output will be logged by smos printed in the simulator.
// In Production the method will return E_ERP_DEV_FUNCTION_ONLY
// Return: Success or Error code.
extern int ERP_DumpHSMMemory(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Externally callable FWAPI Command
// Command to generate a new Blob Trust Key with a new Generation
// Input: unsigned int Desired Generation - if zero, then the highest available Generation
//           in the HSM is incremented by one and used.   Otherwise the input value must
//           not match any existing Blob Key Generation present in the HSM.
// Output: none
// Return: Success or Error code.
extern int ERP_GenerateBlobKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Externally callable FWAPI Command
// Command to delete a Blob Trust Key with a given Generation
// Input: unsigned int Undesired Generation - the input value must
//        match an existing Blob Key Generation present in the HSM.
// Output: none
// Return: Success or Error code.
extern int ERP_DeleteBlobKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Externally callable FWAPI Command
// Command to list the currently loaded Blob Trust Keys
// Input: none
// Output: List of <Generation,SHA256 Hashes of Key Values>
// Return: Success or Error code.
extern int ERP_ListBlobKeys(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Externally callable FWAPI Command
// Command to generate a new Hash Key Blob with an existing Generation
// Input: unsigned int Desired Generation - if zero, then the highest available Generation
//           in the HSM is used.   Otherwise the input value must
//           match an existing Blob Key Generation present in the HSM.
// Output: Hash Key Blob
// Return: Success or Error code.
extern int ERP_GenerateHashKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Externally callable FWAPI Command
// Command to generate a new pseudoname Key Blob with an existing Generation.
// Pseudoname Key blobs expire automatically after 8 months.
// Required Permission: Working
// Input: unsigned int Desired Generation - if zero, then the highest available Generation
//           in the HSM is used.   Otherwise the input value must
//           match an existing Blob Key Generation present in the HSM.
// Output: Pseudoname Key Blob
// Return: Success or Error code.
extern int ERP_GeneratePseudonameKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Externally callable FWAPI Command
// Command to generate a new Derivation Key Blob with an existing Generation
// Input: unsigned int Desired Generation - if zero, then the highest available Generation
//           in the HSM is used.   Otherwise the input value must
//           match an existing Blob Key Generation present in the HSM.
// Output: Derivation Key Blob
// Return: Success or Error code.
extern int ERP_GenerateDerivationKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Externally callable FWAPI Command
// Command to generate a new ECIES KeyPair for ECIES key exchange with an existing Generation
// Input: unsigned int Desired Generation - if zero, then the highest available Generation
//           in the HSM is used.   Otherwise the input value must
//           match an existing Blob Key Generation present in the HSM.
// Output: ECIES KeyPair Blob
// Return: Success or Error code.
extern int ERP_GenerateECIESKeyPair(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Externally callable FWAPI Command
// Generate CSR for an ECIES Keypair
// Input: ECIES KeyPair Blob
// Input: Candidate CSR with all valid fields, except public key and signature
//    which must be present and formally correct, but the content data is irrelevant.
//    The Signature does not need to be valid either.
// Output: ASN1.DER encoded CSR
// Return: Success or Error code.
extern int ERP_GenerateECIESCSR(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Externally callable FWAPI Command
// Command to generate a new EC Signature KeyPair for VAU Signing operations
// Input: unsigned int Desired Generation - if zero, then the highest available Generation
//           in the HSM is used.   Otherwise the input value must
//           match an existing Blob Key Generation present in the HSM.
// Output: ECIES KeyPair Blob
// Return: Success or Error code.
extern int ERP_GenerateVAUSIGKeyPair(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Externally callable FWAPI Command
// Generate CSR for a VAUSIG Keypair
// Input: VAUSIG KeyPair Blob
// Input: Candidate CSR with all valid fields, except public key and signature
//    which must be present and formally correct, but the content data is irrelevant.
//    The Signature does not need to be valid either.
// Output: ASN1.DER encoded CSR
// Return: Success or Error code.
extern int ERP_GenerateVAUSIGCSR(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Externally callable FWAPI Command
// Command to generate a new EC Signature KeyPair for AUT Signing operations
// Input: unsigned int Desired Generation - if zero, then the highest available Generation
//           in the HSM is used.   Otherwise the input value must
//           match an existing Blob Key Generation present in the HSM.
// Output: ECIES KeyPair Blob
// Return: Success or Error code.
extern int ERP_GenerateAUTKeyPair(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Externally callable FWAPI Command
// Generate CSR for a VAUAUT Keypair
// Input: AUT KeyPair Blob
// Input: Candidate CSR with all valid fields, except public key and signature
//    which must be present and formally correct, but the content data is irrelevant.
//    The Signature does not need to be valid either.
// Output: ASN1.DER encoded CSR
// Return: Success or Error code.
extern int ERP_GenerateAUTCSR(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Externally callable FWAPI Command
// Command to generate a new NONCE Blob with an existing Generation
// Input: unsigned int Desired Generation - if zero, then the highest available Generation
//           in the HSM is used.   Otherwise the input value must
//           not match ay existing Blob Key Generations present in the HSM.
// Output: NONCE Blob
// Return: Success or Error code.
extern int ERP_GenerateNONCE(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Not present Command - will return E_ERP_OBSOLETE_FUNCTION
// Return: Success or Error code.
extern int ERP_NotUsed(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Externally callable FWAPI Command
// Command to add a trusted TPM Manufacturer Root CA certificate.
// Input: ASN1.DER encoded x509r3 Certificate for the TPM Manufacturer Root CA.
// Output: Trusted TPM Manufacturer Root Certificate Blob
// Return: Success or Error code.
extern int ERP_TrustTPMMfr(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);        // SFC = 11

// Externally callable FWAPI Command
// Enroll a TPM Endorsement Key.
// Input: TPM Manufacturer Root Blob
// Input: ASN1.DER encoded x509r3 certificate for the Endorsement Key
// Input: NONCE Blob
// Input: Signature with EKPriv over (EKPub | NONCE)
// Output: Trusted EK Blob
// Return: Success or Error code.
extern int ERP_EnrollTPMEK(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);        // SFC = 12

// Externally callable FWAPI Command
// get an Attestation Key credential Chalenge to be signed by the TPM.
// Input: Known Endoresement Key Blob
// Input: TPM Name hash (0x000b + SHA256) of AK Public - used by TPM as name
// Input: TBD - either ASN1.DER encoded public key or x509r3 certificate for the Attestation Key
// Output: TPM2 Secret
// Output: TPM2 Credential
// Output: Credential Challenge Blob
// Return: Success or Error code.
extern int ERP_GetAKChallenge(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);        // SFC = 13

// Externally callable FWAPI Command
// Enroll an Attestation Key using the results of a TPM decryption of the credential challenge.
// Input: Known Endoresement Key Blob
// Input: TPM Name hash (0x000b + SHA256) of AK Public - used by TPM as name
// Input: TBD - either ASN1.DER encoded public key or x509r3 certificate for the Attestation Key
// Input: Decrypted Credential
// Input: Credential Challenge Blob
// Output: Trusted AK Blob
// Return: Success or Error code.
extern int ERP_EnrollTPMAK(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);        // SFC = 14

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
extern int ERP_EnrollEnclave(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);        // SFC = 15

// Externally callable FWAPI Command
// Get a time limited Token to use the HSM as a VAU
// Input: TPM Name hash (0x000b + SHA256) of AK Public - used by TPM as name
// Input: Trusted AK Blob
// Input: NONCE Blob
// Input: Trusted Quote Blob
// Input: Quoted Data - TBD exact sub-structure here?
//        The quote data will include a NONCE-derived value of HMAC(HSM NONCE,"ERP_ATTESTATION")
// Input: TPM Signature over the quoted data using NONCE and AK
// Output: TEE Token Blob
// Return: Success or Error code.
extern int ERP_GetTEEToken(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);        // SFC = 16

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
extern int ERP_DeriveTaskKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);        // SFC = 17

// Externally callable FWAPI Command
// As ERP_deriveTaskKey, but for Audit persistence keys.
// Return: Success or Error code.
extern int ERP_DeriveAuditKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);        // SFC = 18

// Externally callable FWAPI Command
// As ERP_deriveTaskKey, but for Communications persistence keys.
// Return: Success or Error code.
extern int ERP_DeriveCommsKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);        // SFC = 19

// Externally callable FWAPI Command
// As ERP_deriveTaskKey, but for ChargeItem persistence keys.
// Return: Success or Error code.
extern int ERP_DeriveChargeItemKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);        // SFC = 30

// Externally callable FWAPI Command
// Extract AES 256 Hash key
// Input: currently valid TEE Token
// Input: Hash Key Blob
// Output: Symmetric AES256 hash key.
// Return: Success or Error code.
extern int ERP_UnwrapHashKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Externally callable FWAPI Command
// Extract AES 256 Pseudoname key
// Required Permission: Working
// Input: currently valid TEE Token
// Input: Hash Key Blob
// Output: Symmetric AES256 hash key.
// Return: Success or Error code.
extern int ERP_UnwrapPseudonameKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Externally callable FWAPI Command
// Extract rawPayload
// Required Permission: setup or update
// Input: Payload
// Output: rawPayload blob
// Return: Success or Error code.
extern int ERP_WrapRawPayload(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Externally callable FWAPI Command
// Extract rawPayload
// Required Permission: 00000020 ERP Working permission with a valid TEE Token
// Input: tee token
// Input: rawPayload
// Output: rawPayload blob
// Return: Success or Error code.
extern int ERP_WrapRawPayloadWithToken(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Externally callable FWAPI Command
// Extract rawPayload
// Requires: 00000020 ERP Working permission with a valid TEE Token.
// Input: currently valid TEE Token
// Input: Payload Blob
// Output: Unwrapped rawPayload
// Return: Success or Error code.
extern int ERP_UnwrapRawPayload(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Externally callable FWAPI Command
// Command to generate a new Hash Key with an existing Generation
// Input: int - number of bytes of RND requested
// Output: The RND Data
// Return: Success or Error code.
extern int ERP_GetRNDBytes(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Externally callable FWAPI Command
// ERP-9411 - allowed for ERP_SETUP, ERP_WORKING or ERP_UPDATE userpermissions.
// return public key for keypair.
// input: ECIES KeyPair Blob
// output: ASN1.DER encoded public key from the blob.
// Return: Success or Error code.
extern int ERP_GetECPublicKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Externally callable FWAPI Command
// Do ECIES Key Derivation for VAU Protocol
// input: TEE Token
// input: ECIES KeyPair Blob
// input: Client ECIES Public key
// output: AES128 vau protocol key.
// Return: Success or Error code.
extern int ERP_DoECIES128(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Externally callable FWAPI Command
// Extract VAUSIG private key for VAU Signatures
// input: TEE Token
// input: ECSIG KeyPair Blob
// input: Data to be signed
// output: Signature
// Return: Success or Error code.
extern int ERP_GetVAUSIGPrivateKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Export a single Blob Generation using the AES256 MBK.
// Requires: 20000000 - Administrator permission.
// Blob Generation must exist in the HSM
// input: Blob Generation
// output: BUBlob Structure
extern int ERP_ExportSingleBlobKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Import a single Blob Generation using the AES256 MBK.
// Requires: 20000000 - Administrator permission.
// The MBK loaded in the HSM must match that in the BUBlob
// The GEneration in the BUBlob must not already be present in the HSM, neither with the same key value, nor a different one.
// input: BUBlob Structure
// output: None.
extern int ERP_ImportSingleBlobKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Create a new Blob containing the contents of an existing blob but reencoded with a different Generation.
// The intention here is to allow preservation of blob contents when the blob generation of the original blob is to be deleted.   The
//   intention is that only special cases will require this treatment, e.g. Security reasons mandate hard retiral of some keys
// There is a guarantee that the new blob and the old blob will return the same Check Value in calls to GetBlobContentHash()
// Requires: 00000200 ERP Setup or 00002000 ERP Update Permission
// The Generation of the blob must be present in the HSM.
// input:  newBlobGeneration               an integer Blob Generation for the new Blob.   This must be present in the HSM.
// input:  blobIn                          The blob that is to be migrated.   The Blob generation for this blob must be present in the HSM.
// output: new migrated blob.
extern int ERP_MigrateBlob(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// For Setup or Update users: Calculate and return the SHA256 hash of the contents of a blob.
// Requires: 00000200 ERP Setup or 00002000 ERP Update Permission
// Working users should use GetBlobContentHashWithToken
// The Generation of the blob must be present in the HSM.
// The intention here is to allow identification of a key that may be stored in multiple blobs with different generations.
// The only guarantee is that multiple calls to this method with blobs containing the same contents will return the same hash.
// "The same contents" implies that the blobs were related through use of ERP_MigrateBlob.
// input: Blob to be hashed.
// output: hash
extern int ERP_GetBlobContentHash(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

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
extern int ERP_GetBlobContentHashWithToken(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// For Working users with a TEE Token: Sign data using the AUT Token with a brainpoolp256
// Requires: 00000020 ERP Working permission with a valid TEE Token.
// The Generation of the blob must be present in the HSM.
// input: TEE Token
// input: VAUAUT KeyPair Blob
// input: Data to be signed
// Return: Success or Error code.
// output: Signature
extern int ERP_SignVAUAUTToken(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Externally callable FWAPI Command
// Extract rawPayload
// Required Permission: setup or update
// Input: pseudoname log key package payload
// Output: pseudoname log key package blob
// Return: Success or Error code.
extern int ERP_WrapPseudonameLogKeyPackage(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Externally callable FWAPI Command
// Extract AES 128 Pseudoname log key
// Required Permission: Working
// Input: currently valid TEE Token
// Input: pseudoname log Key package Blob
// Output: Symmetric AES128 hash key.
// Return: Success or Error code.
extern int ERP_UnwrapPseudonameLogKeyPackage(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Externally callable FWAPI Command
// wrap externally given log key into blob
// Required Permission: setup or update
// Input: AES-128 bit log key
// Output: pseudoname log key blob
// Return: Success or Error code.
extern int ERP_WrapPseudonameLogKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Externally callable FWAPI Command
// Extract AES 128 Pseudoname log key
// Required Permission: Working
// Input: currently valid TEE Token
// Input: pseudoname log Key Blob
// Output: Symmetric AES128 hash key.
// Return: Success or Error code.
extern int ERP_UnwrapPseudonameLogKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

#endif
