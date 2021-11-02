/**************************************************************************************************
 * $File Identification                   $
 * $Filename          : ERP_ext.h         $
 * $Module version    : FF.FF.01.01       $
 * $Module name       : ERP               $
 * $Release Date      : DD.MM.YYYY        $
 *
 * Author             : Chris Cracknell
 *
 * Description        : Declaration of extern Functions (called by the host application)
 *						This module implements the IBM eRezept custom HSM firmware
 **************************************************************************************************/
#ifndef __ERP_EXTERNAL_API_H
#define __ERP_EXTERNAL_API_H

#include <cryptoserversdk/db.h>

/******************************************************************************
 * Function Prototypes
 ******************************************************************************/
/** @addtogroup ERP_ext
  * @{
  */

// Method to carry out a dump of currently allocated HSM Heap.
// Output will be logged by smos printed in the simulator.
// In Production the method will return E_ERP_DEV_FUNCTION_ONLY
extern int ERP_DumpHSMMemory(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Command to generate a new Blob Trust Key with a new Generation
// Input: unsigned int Desired Generation - if zero, then the highest available Generation
//           in the HSM is incremented by one and used.   Otherwise the input value must
//           not match any existing Blob Key Generations present in the HSM.
// Output: none
extern int ERP_GenerateBlobKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Command to gdelete a Blob Trust Key with a given Generation
// Input: unsigned int Undesired Generation - the input value must
//        match an existing Blob Key Generation present in the HSM.
// Output: none
extern int ERP_DeleteBlobKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Command to list the currently loaded Blob Trust Keys
// Input: none
// Output: List of <Generation,SHA256 Hashes of Key Values>
extern int ERP_ListBlobKeys(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Command to generate a new Hash Key Blob with an existing Generation
// Input: unsigned int Desired Generation - if zero, then the highest available Generation
//           in the HSM is used.   Otherwise the input value must
//           not match any existing Blob Key Generations present in the HSM.
// Output: Hash Key Blob
extern int ERP_GenerateHashKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Command to generate a new Derivation Key Blob with an existing Generation
// Input: unsigned int Desired Generation - if zero, then the highest available Generation
//           in the HSM is used.   Otherwise the input value must
//           not match any existing Blob Key Generations present in the HSM.
// Output: Derivation Key Blob
extern int ERP_GenerateDerivationKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Command to generate a new ECIES KeyPair for ECIES key exchange with an existing Generation
// Input: unsigned int Desired Generation - if zero, then the highest available Generation
//           in the HSM is used.   Otherwise the input value must
//           not match any existing Blob Key Generations present in the HSM.
// Output: ECIES KeyPair Blob
extern int ERP_GenerateECIESKeyPair(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Generate CSR for an ECIES Keypair
// Input: ECIES KeyPair Blob
// Input: Candidate CSR with all valid fields, except public key and signature 
//    which must be present and formally correct, but the content data is irrelevant.
//    The Signature does not need to be valid either.
// Output: ASN1.DER encoded CSR
extern int ERP_GenerateECIESCSR(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Command to generate a new EC Signature KeyPair for VAU Signing operations
// Input: unsigned int Desired Generation - if zero, then the highest available Generation
//           in the HSM is used.   Otherwise the input value must
//           not match any existing Blob Key Generations present in the HSM.
// Output: ECIES KeyPair Blob
extern int ERP_GenerateVAUSIGKeyPair(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Generate CSR for a VAUSIG Keypair
// Input: VAUSIG KeyPair Blob
// Input: Candidate CSR with all valid fields, except public key and signature 
//    which must be present and formally correct, but the content data is irrelevant.
//    The Signature does not need to be valid either.
// Output: ASN1.DER encoded CSR
extern int ERP_GenerateVAUSIGCSR(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Command to generate a new NONCE Blob with an existing Generation
// Input: unsigned int Desired Generation - if zero, then the highest available Generation
//           in the HSM is used.   Otherwise the input value must
//           not match ay existing Blob Key Generations present in the HSM.
// Output: Hash Key Blob
extern int ERP_GenerateNONCE(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Not present Command - will return E_ERP_OBSOLETE_FUNCTION
extern int ERP_NotUsed(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Command to add a trusted TPM Manufacturer Root CA certificate.
// Input: ASN1.DER encoded x509r3 Certificate for the TPM Manufacturer Root CA.
// Output: Trusted TPM Manufacturer Root Certificate Blob 
extern int ERP_TrustTPMMfr(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);		// SFC = 11

// Enroll a TPM Endorsement Key.
// Input: TPM Manufacturer Root Blob
// Input: ASN1.DER encoded x509r3 certificate for the Endorsement Key
// Input: NONCE Blob
// Input: Signature with EKPriv over (EKPub | NONCE)
// Output: Trusted EK Blob
extern int ERP_EnrollTPMEK(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);		// SFC = 12

// get an Attestation Key credential Chalenge to be signed by the TPM.
// Input: Known Endoresement Key Blob
// Input: TPM Name hash (0x000b + SHA256) of AK Public - used by TPM as name
// Input: TBD - either ASN1.DER encoded public key or x509r3 certificate for the Attestation Key
// Output: TPM2 Secret
// Output: TPM2 Credential
// Output: Credential Challenge Blob
extern int ERP_GetAKChallenge(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);		// SFC = 13

// Enroll an Attestation Key using the results of a TPM decryption of the credential challenge.
// Input: Known Endoresement Key Blob
// Input: TPM Name hash (0x000b + SHA256) of AK Public - used by TPM as name
// Input: TBD - either ASN1.DER encoded public key or x509r3 certificate for the Attestation Key
// Input: Decrypted Credential
// Input: Credential Challenge Blob
// Output: Trusted AK Blob
extern int ERP_EnrollTPMAK(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);		// SFC = 14

// Enroll a VAU Software stack quote.
// Input: TPM Name hash (0x000b + SHA256) of AK Public - used by TPM as name
// Input: Trusted AK Blob
// Input: NONCE Blob
// Input: Quote Data from TPM
//        The quote data will include a NONCE-derived value of HMAC(HSM NONCE,"ERP_ENROLLMENT")
// Input: TPM Signature of quote data and NONCE.
// Output: Trusted Quote Blob
extern int ERP_EnrollEnclave(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);		// SFC = 15

// Get a time limited Token to use the HSM as a VAU
// Input: TPM Name hash (0x000b + SHA256) of AK Public - used by TPM as name
// Input: Trusted AK Blob
// Input: NONCE Blob
// Input: Trusted Quote Blob
// Input: Quoted Data - TBD exact sub-structure here?
//        The quote data will include a NONCE-derived value of HMAC(HSM NONCE,"ERP_ATTESTATION")
// Input: TPM Signature over the quoted data using NONCE and AK
// Output: TEE Token Blob
extern int ERP_GetTEEToken(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);		// SFC = 16

// Derive a TASK Persistence symmetric key.
// Input: currently valid TEE Token
// Input: Input Derivation Data
// Input: Initial Derivation 1 is true, 0 is false
//          if Initial Derivation then the HSM will add extra data to the derivation data which must be 
//          stored by the application for subsequent derivations of this key.
// Input: Derivation Key Blob
// Output: Symmetric derived key.
// Output: Used Derivation data - data actually used for the derivation, including any extra added by HSM.
extern int ERP_DeriveTaskKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);		// SFC = 17
// As ERP_deriveTaskKey, but for Audit persistence keys.
extern int ERP_DeriveAuditKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);		// SFC = 18
// As ERP_deriveTaskKey, but for Communications persistence keys.
extern int ERP_DeriveCommsKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);		// SFC = 19

// Extract AES 256 Hash key
// Input: currently valid TEE Token
// Input: Hash Key Blob
// Output: Symmetric AES256 hash key.
extern int ERP_UnwrapHashKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Command to generate a new Hash Key with an existing Generation
// Input: int - number of bytes of RND requested
// Output: The RND Data
extern int ERP_GetRNDBytes(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// return public key for keypair.
// input: TEE Token
// input: ECIES KeyPair Blob
// output: ASN1.DER encoded public key from the blob.
extern int ERP_GetECPublicKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Do ECIES Key Derivation for VAU Protocol
// input: TEE Token
// input: ECIES KeyPair Blob
// input: Client ECIES Public key
// output: AES128 vau protocol key.
extern int ERP_DoECIES128(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

// Extract VAUSIG private key for VAU Signatures
// input: TEE Token
// input: ECSIG KeyPair Blob
// input: Data to be signed
// output: Signature
extern int ERP_GetVAUSIGPrivateKey(T_CMDS_HANDLE* p_hdl, int l_cmd, unsigned char* p_cmd);

#endif
