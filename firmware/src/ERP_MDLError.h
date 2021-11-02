/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021
 * (C) Copyright IBM Corp. 2021
 * SPDX-License-Identifier: CC BY-NC-ND 3.0 DE
 **************************************************************************************************/

#ifndef ERP_MDL_ERROR_H
#define ERP_MDL_ERROR_H

// This file is duplicated in the Client subproject - make sure that changes introduced are copied into both 
// destinations.

//-----------------------------------------------------------------------------
// Error Codes:  (0xB0000000 | (ERP_MDL_ID << 16) | (errno))
//-----------------------------------------------------------------------------

// --- BEGIN ERROR CODES ---

#define E_ERP                         0xB101          // CryptoServer module ERP

// ERP-3712 - If INDEX_ERRORS is defined then firmware will add a unique instance index to any error code in the third byte of the value.
//    it will be disabled by default.

#define E_ERP_SUCCESS                   0x00000000
#define E_ERP_PERMISSION_DENIED         0xB1010001      // permission denied
#define E_ERP_PARAM                     0xB1010002      // invalid parameter
#define E_ERP_PARAM_LEN                 0xB1010003      // invalid parameter length
#define E_ERP_MALLOC                    0xB1010004      // memory allocation failed
#define E_ERP_MODE                      0xB1010005      // invalid mode
#define E_ERP_ITEM_NOT_FOUND            0xB1010006      // item not found
#define E_ERP_MODULE_DEP                0xB1010007      // unresolved module dependency
#define E_ERP_FILE_IO                   0xB1010008      // file I/O error
#define E_ERP_ASN1_PARSE_ERROR          0xB1010009      // ASN1 Data fails to parse correctly.
#define E_ERP_ASN1_CONTENT_ERROR        0xB101000A      // ASN1 content parses, but is not acceptable for the command.
#define E_ERP_UNKNOWN_BLOB_GENERATION   0xB101000B      // Blob Generation does not match any loaded key.
#define E_ERP_NOT_IMPLEMENTED_YET       0xB101000C      // Devtime only - method not yet implemented.
#define E_ERP_BAD_BLOB_GENERATION       0xB101000D      // Blob Generation is not ok for the operation.
#define E_ERP_AES_KEY_ERROR             0xB101000E      // There is an error with using an AES KEY
#define E_ERP_KEY_USAGE_ERROR           0xB101000F      // A key is not allowed to be used for the intended usage 
#define E_ERP_BAD_BLOB_DOMAIN           0xB1010010      // A Blob is for a different domain to this version of the firmware.
#define E_ERP_BAD_BLOB_AD               0xB1010011      // A Sealed Blob has failed its' Associated Data Check.
#define E_ERP_WRONG_BLOB_TYPE           0xB1010012      // A Sealed Blob is not of the correct type for the operation.
#define E_ERP_OBSOLETE_FUNCTION         0xb1010013      // The function called is obsolete and should no longer be called.
#define E_ERP_DEV_FUNCTION_ONLY         0xb1010014      // The function called is onyl available in Development builds.
#define E_ERP_MAX_BLOB_GENERATIONS      0xb1010015      // The maximum number of simultaneously loadblob key generations has been reached,
#define E_ERP_INTERNAL_BUFFER_ERROR     0xB1010016      // Internal error - An internal buffer was too small.
#define E_ERP_NO_ECC_DOMAIN_PARAMETERS  0xb1010017
#define E_ERP_FAILED_ECC_KEYPAIR_GENERATION 0xb1010018
#define E_ERP_CERT_BAD_SUBJECT_ALG      0xB1010019      // x509 Subject key algorithm is not ecdsaWithSHA256.
#define E_ERP_CERT_BAD_SIGNATURE_ALG    0xB101001A      // x509 Signature Algorithm is not ecdsaWithSHA256.
#define E_ERP_CERT_BAD_SUBJECT_ENCODING 0xB101001B      // x509 Subject key is not idECPublicKey.
#define E_ERP_CERT_UNSUPPORTED_CURVE    0xB101001C      // x509 Subject key does non use a curve that we support.
#define E_ERP_CERT_BAD_SIGNATURE_FORMAT 0xB101001D      // x509 Signature body is not correctly formatted.
#define E_ERP_BLOB_EXPIRED              0xB101001E      // An ephemeral blob is past its' sell by date.
#define E_ERP_BAD_ANSIX9_62_LENGTH      0xB101001F      // An ANSI X9.62 encoded public key has the wrong length.
#define E_ERP_BAD_TPM_NAME_ALGORITHM    0xB1010020      // A TPM Name hash algorithm is not SHA256 (0x000B).
#define E_ERP_BAD_ANSIX9_62_ENCODING    0xB1010021      // An ANSI X9.62 encoded public key is badly encoded.
#define E_ERP_TPM_NAME_MISMATCH         0xB1010022      // An ANSI X9.62 encoded or TPMT_PUBLIC encoded public key does not match the TPM name hash.
#define E_ERP_BAD_TPMT_PUBLIC_LENGTH    0xB1010023      // A TPMT_PUBLIC Key has the wrong length.   Should be 0x78
#define E_ERP_BAD_TPMT_PUBLIC_ALGORITHM 0xB1010024      // A TPMT_PUBLIC Key has the wrong algorithm.   Should be 0x023 TPMI_ALG_ECC.
#define E_ERP_BAD_TPMT_PUBLIC_FORMAT    0xB1010025      // A TPMT_PUBLIC Key is badly formatted.
#define E_ERP_FAIL_AK_CREDENTIAL_MATCH  0xB1010026      // The returned plain text AK Challenge credential does not match the challenge.
#define E_ERP_BAD_BLOB_TIME             0xB1010027      // A Blob has an invalid time, e.g. later than now? 
#define E_ERP_TPM_UNSUPPORTED_CURVE     0xB1010028      // An ECC Curve is not supported by the TPM.
#define E_ERP_BAD_TPMT_SIGNATURE_LENGTH 0xB1010029      // The length of the TPMT_SIGNATURE is wrong.
#define E_ERP_BAD_TPMT_SIGNATURE_FORMAT 0xB1010030      // The format of the TPMT_SIGNATURE is wrong.
#define E_ERP_BAD_TPMT_PUBLIC_ATTRIBUTES    0xB1010031  // The attributes of a TPMT_PUBLIC are not acceptable for an attestation key.
#define E_ERP_BAD_QUOTE_HEADER          0xB1010032      // The fixed header data of a TPM Quote is invalid.
#define E_ERP_BAD_QUOTE_LENGTH          0xB1010033      // The TPM Quote length is invalid.
#define E_ERP_QUOTE_NONCE_MISMATCH      0xB1010034      // The Qualifying Data in a TPM Quote (NONCE) does not match the challenge.
#define E_ERP_BAD_QUOTE_FORMAT          0xB1010035      // The TPM Quote format is false.
#define E_ERP_BAD_QUOTE_HASH_FORMAT     0xB1010036      // The TPM Quote Hash format is false.   Must be SHA256 (0x000B)
#define E_ERP_QUOTE_SIGNER_MISMATCH     0xB1010037      // The two TPM Quotes were not signed by the same AK.
#define E_ERP_QUOTE_PCRSET_MISMATCH     0xB1010038      // The two TPM Quotes do not attest the same set of PCRS.
#define E_ERP_QUOTE_DIGEST_MISMATCH     0xB1010039      // The two TPM Quotes do not report the same digest.
#define E_ERP_ECIES_CURVE_MISMATCH      0xB101003a      // The client public key and ECIES keypair do not use the same curve.
#define E_ERP_CSR_ADMISSIONS_MISMATCH   0xB101003b      // The admissions section of a candidate CSR does not match the keypair.
#define E_ERP_BLOB_SEMAPHORE_DEADLOCK   0xB101003c      // The BLOB Semaphore has caused a deadlock.
#define E_ERP_DERIVATION_DATA_LENGTH    0xB101003d      // The derivation data for a key derivation is too short - it must be at least as long as the KeyPrefix.
#define E_ERP_CERT_WRONG_ISCA_VALUE     0xB101003e      // x509 Certificate BasicConstraints isCA value is wrong for the purpose of this certificate.
#define E_ERP_CERT_WRONG_ROOT_STATUS    0xB101003f      // x509 Certificate Root status is wrong for this certificate.   (is root, when it shouldn't be, or vice versa)
#define E_ERP_CERT_BAD_BASIC_CONSTRAINTS 0xB1010040     // x509 Certificate Basic Constraints field is badly formatted.
#define E_ERP_BACKUP_WRONG_MBK_NAME     0xB1010041      // HSM AES 256 Master Backup Key name does not match the backup blob.
#define E_ERP_BACKUP_WRONG_MBK_KCV      0xB1010042      // HSM AES 256 Master Backup Key Check Value (KCV) does not match the backup blob.
#define E_ERP_BACKUP_WRONG_DATA_LEN     0xB1010043      // The length of the encoded Data field in a backup blob is wrong.
#define E_ERP_BACKUP_WRONG_BLOB_KEY_KCV 0xB1010044      // The KCV of the decoded blob key in the backup does not match the KCV in the metadata.
// --- END ERROR CODES ---

#endif
