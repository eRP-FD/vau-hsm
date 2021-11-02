/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021
 * (C) Copyright IBM Corp. 2021
 * SPDX-License-Identifier: CC BY-NC-ND 3.0 DE
 **************************************************************************************************/

#ifndef ERP_ERROR_H_
#define ERP_ERROR_H_

// Error codes from 0xB1010000 Are directly from the firmware
// For error codes not listed here see the Utimaco Docs for meaning.
// Error Codes from 0x42420000 Are from the interface library
#define ERP_ERR_NOERROR                 (unsigned int) 0x00000000
#define ERP_ERR_NO_CONNECTION           (unsigned int) 0x42420001
#define ERP_ERR_ALREADY_LOGGED_IN       (unsigned int) 0x42420002
#define ERP_ERR_BAD_CONNECTION          (unsigned int) 0x42420003
#define ERP_ERR_BAD_CREDENTIAL_FORMAT   (unsigned int) 0x42420004
#define ERP_ERR_NOT_LOGGED_IN           (unsigned int) 0x42420005
#define ERP_ERR_RESPONSE_TOO_SHORT      (unsigned int) 0x42420006
#define ERP_ERR_ASN1ENCODING_ERROR      (unsigned int) 0x42420007
#define ERP_ERR_ASN1DECODING_ERROR      (unsigned int) 0x42420008
#define ERP_ERR_RESPONSE_TOO_LONG       (unsigned int) 0x42420009
#define ERP_ERR_CALLOC_ERROR            (unsigned int) 0x4242000a
#define ERP_ERR_FREE_ERROR              (unsigned int) 0x4242000b
#define ERP_ERR_BAD_RETURN_FORMAT       (unsigned int) 0x4242000c
#define ERP_ERR_BUFFER_TOO_SMALL        (unsigned int) 0x4242000d
#define ERP_ERR_NOT_IMPLEMENTED         (unsigned int) 0x4242000e
#define ERP_ERR_BAD_SESSION_HANDLE      (unsigned int) 0x4242000f
#define ERP_ERR_TOO_MANY_SESSIONS       (unsigned int) 0x42420010
#define ERP_ERR_BAD_DEVICE_SPEC         (unsigned int) 0x42420011
#define ERP_ERR_SET_CLUSTER_FALLBACK    (unsigned int) 0x42420012
// HSM VAU Firmware Errors.
#define ERP_ERR_SUCCESS                   0x00000000
#define ERP_ERR_PERMISSION_DENIED         0xB1010001      // permission denied
#define ERP_ERR_PARAM                     0xB1010002      // invalid parameter
#define ERP_ERR_PARAM_LEN                 0xB1010003      // invalid parameter length
#define ERP_ERR_MALLOC                    0xB1010004      // memory allocation failed
#define ERP_ERR_MODE                      0xB1010005      // invalid mode
#define ERP_ERR_ITEM_NOT_FOUND            0xB1010006      // item not found
#define ERP_ERR_MODULE_DEP                0xB1010007      // unresolved module dependency
#define ERP_ERR_FILE_IO                   0xB1010008      // file I/O error
#define ERP_ERR_ASN1_PARSE_ERROR          0xB1010009      // ASN1 Data fails to parse correctly.
#define ERP_ERR_ASN1_CONTENT_ERROR        0xB101000A      // ASN1 content parses, but is not acceptable for the command.
#define ERP_ERR_UNKNOWN_BLOB_GENERATION   0xB101000B      // Blob Generation does not match any loaded key.
#define ERP_ERR_NOT_IMPLEMENTED_YET       0xB101000C      // Devtime only - method not yet implemented.
#define ERP_ERR_BAD_BLOB_GENERATION       0xB101000D      // Blob Generation is not ok for the operation.
#define ERP_ERR_AES_KEY_ERROR             0xB101000E      // There is an error with using an AES KEY
#define ERP_ERR_KEY_USAGE_ERROR           0xB101000F      // A key is not allowed to be used for the intended usage 
#define ERP_ERR_BAD_BLOB_DOMAIN           0xB1010010      // A Blob is for a different domain to this version of the firmware.
#define ERP_ERR_BAD_BLOB_AD               0xB1010011      // A Sealed Blob has failed its' Associated Data Check.
#define ERP_ERR_WRONG_BLOB_TYPE           0xB1010012      // A Sealed Blob is not of the correct type for the operation.
#define ERP_ERR_OBSOLETE_FUNCTION         0xb1010013      // The function called is obsolete and should no longer be called.
#define ERP_ERR_DEV_FUNCTION_ONLY         0xb1010014      // The function called is onyl available in Development builds.
#define ERP_ERR_MAX_BLOB_GENERATIONS      0xb1010015      // The maximum number of simultaneously loadblob key generations has been reached,
#define ERP_ERR_INTERNAL_BUFFER_ERROR     0xB1010016      // Internal error - An internal buffer was too small.
#define ERP_ERR_NO_ECC_DOMAIN_PARAMETERS  0xb1010017
#define ERP_ERR_FAILED_ECC_KEYPAIR_GENERATION 0xb1010018
#define ERP_ERR_CERT_BAD_SUBJECT_ALG      0xB1010019      // x509 Subject key algorithm is not ecdsaWithSHA256.
#define ERP_ERR_CERT_BAD_SIGNATURE_ALG    0xB101001A      // x509 Signature Algorithm is not ecdsaWithSHA256.
#define ERP_ERR_CERT_BAD_SUBJECT_ENCODING 0xB101001B      // x509 Subject key is not idECPublicKey.
#define ERP_ERR_CERT_UNSUPPORTED_CURVE    0xB101001C      // x509 Subject key does non use a curve that we support.
#define ERP_ERR_CERT_BAD_SIGNATURE_FORMAT 0xB101001D      // x509 Signature body is not correctly formatted.
#define ERP_ERR_BLOB_EXPIRED              0xB101001E      // An ephemeral blob is past its' sell by date.
#define ERP_ERR_BAD_ANSIX9_62_LENGTH      0xB101001F      // An ANSI X9.62 encoded public key has the wrong length.
#define ERP_ERR_BAD_TPM_NAME_ALGORITHM    0xB1010020      // A TPM Name hash algorithm is not SHA256 (0x000B).
#define ERP_ERR_BAD_ANSIX9_62_ENCODING    0xB1010021      // An ANSI X9.62 encoded public key is badly encoded.
#define ERP_ERR_TPM_NAME_MISMATCH         0xB1010022      // An ANSI X9.62 encoded or TPMT_PUBLIC encoded public key does not match the TPM name hash.
#define ERP_ERR_BAD_TPMT_PUBLIC_LENGTH    0xB1010023      // A TPMT_PUBLIC Key has the wrong length.   Should be 0x78
#define ERP_ERR_BAD_TPMT_PUBLIC_ALGORITHM 0xB1010024      // A TPMT_PUBLIC Key has the wrong algorithm.   Should be 0x023 TPMI_ALG_ECC.
#define ERP_ERR_BAD_TPMT_PUBLIC_FORMAT    0xB1010025      // A TPMT_PUBLIC Key is badly formatted.
#define ERP_ERR_FAIL_AK_CREDENTIAL_MATCH  0xB1010026      // The returned plain text AK Challenge credential does not match the challenge.
#define ERP_ERR_BAD_BLOB_TIME             0xB1010027      // A Blob has an invalid time, e.g. later than now? 
#define ERP_ERR_TPM_UNSUPPORTED_CURVE     0xB1010028      // An ECC Curve is not supported by the TPM.
#define ERP_ERR_BAD_TPMT_SIGNATURE_LENGTH 0xB1010029      // The length of the TPMT_SIGNATURE is wrong.
#define ERP_ERR_BAD_TPMT_SIGNATURE_FORMAT 0xB1010030      // The format of the TPMT_SIGNATURE is wrong.
#define ERP_ERR_BAD_TPMT_PUBLIC_ATTRIBUTES    0xB1010031  // The attributes of a TPMT_PUBLIC are not acceptable for an attestation key.
#define ERP_ERR_BAD_QUOTE_HEADER          0xB1010032      // The fixed header data of a TPM Quote is invalid.
#define ERP_ERR_BAD_QUOTE_LENGTH          0xB1010033      // The TPM Quote length is invalid.
#define ERP_ERR_QUOTE_NONCE_MISMATCH      0xB1010034      // The Qualifying Data in a TPM Quote (NONCE) does not match the challenge.
#define ERP_ERR_BAD_QUOTE_FORMAT          0xB1010035      // The TPM Quote format is false.
#define ERP_ERR_BAD_QUOTE_HASH_FORMAT     0xB1010036      // The TPM Quote Hash format is false.   Must be SHA256 (0x000B)
#define ERP_ERR_QUOTE_SIGNER_MISMATCH     0xB1010037      // The two TPM Quotes were not signed by the same AK.
#define ERP_ERR_QUOTE_PCRSET_MISMATCH     0xB1010038      // The two TPM Quotes do not attest the same set of PCRS.
#define ERP_ERR_QUOTE_DIGEST_MISMATCH     0xB1010039      // The two TPM Quotes do not report the same digest.
#define ERP_ERR_ECIES_CURVE_MISMATCH      0xB101003a      // The client public key and ECIES keypair do not use the same curve.
#define ERP_ERR_CSR_ADMISSIONS_MISMATCH   0xB101003b      // The admissions section of a candidate CSR does not match the keypair.
#define ERP_ERR_BLOB_SEMAPHORE_DEADLOCK   0xB101003c      // The BLOB Semaphore has caused a deadlock.
#define ERP_ERR_DERIVATION_DATA_LENGTH    0xB101003d      // The derivation data for a key derivation is too short - it must be at least as long as the KeyPrefix.
#define ERP_ERR_CERT_WRONG_ISCA_VALUE     0xB101003e      // x509 Certificate BasicConstraints isCA value is wrong for the purpose of this certificate.
#define ERP_ERR_CERT_WRONG_ROOT_STATUS    0xB101003f      // x509 Certificate Root status is wrong for this certificate.   (is root, when it shouldn't be, or vice versa)
#define ERP_ERR_CERT_BAD_BASIC_CONSTRAINTS 0xB1010040     // x509 Certificate Basic Constraints field is badly formatted.
#define ERP_ERR_BACKUP_WRONG_MBK_NAME     0xB1010041      // HSM AES 256 Master Backup Key name does not match the backup blob.
#define ERP_ERR_BACKUP_WRONG_MBK_KCV      0xB1010042      // HSM AES 256 Master Backup Key Check Value (KCV) does not match the backup blob.
#define ERP_ERR_BACKUP_WRONG_DATA_LEN     0xB1010043      // The length of the encoded Data field in a backup blob is wrong.
#define ERP_ERR_BACKUP_WRONG_BLOB_KEY_KCV 0xB1010044      // The KCV of the decoded blob key in the backup does not match the KCV in the metadata.
// END FIRMWARE ERROR CODES
 
// Codes from Utimaco:
#define E_ASN1_ALL            0xB0910000      /* BIT MASK for all Utimaco ASN Error codes.                         */
#define E_ASN1_MEM            0xB0910001      /* Memory Error                           */
#define E_ASN1_FLAG           0xB0910002      /* Parameter flag is incorrect            */
#define E_ASN1_TAB_OVL        0xB0910003      /* ASN1_ITEM table overflow               */
#define E_ASN1_BAD_ZKA        0xB0910004      /* bad ZKA format                         */
#define E_ASN1_DATASIZE       0xB0910005      /* ASN1 data overrun                      */
#define E_ASN1_TAGSIZE        0xB0910006      /* tag too big                            */
#define E_ASN1_INDEF_LEN      0xB0910007      /* indefinite length not supportet        */
#define E_ASN1_LENSIZE        0xB0910008      /* lenght field too big                   */
#define E_ASN1_STACK_OVL      0xB0910009      /* internal stack overflow                */
#define E_ASN1_NOT_FOUND      0xB091000A      /* item not found                         */
#define E_ASN1_BUFF_OVL       0xB091000B      /* ASN1 buffer overflow                   */
#define E_ASN1_ITEMCOUNT      0xB091000C      /* bad value of 'nitems' in ITEM table    */
#define E_ASN1_BADTAG         0xB091000D      /* zero tag                               */
#define E_ASN1_BAD_PKCS1      0xB091000E      /* bad PKCS#1 format                      */
#define E_ASN1_DECODE_ERR     0xB091000F      /* decoding error                         */
#define E_ASN1_SIZE_EXCEEDED  0xB0910010      /* calculated size exceeds given datasize */

#define E_ECDSA_VERIFY_FAILED 0xB09C0007      /* signature verification failed                */

  // error codes that are not present in the client code
#define E_AES_GCM_AUTH_TAG_FAILED 0xB08B000E  /* Tag verification on CCM/GCM decrypt failed */

// If INDEX_ERRORS is defined in the firmware build then error codes will have been modified in the 
//    third byte to uniqely identify their source location.
// This macro will strip the index out allowing direct comparisons with the above codes.
#define ERR_INDEX_MASK 0xFFFF00FF
#define STRIP_ERR_INDEX(x) (x & ERR_INDEX_MASK)

#endif
