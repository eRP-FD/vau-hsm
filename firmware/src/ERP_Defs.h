/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021, 2024
 * (C) Copyright IBM Corp. 2021, 2024
 *
 * non-exclusively licensed to gematik GmbH
 **************************************************************************************************/

#ifndef ERP_DEFS_H
#define ERP_DEFS_H

// ERP-7949 Use named literals for permissions
#define ERP_SETUP_PERMISSION 2
#define ERP_WORKING_PERMISSION 1
#define ERP_UPDATE_PERMISSION 3
// All of these in bits...
#define SHA_256_LEN 256
#define SHA_384_LEN 384
#define SHA_512_LEN 512
#define AES_256_LEN 256
#define AES_128_LEN 128
#define NONCE_LEN 256
#define MAX_RND_BYTES 320

typedef enum SignatureAlgorithm {
    SIGNATURE_ALGORITHM_unsupported = 0,
    SIGNATURE_ALGORITHM_ecdsaWithSHA256 = 1,
    SIGNATURE_ALGORITHM_ecdsaWithSHA384,
    SIGNATURE_ALGORITHM_ecdsaWithSHA512,
} SignatureAlgorithm_t;

typedef enum CurveId {
    CurveId_Unknown = 0,
    CurveId_NistP256,
    CurveId_Brainpoolp256r1,
    CurveId_Secp384r1,
    CurveId_Secp521r1,
} CurveId_t;

// Size of EC point coordinate in bits
#define EC_COORD_SIZE 0x100
// Size of TPM key Name hashes in bytes.
#define TPM_NAME_LEN (SHA_256_LEN/8) + 2
// ERP-10197 - Expiry period of pseudoname Key Blobs in seconds - currently eight Months
// Synodic month is the lunar month is 29.531 days.The number here is actually a 30 day month.
// Average calendar month is 30.43 days.
// The logic here is that intended working lifetime of this is six months.
//    Plus a month before to allow creation and deployment overhead and
//    a month afterwards to allow imprecise retirment
// The exact length of the month is not critical.
#define THIRTY_DAY_MONTH_S (30*24*60*60)
#define PSEUDONAME_BLOB_EXPIRY THIRTY_DAY_MONTH_S * 8
// The Blob Domain for which this firmware has been built.
// This can be modified by compilation option during the build process.
// Intended values are "SIML" - Simulator
// "REFZ" - reference, RU And TU.
// "PROD" - production, PU.
// This is intended to make it really easy to identify in which domain a blob has been generated.
// The blob domain will be visible in plain in the blob structure.

#ifndef BLOB_DOMAIN
#define BLOB_DOMAIN "SIML"
#endif

// Sometimes we cannot avoid using a big buffer when there is no way to know how big a buffer needs to be.
//    Where we use this in the code, we need to chceck the results for an overflow error.
// The Utimaco Methods that require this will return a buffer overflow error, so writeover past the
//    end of the buffer will not happen.
#define ERP_BIG_BUFFER 2000

// The maximum number of simultaneously loaded blob generation keys in the HSM
#define MAX_LOADED_BLOB_GENERATIONS 200
#define CHECK_NOT_NULL(err,ptr,index) if (ptr == NULL) { err = E_ERP_MALLOC; INDEX_ERR(err,index);}

// TPM Curve IDs.
// Note most of these are just assigned by TCG but not necessarily actually supported by a TPM.
#define TPM_ECC_NONE 0x0000
#define TPM_ECC_NIST_P192 0x0001
#define TPM_ECC_NIST_P224 0x0002
// The TCG Standard
#define TPM_ECC_NIST_P256 0x0003
#define TPM_ECC_NIST_P384 0x0004
#define TPM_ECC_NIST_P521 0x0005
// TCG Standard curve to support ECDAA
#define TPM_ECC_BN_P256 0x0010
#define TPM_ECC_BN_P638 0x0011
#define TPM_ECC_SM2_P256 0x0020
// Brainpool
#define TPM_ECC_BP_P256_R1 0x0030
#define TPM_ECC_BP_P384_R1 0x0031
#define TPM_ECC_BP_P512_R1 0x0032
#define TPM_ECC_CURVE_25519 0x0040

// TPM Object Attributes:
// Differing Endianness determines that we cannot just define these as unsigned ints.
#define TPMA_OBJECT_RESERVED1           0 // 0x00000001
#define TPMA_OBJECT_FIXEDTPM            1 // 0x00000002
#define TPMA_OBJECT_STCLEAR             2 // 0x00000004
#define TPMA_OBJECT_FIXEDPARENT         4 // 0x00000010
#define TPMA_OBJECT_SENSITIVEDATAORIGIN 5 // 0x00000020
#define TPMA_OBJECT_USERWITHAUTH        6 // 0x00000040
#define TPMA_OBJECT_ADMINWITHPOLICY     7 //0x00000080
#define TPMA_OBJECT_NODA                10 // 0x00000400
#define TPMA_OBJECT_ENCRYPTEDDUPLICATION 11 // 0x00000800
#define TPMA_OBJECT_RESTRICTED          16 // 0x00010000
#define TPMA_OBJECT_DECRYPT             17 // 0x00020000
#define TPMA_OBJECT_SIGN                18 // 0x00040000
// These are bit flags that we don't actually use.
#define TPMA_OBJECT_RESERVED2           0x00000008
#define TPMA_OBJECT_RESERVED3           0x00000300
#define TPMA_OBJECT_RESERVED4           0x0000f000
#define TPMA_OBJECT_RESERVED5           0xfff80000

#define FREE_IF_NOT_NULL(x) if (x != NULL) {os_mem_del_set(x,0); x = NULL;}

// ERP-3712 - This MACRO will add a unique instance index to any error code in the third byte of the value.
//    it will be disabled by default.
// Uncomment this line to force this feature.
// #define INDEX_ERRORS
#ifdef INDEX_ERRORS
#define INDEX_ERR(errCode,index) (errCode |= ((index <<8) & 0x0000FF00))
#else
#define INDEX_ERR(errCode,index)
#endif

#endif
