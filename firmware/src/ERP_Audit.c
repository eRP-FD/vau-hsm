// Audit log code for the IBM eRezept VAU HSM Custom firmware.

#include "ERP_Audit.h"
#include "ERP_MDLError.h"

// Needed to avoid bug warning in winnt.h
#define no_init_all 

#include <cryptoserversdk/load_store.h>
#include <cryptoserversdk/stype.h>
#include <cryptoserversdk/memutil.h>

#include <cryptoserversdk/os_mem.h>
#include <cryptoserversdk/os_str.h>
#include <cryptoserversdk/os_task.h>
#include <cryptoserversdk/os_audit.h>

static const unsigned char AuditMessages[ERP_AUDIT_LastUsedId + 1][ERP_AUDIT_MAX_MESSAGE] = {
    "ERP Not an Event.   Report to Development team.", // ERP_AUDIT_No_Event = 0, // reserve this for programmatic use.
    "ERP New Blob Generation key generated.", // = 1,
    "ERP Blob Generation Key deleted.", // = 2,
    "ERP Blob Key Database exported.", // = 3,
    "ERP Blob Key database imported.", // = 4,
    "ERP Blob Migrated to new Generation.", // = 5,
    "ERP Failed Blob Migration.", // = 6,
    "ERP Failed Blob Use bad generation.", // = 7,
    "ERP Failed Blob Use Blob Time.", // = 8,
    "ERP Failed Blob Use Bad Decrypt.", // = 9,
    "ERP Failed Blob Use wrong Blob Type.", // = 10,
    "ERP TPM Manufacturer Root Certificate Enrolled.", // = 11,
    "ERP TPM Endorsement key Enrolled.", // = 12,
    "ERP TPM Attestation Key Enrolled.", // = 13,
    "ERP TPM Quote Enrolled.", // = 14,
    "ERP Failed TPM EK Enrollment.", // = 15,
    "ERP Failed TPM AK Enrollment.", // = 16,
    "ERP Failed TPM Quote Enrollment.", // = 17,
    "ERP Key Derivation Key generated.", // = 18,
    "ERP Hash Key generated.", // = 19,
    "ERP Failed Key Derivation Key generation.", // = 20,
    "ERP Failed Hash Key generation.", // = 21,
    "ERP Logon Failure.", // = 22,
    "ERP Permission Failure.", // = 23,
    "ERP Failed getTEEToken.", // = 24,
    "ERP Formal Parameter Check failed.", // = 25,
    "ERP Internal memory error.", // = 26,
    "ERP Internal error.", // = 27,
    "ERP Failed dNew Blob Generation key generation.", // = 28,
    "ERP Failed Key Derivation.", // = 29,
    "ERP Failed Get AK Challenge.", // = 30
    "ERP Failed TPM Manufacturer Root Certificate Enrollment.", // = 31
    "ERP Failed Get NONCE.", // = 32
    "ERP Failed Blob Generation Key Deletion.", // = 33
    "ERP Not an Event Report to Development Team." };//  34

unsigned int getAuditClass(ERP_AuditID_t id)
{
    unsigned int class = OS_AUDIT_CLASS_FIRMWARE;
    switch (id)
    {
        case ERP_AUDIT_New_Blob_Generation_Key_Generated: // = 1,
        case ERP_AUDIT_Blob_Generation_Key_Deleted: // = 2,
        case ERP_AUDIT_Blob_Key_Database_Exported: // = 3,
        case ERP_AUDIT_Blob_Key_Database_Imported: // = 4,
        case ERP_AUDIT_Blob_Migrated_To_New_Generation: // = 5,
        case ERP_AUDIT_TPM_Manufacturer_Root_Certificate_Enrolled: // = 11,
        case ERP_AUDIT_TPM_Endorsement_Key_Enrolled: // = 12,
        case ERP_AUDIT_TPM_Attestation_Key_Enrolled: // = 13,
        case ERP_AUDIT_TPM_Quote_Enrolled: // = 14,
        case ERP_AUDIT_Key_Derivation_Key_Generated: // = 18,
        case ERP_AUDIT_Hash_Key_Generated: // = 19,
            class = ERP_MDL_AUDIT_SETUP_MASK;
            break;

        case ERP_AUDIT_Failed_Blob_Migration: // = 6,
        case ERP_AUDIT_Failed_Blob_Use_Bad_Generation: // = 7,
        case ERP_AUDIT_Failed_Blob_Use_Blob_Time: // = 8,
        case ERP_AUDIT_Failed_Blob_Use_Bad_Decrypt: // = 9,
        case ERP_AUDIT_Failed_Blob_Use_wrong_Blob_Type: // = 10,
        case ERP_AUDIT_Failed_TPM_EK_Enrollment: // = 15,
        case ERP_AUDIT_Failed_TPM_AK_Enrollment: // = 16,
        case ERP_AUDIT_Failed_TPM_Quote_Enrollment: // = 17,
        case ERP_AUDIT_Failed_Key_Derivation_Key_Generation: // = 20,
        case ERP_AUDIT_Failed_Hash_Key_Generation: // = 21,
        case ERP_AUDIT_Failed_New_Blob_Generation_Key_Generated: // = 28,
        case ERP_AUDIT_Failed_Blob_Generation_Key_Deletion: // = 33,
        case ERP_AUDIT_Failed_TPM_Manufacturer_Root_Certificate_Enrollment: // = 31,
        case ERP_AUDIT_Failed_Get_AK_Challenge: // = 30,
            class = ERP_MDL_AUDIT_FAILED_SETUP_MASK;
            break;

        case ERP_AUDIT_Formal_Parameter_Check_Failed: // = 25,
        case ERP_AUDIT_Failed_Key_Derivation: // = 29,
        case ERP_AUDIT_Failed_Get_NONCE: // = 32,
        case ERP_AUDIT_Permission_Failure: // = 23,
        case ERP_AUDIT_Failed_getTEEToken: // = 24,
            class = ERP_MDL_AUDIT_FAILED_WORKING_MASK;
            break;

        case ERP_AUDIT_Logon_Failure: // = 22,
        case ERP_AUDIT_Internal_Memory_Error: // = 26,
        case ERP_AUDIT_Internal_Error: // = 27,
        case ERP_AUDIT_No_Event: // = 0, // reserve this for programmatic use.
        case ERP_AUDIT_LastUsedId: // = 34 // Used for programmatic reasons.
        default: // Use Default.
            break;
    }
    return class;

}
// Generic handler for an ERP Error code, including E_ERP_SUCCESS
unsigned int auditErr(unsigned int err)
{
    ERP_AuditID_t id = ERP_AUDIT_No_Event;
    if (err == E_ERP_SUCCESS)
    {
        return err;
    }
    switch (err)
    { // Make sure that this list includes new errors as they are added.
        case E_ERP_MALLOC: //                    0xB1010004      // memory allocation failed
            id = ERP_AUDIT_Internal_Memory_Error;
            break;
        case E_ERP_PERMISSION_DENIED: //         0xB1010001      // permission denied
        case E_ERP_PARAM: //                     0xB1010002      // invalid parameter
        case E_ERP_PARAM_LEN: //                0xB1010003      // invalid parameter length
        case E_ERP_MODE: //                      0xB1010005      // invalid mode
        case E_ERP_ITEM_NOT_FOUND: //            0xB1010006      // item not found
        case E_ERP_MODULE_DEP: //                0xB1010007      // unresolved module dependency
        case E_ERP_FILE_IO: //                   0xB1010008      // file I/O error
        case E_ERP_ASN1_PARSE_ERROR: //          0xB1010009      // ASN1 Data fails to parse correctly.
        case E_ERP_ASN1_CONTENT_ERROR: //        0xB101000A      // ASN1 content parses, but is not acceptable for the command.
        case E_ERP_UNKNOWN_BLOB_GENERATION: //    0xB101000B      // Blob Generation does not match any loaded key.
        case E_ERP_NOT_IMPLEMENTED_YET: //       0xB101000C      // Devtime only - method not yet implemented.
        case E_ERP_BAD_BLOB_GENERATION: //       0xB101000D      // Blob Generation is not ok for the operation.
        case E_ERP_AES_KEY_ERROR: //             0xB101000E      // There is an error with using an AES KEY
        case E_ERP_KEY_USAGE_ERROR: //           0xB101000F      // A key is not allowed to be used for the intended usage 
        case E_ERP_BAD_BLOB_DOMAIN: //           0xB1010010      // A Blod is for a different domain to this version of the firmware.
        case E_ERP_BAD_BLOB_AD: //               0xB1010011      // A Sealed Blob has failed its' Associated Data Check.
        case E_ERP_WRONG_BLOB_TYPE: //           0xB1010012      // A Sealed Blob is not of the correct type for the operation.
        case E_ERP_OBSOLETE_FUNCTION: //         0xb1010013      // The function called is obsolete and should no longer be called.
        case E_ERP_DEV_FUNCTION_ONLY: //         0xb1b10014      // The function called is onyl available in Development builds.
        case E_ERP_INTERNAL_BUFFER_ERROR: //     0xB1B10016      // Internal error - An internal buffer was too small.
        case  E_ERP_NO_ECC_DOMAIN_PARAMETERS: //  0xb1b10017
        case  E_ERP_FAILED_ECC_KEYPAIR_GENERATION: // 0xb1b10018
        case  E_ERP_CERT_BAD_SUBJECT_ALG: //      0xB1B10019      // x509 Subject key algorithm is not ecdsaWithSHA256.
        case  E_ERP_CERT_BAD_SIGNATURE_ALG: //    0xB1B1001A      // x509 Signature Algorithm is not ecdsaWithSHA256.
        case  E_ERP_CERT_BAD_SUBJECT_ENCODING: // 0xB1B1001B      // x509 Subject key is not idECPublicKey.
        case  E_ERP_CERT_UNSUPPORTED_CURVE: //    0xB1B1001C      // x509 Subject key does non use a curve that we support.
        case  E_ERP_CERT_BAD_SIGNATURE_FORMAT: // 0xB1B1001D      // x509 Signature body is not correctly formatted.
        case  E_ERP_BLOB_EXPIRED: //              0xB1B1001E      // An ephemeral blob is past its' sell by date.
        case  E_ERP_BAD_ANSIX9_62_LENGTH: //      0xB1B1001F      // An ANSI X9.62 encoded public key has the wrong length.
        case  E_ERP_BAD_TPM_NAME_ALGORITHM: //    0xB1B10020      // A TPM Name hash algorithm is not SHA256 (0x000B).
        case  E_ERP_BAD_ANSIX9_62_ENCODING: //    0xB1B10021      // An ANSI X9.62 encoded public key is badly encoded.
        case  E_ERP_TPM_NAME_MISMATCH: //         0xB1B10022      // An ANSI X9.62 encoded or TPMT_PUBLIC encoded public key does not match the TPM name hash.
        case  E_ERP_BAD_TPMT_PUBLIC_LENGTH: //    0xB1B10023      // A TPMT_PUBLIC Key has the wrong length.   Should be 0x78
        case  E_ERP_BAD_TPMT_PUBLIC_ALGORITHM: // 0xB1B10024      // A TPMT_PUBLIC Key has the wrong algorithm.   Should be 0x023 TPMI_ALG_ECC.
        case  E_ERP_BAD_TPMT_PUBLIC_FORMAT: //    0xB1B10025      // A TPMT_PUBLIC Key is badly formatted.
        case  E_ERP_FAIL_AK_CREDENTIAL_MATCH: //  0xB1B10026      // The returned plain text AK Challenge credential does not match the challenge.
        case  E_ERP_BAD_BLOB_TIME: //             0xB1B10027      // A Blob has an invalid time, e.g. later than now? 
        case  E_ERP_TPM_UNSUPPORTED_CURVE: //     0xB1B10028      // An ECC Curve is not supported by the TPM.
        case  E_ERP_BAD_TPMT_SIGNATURE_LENGTH: // 0xB1B10029      // The length of the TPMT_SIGNATURE is wrong.
        case  E_ERP_BAD_TPMT_SIGNATURE_FORMAT: // 0xB1B10030      // The format of the TPMT_SIGNATURE is wrong.
        case  E_ERP_BAD_TPMT_PUBLIC_ATTRIBUTES: //    0xB1B10031  // The attributes of a TPMT_PUBLIC are not acceptable for an attestation key.
        case  E_ERP_BAD_QUOTE_HEADER: //          0xB1B10032      // The fixed header data of a TPM Quote is invalid.
        case  E_ERP_BAD_QUOTE_LENGTH: //          0xB1B10033      // The TPM Quote length is invalid.
        case  E_ERP_QUOTE_NONCE_MISMATCH: //      0xB1B10034      // The Qualifying Data in a TPM Quote (NONCE) does not match the challenge.
        case  E_ERP_BAD_QUOTE_FORMAT: //          0xB1B10035      // The TPM Quote format is false.
        case  E_ERP_BAD_QUOTE_HASH_FORMAT: //     0xB1B10036      // The TPM Quote Hash format is false.   Must be SHA256 (0x000B)
        case  E_ERP_QUOTE_SIGNER_MISMATCH: //     0xB1B10037      // The two TPM Quotes were not signed by the same AK.
        case  E_ERP_QUOTE_PCRSET_MISMATCH: //     0xB1B10038      // The two TPM Quotes do not attest the same set of PCRS.
        case  E_ERP_QUOTE_DIGEST_MISMATCH: //     0xB1B10039      // The two TPM Quotes do not report the same digest.
        case  E_ERP_ECIES_CURVE_MISMATCH: //      0xB1B1003a      // The client public key and ECIES keypair do not use the same curve.
                default:
            // Most valid errors should be handled with an id coming from the caller.
            id = ERP_AUDIT_Internal_Error;
            break;
    }
    return auditErrWithID(err, id);
}
// Handler for an error code for a particular event
unsigned int auditErrWithID(unsigned int err, ERP_AuditID_t id)
{
    return auditErrWithIDAndMessage(err,id, NULL);
}
// Handler for an error code for a particular event with extra message detail.
unsigned int auditErrWithIDAndMessage(unsigned int err, ERP_AuditID_t id, const char* message)
{
    char Trunc[] = "(Truncated...)";
    // Length of "truncated" string above.
    #define TRUNC_LEN (ERP_AUDIT_MAX_MESSAGE + 16)

    char MsgBuffer[TRUNC_LEN] = "";
    
    // First the basic message for the id.
    os_str_cpy(&(MsgBuffer[0]), AuditMessages[id]);
    // Messages in table must be less than max message len.
    int msgLen = os_str_len(&(MsgBuffer[0]));
    // Then the error code if any:
    if (err != E_ERP_SUCCESS)
    {
        msgLen += os_str_snprintf(&(MsgBuffer[msgLen]), ERP_AUDIT_MAX_MESSAGE - msgLen, "   Error Code: %.08x.", err);
    }
    if (message != NULL)
    {
        // Strip the const on message here.   Just because the os_str method 
        //    doesn't take const doesn't mean we shouldn't use it ourselves.
        msgLen += os_str_snprintf(&(MsgBuffer[msgLen]), ERP_AUDIT_MAX_MESSAGE - msgLen, (char*) message);
    }
    // Should never actually be greater than max, but...
    if (msgLen >= ERP_AUDIT_MAX_MESSAGE)
    { // Add a truncated tag to the end of the message.
       msgLen += os_str_snprintf(&(MsgBuffer[ERP_AUDIT_MAX_MESSAGE]), TRUNC_LEN - ERP_AUDIT_MAX_MESSAGE, Trunc);
    }
    os_audit_write(getAuditClass(id), "%s", &(MsgBuffer[0]));

    // Return the original error. 
    return err;
}
