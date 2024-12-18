/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021, 2024
 * (C) Copyright IBM Corp. 2021, 2024
 *
 * non-exclusively licensed to gematik GmbH
 *
 * Description: Header file for Audit Event IDs. May be included on client side.
 **************************************************************************************************/

#ifndef ERP_AUDIT_IDS_H
#define ERP_AUDIT_IDS_H

typedef enum ERP_AuditID {
    ERP_AUDIT_No_Event = 0, // reserve this for programmatic use.
    ERP_AUDIT_New_Blob_Generation_Key_Generated                     = 1,
    ERP_AUDIT_Blob_Generation_Key_Deleted                           = 2,
    ERP_AUDIT_Blob_Key_Database_Exported                            = 3,
    ERP_AUDIT_Blob_Key_Database_Imported                            = 4,
    ERP_AUDIT_Blob_Migrated_To_New_Generation                       = 5,
    ERP_AUDIT_Failed_Blob_Migration                                 = 6,
    ERP_AUDIT_Failed_Blob_Use_Bad_Generation                        = 7,
    ERP_AUDIT_Failed_Blob_Use_Blob_Time                             = 8,
    ERP_AUDIT_Failed_Blob_Use_Bad_Decrypt                           = 9,
    ERP_AUDIT_Failed_Blob_Use_wrong_Blob_Type                       = 10,
    ERP_AUDIT_TPM_Manufacturer_Root_Certificate_Enrolled            = 11,
    ERP_AUDIT_TPM_Endorsement_Key_Enrolled                          = 12,
    ERP_AUDIT_TPM_Attestation_Key_Enrolled                          = 13,
    ERP_AUDIT_TPM_Quote_Enrolled                                    = 14,
    ERP_AUDIT_Failed_TPM_EK_Enrollment                              = 15,
    ERP_AUDIT_Failed_TPM_AK_Enrollment                              = 16,
    ERP_AUDIT_Failed_TPM_Quote_Enrollment                           = 17,
    ERP_AUDIT_Key_Derivation_Key_Generated                          = 18,
    ERP_AUDIT_Hash_Key_Generated                                    = 19,
    ERP_AUDIT_Failed_Key_Derivation_Key_Generation                  = 20,
    ERP_AUDIT_Failed_Hash_Key_Generation                            = 21,
    ERP_AUDIT_Logon_Failure                                         = 22,
    ERP_AUDIT_Permission_Failure                                    = 23,
    ERP_AUDIT_Failed_getTEEToken                                    = 24,
    ERP_AUDIT_Formal_Parameter_Check_Failed                         = 25,
    ERP_AUDIT_Internal_Memory_Error                                 = 26,
    ERP_AUDIT_Internal_Error                                        = 27,
    ERP_AUDIT_Failed_New_Blob_Generation_Key_Generated              = 28,
    ERP_AUDIT_Failed_Key_Derivation                                 = 29,
    ERP_AUDIT_Failed_Get_AK_Challenge                               = 30,
    ERP_AUDIT_Failed_TPM_Manufacturer_Root_Certificate_Enrollment   = 31,
    ERP_AUDIT_Failed_Get_NONCE                                      = 32,
    ERP_AUDIT_Failed_Blob_Generation_Key_Deletion                   = 33,
    ERP_AUDIT_Failed_EC_KeyPair_Generation                          = 34,
    ERP_AUDIT_EC_KeyPair_Generated                                  = 35,
    ERP_AUDIT_EC_CSR_Generated                                      = 36,
    ERP_AUDIT_Failed_EC_CSR_Generation                              = 37,
    ERP_AUDIT_Failed_EC_Get_Public_Key                              = 38,
    ERP_AUDIT_Failed_ECIES_DO_VAUECIES                              = 39,
    ERP_AUDIT_Failed_VAUSIG_Get_Private_Key                         = 40,
    ERP_AUDIT_Failed_Unwrap_Hash_Key                                = 41,
    ERP_AUDIT_Exported_Single_Blob_Generation                       = 42,
    ERP_AUDIT_Imported_Single_Blob_Generation                       = 43,
    ERP_AUDIT_Failed_Export_Single_Blob_Generation                  = 44,
    ERP_AUDIT_Failed_Import_Single_Blob_Generation                  = 45,
    ERP_AUDIT_Failed_Get_Blob_Content_Hash                          = 46,
    ERP_AUDIT_Failed_Migrate_Blob                                   = 47,
    ERP_AUDIT_Pseudoname_Key_Generated                              = 48,
    ERP_AUDIT_Failed_Pseudoname_Key_Generation                      = 49,
    ERP_AUDIT_Failed_Unwrap_Pseudoname_Key                          = 50,
    ERP_AUDIT_Wrap_Raw_Payload                                      = 51,
    ERP_AUDIT_Failed_Wrap_Raw_Payload                               = 52,
    ERP_AUDIT_Failed_Unwrap_Raw_Payload                             = 53,
    ERP_AUDIT_Failed_SignVAUAUTToken                                = 54,
    ERP_AUDIT_LastUsedId                                            = 55 // Used for programmatic reasons.
}ERP_AuditID_t;

// Used for successful setup operations
#define ERP_MDL_AUDIT_SETUP_CLASS 24
#define ERP_MDL_AUDIT_SETUP_MASK 0x01000000
// Failed setup operations
#define ERP_MDL_AUDIT_FAILED_SETUP_CLASS 25
#define ERP_MDL_AUDIT_FAILED_SETUP_MASK 0x02000000
// Failed runtime operations, get TEEToken, derive key etc.
#define ERP_MDL_AUDIT_WORKING_FAIL_CLASS 26
#define ERP_MDL_AUDIT_FAILED_WORKING_MASK 0x04000000
// also using:
// For Permissions related failures
//        OS_AUDIT_CLASS_AUTH_FAILED 0x00000100 9 Failed authentications / logins
// Generated by smos for backup/restore operations
//        OS_AUDIT_CLASS_BACKUP_RESTORE 0x00000200 10 Backup and restore operations
//        OS_AUDIT_CLASS_MBK 0x00000020 6 Master Backup Key management

#endif
