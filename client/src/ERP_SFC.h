/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021, 2023
 * (C) Copyright IBM Corp. 2021, 2023
 *
 * non-exclusively licensed to gematik GmbH
 **************************************************************************************************/

#ifndef ERP_SFC_H
#define ERP_SFC_H

// module id of example module
#define ERP_MDL_ID 0x101

// sub function codes of the example module
// These values define the entry points for the firmware module and MUST match those defined in firmware
//   file ERP_GlobalGlue.c
#define ERP_SFC_GENERATE_BLOB_KEY        0
#define ERP_SFC_LIST_BLOB_KEYS           1
#define ERP_SFC_GENERATE_HASH_KEY        2
#define ERP_SFC_UNWRAP_HASH_KEY          3
#define ERP_SFC_GENERATE_ECIES_KEYPAIR   4
#define ERP_SFC_GENERATE_ECIES_CSR       5
#define ERP_SFC_DUMP_HSM_MEMORY          6
#define ERP_SFC_DELETE_BLOB_KEY          7
#define ERP_SFC_GENERATE_NONCE           8
#define ERP_SFC_GENERATE_DERIVATION_KEY  9
#define ERP_SFC_DO_ECIES_128             10
#define ERP_SFC_TRUST_TPM_MFR            11
#define ERP_SFC_ENROLL_TPM_EK            12
#define ERP_SFC_GET_AK_CHALLENGE         13
#define ERP_SFC_ENROLL_TPM_AK            14
#define ERP_SFC_ENROLL_ENCLAVE           15
#define ERP_SFC_GET_TEE_TOKEN            16
#define ERP_SFC_DERIVE_TASK_KEY          17
#define ERP_SFC_DERIVE_AUDIT_KEY         18
#define ERP_SFC_DERIVE_COMMS_KEY         19
#define ERP_SFC_GET_EC_PUBLIC_KEY        20
#define ERP_SFC_GET_RND_BYTES            21
#define ERP_SFC_GENERATE_VAUSIG_KEYPAIR  22
#define ERP_SFC_GENERATE_VAUSIG_CSR      23
#define ERP_SFC_GET_VAUSIG_PRIVATE_KEY   24
#define ERP_SFC_EXPORT_SINGLE_BLOB_KEY   25
#define ERP_SFC_IMPORT_SINGLE_BLOB_KEY   26
#define ERP_SFC_MIGRATE_BLOB             27
#define ERP_SFC_GET_BLOB_CONTENT_HASH    28
#define ERP_SFC_GET_BLOB_CONTENT_HASH_WITH_TOKEN    29
#define ERP_SFC_DERIVE_CHARGE_ITEM_KEY   30
#define ERP_SFC_GENERATE_PSEUDONAME_KEY  31
#define ERP_SFC_UNWRAP_PSEUDONAME_KEY    32
#define ERP_SFC_WRAP_PAYLOAD             33
#define ERP_SFC_WRAP_PAYLOAD_WITH_TOKEN  34
#define ERP_SFC_UNWRAP_PAYLOAD           35

#endif
