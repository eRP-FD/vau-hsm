#ifndef ERP_SFC_H
#define ERP_SFC_H

// module id of example module
#define ERP_MDL_ID 0x101

// sub function codes of the example module
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

#endif