/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021, 2023
 * (C) Copyright IBM Corp. 2021, 2023
 *
 * non-exclusively licensed to gematik GmbH
 **************************************************************************************************/

#ifndef ERP_ASN_UTILS_H_
#define ERP_ASN_UTILS_H_

#include <stddef.h>

struct ERPBlob_s; // Structure from API header
struct SingleBlobOutput_s; // Structure from API Header
struct BUBlobOutput_s; // Structure from API Header
struct SingleBlob; // Generated ASN1C header
struct asn_enc_rval_s;
struct asn_TYPE_descriptor_s;

struct OCTET_STRING;
struct ASN__PRIMITIVE_TYPE_s;

typedef struct {
    size_t Length;
    size_t LastOffset;
    unsigned char* data;
} writeBuffer_t;

// Utility method to handle dynamic allocation of buffer for a DER
//    encoding.
// The buffer is allocated with calloc and must be freed with free ()
struct asn_enc_rval_s der_encode_dynamic_buffer(
    const struct asn_TYPE_descriptor_s* type_descriptor,
    const void* struct_ptr, /* Structure to be encoded */
    size_t* pOutLen, // Output data length
    unsigned char** ppOutData); // Pointer to hold output data,

// Allocates and sets an asn1 integer
int make_asn_integer(struct ASN__PRIMITIVE_TYPE_s** ppOut, unsigned long val);

int asn_int2INTEGER(struct ASN__PRIMITIVE_TYPE_s* pI, unsigned int in);

int asn_string2IA5String(struct OCTET_STRING* str, const char* inStr);

int asn_buffer2OctetString(struct OCTET_STRING* octs, const unsigned char* inBuff, size_t buffLen);

int asn_ERPBlob2ASNSingleBlob(struct SingleBlob* pOut, const struct ERPBlob_s* pIn);

// Handles a result containing a single blob and fills it into a SingleBlobOutput structure.
// Error codes may be returned in pRetVal->returnCode.
void HandleSingleBlobResult(unsigned char* p_answ, unsigned int p_l_answ, struct SingleBlobOutput_s* pRetVal);

// Handles a result containing a single BackupBlob and fills it into a BUBlobOutput structure.
// Error codes may be returned in pRetVal->returnCode.
void HandleBUBlobResult(unsigned char* p_answ, unsigned int p_l_answ, struct BUBlobOutput_s* pRetVal);

#endif
