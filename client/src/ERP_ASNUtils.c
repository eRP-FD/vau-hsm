#include "ERP_ASNUtils.h"

#include "ERP_Client.h"
#include "ERP_Error.h"

#include <asn1_hsmclient/SingleBlob.h>

#include <asn1c/IA5String.h>
#include <asn1c/INTEGER.h>

#include <string.h>

#define UNUSED(x) (void)(x)
/*
 * Generic type of an application-defined callback to return various
 * types of data to the application.
 * EXPECTED RETURN VALUES:
 *  -1: Failed to consume bytes. Abort the mission.
 * Non-negative return values indicate success, and ignored.
 */
 //typedef int (asn_app_consume_bytes_f)(const void *buffer, size_t size,
 //	void *application_specific_key);
int write_asn_stream(const void* buffer, size_t size,
	void* app_key)
{
	writeBuffer_t* outBuff = (writeBuffer_t*)app_key;
	if (size + outBuff->LastOffset > outBuff->Length)
	{
		return -1;
	}
	memcpy(&(outBuff->data[outBuff->LastOffset]), buffer, size);
	outBuff->LastOffset += size;
	return 0;
}

/*
 * Generic type of an application-defined callback to return various
 * types of data to the application.
 * This implementation will count the bytes returned.
 * EXPECTED RETURN VALUES:
 *  -1: Failed to consume bytes. Abort the mission.
 * Non-negative return values indicate success, and ignored.
 */
int count_asn_stream(const void* buffer, size_t size,
	void* app_key)
{
	UNUSED(buffer); // Avoid C4100 unused formal parameter
	size_t* counter = (size_t*)app_key;
	(*counter) += size;
	return 0;
}

// Utility method to handle dynamic allocation of buffer for a DER
//    encoding.
// The buffer is allocated with calloc and must be freed with free ()
asn_enc_rval_t der_encode_dynamic_buffer(
	const struct asn_TYPE_descriptor_s* type_descriptor,
	const void* struct_ptr, /* Structure to be encoded */
	size_t* pOutLen, // Output data length
	unsigned char** ppOutData) // Pointer to hold output data,
{
	size_t buffLength = 0;
	asn_enc_rval_t retVal = der_encode(
		type_descriptor,
		struct_ptr,
		count_asn_stream,
		&buffLength);
	if (retVal.encoded != -1)
	{
		*pOutLen = buffLength;
		*ppOutData = calloc((buffLength+1), sizeof(unsigned char));
		if (*ppOutData == NULL)
		{
			retVal.encoded = -1;
			retVal.failed_type = type_descriptor;
			retVal.structure_ptr = struct_ptr;
		}
	}
	if (retVal.encoded != -1)
	{
		writeBuffer_t inBuff;
		inBuff.Length = ((*pOutLen)+1);
		inBuff.LastOffset = 0;
		inBuff.data = *ppOutData;

		retVal = der_encode(
			type_descriptor,
			struct_ptr,
			write_asn_stream,
			&inBuff);
	}
	return retVal;
}

// Allocates and sets an asn1 integer
int make_asn_integer(struct ASN__PRIMITIVE_TYPE_s** ppOut, unsigned long val)
{
	int err = ERP_ERR_NOERROR;

	*ppOut = (INTEGER_t *)calloc(sizeof(INTEGER_t), 1);
	if (*ppOut == NULL)
	{
		err = ERP_ERR_CALLOC_ERROR;
	}
	if (err == ERP_ERR_NOERROR)
	{
		err = asn_long2INTEGER(*ppOut, val);
	}
	return err;
}

int asn_int2INTEGER(struct ASN__PRIMITIVE_TYPE_s * pI, unsigned int in)
{
	return asn_ulong2INTEGER(pI, in);
}

int asn_string2IA5String(struct OCTET_STRING * str, const char* inStr)
{
	int err = ERP_ERR_NOERROR;

	if (str == NULL)
	{
		err = ERP_ERR_CALLOC_ERROR;
	}
	if (err == ERP_ERR_NOERROR)
	{
		str->size = strlen(inStr);
		str->buf = (uint8_t *)calloc(sizeof(char), str->size);
		if (str->buf == NULL)
		{
			err = ERP_ERR_CALLOC_ERROR;
		}
	}
	if (err == ERP_ERR_NOERROR)
	{
		memcpy(str->buf, inStr, str->size);
	}
	return err;
}

int asn_buffer2OctetString(struct OCTET_STRING * octs, const unsigned char* inBuff, size_t buffLen)
{
	int err = ERP_ERR_NOERROR;

	if (octs == NULL)
	{
		err = ERP_ERR_CALLOC_ERROR;
	}
	if (err == ERP_ERR_NOERROR)
	{
		octs->size = buffLen;
		octs->buf = (uint8_t*)calloc(sizeof(char), octs->size);
		if (octs->buf == NULL)
		{
			err = ERP_ERR_CALLOC_ERROR;
		}
	}
	if (err == ERP_ERR_NOERROR)
	{
		memcpy(octs->buf, inBuff, octs->size);
	}
	return err;
}

int asn_ERPBlob2ASNSingleBlob(struct SingleBlob * pOut, const struct ERPBlob_s * pIn)
{
	int err = ERP_ERR_NOERROR;
    if (pIn->BlobLength > MAX_BUFFER)
    {
        err = ERP_ERR_BUFFER_TOO_SMALL;
    }
    if (err == ERP_ERR_NOERROR)
    {
        pOut->blobGeneration = pIn->BlobGeneration;
        err = asn_buffer2OctetString(&(pOut->aBlob), (const unsigned char*)&(pIn->BlobData[0]), pIn->BlobLength);
    }
	return err;
}

// Requires local variable int err...
// This will take an asn1c data type of the form {buf,size,...)
//   and delete buf if it is non NULL.
#define ASN1_FREE_FIELD(field) 	if (err == ERP_ERR_NOERROR) \
{if (field.buf != NULL) { free(field.buf); } }
// free(field); }

// Handles a result containing a single blob and fills it into a SingleBlobOutput structure.
// Error codes may be returned in pRetVal->returnCode.
void HandleSingleBlobResult(unsigned char* p_answ, unsigned int p_l_answ, struct SingleBlobOutput_s * pRetVal)
{
	// Extract Single Blob from result:
	SingleBlob_t* TokenOut = NULL;    /* Note this 0! */

	if (pRetVal->returnCode == ERP_ERR_NOERROR)
	{
		asn_dec_rval_t rval;

		rval = asn_DEF_SingleBlob.op->ber_decoder(0,
			&asn_DEF_SingleBlob,
			(void**)&TokenOut,
			p_answ, p_l_answ,
			0);

		if (rval.code != RC_OK)
		{
			pRetVal->returnCode = ERP_ERR_ASN1DECODING_ERROR;
		}
	}

	if (pRetVal->returnCode == ERP_ERR_NOERROR)
	{
		if (TokenOut->aBlob.size > MAX_BUFFER)
		{
			pRetVal->returnCode = ERP_ERR_BUFFER_TOO_SMALL;
		}
		else {
			pRetVal->BlobOut.BlobLength = TokenOut->aBlob.size;
			memcpy(pRetVal->BlobOut.BlobData, TokenOut->aBlob.buf, TokenOut->aBlob.size);
			// First four bytes of 
			pRetVal->BlobOut.BlobGeneration = TokenOut->blobGeneration;
		}
	}

	if (TokenOut != NULL)
	{
		asn_DEF_SingleBlob.op->free_struct(
			&asn_DEF_SingleBlob, TokenOut, 0);
	}
}
