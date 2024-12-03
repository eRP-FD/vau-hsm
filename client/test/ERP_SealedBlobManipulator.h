/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021, 2024
 * (C) Copyright IBM Corp. 2021, 2024
 *
 * non-exclusively licensed to gematik GmbH
 **************************************************************************************************/

#ifndef ERP_SEALED_BLOB_MANIPULATOR_H
#define ERP_SEALED_BLOB_MANIPULATOR_H

#include "ERP_Client.h"
#include "ERP_Error.h"

#include <cstring>
#include <string>
#include <vector>

#define BLOB_IV_LEN 12
#define BLOB_AD_HASH_LEN 16
#define BLOB_DOMAIN_LEN 5

#ifdef _MSC_VER
    #pragma warning(push)
    #pragma warning(disable : 4200) // disable warning for zero-sized member
#else
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wpedantic"
#endif

extern "C" {
 typedef struct {
  // This is generated from the encoded data and is reproduced here as a convenience.
  unsigned char BlobID[SHA_256_LEN]; // SHA256 hash of encoded part - usable as ID.
  // Following is AD for AES_GCM
  unsigned int Generation; // The Generation of the BlobKey to be used for unwrapping.
  unsigned char Domain[BLOB_DOMAIN_LEN]; // null terminated "SIML", "DVLP", "REFZ", "TEST" or "PROD".
  // End of AES-GCM AD.
  unsigned char ICV[BLOB_IV_LEN]; // AES GCM 96 bits ICV
  unsigned char AuthTag[BLOB_AD_HASH_LEN]; // AES GCM 128 bits Authorisation Tag.
  unsigned int EncodedDataLength; // is necessary?
// NOLINTNEXTLINE
  unsigned char EncodedData[]; // Intentional Open ended array.
} SealedBlob_t;
} // End extern "C"

#ifdef _MSC_VER
#pragma warning(pop) // disable warning for zero-sized member
#else
#pragma GCC diagnostic pop
#endif


/*
 * Input: Valid Blob
 * This class will apply manipulations to the SealedBlob_t data and provide the expected errors
 */
class SealedBlobManipulator
{
public:

  typedef enum { EXPECT_ERR_EQ, EXPECT_ERR_NE } expectErrorVariant;
  typedef struct
  {
    std::string TestName; /* used s.t. we can determine the name of a failed test */
    ERPBlob blob;
    expectErrorVariant expectErrVar;
    unsigned int expectErr;
  } sealedBlobManipulation_t;

  SealedBlobManipulator(ERPBlob validBlob)
  {
    m_validBlob = validBlob;
  }

  std::vector<sealedBlobManipulation_t> getManipulations()
  {
    std::vector<sealedBlobManipulation_t> out;

    out.push_back(memset_0());
    out.push_back(blobID());
    out.push_back(generation_0());
    out.push_back(generation_9999());
    out.push_back(incorrectBlobDomain());
    for(const char *domain : {"DVLP", "REFZ", "TEST", "PROD"}) { out.push_back(wrongBlobDomain((unsigned char*)domain)); }
    out.push_back(ICV());
    out.push_back(AuthTag());
    out.push_back(encodedDataLength_plus1());
    out.push_back(encodedDataLength_minus1());
    out.push_back(encodedDataLength_plus999999999());
    out.push_back(encodedDataLength_0());
    out.push_back(encodedData());

    return out;
  }

private:
  /*
   * manipulations to SealedBlobs and the expected errors
   */

  /* arbitrary manipulations */
  sealedBlobManipulation_t memset_0()
  {
    sealedBlobManipulation_t out;
    out.TestName = __FUNCTION__;
    out.blob = m_validBlob;
    auto *sealedDataPtr = (SealedBlob_t*)out.blob.BlobData;

    std::memset(sealedDataPtr, 0, sizeof(SealedBlob_t));

    /* expect any error but ERP_ERR_NOERROR */
    out.expectErr = ERP_ERR_NOERROR;
    out.expectErrVar = EXPECT_ERR_NE;

    return out;
  }

  /* change BlobID - expect no error since it's not protected */
  sealedBlobManipulation_t blobID()
  {
    sealedBlobManipulation_t out;
    out.TestName = __FUNCTION__;
    out.blob = m_validBlob;
    auto *sealedDataPtr = (SealedBlob_t*)out.blob.BlobData;

    sealedDataPtr->BlobID[0]++;
    sealedDataPtr->BlobID[SHA_256_LEN-1]--;

    /* expect no error */
    out.expectErr = ERP_ERR_NOERROR;
    out.expectErrVar = EXPECT_ERR_EQ;

    return out;
  }

  /* test messing with generations */
  sealedBlobManipulation_t generation_0()
  {
    sealedBlobManipulation_t out;
    out.TestName = __FUNCTION__;
    out.blob = m_validBlob;
    auto *sealedDataPtr = (SealedBlob_t*)out.blob.BlobData;

    sealedDataPtr->Generation = 0;

    /*
<     * 0 is just not possible for a sealed blob - it is not a real generation.
     */
    out.expectErr = ERP_ERR_BAD_BLOB_GENERATION;
    out.expectErrVar = EXPECT_ERR_EQ;

    return out;
  }
  sealedBlobManipulation_t generation_9999()
  {
    sealedBlobManipulation_t out;
    out.TestName = __FUNCTION__;
    out.blob = m_validBlob;
    auto *sealedDataPtr = (SealedBlob_t*)out.blob.BlobData;

    sealedDataPtr->Generation = 9999;

    out.expectErr = ERP_ERR_BAD_BLOB_GENERATION;
    out.expectErrVar = EXPECT_ERR_EQ;

    return out;
  }

  /* Bad Blob Domain */
  sealedBlobManipulation_t incorrectBlobDomain()
  {
    sealedBlobManipulation_t out;
    out.TestName = __FUNCTION__;
    out.blob = m_validBlob;
    auto *sealedDataPtr = (SealedBlob_t*)out.blob.BlobData;

    sealedDataPtr->Domain[0]++;

    out.expectErr = ERP_ERR_BAD_BLOB_DOMAIN;
    out.expectErrVar = EXPECT_ERR_EQ;

    return out;
  }

  /* Wrong Domain (should not pass SIML) */
  sealedBlobManipulation_t wrongBlobDomain(unsigned char *domain)
  {
    sealedBlobManipulation_t out;
    out.TestName = __FUNCTION__;
    out.blob = m_validBlob;
    auto *sealedDataPtr = (SealedBlob_t*)out.blob.BlobData;
    std::memcpy(sealedDataPtr->Domain, domain, sizeof(sealedDataPtr->Domain));

    out.expectErr = ERP_ERR_BAD_BLOB_DOMAIN;
    out.expectErrVar = EXPECT_ERR_EQ;

    return out;
  }

  /* modify ICV */
  sealedBlobManipulation_t ICV()
  {
    sealedBlobManipulation_t out;
    out.TestName = __FUNCTION__;
    out.blob = m_validBlob;
    auto *sealedDataPtr = (SealedBlob_t*)out.blob.BlobData;
    sealedDataPtr->ICV[5]--;

    out.expectErr = ERP_ERR_BAD_BLOB_AD;
    out.expectErrVar = EXPECT_ERR_EQ;

    return out;
  }

  /* Modify AuthTag */
  sealedBlobManipulation_t AuthTag()
  {
    sealedBlobManipulation_t out;
    out.TestName = __FUNCTION__;
    out.blob = m_validBlob;
    auto *sealedDataPtr = (SealedBlob_t*)out.blob.BlobData;
    sealedDataPtr->AuthTag[5]--;

    out.expectErr = ERP_ERR_BAD_BLOB_AD;
    out.expectErrVar = EXPECT_ERR_EQ;

    return out;
  }

  /* Modify EncodedDataLength */
  sealedBlobManipulation_t encodedDataLength_plus1()
  {
    sealedBlobManipulation_t out;
    out.TestName = __FUNCTION__;
    out.blob = m_validBlob;
    auto *sealedDataPtr = (SealedBlob_t*)out.blob.BlobData;
    sealedDataPtr->EncodedDataLength++;

    /* not clear which error to expect */
    out.expectErr = ERP_ERR_ASN1_CONTENT_ERROR;
    out.expectErrVar = EXPECT_ERR_EQ;

    return out;
  }
  sealedBlobManipulation_t encodedDataLength_minus1()
  {
    sealedBlobManipulation_t out;
    out.TestName = __FUNCTION__;
    out.blob = m_validBlob;
    auto *sealedDataPtr = (SealedBlob_t*)out.blob.BlobData;
    sealedDataPtr->EncodedDataLength--;

    out.expectErr = ERP_ERR_ASN1_CONTENT_ERROR;
    out.expectErrVar = EXPECT_ERR_EQ;

    return out;
  }
  sealedBlobManipulation_t encodedDataLength_plus999999999()
  {
    sealedBlobManipulation_t out;
    out.TestName = __FUNCTION__;
    out.blob = m_validBlob;
    auto *sealedDataPtr = (SealedBlob_t*)out.blob.BlobData;
    sealedDataPtr->EncodedDataLength += 999999999;

    /* expect to run out of memory */
    out.expectErr = ERP_ERR_ASN1_CONTENT_ERROR;
    out.expectErrVar = EXPECT_ERR_EQ;

    return out;
  }
  sealedBlobManipulation_t encodedDataLength_0()
  {
    sealedBlobManipulation_t out;
    out.TestName = __FUNCTION__;
    out.blob = m_validBlob;
    auto *sealedDataPtr = (SealedBlob_t*)out.blob.BlobData;
    sealedDataPtr->EncodedDataLength = 0;

    /* not clear which error to expect */
    out.expectErr = ERP_ERR_ASN1_CONTENT_ERROR;
    out.expectErrVar = EXPECT_ERR_EQ;

    return out;
  }

  /* modify EncodedData */
  sealedBlobManipulation_t encodedData()
  {
    sealedBlobManipulation_t out;
    out.TestName = __FUNCTION__;
    out.blob = m_validBlob;
    auto *sealedDataPtr = (SealedBlob_t*)out.blob.BlobData;
    sealedDataPtr->EncodedData[5]++;

    /* should give an authentication error */
    out.expectErr = ERP_ERR_BAD_BLOB_AD;
    out.expectErrVar = EXPECT_ERR_EQ;

    return out;
  }

  ERPBlob m_validBlob;
};

#endif // ERP_SEALED_BLOB_MANIPULATOR_H
