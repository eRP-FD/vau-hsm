/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021, 2024
 * (C) Copyright IBM Corp. 2021, 2024
 *
 * non-exclusively licensed to gematik GmbH
 **************************************************************************************************/

#include "ERP_Client.h"
#include "ERP_Error.h"
#include "ERP_TestParams.h"
#include "ERP_TestUtils.h"
#include "ERP_TestsBase.h"

#include <gtest/gtest.h>

#include <cstring>
#include <memory>
#include <vector>

class WrapRawPayloadTestsFixture : public ErpBaseTestsFixture
{
};


TEST_F(WrapRawPayloadTestsFixture, WrapUnwrapRawPayload)
{
    unsigned int Gen = THE_ANSWER;
    const char inputData[] = "hello";
    SingleBlobOutput out;
    teststep_WrapRawPayload(m_logonSession, Gen, sizeof(inputData), (const unsigned char*)inputData, &out);
    ASSERT_EQ(ERP_ERR_NOERROR, out.returnCode);

    RawPayloadOutput outputRaw = {0, 0, {0}};
    teststep_UnwrapRawPayload(m_logonSession, &out.BlobOut, &outputRaw);
    EXPECT_EQ(ERP_ERR_NOERROR, outputRaw.returnCode);
    ASSERT_TRUE(0 == memcmp(&(outputRaw.rawPayload[0]), &(inputData[0]), sizeof(inputData)));
    ASSERT_EQ(outputRaw.payloadLen, sizeof(inputData));
}

TEST_F(WrapRawPayloadTestsFixture, WrapPayloadWithToken)
{
    unsigned int Gen = THE_ANSWER;
    const char data[] = "helloworld123456489123186146";
    SingleBlobOutput blobOutput;
    teststep_WrapRawPayloadWithToken(m_logonSession, Gen, sizeof(data), (const unsigned char*)data, &blobOutput);
    ASSERT_EQ(ERP_ERR_NOERROR, blobOutput.returnCode);

    // unwrap the data again
    RawPayloadOutput outputPayload = {0, 0, {0}};
    teststep_UnwrapRawPayload(m_logonSession, &blobOutput.BlobOut, &outputPayload);
    ASSERT_EQ(ERP_ERR_NOERROR, outputPayload.returnCode);
    ASSERT_TRUE(0 == memcmp(&(outputPayload.rawPayload[0]), &(data[0]), sizeof(data)));
}

// The intent of this test is that it be run and then the HSM Memory dumps are inspected to see if the
//   number of allocated memory blocks is growing.
TEST_F(WrapRawPayloadTestsFixture, LoadLoopTests)
{
    const unsigned int Gen = THE_ANSWER;
    RawPayloadInput input = {};
    input.desiredGeneration = Gen;

    ERP_DumpHSMMemory(m_logonSession);
    for (int i = 0; i < BIG_LOOP; i++)
    {
        UIntInput desiredBytes = { MAX_RND_BYTES };
        RNDBytesOutput rndOut = ERP_GetRNDBytes(m_logonSession, desiredBytes);
        EXPECT_EQ(ERP_ERR_NOERROR, rndOut.returnCode);
        EXPECT_EQ(desiredBytes.intValue, rndOut.RNDDataLen);

        // wrap without tee token
        {
            memcpy(input.rawPayload, rndOut.RNDData, rndOut.RNDDataLen);
            input.payloadLen = desiredBytes.intValue;
            SingleBlobOutput outBlob = ERP_WrapRawPayload(m_logonSession, input);
            ASSERT_EQ(ERP_ERR_NOERROR, outBlob.returnCode);

            RawPayloadOutput outputPayload = {0, 0, {0}};
            teststep_UnwrapRawPayload(m_logonSession, &outBlob.BlobOut, &outputPayload);
            ASSERT_EQ(ERP_ERR_NOERROR, outputPayload.returnCode);
            ASSERT_TRUE(0 == memcmp(&(outputPayload.rawPayload[0]), &rndOut.RNDData[0], rndOut.RNDDataLen));
        }

        // wrap with tee token
        {
            SingleBlobOutput outBlobWithToken;
            teststep_WrapRawPayloadWithToken(m_logonSession, Gen, rndOut.RNDDataLen, rndOut.RNDData, &outBlobWithToken);

            RawPayloadOutput outputPayload = {0, 0, {0}};
            teststep_UnwrapRawPayload(m_logonSession, &outBlobWithToken.BlobOut, &outputPayload);
            ASSERT_EQ(ERP_ERR_NOERROR, outputPayload.returnCode);
            ASSERT_TRUE(0 == memcmp(&(outputPayload.rawPayload[0]), &rndOut.RNDData[0], rndOut.RNDDataLen));
        }
    }
    ERP_DumpHSMMemory(m_logonSession);
}
