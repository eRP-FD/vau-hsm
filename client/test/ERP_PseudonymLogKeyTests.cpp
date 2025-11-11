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

class PseudonymLogKeyTestsFixture : public ErpBaseTestsFixture
{
};


TEST_F(PseudonymLogKeyTestsFixture, WrapUnwrapKeyLogPackage)
{
    unsigned int Gen = THE_ANSWER;
    RawPayloadInput input = {};
    input.desiredGeneration = Gen;
    memcpy(input.rawPayload, "hello", 5);
    input.payloadLen = 5;
    SingleBlobOutput out = ERP_WrapPseudonameLogKeyPackage(m_logonSession, input);
    ASSERT_EQ(ERP_ERR_NOERROR, out.returnCode);

    RawPayloadOutput outputRaw = {0, 0, {0}};
    teststep_UnwrapPseudonameLogKeyPackage(m_logonSession, &out.BlobOut, &outputRaw);
    EXPECT_EQ(ERP_ERR_NOERROR, outputRaw.returnCode);
    ASSERT_EQ(outputRaw.payloadLen, input.payloadLen);
    ASSERT_TRUE(0 == memcmp(&(outputRaw.rawPayload[0]), &(input.rawPayload[0]), input.payloadLen));
}

TEST_F(PseudonymLogKeyTestsFixture, WrapUnwrapKeyLog)
{
    unsigned int Gen = THE_ANSWER;
    const char key[AES_128_LEN] = "helloworld12345";
    SingleBlobOutput blobOutput;
    teststep_WrapPseudonameLogKey(m_logonSession, Gen, (const unsigned char*)key, &blobOutput);
    ASSERT_EQ(ERP_ERR_NOERROR, blobOutput.returnCode);

    // unwrap the data again
    AES128KeyOutput aesOutput = {0, {0}};
    teststep_UnwrapPseudonameLogKey(m_logonSession, &blobOutput.BlobOut, &aesOutput);
    ASSERT_EQ(ERP_ERR_NOERROR, aesOutput.returnCode);
    ASSERT_TRUE(0 == memcmp(&(aesOutput.AESKey[0]), &(key[0]), sizeof(key)));
}

// The intent of this test is that it be run and then the HSM Memory dumps are inspected to see if the
//   number of allocated memory blocks is growing.
TEST_F(PseudonymLogKeyTestsFixture, LoadLoopTests)
{
    const unsigned int Gen = THE_ANSWER;

    ERP_DumpHSMMemory(m_logonSession);
    for (int i = 0; i < BIG_LOOP; i++)
    {
        UIntInput desiredBytes = { AES_128_LEN };
        RNDBytesOutput rndOut = ERP_GetRNDBytes(m_logonSession, desiredBytes);
        EXPECT_EQ(ERP_ERR_NOERROR, rndOut.returnCode);
        EXPECT_EQ(desiredBytes.intValue, rndOut.RNDDataLen);

        {
            SingleBlobOutput outBlob;
            teststep_WrapPseudonameLogKey(m_logonSession, Gen, rndOut.RNDData, &outBlob);

            AES128KeyOutput aesOutput = {0, {0}};
            teststep_UnwrapPseudonameLogKey(m_logonSession, &outBlob.BlobOut, &aesOutput);
            ASSERT_EQ(ERP_ERR_NOERROR, aesOutput.returnCode);
            ASSERT_TRUE(0 == memcmp(&(aesOutput.AESKey[0]), &rndOut.RNDData[0], rndOut.RNDDataLen));
        }
    }
    ERP_DumpHSMMemory(m_logonSession);
}
