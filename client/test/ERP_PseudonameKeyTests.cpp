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

#include <gtest/gtest.h>

#include <memory>
#include <vector>

class ErpPseudonameKeyTestFixture : public ::testing::Test {
public:
    HSMSession m_logonSession = { 0, 0, 0, HSMUninitialised, 0, ERP_ERR_NOERROR, 0 };
    static const std::string devIP;

    ErpPseudonameKeyTestFixture() = default;

    void connect() {
        // This method is intended to be invoked for each test just before the test starts
        m_logonSession = ERP_Connect(devIP.c_str(), TEST_CONNECT_TIMEOUT_MS, TEST_READ_TIMEOUT_MS);
    }
    void logonSetup() {
        bool doLogon = true;
        if (doLogon)
        {
            // user ERP_SETUP with "password" and permissions 00000200
            const static std::string setupUsername = "ERP_SETUP";
            const static std::string password = "password";

            // to log in a smart card user, set the key spec instead of the password:
            /*
               const unsigned char prv_key_spec[] = ":cs2:auto:USB0";
               const unsigned char *password = NULL;
             */

             // For now, log in both tyes of user.
            m_logonSession = ERP_LogonPassword(m_logonSession, setupUsername.c_str(), password.c_str());
            ASSERT_EQ(HSMLoggedIn, m_logonSession.status);
        }
    }
    void logonWorking() {
        bool doLogon = true;
        if (doLogon)
        {
            // user ERP_WORK with "password" and permissions 00000020
            const static std::string workUsername = "ERP_WORK";
            const static std::string password = "password";

            // to log in a smart card user, set the key spec instead of the password:
            /*
               const unsigned char prv_key_spec[] = ":cs2:auto:USB0";
               const unsigned char *password = NULL;
             */

            m_logonSession = ERP_LogonPassword(m_logonSession, workUsername.c_str(), password.c_str());
            ASSERT_EQ(HSMLoggedIn, m_logonSession.status);
        }
    }
    void logoff()
    {
        if (m_logonSession.status == HSMLoggedIn)
        {
            m_logonSession = ERP_Logoff(m_logonSession);
            ASSERT_EQ(HSMAnonymousOpen, m_logonSession.status);
        }
    }
    void SetUp() override {
        // This method is intended to be invoked for each test just before the test starts
        connect();
        EXPECT_EQ(HSMAnonymousOpen, m_logonSession.status);
        logonSetup();
        logonWorking();
    }

    void TearDown() override {
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
        logoff();
        m_logonSession = ERP_Disconnect(m_logonSession);

        EXPECT_TRUE((m_logonSession.errorCode == ERP_ERR_NOERROR) ||
            (m_logonSession.errorCode == ERP_ERR_NO_CONNECTION));
    }
};

const std::string ErpPseudonameKeyTestFixture::devIP = SINGLE_SIM_HSM;

TEST_F(ErpPseudonameKeyTestFixture, GeneratePseudonameKey)
{
    unsigned int Gen = THE_ANSWER;
    UIntInput in = { Gen };
    SingleBlobOutput out = ERP_GeneratePseudonameKey(ErpPseudonameKeyTestFixture::m_logonSession, in);
    // If we want to use this blob in later test runs then we need to copy it to the saved directory
    ASSERT_EQ(ERP_ERR_NOERROR, out.returnCode);
    writeBlobResourceFile("PseudonameKey.blob", &(out.BlobOut));
}
TEST_F(ErpPseudonameKeyTestFixture, UnwrapPseudonameKey)
{
    std::unique_ptr<ERPBlob> savedKeyPairBlob =
        std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/PseudonameKeySaved.blob"));
    ASSERT_NE(nullptr, savedKeyPairBlob);
    AES256KeyOutput keyOut = { 0,{0} };
    teststep_UnwrapPseudonameKey(ErpPseudonameKeyTestFixture::m_logonSession, savedKeyPairBlob.get(), &keyOut);
    EXPECT_EQ(ERP_ERR_NOERROR, keyOut.returnCode);
    const unsigned char expectedKey[] = {
        0xd3, 0x76, 0x59, 0xff, 0x63, 0x98, 0x67, 0x84,
        0x67, 0xf8, 0x71, 0xea, 0xd9, 0xde, 0x77, 0xb1,
        0x29, 0xe3, 0xd3, 0xee, 0x57, 0xd4, 0x96, 0xfa,
        0xcd, 0x38, 0xe4, 0x43, 0x6d, 0x9b, 0xfe, 0xea
    };
    ASSERT_TRUE(0 == memcmp(&(keyOut.Key[0]), &(expectedKey[0]), 32));

    writeERPResourceFile("ERPPseudonameKey.bin",
        std::vector<std::uint8_t>(&(keyOut.Key[0]), &(keyOut.Key[0]) + AES_256_LEN));
}

// The intent of this test is to allow triggering of a single memory dump manually when using
//   the test suite for memory leak hunting.   i.e. run before and after a suspect other test.
TEST_F(ErpPseudonameKeyTestFixture, DumpMemoryTrace)
{
    teststep_DumpHSMMemory(ErpPseudonameKeyTestFixture::m_logonSession);
}

// The intent of this test is that it be run and then the HSM Memory dumps are inspected to see if the
//   number of allocated memory blocks is growing.
// This has actually grown to include other operations than psuedoname since the parameterised test suite in ERP_Tests.cpp
//   had a problem causing MSVS Test to crash.
TEST_F(ErpPseudonameKeyTestFixture, LoadLoopTests)
{
    std::unique_ptr<ERPBlob> savedKeyPairBlob =
        std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/VAUSIGKeyPairSaved_UT.blob"));
    ASSERT_NE(nullptr, savedKeyPairBlob);

    SingleBlobInput get = { {0,0,{0}} };
    get.BlobIn = *savedKeyPairBlob;

    TwoBlobGetKeyInput vauSIG = { {0,0,{0}}, {0,0,{0}} };
    vauSIG.Key = *savedKeyPairBlob;
    // Take the TEEToken from a previous test run:
    auto teeToken = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/StaticTEETokenSaved.blob"));
    ASSERT_NE(nullptr, teeToken);
    vauSIG.TEEToken = *teeToken;

    EmptyOutput dmpOut = ERP_DumpHSMMemory(ErpPseudonameKeyTestFixture::m_logonSession);
    for (int i = 0; i < BIG_LOOP; i++)
    {
        // Dump the memory on the simulator output, used to investigate memory leaks
        (void)ERP_DumpHSMMemory(ErpPseudonameKeyTestFixture::m_logonSession);
        UIntInput desiredBytes = { RND_256_LEN };
        RNDBytesOutput rndOut = ERP_GetRNDBytes(ErpPseudonameKeyTestFixture::m_logonSession, desiredBytes);
        EXPECT_EQ(ERP_ERR_NOERROR, rndOut.returnCode);
        EXPECT_EQ(RND_256_LEN, rndOut.RNDDataLen);
        unsigned int Gen = THE_ANSWER;
        UIntInput in = { Gen };
        SingleBlobOutput out = ERP_GeneratePseudonameKey(ErpPseudonameKeyTestFixture::m_logonSession, in);
        // If we want to use this blob in later test runs then we need to copy it to the saved directory
        ASSERT_EQ(ERP_ERR_NOERROR, out.returnCode);
        SingleBlobOutput out2 = ERP_GenerateDerivationKey(ErpPseudonameKeyTestFixture::m_logonSession, in);
        // If we want to use this blob in later test runs then we need to copy it to the saved directory
        ASSERT_EQ(ERP_ERR_NOERROR, out2.returnCode);
        NONCEOutput quoteNONCE = ERP_GenerateNONCE(ErpPseudonameKeyTestFixture::m_logonSession, in);
        ASSERT_EQ(ERP_ERR_NOERROR, quoteNONCE.returnCode);
        AES256KeyOutput keyOut = { 0,{0} };
        teststep_UnwrapPseudonameKey(ErpPseudonameKeyTestFixture::m_logonSession, &(out.BlobOut), &keyOut);
        EXPECT_EQ(ERP_ERR_NOERROR, keyOut.returnCode);
        PrivateKeyOutput privKeyOut = ERP_GetVAUSIGPrivateKey(ErpPseudonameKeyTestFixture::m_logonSession, vauSIG);
        ASSERT_EQ(ERP_ERR_NOERROR, privKeyOut.returnCode);
        PublicKeyOutput pubKeyOut = ERP_GetECPublicKey(ErpPseudonameKeyTestFixture::m_logonSession, get);
        EXPECT_EQ(ERP_ERR_NOERROR, pubKeyOut.returnCode);
    }
    dmpOut = ERP_DumpHSMMemory(ErpPseudonameKeyTestFixture::m_logonSession);
}
