/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2022
 * (C) Copyright IBM Corp. 2022
 * SPDX-License-Identifier: CC BY-NC-ND 3.0 DE
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
