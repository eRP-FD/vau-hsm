/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021
 * (C) Copyright IBM Corp. 2021
 * SPDX-License-Identifier: CC BY-NC-ND 3.0 DE
 **************************************************************************************************/

#include "ERP_Client.h"
#include "ERP_Error.h"
#include "ERP_TestParams.h"
#include "ERP_TestUtils.h"

#include <gtest/gtest.h>

#include <memory>
#include <vector>

class ErpHashKeyTestFixture : public ::testing::Test {
public:
    static HSMSession m_logonSession;
    static const std::string devIP;

    ErpHashKeyTestFixture() = default;

    void static connect() {
        // code here will execute just before the test ensues 
        m_logonSession = ERP_Connect(devIP.c_str(), TEST_CONNECT_TIMEOUT_MS, TEST_READ_TIMEOUT_MS);
    }
    void static logonSetup() {
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
    void static logonWorking() {
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
    void static logoff()
    {
        if (m_logonSession.status == HSMLoggedIn)
        {
            m_logonSession = ERP_Logoff(m_logonSession);
            ASSERT_EQ(HSMAnonymousOpen, m_logonSession.status);
        }
    }
    void SetUp() override {
        // code here will execute just before the test ensues 
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

HSMSession ErpHashKeyTestFixture::m_logonSession = { 0, 0, 0, HSMUninitialised, 0, ERP_ERR_NOERROR, 0 };
const std::string ErpHashKeyTestFixture::devIP = SINGLE_SIM_HSM;

TEST_F(ErpHashKeyTestFixture, GenerateHashKey)
{
    unsigned int Gen = THE_ANSWER;
    UIntInput in = { Gen };
    SingleBlobOutput out = ERP_GenerateHashKey(ErpHashKeyTestFixture::m_logonSession, in);
    // If we want to use this blob in later test runs then we need to copy it to the saved directory
    ASSERT_EQ(ERP_ERR_NOERROR, out.returnCode);
    writeBlobResourceFile("HashKey.blob", &(out.BlobOut));
}
TEST_F(ErpHashKeyTestFixture, UnwrapHashKey)
{
    std::unique_ptr<ERPBlob> savedKeyPairBlob =
        std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/HashKeySaved.blob"));
    ASSERT_NE(nullptr, savedKeyPairBlob);
    AES256KeyOutput keyOut = { 0,{0} };
    teststep_UnwrapHashKey(ErpHashKeyTestFixture::m_logonSession, savedKeyPairBlob.get(),&keyOut);
    EXPECT_EQ(ERP_ERR_NOERROR, keyOut.returnCode);
    const unsigned char expectedKey[] = { 
        0xa7, 0xab, 0xd1, 0x94, 0xe5, 0x0b, 0x14, 0x0c, 0x9b, 0xe7, 0xfe, 0xe7, 0xbb, 0x39, 0x07, 0xd9
        ,0xbe, 0xd8, 0xda, 0xdc, 0x2f, 0xc8, 0x3f, 0x9c, 0xaa, 0x41, 0x05, 0xa8, 0xc1, 0x1a, 0xc2, 0xf8
    };
    ASSERT_TRUE(0 == memcmp(&(keyOut.Key[0]), &(expectedKey[0]), 32));

    writeERPResourceFile("ERPHashKey.bin",
        std::vector<std::uint8_t>(&(keyOut.Key[0]), &(keyOut.Key[0]) + AES_256_LEN));
}
