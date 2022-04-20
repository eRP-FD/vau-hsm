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

class ErpVAUSIGTestFixture : public ::testing::Test {
public:
    static HSMSession m_logonSession;
    static const std::string devIP;

    ErpVAUSIGTestFixture() = default;

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

HSMSession ErpVAUSIGTestFixture::m_logonSession = { 0, 0, 0, HSMUninitialised, 0, ERP_ERR_NOERROR, 0 };
const std::string ErpVAUSIGTestFixture::devIP = SINGLE_SIM_HSM;

TEST_F(ErpVAUSIGTestFixture, GenerateVAUSIGKeypair)
{
    unsigned int Gen = THE_ANSWER;
    UIntInput in = { Gen };
    SingleBlobOutput out = ERP_GenerateVAUSIGKeyPair(ErpVAUSIGTestFixture::m_logonSession, in);
    // If we want to use this blob in later test runs then we need to copy it to the saved directory
    writeBlobResourceFile("VAUSIGKeyPair.blob", &(out.BlobOut));
    EXPECT_EQ(ERP_ERR_NOERROR, out.returnCode);
}

TEST_F(ErpVAUSIGTestFixture, GetVAUSIGPublicKey)
{
    std::unique_ptr<ERPBlob> savedKeyPairBlob =
        std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/VAUSIGKeyPairSaved_UT.blob"));
    ASSERT_NE(nullptr, savedKeyPairBlob);

    SingleBlobInput get = { {0,0,{0}} };
    get.BlobIn = *savedKeyPairBlob;
    PublicKeyOutput keyOut = ERP_GetECPublicKey(ErpVAUSIGTestFixture::m_logonSession, get);
    EXPECT_EQ(ERP_ERR_NOERROR, keyOut.returnCode);
    writeERPResourceFile("VAUSIGPublicKey.bin",
        std::vector<std::uint8_t>(&(keyOut.keyData[0]), &(keyOut.keyData[0]) + keyOut.keyLength));
}

TEST_F(ErpVAUSIGTestFixture, getVAUSIGPrivateKey)
{
    std::unique_ptr<ERPBlob> savedKeyPairBlob =
        std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/VAUSIGKeyPairSaved_UT.blob"));
    ASSERT_NE(nullptr, savedKeyPairBlob);

    TwoBlobGetKeyInput vauSIG = { {0,0,{0}}, {0,0,{0}} };
    vauSIG.Key = *savedKeyPairBlob;
    // Take the TEEToken from a previous test run:
    auto teeToken = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/StaticTEETokenSaved.blob"));
    ASSERT_NE(nullptr, teeToken);
    vauSIG.TEEToken = *teeToken;
    PrivateKeyOutput keyOut = ERP_GetVAUSIGPrivateKey(ErpVAUSIGTestFixture::m_logonSession, vauSIG);
    ASSERT_EQ(ERP_ERR_NOERROR, keyOut.returnCode);

    // Check of expected output.
    const unsigned char expectedKey[] = { 0x30, 0x81, 0x95, 0x02, 0x01, 0x00, 0x30, 0x14, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 
        0x01, 0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07, 0x04, 0x7a, 0x30, 0x78,
        0x02, 0x01, 0x01, 0x04, 0x20, 0x52, 0xbb, 0xa0, 0x49, 0xee, 0x4f, 0x9a, 0x4d, 0xcc, 0xc5, 0x30,
        0xd4, 0x17, 0x01, 0x69, 0x09, 0x86, 0x76, 0x81, 0x47, 0x99, 0x78, 0x3d, 0xaf, 0xb0, 0x15, 0x49,
        0x33, 0xcb, 0xa2, 0x9c, 0x96, 0xa0, 0x0b, 0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01,
        0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x47, 0x32, 0x18, 0x41, 0x69, 0xd6, 0xe1, 0x6b,
        0x56, 0xfb, 0x5b, 0x0e, 0xc6, 0xb7, 0xe9, 0xac, 0x34, 0xc8, 0x9c, 0x7e, 0x83, 0x63, 0x72, 0xe8,
        0xa6, 0x63, 0xe3, 0x0f, 0xe7, 0x51, 0xd3, 0xb2, 0x4b, 0xfb, 0x79, 0xb1, 0x6d, 0x5e, 0x18, 0xa3,
        0x67, 0x46, 0x30, 0x3c, 0xae, 0x2b, 0xea, 0xfe, 0x76, 0xd4, 0x19, 0xd3, 0x3b, 0xbe, 0xbf, 0x44,
        0xdf, 0xd6, 0x5f, 0xf9, 0x73, 0xef, 0x0f, 0x9e };
    ASSERT_EQ(sizeof(expectedKey), keyOut.keyLength);
    ASSERT_TRUE(0 == memcmp(&(keyOut.keyData[0]), &(expectedKey[0]), sizeof(expectedKey)));
}

TEST_F(ErpVAUSIGTestFixture, generateVAUSIGCSR)
{
    std::unique_ptr<ERPBlob> savedKeyPairBlob =
        std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/VAUSIGKeyPairSaved_UT.blob"));
    ASSERT_NE(nullptr, savedKeyPairBlob);

    GetVAUCSRInput vauCSR = { {0,0,{0}} ,0, {0} };
    vauCSR.KeyPair = *savedKeyPairBlob;
    // At the moment these candidate CSRs are from the ePA TU authn.
    auto candidateCSR = readERPResourceFile("candidateVAUSIG.csr");
    ASSERT_GT(candidateCSR.size(), 0);
    vauCSR.candidateCSRLength = candidateCSR.size();
    memcpy(&(vauCSR.candidateCSR[0]), candidateCSR.data(), candidateCSR.size());
    x509CSROutput keyOut = ERP_GenerateVAUSIGCSR(ErpVAUSIGTestFixture::m_logonSession, vauCSR);
    ASSERT_EQ(ERP_ERR_NOERROR, keyOut.returnCode);

    // TODO(chris) - set up check of expected output.
//    unsigned char expectedKey[] = { 0x30, 0x81, 0x95, 0x02, 0x01, 0x00, 0x30, 0x14, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
//        0xdf, 0xd6, 0x5f, 0xf9, 0x73, 0xef, 0x0f, 0x9e };
//    ASSERT_EQ(sizeof(expectedKey), keyOut.keyLength);
//    ASSERT_TRUE(0 == memcmp(&(keyOut.keyData[0]), &(expectedKey[0]), sizeof(expectedKey)));
    // TODO(chris) check CSR Signature?
    writeERPResourceFile("generatedVAUSIG.csr",
        std::vector<std::uint8_t>(&(keyOut.CSRData[0]), &(keyOut.CSRData[0]) + keyOut.CSRDataLength));
}
