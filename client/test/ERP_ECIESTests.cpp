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

class ErpECIESTestFixture : public ::testing::Test {
public:
    HSMSession m_logonSession = { 0, 0, 0, HSMUninitialised, 0, ERP_ERR_NOERROR, 0 };
    static const std::string devIP;

    ErpECIESTestFixture() = default;

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

const std::string ErpECIESTestFixture::devIP = SINGLE_SIM_HSM;

TEST_F(ErpECIESTestFixture, GenerateECIESKeypair)
{
    unsigned int Gen = THE_ANSWER;
    UIntInput in = { Gen };
    SingleBlobOutput out = ERP_GenerateECIESKeyPair(ErpECIESTestFixture::m_logonSession, in);
    // If we want to use this blob in later test runs then we need to copy it to the saved directory
    writeBlobResourceFile("ECIESKeyPair.blob", &(out.BlobOut));
    EXPECT_EQ(ERP_ERR_NOERROR, out.returnCode);
 }
TEST_F(ErpECIESTestFixture, GetECIESPublicKey)
{
    std::unique_ptr<ERPBlob> savedKeyPairBlob =
        std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/ECIESKeyPairSaved.blob"));
    ASSERT_NE(nullptr, savedKeyPairBlob);

    SingleBlobInput get = { {0,0,{0}} };
    get.BlobIn = *savedKeyPairBlob;
    PublicKeyOutput keyOut = ERP_GetECPublicKey(ErpECIESTestFixture::m_logonSession, get);
    EXPECT_EQ(ERP_ERR_NOERROR, keyOut.returnCode);
    writeERPResourceFile("ECIESPublicKey.bin",
        std::vector<std::uint8_t>(&(keyOut.keyData[0]), &(keyOut.keyData[0]) + keyOut.keyLength));
}

TEST_F(ErpECIESTestFixture, doVAUECIES)
{
    std::unique_ptr<ERPBlob> savedKeyPairBlob =
        std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/ECIESKeyPairSaved.blob"));
    ASSERT_NE(nullptr, savedKeyPairBlob);

    DoVAUECIESInput vauECIES = { {0,0,{0}}, {0,0,{0}},0, {0} };
    vauECIES.ECIESKeyPair = *savedKeyPairBlob;
    // Take the TEEToken from a previous test run:
    auto teeToken = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/StaticTEETokenSaved.blob"));
    ASSERT_NE(nullptr, teeToken);
    vauECIES.TEEToken = *teeToken;
    auto clientPub = readERPResourceFile("saved/clientECIESPub.bin");
//    auto clientPub = readERPResourceFile("saved/GemSpecClientECIESPub.bin");
    ASSERT_GT(clientPub.size(),0);
    memcpy(&(vauECIES.clientPublicKeyData[0]),clientPub.data(),clientPub.size());
    vauECIES.clientPublicKeyLength = clientPub.size();
    AES128KeyOutput keyOut = ERP_DoVAUECIES128(ErpECIESTestFixture::m_logonSession, vauECIES);
    ASSERT_EQ(ERP_ERR_NOERROR, keyOut.returnCode);
    const unsigned char expectedKey[] = { 0xda, 0x7c, 0x96, 0x48, 0xf7, 0xab, 0xa4, 0x6d
        , 0x6f, 0x7b, 0x98, 0x5e, 0xf8, 0xa9, 0x4b, 0x02 };
    ASSERT_TRUE(0 == memcmp(&(keyOut.AESKey[0]), &(expectedKey[0]), 16));
}

TEST_F(ErpECIESTestFixture, generateECIESCSR)
{
    std::unique_ptr<ERPBlob> savedKeyPairBlob =
        std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/ECIESKeyPairSaved.blob"));
    ASSERT_NE(nullptr, savedKeyPairBlob);

    GetVAUCSRInput eciesCSR = { {0,0,{0}} ,0, {0} };
    eciesCSR.KeyPair = *savedKeyPairBlob;
    // At the moment these candidate CSRs are from the ePA TU authn.
    auto candidateCSR = readERPResourceFile("candidateECIES.csr");
    ASSERT_GT(candidateCSR.size(), 0);
    eciesCSR.candidateCSRLength = candidateCSR.size();
    memcpy(&(eciesCSR.candidateCSR[0]), candidateCSR.data(), candidateCSR.size());
    x509CSROutput keyOut = { 0,0,{0} };
    for (int i = 0; i < MEDIUM_LOOP; i++)
    {
        keyOut = ERP_GenerateECIESCSR(ErpECIESTestFixture::m_logonSession, eciesCSR);
        ASSERT_EQ(ERP_ERR_NOERROR, keyOut.returnCode);
    }

    // TODO(chris) - set up check of expected output.
//    unsigned char expectedKey[] = { 0x30, 0x81, 0x95, 0x02, 0x01, 0x00, 0x30, 0x14, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
//        0xdf, 0xd6, 0x5f, 0xf9, 0x73, 0xef, 0x0f, 0x9e };
//    ASSERT_EQ(sizeof(expectedKey), keyOut.keyLength);
//    ASSERT_TRUE(0 == memcmp(&(keyOut.keyData[0]), &(expectedKey[0]), sizeof(expectedKey)));
    // TODO(chris) check CSR Signature?
    writeERPResourceFile("generatedECIES.csr",
        std::vector<std::uint8_t>(&(keyOut.CSRData[0]), &(keyOut.CSRData[0]) + keyOut.CSRDataLength));
}
