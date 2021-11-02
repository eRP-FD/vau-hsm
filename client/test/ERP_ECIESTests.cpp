#include "ERP_Client.h"
#include "ERP_SFC.h"
#include "ERP_Error.h"
#include "ERP_TestUtils.h"
#include "ERP_TestParams.h"
#include <gtest/gtest.h>

#include <vector>
#include <fstream>
#include <memory>
#include <cstddef>

class ErpECIESTestFixture : public ::testing::Test {
public:
    static HSMSession m_logonSession;
    static const std::string devIP;

    ErpECIESTestFixture() {
        // initialization code here
    }

    void connect() {
        // code here will execute just before the test ensues 
        m_logonSession = ERP_Connect(devIP.c_str(), 5000, 1800000);
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

HSMSession ErpECIESTestFixture::m_logonSession = { 0, 0, 0, HSMUninitialised, 0, ERP_ERR_NOERROR, 0 };
const std::string ErpECIESTestFixture::devIP = SINGLE_SIM_HSM;

TEST_F(ErpECIESTestFixture, GenerateECIESKeypair)
{
    unsigned int Gen = 0x42;
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
    ASSERT_NE(nullptr, savedKeyPairBlob.get());

    SingleBlobInput get = { {0,0,{0}} };
    get.BlobIn = *savedKeyPairBlob;
    PublicKeyOutput keyOut = ERP_GetECPublicKey(ErpECIESTestFixture::m_logonSession, get);
    EXPECT_EQ(ERP_ERR_NOERROR, keyOut.returnCode);
    writeERPResourceFile("ECIESPublicKey.bin",
        std::vector<char>(keyOut.keyData, keyOut.keyData + keyOut.keyLength));
}

TEST_F(ErpECIESTestFixture, doVAUECIES)
{
    std::unique_ptr<ERPBlob> savedKeyPairBlob = 
        std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/ECIESKeyPairSaved.blob"));
    ASSERT_NE(nullptr, savedKeyPairBlob.get());

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
    unsigned char expectedKey[] = { 0xda, 0x7c, 0x96, 0x48, 0xf7, 0xab, 0xa4, 0x6d
        , 0x6f, 0x7b, 0x98, 0x5e, 0xf8, 0xa9, 0x4b, 0x02 };
    ASSERT_TRUE(0 == memcmp(&(keyOut.AESKey[0]), &(expectedKey[0]), 16));
}

TEST_F(ErpECIESTestFixture, generateECIESCSR)
{
    std::unique_ptr<ERPBlob> savedKeyPairBlob =
        std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/ECIESKeyPairSaved.blob"));
    ASSERT_NE(nullptr, savedKeyPairBlob.get());

    GetVAUCSRInput eciesCSR = { {0,0,{0}} ,0, {0} };
    eciesCSR.KeyPair = *savedKeyPairBlob;
    // At the moment these candidate CSRs are from the ePA TU authn.
    auto candidateCSR = readERPResourceFile("candidateECIES.csr");
    ASSERT_GT(candidateCSR.size(), 0);
    eciesCSR.candidateCSRLength = candidateCSR.size();
    memcpy(&(eciesCSR.candidateCSR[0]), candidateCSR.data(), candidateCSR.size());
    x509CSROutput keyOut = { 0,0,{0} };
    for (int i = 0; i < 100; i++)
    {
        keyOut = ERP_GenerateECIESCSR(ErpECIESTestFixture::m_logonSession, eciesCSR);
        ASSERT_EQ(ERP_ERR_NOERROR, keyOut.returnCode);
    }

    // TO DO - set up check of expected output.
//    unsigned char expectedKey[] = { 0x30, 0x81, 0x95, 0x02, 0x01, 0x00, 0x30, 0x14, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
//        0xdf, 0xd6, 0x5f, 0xf9, 0x73, 0xef, 0x0f, 0x9e };
//    ASSERT_EQ(sizeof(expectedKey), keyOut.keyLength);
//    ASSERT_TRUE(0 == memcmp(&(keyOut.keyData[0]), &(expectedKey[0]), sizeof(expectedKey)));
    // TO DO check CSR Signature?
    writeERPResourceFile("generatedECIES.csr",
        std::vector<char>(keyOut.CSRData, keyOut.CSRData + keyOut.CSRDataLength));
}