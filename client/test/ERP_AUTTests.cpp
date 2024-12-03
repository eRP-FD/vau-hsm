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

class ErpAUTTestFixture : public ::testing::Test {
public:
    HSMSession m_logonSession = { 0, 0, 0, HSMUninitialised, 0, ERP_ERR_NOERROR, 0 };
    static const std::string devIP;

    ErpAUTTestFixture() = default;

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

const std::string ErpAUTTestFixture::devIP = SINGLE_SIM_HSM;

TEST_F(ErpAUTTestFixture, GenerateAUTKeypair)
{
    unsigned int Gen = THE_ANSWER;
    UIntInput in = { Gen };
    SingleBlobOutput out = ERP_GenerateAUTKeyPair(ErpAUTTestFixture::m_logonSession, in);
    // If we want to use this blob in later test runs then we need to copy it to the saved directory
    writeBlobResourceFile("AUTKeyPair.blob", &(out.BlobOut));
    EXPECT_EQ(ERP_ERR_NOERROR, out.returnCode);
}

TEST_F(ErpAUTTestFixture, GetAUTPublicKey)
{
    std::unique_ptr<ERPBlob> savedKeyPairBlob =
        std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/AUTKeyPairSaved.blob"));
    ASSERT_NE(nullptr, savedKeyPairBlob);

    SingleBlobInput get = { {0,0,{0}} };
    get.BlobIn = *savedKeyPairBlob;
    PublicKeyOutput keyOut = ERP_GetECPublicKey(ErpAUTTestFixture::m_logonSession, get);
    EXPECT_EQ(ERP_ERR_NOERROR, keyOut.returnCode);
    writeERPResourceFile("AUTPublicKey.bin",
        std::vector<std::uint8_t>(&(keyOut.keyData[0]), &(keyOut.keyData[0]) + keyOut.keyLength));
}


TEST_F(ErpAUTTestFixture, generateAUTCSR)
{
    std::unique_ptr<ERPBlob> savedKeyPairBlob =
        std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/AUTKeyPairSaved.blob"));
    ASSERT_NE(nullptr, savedKeyPairBlob);

    GetVAUCSRInput autCSR = { {0,0,{0}} ,0, {0} };
    autCSR.KeyPair = *savedKeyPairBlob;
    // At the moment these candidate CSRs are from the ePA TU authn.
    auto candidateCSR = readERPResourceFile("candidateAUT.csr");
    ASSERT_GT(candidateCSR.size(), 0);
    autCSR.candidateCSRLength = candidateCSR.size();
    memcpy(&(autCSR.candidateCSR[0]), candidateCSR.data(), candidateCSR.size());
    x509CSROutput keyOut = ERP_GenerateAUTCSR(ErpAUTTestFixture::m_logonSession, autCSR);
    ASSERT_EQ(ERP_ERR_NOERROR, keyOut.returnCode);

    writeERPResourceFile("generatedAUT.csr",
        std::vector<std::uint8_t>(&(keyOut.CSRData[0]), &(keyOut.CSRData[0]) + keyOut.CSRDataLength));
}

TEST_F(ErpAUTTestFixture, signWithAutKey)
{
    std::unique_ptr<ERPBlob> savedKeyPairBlob =
        std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/AUTKeyPairSaved.blob"));
    ASSERT_NE(nullptr, savedKeyPairBlob);
    auto teeToken = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/StaticTEETokenSaved.blob"));
    AutSignatureInput in = {};
    in.TEEToken = *teeToken;
    in.AutKeyPair = *savedKeyPairBlob;
    const char inputData[] = "hello";
    memcpy(in.signableData, inputData, sizeof(inputData));
    in.signableLength = sizeof(inputData);
    AutSignatureOutput out = ERP_SignVAUAUTToken(ErpAUTTestFixture::m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, out.returnCode);
    ASSERT_EQ(64, out.signatureLength);
}


// The intent of this test is that it be run and then the HSM Memory dumps are inspected to see if the
//   number of allocated memory blocks is growing.
TEST_F(ErpAUTTestFixture, LoadLoopTests)
{
    const unsigned int Gen = THE_ANSWER;

    GetVAUCSRInput autCSR = { {0,0,{0}} ,0, {0} };
    // At the moment these candidate CSRs are from the ePA authn.
    auto candidateCSR = readERPResourceFile("candidateAUT.csr");
    ASSERT_GT(candidateCSR.size(), 0);
    autCSR.candidateCSRLength = candidateCSR.size();
    memcpy(&(autCSR.candidateCSR[0]), candidateCSR.data(), candidateCSR.size());

    std::unique_ptr<ERPBlob> savedKeyPairBlob =
        std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/AUTKeyPairSaved.blob"));
    ASSERT_NE(nullptr, savedKeyPairBlob);

    autCSR.KeyPair = *savedKeyPairBlob;

    auto teeToken = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/StaticTEETokenSaved.blob"));
    AutSignatureInput in = {};
    in.TEEToken = *teeToken;
    in.AutKeyPair = *savedKeyPairBlob;
    const char inputData[] = "hello";
    memcpy(in.signableData, inputData, sizeof(inputData));
    in.signableLength = sizeof(inputData);

    ERP_DumpHSMMemory(m_logonSession);
    for (int i = 0; i < BIG_LOOP; i++)
    {
        // ERP_GenerateAUTCSR
        {
            x509CSROutput keyOut = ERP_GenerateAUTCSR(ErpAUTTestFixture::m_logonSession, autCSR);
            ASSERT_EQ(ERP_ERR_NOERROR, keyOut.returnCode);
        }

        // ERP_SignVAUAUTToken
        {
            AutSignatureOutput out = ERP_SignVAUAUTToken(ErpAUTTestFixture::m_logonSession, in);
            ASSERT_EQ(ERP_ERR_NOERROR, out.returnCode);
        }
        // ERP_GenerateAUTKeyPair
        {
            UIntInput inGen = { Gen };
            SingleBlobOutput out = ERP_GenerateAUTKeyPair(ErpAUTTestFixture::m_logonSession, inGen);
            ASSERT_EQ(ERP_ERR_NOERROR, out.returnCode);
        }
    }
    ERP_DumpHSMMemory(m_logonSession);
}
