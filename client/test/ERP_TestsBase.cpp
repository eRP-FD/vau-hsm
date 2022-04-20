/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021
 * (C) Copyright IBM Corp. 2021
 * SPDX-License-Identifier: CC BY-NC-ND 3.0 DE
 **************************************************************************************************/

#include "ERP_Client.h"
#include "ERP_Error.h"
#include "ERP_TestParams.h"
#include "ERP_TestUtils.h"
#include "ERP_TestsBase.h"

#include <fstream>

const std::string ErpBaseTestsFixture::devIP = SINGLE_SIM_HSM;

HSMSession ErpBaseTestsFixture::m_logonSession = {0, 0, 0, HSMUninitialised, 0, ERP_ERR_NOERROR, 0};

ErpBaseTestsFixture::ErpBaseTestsFixture()
{
    m_logonSession = {0, 0, 0, HSMUninitialised, 0, ERP_ERR_NOERROR, 0};
}

void ErpBaseTestsFixture::connect()
{
    // code here will execute just before the test ensues
    m_logonSession = ERP_Connect(devIP.c_str(), TEST_CONNECT_TIMEOUT_MS, TEST_READ_TIMEOUT_MS);
}

void ErpBaseTestsFixture::logonSetup()
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

void ErpBaseTestsFixture::logonWorking()
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

void ErpBaseTestsFixture::logoff()
{
    if (m_logonSession.status == HSMLoggedIn) {
        m_logonSession = ERP_Logoff(m_logonSession);
        ASSERT_EQ(HSMAnonymousOpen, m_logonSession.status);
    }
}

const unsigned int ErpBaseTestsFixture::generationSaved = THE_ANSWER;
std::unique_ptr<ERPBlob> ErpBaseTestsFixture::savedTrustedRoot;
std::unique_ptr<ERPBlob> ErpBaseTestsFixture::savedTrustedEK;
std::unique_ptr<ERPBlob> ErpBaseTestsFixture::savedAKChallenge1Blob;
std::unique_ptr<ERPBlob> ErpBaseTestsFixture::savedAKChallenge2Blob;
std::unique_ptr<ERPBlob> ErpBaseTestsFixture::savedTrustedAK;
std::unique_ptr<ERPBlob> ErpBaseTestsFixture::teeToken;
std::unique_ptr<ERPBlob> ErpBaseTestsFixture::savedECIESKeyPairBlob;
std::unique_ptr<ERPBlob> ErpBaseTestsFixture::savedEnrollmentNONCE;
std::unique_ptr<ERPBlob> ErpBaseTestsFixture::savedAttestationNONCE;
std::unique_ptr<ERPBlob> ErpBaseTestsFixture::savedTrustedQuote;
std::unique_ptr<ERPBlob> ErpBaseTestsFixture::savedVAUSIGKeyPairBlob;

std::vector<std::uint8_t> ErpBaseTestsFixture::savedAKName;
std::vector<std::uint8_t> ErpBaseTestsFixture::clientPub;
std::vector<std::uint8_t> ErpBaseTestsFixture::savedAKPub;
std::vector<std::uint8_t> ErpBaseTestsFixture::savedEnrollmentQuote;
std::vector<std::uint8_t> ErpBaseTestsFixture::savedEnrollmentQuoteSignature;
std::vector<std::uint8_t> ErpBaseTestsFixture::savedAttestationQuote;
std::vector<std::uint8_t> ErpBaseTestsFixture::savedAttestationQuoteSignature;
std::vector<std::uint8_t> ErpBaseTestsFixture::savedDecCred;

void ErpBaseTestsFixture::SetUpTestSuite()
{
    savedTrustedRoot = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/trustedRootSaved.blob"));
    savedTrustedEK = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/trustedEKSaved.blob"));
    savedAKChallenge1Blob = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/AKChallengeSaved.blob"));
    savedAKChallenge2Blob = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/AKChallenge2Saved.blob"));
    savedTrustedAK = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/trustedAkSaved.blob"));
    teeToken = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/StaticTEETokenSaved.blob"));
    savedECIESKeyPairBlob = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/ECIESKeyPairSaved.blob"));
    savedEnrollmentNONCE = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/EnrollmentQuoteNONCESaved.blob"));
    savedAttestationNONCE = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/AttestationQuoteNONCESaved.blob"));
    savedTrustedQuote = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/trustedQuoteSaved.blob"));
    savedVAUSIGKeyPairBlob = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/VAUSIGKeyPairSaved_UT.blob"));
    clientPub = readERPResourceFile("saved/clientECIESPub.bin");
    savedAKName = readERPResourceFile("saved/h80000002.bin");
    savedAKPub = readERPResourceFile("saved/AKPub.bin");
    savedEnrollmentQuote = readERPResourceFile("saved/EnrollmentQuoteSaved.bin");
    savedEnrollmentQuoteSignature = readERPResourceFile("saved/EnrollmentQuoteSigSaved.bin");
    savedAttestationQuote = readERPResourceFile("saved/AttestationQuoteSaved.bin");
    savedAttestationQuoteSignature = readERPResourceFile("saved/AttestationQuoteSigSaved.bin");
    savedDecCred = readERPResourceFile("saved/credDecHSMSaved.bin");

    ASSERT_NE(nullptr, savedTrustedRoot);
    ASSERT_NE(nullptr, savedTrustedEK);
    ASSERT_NE(nullptr, savedTrustedAK);
    ASSERT_NE(nullptr, savedECIESKeyPairBlob);
    ASSERT_NE(nullptr, teeToken);
    ASSERT_NE(nullptr, savedEnrollmentNONCE);
    ASSERT_NE(nullptr, savedAttestationNONCE);
    ASSERT_NE(nullptr, savedTrustedQuote);
    ASSERT_NE(nullptr, savedVAUSIGKeyPairBlob);

    ASSERT_NE(clientPub.empty(), true);
    ASSERT_NE(savedAKName.empty(), true);
    ASSERT_NE(savedEnrollmentQuote.empty(), true);
    ASSERT_NE(savedEnrollmentQuoteSignature.empty(), true);
    ASSERT_NE(savedAttestationQuote.empty(), true);
    ASSERT_NE(savedAttestationQuoteSignature.empty(), true);

}

void ErpBaseTestsFixture::SetUp()
{
    // code here will execute just before the test ensues
    connect();
    EXPECT_EQ(HSMAnonymousOpen, m_logonSession.status);
    logonSetup();
    logonWorking();
}


void ErpBaseTestsFixture::TearDown()
{
    // code here will be called just after the test completes
    // ok to through exceptions from here if need be
    logoff();
    m_logonSession = ERP_Disconnect(m_logonSession);

    EXPECT_TRUE((m_logonSession.errorCode == ERP_ERR_NOERROR) ||
                (m_logonSession.errorCode == ERP_ERR_NO_CONNECTION));
}

void ErpBaseTestsFixture::logon(const std::vector<ErpBaseTestsFixture::users> &setOfUsers)
{
    static const char *userNames[] =
            {"ERP_SETUP", "ERP_WORK", "ERP_SET1", "ERP_SET2", "ERP_UPDT"};

    const static std::string password = "password";

    logoff();

    for (ErpBaseTestsFixture::users u: setOfUsers) {
        auto userName = userNames[u];

        printf("Logon user %s\n", userName);
        m_logonSession = ERP_LogonPassword(m_logonSession, userName, password.c_str());
        ASSERT_EQ(HSMLoggedIn, m_logonSession.status);
    }
}
