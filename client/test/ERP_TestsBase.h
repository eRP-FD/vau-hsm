/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021, 2024
 * (C) Copyright IBM Corp. 2021, 2024
 *
 * non-exclusively licensed to gematik GmbH
 **************************************************************************************************/

#ifndef ERP_TEST_BASE_H
#define ERP_TEST_BASE_H

#include "ERP_Client.h"

#include <gtest/gtest.h>

class ErpBaseTestsFixture : public ::testing::Test {
public:

    enum users {
        Setup=0, Working=1, Set1=2, Set2=3, Update=4
    };

    HSMSession m_logonSession = { 0, 0, 0, HSMUninitialised, 0, ERP_ERR_NOERROR, 0 };
    static const std::string devIP;

    ErpBaseTestsFixture();

    void connect();

    void logonSetup();

    void logonWorking();

    void logon(const std::vector<ErpBaseTestsFixture::users>& setOfUsers);

    void logoff();

    static void SetUpTestSuite();

    void SetUp() override;

    void TearDown() override;

    // this blob key generation is used for the tests with the pre computed blobs
    static const unsigned int generationSaved;
    static std::unique_ptr<ERPBlob> savedTrustedRoot;
    static std::unique_ptr<ERPBlob> savedTrustedEK;
    static std::unique_ptr<ERPBlob> savedAKChallenge1Blob;
    static std::unique_ptr<ERPBlob> savedAKChallenge2Blob;
    static std::unique_ptr<ERPBlob> savedTrustedAK;
    static std::unique_ptr<ERPBlob> teeToken;
    static std::unique_ptr<ERPBlob> savedECIESKeyPairBlob;
    static std::unique_ptr<ERPBlob> savedVAUAUTKeyPairBlob;
    static std::unique_ptr<ERPBlob> savedEnrollmentNONCE;
    static std::unique_ptr<ERPBlob> savedAttestationNONCE;
    static std::unique_ptr<ERPBlob> savedTrustedQuote;
    static std::unique_ptr<ERPBlob> savedVAUSIGKeyPairBlob;

    static std::vector<std::uint8_t> savedAKName;
    static std::vector<std::uint8_t> clientPub;
    static std::vector<std::uint8_t> savedAKPub;
    static std::vector<std::uint8_t> savedEnrollmentQuote;
    static std::vector<std::uint8_t> savedEnrollmentQuoteSignature;
    static std::vector<std::uint8_t> savedAttestationQuote;
    static std::vector<std::uint8_t> savedAttestationQuoteSignature;
    static std::vector<std::uint8_t> savedDecCred;
};

#endif // ERP_TEST_BASE_H
