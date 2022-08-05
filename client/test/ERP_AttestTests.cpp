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

#include <cstddef>
#include <memory>
#include <vector>

class ErpAttestationTestFixture : public ::testing::Test {
public:
    HSMSession m_logonSession = { 0, 0, 0, HSMUninitialised, 0, ERP_ERR_NOERROR, 0 };
    static const std::string devIP;
    static ERPBlob m_SavedTEEToken;

    ErpAttestationTestFixture() = default;

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
    void logonUpdate() {
        bool doLogon = true;
        if (doLogon)
        {
            // user ERP_WORK with "password" and permissions 00000020
            const static std::string workUsername = "ERP_UPDT";
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

const std::string ErpAttestationTestFixture::devIP = SINGLE_SIM_HSM;
ERPBlob ErpAttestationTestFixture::m_SavedTEEToken = { 0,0,{'\0'} };

// Check that a proposed TPM Manufacturer root ca certificate is actually a CA.
TEST_F(ErpAttestationTestFixture, MfrCertIsNotRoot)
{
    unsigned int err = ERP_ERR_NOERROR;
    unsigned int Gen = THE_ANSWER; // This should be present on default simulator.
    // Sequence:
    // 1. Trust Mfr Root CA Certificate
    auto pTrustedRoot = getEmptyBlob(Gen);
    auto MfrRootCert = readERPResourceFile("EKCertECC.crt");

    err = teststep_TrustTPMMfr(ErpAttestationTestFixture::m_logonSession, Gen, pTrustedRoot.get(), MfrRootCert);
    EXPECT_EQ(ERP_ERR_CERT_WRONG_ISCA_VALUE, err);
}

// Check that a proposed TPM Manufacturer root ca certificate is actually a CA.
TEST_F(ErpAttestationTestFixture, MfrCertGood)
{
    unsigned int err = ERP_ERR_NOERROR;
    unsigned int Gen = THE_ANSWER; // This should be present on default simulator.
    // Sequence:
    // 1. Trust Mfr Root CA Certificate
    auto pTrustedRoot = getEmptyBlob(Gen);
    auto MfrRootCert = readERPResourceFile("cacertecc.crt");

    err = teststep_TrustTPMMfr(ErpAttestationTestFixture::m_logonSession, Gen, pTrustedRoot.get(), MfrRootCert);
    EXPECT_EQ(ERP_ERR_NOERROR, err);
}

// Check that a proposed TPM Manufacturer root ca certificate uses ECC
TEST_F(ErpAttestationTestFixture, MfrCertIsNotECC)
{
    unsigned int err = ERP_ERR_NOERROR;
    unsigned int Gen = THE_ANSWER; // This should be present on default simulator.
    // Sequence:
    // 1. Trust Mfr Root CA Certificate
    auto pTrustedRoot = getEmptyBlob(Gen);
    auto MfrRootCert = readERPResourceFile("cacert.crt"); // This is an RSA Cert.

    err = teststep_TrustTPMMfr(ErpAttestationTestFixture::m_logonSession, Gen, pTrustedRoot.get(), MfrRootCert);
    EXPECT_EQ(ERP_ERR_CERT_BAD_SUBJECT_ALG, err);
}

// Check that The Nuvoton TPM CA Cert can be loaded..
TEST_F(ErpAttestationTestFixture, TrustNuvotonCert)
{
    unsigned int err = ERP_ERR_NOERROR;
    unsigned int Gen = THE_ANSWER; // This should be present on default simulator.
    // Sequence:
    // 1. Trust Mfr Root CA Certificate
    auto pTrustedRoot = getEmptyBlob(Gen);
    auto MfrRootCert = readERPResourceFile("NuvotonTPMRootCA1110.crt");

    err = teststep_TrustTPMMfr(ErpAttestationTestFixture::m_logonSession, Gen, pTrustedRoot.get(), MfrRootCert);
    EXPECT_EQ(ERP_ERR_NOERROR, err);
}

// Test case to check that passing Mfr cert to trustTPMEK fails.
TEST_F(ErpAttestationTestFixture, EKCertIsRoot)
{
    unsigned int err = ERP_ERR_NOERROR;
    unsigned int Gen = THE_ANSWER; // This should be present on default simulator.
    // Sequence:
    // 1. Trust Mfr Root CA Certificate
    auto pTrustedRoot = getEmptyBlob(Gen);
    auto MfrRootCert = readERPResourceFile("cacertecc.crt");

    err = teststep_TrustTPMMfr(ErpAttestationTestFixture::m_logonSession, Gen, pTrustedRoot.get(), MfrRootCert);
    EXPECT_EQ(ERP_ERR_NOERROR, err);

    // 4. Enroll EK
    auto pTrustedEK = getEmptyBlob(Gen);
    if (err == ERP_ERR_SUCCESS)
    {
        err = teststep_EnrollTPMEK(
            ErpAttestationTestFixture::m_logonSession,
            Gen,
            pTrustedRoot.get(),
            pTrustedEK.get(),
            MfrRootCert.size(),
            MfrRootCert.data());
    }
    EXPECT_EQ(ERP_ERR_CERT_WRONG_ISCA_VALUE, err);
}
TEST_F(ErpAttestationTestFixture, AttestationSequencePart1)
{
    unsigned int err = ERP_ERR_NOERROR;
    unsigned int Gen = THE_ANSWER; // This should be present on default simulator.
    // Sequence:
    // 1. Trust Mfr Root CA Certificate
    auto pTrustedRoot = getEmptyBlob(Gen);
    auto MfrRootCert = readERPResourceFile("cacertecc.crt");

    err = teststep_TrustTPMMfr(ErpAttestationTestFixture::m_logonSession, Gen, pTrustedRoot.get(), MfrRootCert);

    if (err == ERP_ERR_SUCCESS)
    {
        // Save this in case we want to take a snapshot of a TPM decryption.
        err = writeBlobResourceFile("saved/trustedRoot.blob", pTrustedRoot.get());
    }

    UIntInput genIn = { Gen };

    // 2. Missing Step to call TPM to get the EK Cert
    //    for now just use some certificate from a file.
    auto pEKCert = readERPResourceFile("EKCertECC.crt");

    // 3. Obsolete - Step to call TPM to sign the {EKPub | NONCE}

    // 4. Enroll EK
    auto pTrustedEK = getEmptyBlob(Gen);
    if (err == ERP_ERR_SUCCESS)
    {
        err = teststep_EnrollTPMEK(
            ErpAttestationTestFixture::m_logonSession,
            Gen,
            pTrustedRoot.get(),
            pTrustedEK.get(),
            pEKCert.size(),
            pEKCert.data());
    }
    if (err == ERP_ERR_SUCCESS)
    {
        // Save this in case we want to take a snapshot of a TPM decryption.
        err = writeBlobResourceFile("saved/trustedEK.blob", pTrustedEK.get());
    }

    // 5. getAKChallenge
    // Inputs:
    auto pAKName = readERPResourceFile("h80000002.bin");
    // AK Public key is now in TPMTPUBLIC format
    auto pAKPub = readERPResourceFile("AKPub.bin");
    // Outputs
    auto pCredChallengeBlob = getEmptyBlob(Gen);
    std::uint8_t encCredentialData[MAX_BUFFER] = "";
    size_t encCredentialLength = 0;
    std::uint8_t secretData[MAX_BUFFER] = "";
    size_t secretLength = 0;
    if (err == ERP_ERR_SUCCESS)
    {
        err = teststep_GetAKChallenge(
            ErpAttestationTestFixture::m_logonSession,
            Gen,
            pTrustedEK.get(),
            pAKName.data(), // SHA_1_LEN...
            pAKPub.size() - 2, // file includes two leading length bytes that we don't want.
            pAKPub.data() + 2,
            pCredChallengeBlob.get(),
            &encCredentialLength,
            &(encCredentialData[0]),
            &secretLength,
            &(secretData[0]));
    }
    if (err == ERP_ERR_NOERROR)
    {
        writeERPResourceFile("encCredHSM.bin", std::vector<std::uint8_t>(
            &(encCredentialData[0]), &(encCredentialData[0]) + encCredentialLength));
        writeERPResourceFile("secretHSM.bin", std::vector<std::uint8_t>(
            &(secretData[0]), &(secretData[0]) + secretLength));
        writeBlobResourceFile("AKChallenge.blob", pCredChallengeBlob.get());
    }
    // 8. getNONCE for TPM Enrollment Quote - do this out of sequence to allow a single manual TPM step.
    NONCEOutput quoteNONCE = ERP_GenerateNONCE(ErpAttestationTestFixture::m_logonSession, genIn);
    writeBlobResourceFile("EnrollmentQuoteNONCE.blob", &(quoteNONCE.BlobOut));
    std::uint8_t variedEnrollmentNONCE[NONCE_LEN];
    // Don't save the NONCE, but save the varied NONCE value instead.
    if (err == ERP_ERR_SUCCESS)
    {
        err = varyNONCE("ERP_ENROLLMENT", &(quoteNONCE.NONCE[0]), &(variedEnrollmentNONCE[0]));
    }
    if (err == ERP_ERR_SUCCESS)
    {
        writeERPResourceFile("EnrollmentQuoteNONCE.bin", std::vector<std::uint8_t>(&(variedEnrollmentNONCE[0]), &(variedEnrollmentNONCE[0]) + RND_256_LEN));
    }
    // 10. get New NONCE for TEE Token request - do this out of sequence to allow a single manual TPM step.
    NONCEOutput attestNONCE = ERP_GenerateNONCE(ErpAttestationTestFixture::m_logonSession, genIn);
    writeBlobResourceFile("AttestationQuoteNONCE.Blob", &(attestNONCE.BlobOut));
    std::uint8_t variedAttestationNONCE[NONCE_LEN];
    if (err == ERP_ERR_SUCCESS)
    {
        err = varyNONCE("ERP_ATTESTATION", &(attestNONCE.NONCE[0]), &(variedAttestationNONCE[0]));
    }
    if (err == ERP_ERR_SUCCESS)
    {
        writeERPResourceFile("AttestationQuoteNONCE.bin", std::vector<std::uint8_t>(&(variedAttestationNONCE[0]), &(variedAttestationNONCE[0]) + RND_256_LEN));
    }
    // 6. Go to TPM to answer challenge...
    // If done, this will create AKChallenge.blob and creddecHSM.bin.   If you wish to use these in the next steps copy
    //    then to  saved/AKChallengeSaved.blob and saved/credDecHSMSaved.bin
    // ---- MARKER ----
    // This is where to break the tests and generate e test response on the tpm.   If
    //    you do then copy the results into the saved directory.
}

TEST_F(ErpAttestationTestFixture, AttestationSequencePart2)
{
    unsigned int err = ERP_ERR_NOERROR;
    unsigned int Gen = THE_ANSWER; // This should be present on default simulator.
    // 7. Enroll AK
    // Use blob and decyrpted credential from a previous test run
    std::unique_ptr<ERPBlob> savedAKChallengeBlob = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/AKChallengeSaved.blob"));
    std::unique_ptr<ERPBlob> savedTrustedEKBlob = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/trustedEKSaved.blob"));
    auto savedDecCred = readERPResourceFile("saved/credDecHSMSaved.bin");
    auto savedAKPub = readERPResourceFile("saved/AKPub.bin");
    auto savedAKName = readERPResourceFile("saved/h80000002.bin");
    auto pTrustedAK = getEmptyBlob(Gen);
    if (err == ERP_ERR_SUCCESS)
    {
        err = teststep_EnrollAK(
            ErpAttestationTestFixture::m_logonSession,
            Gen,
            savedTrustedEKBlob.get(),
            savedAKChallengeBlob.get(),
            savedAKName.data(),
            savedAKPub.size()-2,
            savedAKPub.data()+2,
            savedDecCred.size(),
            savedDecCred.data(),
            pTrustedAK.get());
    }

    writeBlobResourceFile("saved/TrustedAk.blob", pTrustedAK.get());

    // 9. get Quote from TPM. - done in previous test.
    auto enrollQuote = readERPResourceFile("saved/EnrollmentQuoteSaved.bin");
    auto enrollSig = readERPResourceFile("saved/EnrollmentQuoteSigSaved.bin");
    std::unique_ptr<ERPBlob> savedEnrollmentNONCE = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/EnrollmentQuoteNONCESaved.blob"));
    // 7. Enroll Enclave
    auto pTrustedQuote = getEmptyBlob(Gen);
    if (err == ERP_ERR_SUCCESS)
    {
        err = teststep_TrustQuote(
            ErpAttestationTestFixture::m_logonSession,
            Gen,
            pTrustedAK.get(),
            savedEnrollmentNONCE.get(),
            savedAKName.data(),
            enrollQuote.size(), enrollQuote.data(),
            enrollSig.size(), enrollSig.data(),
            pTrustedQuote.get());
    }
    writeBlobResourceFile("saved/TrustedQuote.blob", pTrustedQuote.get());
    std::unique_ptr<ERPBlob> savedAttestationNONCE = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/AttestationQuoteNONCESaved.blob"));
    auto attestQuote = readERPResourceFile("saved/AttestationQuoteSaved.bin");
    auto attestSig = readERPResourceFile("saved/AttestationQuoteSigSaved.bin");
    // 11. getTEEToken
    auto pTEEToken = getEmptyBlob(Gen);
    if (err == ERP_ERR_SUCCESS)
    {
        err = teststep_getTEEToken(
            ErpAttestationTestFixture::m_logonSession,
            pTrustedAK.get(),
            pTrustedQuote.get(),
            savedAttestationNONCE.get(),
            savedAKName.data(),
            attestQuote.size(), attestQuote.data(),
            attestSig.size(), attestSig.data(),
            pTEEToken.get());
    }
    // Save the TEEToken for use in other tests.
    if (err == ERP_ERR_SUCCESS)
    {
        err = writeBlobResourceFile("saved/StaticTEEToken.blob", pTEEToken.get());
    }
    // 12. Derive or retrieve a new Derivation Key Blob.
    auto pDerivationKeyBlob = getEmptyBlob(Gen);
    if (err == ERP_ERR_SUCCESS)
    {
        err = teststep_GenerateDerivationKey(ErpAttestationTestFixture::m_logonSession, Gen, pDerivationKeyBlob.get());
        // Alternatively - Fill derivationKeyBlob from previously generated data...
    }
    // Save the Derivation Key for use in other tests.
    if (err == ERP_ERR_SUCCESS)
    {
        err = writeBlobResourceFile("saved/StaticDerivationKey.blob", pDerivationKeyBlob.get());
    }
    // 13. derive Task persistence Key for initial derivation
    // Each of these teststeps does an initial derivation and then a subsequent one and 
    //   compares the results which should be equal.
    // The second check in each of these teststeps is that the derivation for a different
    //   class of key produces a different result.
    teststep_GoodKeyDerivation(ErpAttestationTestFixture::m_logonSession,
        pTEEToken.get(),
        savedAKName.data(), // SHA_1_LEN...
        teststep_deriveTaskPersistenceKey,
        teststep_deriveCommsKey);
    teststep_GoodKeyDerivation(ErpAttestationTestFixture::m_logonSession,
        pTEEToken.get(),
        savedAKName.data(), // SHA_1_LEN...
        teststep_deriveCommsKey,
        teststep_deriveAuditKey);
    teststep_GoodKeyDerivation(ErpAttestationTestFixture::m_logonSession,
        pTEEToken.get(),
        savedAKName.data(), // SHA_1_LEN...
        teststep_deriveAuditKey,
        teststep_deriveChargeItemKey);
    teststep_GoodKeyDerivation(ErpAttestationTestFixture::m_logonSession,
        pTEEToken.get(),
        savedAKName.data(), // SHA_1_LEN...
        teststep_deriveChargeItemKey,
        teststep_deriveAuditKey);

    // Save the last TEEToken for anyone else who wants to use it.
    ErpAttestationTestFixture::m_SavedTEEToken = *pTEEToken;
    EXPECT_EQ(ERP_ERR_NOERROR, err);
}

// Test that the key derivation is possible with static data from previous test.
TEST_F(ErpAttestationTestFixture, StaticKeyDerivation)
{
    unsigned int err = ERP_ERR_NOERROR;
    auto pAKName = readERPResourceFile("saved/h80000002.bin");
    std::unique_ptr<ERPBlob> teeToken = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/StaticTEETokenSaved.blob"));
    std::unique_ptr<ERPBlob> derivationKey = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/StaticDerivationKey.blob"));
    // 13. derive Task persistence Key for initial derivation
    auto derivationData = asciiToBuffer("(Dummy Derivation Data) KVNR:Z123-45678");
    std::uint8_t usedDerivationData[MAX_BUFFER];
    size_t usedDerivationDataLength = 0;
    std::uint8_t initialDerivedKey[AES_256_LEN];
    if (err == ERP_ERR_SUCCESS)
    {
        err = teststep_deriveTaskPersistenceKey(
            ErpAttestationTestFixture::m_logonSession,
            pAKName.data(), // SHA_1_LEN...
            teeToken.get(),
            derivationKey.get(),
            derivationData.size(),
            derivationData.data(),
            1, // 1 => Initial Derivation, 0 => subsequent Derivation. 
            // Output
            &usedDerivationDataLength,
            &(usedDerivationData[0]), // MAX_BUFFER
            &(initialDerivedKey[0])); // AES_256_LEN
    }
    ASSERT_EQ(ERP_ERR_NOERROR, err);
    EXPECT_EQ(0, memcmp(&(derivationData[0]), &(usedDerivationData[0]), derivationData.size()));
    EXPECT_EQ(derivationData.size() + 34, usedDerivationDataLength);
}

// Test that the key derivation is possible with the new update user 00002000
// Other tests for the update user will go into the general permissions testing.
TEST_F(ErpAttestationTestFixture, UpdateUserTest)
{
    const unsigned int Gen = THE_ANSWER;
    logoff();
    logonUpdate();
    auto pDerivationKeyBlob = getEmptyBlob(Gen);
    EXPECT_EQ(ERP_ERR_NOERROR, teststep_GenerateDerivationKey(
        ErpAttestationTestFixture::m_logonSession, Gen, pDerivationKeyBlob.get()));
    logoff();
    logonSetup();
    EXPECT_EQ(ERP_ERR_NOERROR, teststep_GenerateDerivationKey(
        ErpAttestationTestFixture::m_logonSession, Gen, pDerivationKeyBlob.get()));
    logoff();
    logonWorking();
    EXPECT_EQ(ERP_ERR_PERMISSION_DENIED, teststep_GenerateDerivationKey(
        ErpAttestationTestFixture::m_logonSession, Gen, pDerivationKeyBlob.get()));
}

// Test of the utility method to parse a TPM quote and return the PCR information.
TEST_F(ErpAttestationTestFixture, ParseTPMQuoteTest)
{
    // 9. get Quote from TPM. - done in previous test.
    auto enrollQuote = readERPResourceFile("saved/EnrollmentQuoteSaved.bin");
    ASSERT_EQ(enrollQuote.size(), TPM_QUOTE_LENGTH);
    TPMQuoteInput input;
    memcpy(&(input.QuoteData[0]), enrollQuote.data(), TPM_QUOTE_LENGTH);
    auto retVal = ERP_ParseTPMQuote(input);
    ASSERT_EQ(retVal.returnCode, ERP_ERR_NOERROR);
    uint8_t expectedPCRSet[TPM_PCRSET_LENGTH] = { 0x0F,0x00,0x00 };  //NOLINT  (readability-magic-numbers)
    ASSERT_EQ(0, memcmp(&(expectedPCRSet[0]), &(retVal.PCRSETFlags[0]), TPM_PCRSET_LENGTH));
    uint8_t expectedPCRDigest[TPM_PCR_DIGESTHASH_LENGTH] = {
        0x38, 0x72, 0x3a, 0x2e, 0x5e, 0x8a, 0x17, 0xaa, 0x79, 0x50, 0xdc, 0x00, 0x82, 0x09, 0x94, 0x4e, //NOLINT  (readability-magic-numbers)
        0x89, 0x8f, 0x69, 0xa7, 0xbd, 0x10, 0xa2, 0x3c, 0x83, 0x9d, 0x34, 0x1e, 0x93, 0x5f, 0xd5, 0xca }; //NOLINT  (readability-magic-numbers)
    ASSERT_EQ(0, memcmp(&(expectedPCRDigest[0]), &(retVal.PCRHash[0]), TPM_PCR_DIGESTHASH_LENGTH));
    uint8_t expectedQualifiedSignerName[TPM_NAME_LEN] = {
       0x00, 0x0B,  //NOLINT  (readability-magic-numbers)
       0xA9, 0x17, 0x18, 0xA7, 0xF6, 0x6E, 0xE2, 0xC3, 0x00, 0x9D, 0x06, 0x61, 0xFB, 0xE3, 0xA4, 0xFB,  //NOLINT  (readability-magic-numbers)
       0x19, 0xCA, 0x1D, 0xE8, 0x51, 0x92, 0xAC, 0xC6, 0xE4, 0x75, 0x8B, 0x3A, 0xC5, 0xDF, 0x09, 0xE0  }; //NOLINT  (readability-magic-numbers)
    ASSERT_EQ(0, memcmp(&(expectedQualifiedSignerName[0]), &(retVal.qualifiedSignerName[0]), TPM_NAME_LEN));
    uint8_t expectedQualifyingInformation[NONCE_LEN] = { 
        0xB6, 0x61, 0x0D, 0x0A, 0x5B, 0x19, 0xBE, 0x0E, 0x7B, 0x59, 0x22, 0xD0, 0x7C, 0xCC, 0x8D, 0x88,  //NOLINT  (readability-magic-numbers)
        0xE3, 0xB4, 0x09, 0x61, 0x0C, 0xE9, 0xF8, 0xAE, 0x89, 0x41, 0x0E, 0x36, 0x8B, 0xC0, 0x78, 0x68 }; //NOLINT  (readability-magic-numbers)
    ASSERT_EQ(0, memcmp(&(expectedQualifyingInformation[0]), &(retVal.qualifyingInformation[0]), NONCE_LEN));
    // Some Bad Data - start with thoe good and poke bad bytes into it.
    std::vector zeroVector = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }; //NOLINT  (readability-magic-numbers)
    unsigned int offset = 0;
    // All zero.
    memset(&(input.QuoteData[0]), 0, TPM_QUOTE_LENGTH);
    retVal = ERP_ParseTPMQuote(input);
    ASSERT_EQ(ERP_ERR_BAD_QUOTE_HEADER, retVal.returnCode);
    // First Byte
    memcpy(&(input.QuoteData[0]), enrollQuote.data(), TPM_QUOTE_LENGTH);
    memcpy(&(input.QuoteData[offset]), zeroVector.data(), 1);
    retVal = ERP_ParseTPMQuote(input);
    ASSERT_EQ(ERP_ERR_BAD_QUOTE_HEADER, retVal.returnCode);
    // "TCG" in Header
    memcpy(&(input.QuoteData[0]), enrollQuote.data(), TPM_QUOTE_LENGTH);
    memcpy(&(input.QuoteData[offset + 1]), zeroVector.data(), 3);
    retVal = ERP_ParseTPMQuote(input);
    ASSERT_EQ(ERP_ERR_BAD_QUOTE_HEADER, retVal.returnCode);
    offset += 6; //NOLINT  (readability-magic-numbers)
    // QualifyingName length
    memcpy(&(input.QuoteData[0]), enrollQuote.data(), TPM_QUOTE_LENGTH);
    memcpy(&(input.QuoteData[offset]), zeroVector.data(), 2);
    retVal = ERP_ParseTPMQuote(input);
    ASSERT_EQ(ERP_ERR_BAD_QUOTE_FORMAT, retVal.returnCode);
    // QualifyingName length
    memcpy(&(input.QuoteData[0]), enrollQuote.data(), TPM_QUOTE_LENGTH);
    input.QuoteData[offset + 1] = THE_ANSWER;
    retVal = ERP_ParseTPMQuote(input);
    ASSERT_EQ(ERP_ERR_BAD_QUOTE_FORMAT, retVal.returnCode);
    offset += 2; //NOLINT  (readability-magic-numbers)
    // Qualifying Name Algorithm
    memcpy(&(input.QuoteData[0]), enrollQuote.data(), TPM_QUOTE_LENGTH);
    memcpy(&(input.QuoteData[offset]), zeroVector.data(), 2);
    retVal = ERP_ParseTPMQuote(input);
    ASSERT_EQ(ERP_ERR_BAD_TPM_NAME_ALGORITHM, retVal.returnCode);
    // Qualifying Name Algorithm
    memcpy(&(input.QuoteData[0]), enrollQuote.data(), TPM_QUOTE_LENGTH);
    input.QuoteData[offset + 1] = THE_ANSWER;
    retVal = ERP_ParseTPMQuote(input);
    ASSERT_EQ(ERP_ERR_BAD_TPM_NAME_ALGORITHM, retVal.returnCode);
    offset += TPM_NAME_LEN;
    // QualifyingData length
    memcpy(&(input.QuoteData[0]), enrollQuote.data(), TPM_QUOTE_LENGTH);
    memcpy(&(input.QuoteData[offset]), zeroVector.data(), 2);
    retVal = ERP_ParseTPMQuote(input);
    ASSERT_EQ(ERP_ERR_BAD_QUOTE_HASH_FORMAT, retVal.returnCode);
    // QualifyingData length
    memcpy(&(input.QuoteData[0]), enrollQuote.data(), TPM_QUOTE_LENGTH);
    input.QuoteData[offset + 1] = THE_ANSWER;
    retVal = ERP_ParseTPMQuote(input);
    ASSERT_EQ(ERP_ERR_BAD_QUOTE_HASH_FORMAT, retVal.returnCode);
    offset += 2; //NOLINT  (readability-magic-numbers)
    offset += NONCE_LEN;
    offset += 25; // Clock, VErsion, et.c. //NOLINT  (readability-magic-numbers)
    // PCR Digest Count
    memcpy(&(input.QuoteData[0]), enrollQuote.data(), TPM_QUOTE_LENGTH);
    memcpy(&(input.QuoteData[offset]), zeroVector.data(), 4);
    retVal = ERP_ParseTPMQuote(input);
    ASSERT_EQ(ERP_ERR_BAD_QUOTE_FORMAT, retVal.returnCode);
    // PCR Digest Count
    memcpy(&(input.QuoteData[0]), enrollQuote.data(), TPM_QUOTE_LENGTH);
    input.QuoteData[offset + 3] = THE_ANSWER;
    retVal = ERP_ParseTPMQuote(input);
    ASSERT_EQ(ERP_ERR_BAD_QUOTE_FORMAT, retVal.returnCode);
    offset += 4; //NOLINT  (readability-magic-numbers)
    // PCR Hash Algorithm
    memcpy(&(input.QuoteData[0]), enrollQuote.data(), TPM_QUOTE_LENGTH);
    memcpy(&(input.QuoteData[offset]), zeroVector.data(), 2);
    retVal = ERP_ParseTPMQuote(input);
    ASSERT_EQ(ERP_ERR_BAD_QUOTE_HASH_FORMAT, retVal.returnCode);
    // PCR Hash Algorithm
    memcpy(&(input.QuoteData[0]), enrollQuote.data(), TPM_QUOTE_LENGTH);
    input.QuoteData[offset + 1] = THE_ANSWER;
    retVal = ERP_ParseTPMQuote(input);
    ASSERT_EQ(ERP_ERR_BAD_QUOTE_HASH_FORMAT, retVal.returnCode);
    offset += 2;
    // PCR Selection Array Size
    memcpy(&(input.QuoteData[0]), enrollQuote.data(), TPM_QUOTE_LENGTH);
    input.QuoteData[offset] = THE_ANSWER;
    retVal = ERP_ParseTPMQuote(input);
    ASSERT_EQ(ERP_ERR_BAD_QUOTE_FORMAT, retVal.returnCode);
    offset++;
    // PCR Flags - no checks on content.
    offset += 3;
    // PCR Digest length
    memcpy(&(input.QuoteData[0]), enrollQuote.data(), TPM_QUOTE_LENGTH);
    memcpy(&(input.QuoteData[offset]), zeroVector.data(), 2);
    retVal = ERP_ParseTPMQuote(input);
    ASSERT_EQ(ERP_ERR_BAD_QUOTE_FORMAT, retVal.returnCode);
    // PCR Digest length
    memcpy(&(input.QuoteData[0]), enrollQuote.data(), TPM_QUOTE_LENGTH);
    input.QuoteData[offset + 1] = THE_ANSWER;
    retVal = ERP_ParseTPMQuote(input);
    ASSERT_EQ(ERP_ERR_BAD_QUOTE_FORMAT, retVal.returnCode);
    offset += 2; //NOLINT  (readability-magic-numbers)
    offset += TPM_PCR_DIGESTHASH_LENGTH;
    ASSERT_EQ(offset, (unsigned int) TPM_QUOTE_LENGTH);
}
