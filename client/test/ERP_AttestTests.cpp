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

class ErpAttestationTestFixture : public ::testing::Test {
public:
    static HSMSession m_logonSession;
    static const std::string devIP;
    static ERPBlob m_SavedTEEToken;

    ErpAttestationTestFixture() {
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

HSMSession ErpAttestationTestFixture::m_logonSession = { 0, 0, 0, HSMUninitialised, 0, ERP_ERR_NOERROR, 0 };
const std::string ErpAttestationTestFixture::devIP = SINGLE_SIM_HSM;
ERPBlob ErpAttestationTestFixture::m_SavedTEEToken = { 0,0,{'\0'} };

TEST_F(ErpAttestationTestFixture, AttestationSequencePart1)
{
    unsigned int err = 0;
    unsigned int Gen = 0x42; // This should be present on default simulator.
    // Sequence:
    // 1. Trust Mfr Root CA Certificate
    auto pTrustedRoot = getEmptyBlob(Gen);
    auto MfrRootCert = readERPResourceFile("cacertecc.crt");

    err = teststep_TrustTPMMfr(ErpAttestationTestFixture::m_logonSession, Gen, pTrustedRoot.get(), MfrRootCert);

    if (err == 0)
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
    if (err == 0)
    {
        err = teststep_EnrollTPMEK(
            ErpAttestationTestFixture::m_logonSession,
            Gen,
            pTrustedRoot.get(),
            pTrustedEK.get(),
            pEKCert.size(),
            reinterpret_cast<unsigned char*>(pEKCert.data()));
    }
    if (err == 0)
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
    unsigned char encCredentialData[MAX_BUFFER] = "";
    size_t encCredentialLength = 0;
    unsigned char secretData[MAX_BUFFER] = "";
    size_t secretLength = 0;
    if (err == 0)
    {
        err = teststep_GetAKChallenge(
            ErpAttestationTestFixture::m_logonSession,
            Gen,
            pTrustedEK.get(),
            reinterpret_cast<unsigned char*>(pAKName.data()), // SHA_1_LEN...
            pAKPub.size() - 2, // file includes two leading length bytes that we don't want.
            reinterpret_cast<unsigned char*>((pAKPub.data() + 2)),
            pCredChallengeBlob.get(),
            &encCredentialLength,
            &(encCredentialData[0]),
            &secretLength,
            &(secretData[0]));
    }
    if (err == ERP_ERR_NOERROR)
    {
        writeERPResourceFile("encCredHSM.bin", std::vector<char>(
            &(encCredentialData[0]), &(encCredentialData[0]) + encCredentialLength));
        writeERPResourceFile("secretHSM.bin", std::vector<char>(
            &(secretData[0]), &(secretData[0]) + secretLength));
        writeBlobResourceFile("AKChallenge.blob", pCredChallengeBlob.get());
    }
    // 8. getNONCE for TPM Enrollment Quote - do this out of sequence to allow a single manual TPM step.
    NONCEOutput quoteNONCE = ERP_GenerateNONCE(ErpAttestationTestFixture::m_logonSession, genIn);
    writeBlobResourceFile("EnrollmentQuoteNONCE.blob", &(quoteNONCE.BlobOut));
    unsigned char variedEnrollmentNONCE[NONCE_LEN];
    // Don't save the NONCE, but save the varied NONCE value instead.
    if (err == 0)
    {
        err = varyNONCE("ERP_ENROLLMENT", quoteNONCE.NONCE, &(variedEnrollmentNONCE[0]));
    }
    if (err == 0)
    {
        writeERPResourceFile("EnrollmentQuoteNONCE.bin", std::vector<char>(variedEnrollmentNONCE, variedEnrollmentNONCE + 0x20));
    }
    // 10. get New NONCE for TEE Token request - do this out of sequence to allow a single manual TPM step.
    NONCEOutput attestNONCE = ERP_GenerateNONCE(ErpAttestationTestFixture::m_logonSession, genIn);
    writeBlobResourceFile("AttestationQuoteNONCE.Blob", &(attestNONCE.BlobOut));
    unsigned char variedAttestationNONCE[NONCE_LEN];
    if (err == 0)
    {
        err = varyNONCE("ERP_ATTESTATION", attestNONCE.NONCE, &(variedAttestationNONCE[0]));
    }
    if (err == 0)
    {
        writeERPResourceFile("AttestationQuoteNONCE.bin", std::vector<char>(variedAttestationNONCE, variedAttestationNONCE + 0x20));
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
    unsigned int Gen = 0x42; // This should be present on default simulator.
    // 7. Enroll AK
    // Use blob and decyrpted credential from a previous test run
    std::unique_ptr<ERPBlob> savedAKChallengeBlob = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/AKChallengeSaved.blob"));
    std::unique_ptr<ERPBlob> savedTrustedEKBlob = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/trustedEKSaved.blob"));
    auto savedDecCred = readERPResourceFile("saved/credDecHSMSaved.bin");
    auto savedAKPub = readERPResourceFile("saved/AKPub.bin");
    auto savedAKName = readERPResourceFile("saved/h80000002.bin");
    auto pTrustedAK = getEmptyBlob(Gen);
    if (err == 0)
    {
        err = teststep_EnrollAK(
            ErpAttestationTestFixture::m_logonSession,
            Gen,
            savedTrustedEKBlob.get(),
            savedAKChallengeBlob.get(),
            reinterpret_cast<unsigned char*>(savedAKName.data()),
            savedAKPub.size()-2,
            reinterpret_cast<unsigned char*>(savedAKPub.data()+2),
            savedDecCred.size(),
            (unsigned char *)savedDecCred.data(),
            pTrustedAK.get());
    }

    writeBlobResourceFile("saved/TrustedAk.blob", pTrustedAK.get());

    // 9. get Quote from TPM. - done in previous test.
    auto enrollQuote = readERPResourceFile("saved/EnrollmentQuoteSaved.bin");
    auto enrollSig = readERPResourceFile("saved/EnrollmentQuoteSigSaved.bin");
    std::unique_ptr<ERPBlob> savedEnrollmentNONCE = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/EnrollmentQuoteNONCESaved.blob"));
    // 7. Enroll Enclave
    auto pTrustedQuote = getEmptyBlob(Gen);
    if (err == 0)
    {
        err = teststep_TrustQuote(
            ErpAttestationTestFixture::m_logonSession,
            Gen,
            pTrustedAK.get(),
            savedEnrollmentNONCE.get(),
            reinterpret_cast<unsigned char*>(savedAKName.data()),
            enrollQuote.size(), reinterpret_cast<unsigned char *>(enrollQuote.data()),
            enrollSig.size(), reinterpret_cast<unsigned char *>(enrollSig.data()),
            pTrustedQuote.get());
    }
    writeBlobResourceFile("saved/TrustedQuote.blob", pTrustedQuote.get());
    std::unique_ptr<ERPBlob> savedAttestationNONCE = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/AttestationQuoteNONCESaved.blob"));
    auto attestQuote = readERPResourceFile("saved/AttestationQuoteSaved.bin");
    auto attestSig = readERPResourceFile("saved/AttestationQuoteSigSaved.bin");
    // 11. getTEEToken
    auto pTEEToken = getEmptyBlob(Gen);
    if (err == 0)
    {
        err = teststep_getTEEToken(
            ErpAttestationTestFixture::m_logonSession,
            pTrustedAK.get(),
            pTrustedQuote.get(),
            savedAttestationNONCE.get(),
            reinterpret_cast<unsigned char*>(savedAKName.data()),
            attestQuote.size(), reinterpret_cast<unsigned char*>(attestQuote.data()),
            attestSig.size(), reinterpret_cast<unsigned char*>(attestSig.data()),
            pTEEToken.get());
    }
    // Save the TEEToken for use in other tests.
    if (err == 0)
    {
        err = writeBlobResourceFile("saved/StaticTEEToken.blob", pTEEToken.get());
    }
    // 12. Derive or retrieve a new Derivation Key Blob.
    auto pDerivationKeyBlob = getEmptyBlob(Gen);
    if (err == 0)
    {
        if (1) // 1 == TRUE...
        {
            err = teststep_GenerateDerivationKey(ErpAttestationTestFixture::m_logonSession, Gen, pDerivationKeyBlob.get());
        }
        else {
            // Fill derivationKeyBlob from previously generated data...
        }
    }
    // Save the Derivation Key for use in other tests.
    if (err == 0)
    {
        err = writeBlobResourceFile("saved/StaticDerivationKey.blob", pDerivationKeyBlob.get());
    }
    // 13. derive Task persistence Key for initial derivation
    unsigned char derivationData[] = "(Dummy Derivation Data) KVNR:Z123-45678";
    size_t derivationDataLength = strlen((const char*)derivationData) + 1;
    unsigned char usedDerivationData[MAX_BUFFER];
    size_t usedDerivationDataLength = 0;
    unsigned char initialDerivedKey[AES_256_LEN];
    if (err == 0)
    {
        err = teststep_deriveTaskPersistenceKey(
            ErpAttestationTestFixture::m_logonSession,
            reinterpret_cast<unsigned char*>(savedAKName.data()), // SHA_1_LEN...
            pTEEToken.get(),
            pDerivationKeyBlob.get(),
            derivationDataLength,
            derivationData,
            1, // 1 => Initial Derivation, 0 => subsequent Derivation. 
            // Output
            &usedDerivationDataLength,
            usedDerivationData, // MAX_BUFFER
            initialDerivedKey); // AES_256_LEN
    }
    // 14. Derive Task persistence key again for a non-initial derivation
    unsigned char subsequentDerivedKey[AES_256_LEN];
    for (int m = 0; m < 10; m++)
    {
        if (err == 0)
        {
            err = teststep_deriveTaskPersistenceKey(
                ErpAttestationTestFixture::m_logonSession,
                reinterpret_cast<unsigned char*>(savedAKName.data()), // SHA_1_LEN...
                pTEEToken.get(),
                pDerivationKeyBlob.get(),
                usedDerivationDataLength,
                usedDerivationData,
                0, // 1 => Initial Derivation, 0 => subsequent Derivation. 
                // Output
                &usedDerivationDataLength,
                usedDerivationData, // MAX_BUFFER
                subsequentDerivedKey); // AES_256_LEN
        }
    }
    // 15. Compare the two keys
    // TO DO.
    // Save the last TEEToken for anyone else who wants to use it.
    ErpAttestationTestFixture::m_SavedTEEToken = *(pTEEToken.get());
    EXPECT_EQ(ERP_ERR_NOERROR, err);
}

// Test that the key derivation is possible with static data from previous test.
TEST_F(ErpAttestationTestFixture, StaticKeyDerivation)
{
    unsigned int err = 0;
    auto pAKName = readERPResourceFile("saved/h80000002.bin");
    std::unique_ptr<ERPBlob> teeToken = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/StaticTEETokenSaved.blob"));
    std::unique_ptr<ERPBlob> derivationKey = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/StaticDerivationKey.blob"));
    // 13. derive Task persistence Key for initial derivation
    unsigned char derivationData[] = "(Dummy Derivation Data) KVNR:Z123-45678";
    size_t derivationDataLength = strlen((const char*)derivationData) + 1;
    unsigned char usedDerivationData[MAX_BUFFER];
    size_t usedDerivationDataLength = 0;
    unsigned char initialDerivedKey[AES_256_LEN];
    if (err == 0)
    {
        err = teststep_deriveTaskPersistenceKey(
            ErpAttestationTestFixture::m_logonSession,
            reinterpret_cast<unsigned char*>(pAKName.data()), // SHA_1_LEN...
            teeToken.get(),
            derivationKey.get(),
            derivationDataLength,
            derivationData,
            1, // 1 => Initial Derivation, 0 => subsequent Derivation. 
            // Output
            &usedDerivationDataLength,
            usedDerivationData, // MAX_BUFFER
            initialDerivedKey); // AES_256_LEN
    }
    ASSERT_EQ(ERP_ERR_NOERROR, err);
    EXPECT_EQ(0, memcmp(&(derivationData[0]), &(usedDerivationData[0]), derivationDataLength));
    EXPECT_EQ(derivationDataLength + 34, usedDerivationDataLength);
}

// Test that the key derivation is possible with the new update user 00002000
// Other tests for the update user will go into the general permissions testing.
TEST_F(ErpAttestationTestFixture, UpdateUserTest)
{
    unsigned int Gen = 0x42;
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