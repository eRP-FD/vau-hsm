/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021, 2023
 * (C) Copyright IBM Corp. 2021, 2023
 *
 * non-exclusively licensed to gematik GmbH
 **************************************************************************************************/

#include "ERP_Client.h"
#include "ERP_Error.h"
#include "ERP_SFC.h"
#include "ERP_TestParams.h"
#include "ERP_TestUtils.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <fstream>
#include <memory>
#include <vector>

class ErpClusterTestFixture : public ::testing::Test {
public:
    HSMSession m_logonSession = { 0, 0, 0, HSMUninitialised, 0, ERP_ERR_NOERROR, 0 };
    static ERPBlob m_SavedTEEToken;

    ErpClusterTestFixture() {
        // initialization code here
    }

    void connect() {
        // This method is intended to be invoked for each test just before the test starts
        const char* devArray[] = CLUSTER_HSM; // 10 is maximum
        int nDevices = 0;
        while ((devArray[nDevices] != NULL) && (nDevices < 10))
        {
            nDevices++;
        }
        ASSERT_LT(nDevices, 10);
        devArray[nDevices] = NULL;

        m_logonSession = ERP_ClusterConnect(devArray, TEST_CONNECT_TIMEOUT_MS, TEST_READ_TIMEOUT_MS,TEST_RECONNECT_INTERVAL_MS);
    }
    void logonSetup() {
        bool doLogon = true;
        if (doLogon)
        {
            // user ERP_SETUP with "password" and permissions 00000200
            const static std::string setupUsername = "ERP_SETUP";
            const static std::string password = "password";

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

ERPBlob ErpClusterTestFixture::m_SavedTEEToken = { 0,0,{'\0'} };

TEST_F(ErpClusterTestFixture, AttestationSequencePart1)
{
    unsigned int err = ERP_ERR_NOERROR;
    unsigned int Gen = THE_ANSWER; // This should be present on default simulator.
    // Sequence:
    // 1. Trust Mfr Root CA Certificate
    auto pTrustedRoot = getEmptyBlob(Gen);
    auto MfrRootCert = readERPResourceFile("cacertecc.crt");

    err = teststep_TrustTPMMfr(ErpClusterTestFixture::m_logonSession, Gen, pTrustedRoot.get(), MfrRootCert);

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
            ErpClusterTestFixture::m_logonSession,
            Gen,
            pTrustedRoot.get(),
            pTrustedEK.get(),
            pEKCert.size(),
            reinterpret_cast<unsigned char*>(pEKCert.data()));
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
    unsigned char encCredentialData[MAX_BUFFER] = "";
    size_t encCredentialLength = 0;
    unsigned char secretData[MAX_BUFFER] = "";
    size_t secretLength = 0;
    if (err == ERP_ERR_SUCCESS)
    {
        err = teststep_GetAKChallenge(
            ErpClusterTestFixture::m_logonSession,
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
    NONCEOutput quoteNONCE = ERP_GenerateNONCE(ErpClusterTestFixture::m_logonSession, genIn);
    writeBlobResourceFile("EnrollmentQuoteNONCE.blob", &(quoteNONCE.BlobOut));
    unsigned char variedEnrollmentNONCE[NONCE_LEN];
    // Don't save the NONCE, but save the varied NONCE value instead.
    if (err == ERP_ERR_SUCCESS)
    {
        err = varyNONCE("ERP_ENROLLMENT", quoteNONCE.NONCE, &(variedEnrollmentNONCE[0]));
    }
    if (err == ERP_ERR_SUCCESS)
    {
        writeERPResourceFile("EnrollmentQuoteNONCE.bin", std::vector<char>(variedEnrollmentNONCE, variedEnrollmentNONCE + 0x20));
    }
    // 10. get New NONCE for TEE Token request - do this out of sequence to allow a single manual TPM step.
    NONCEOutput attestNONCE = ERP_GenerateNONCE(ErpClusterTestFixture::m_logonSession, genIn);
    writeBlobResourceFile("AttestationQuoteNONCE.Blob", &(attestNONCE.BlobOut));
    unsigned char variedAttestationNONCE[NONCE_LEN];
    if (err == ERP_ERR_SUCCESS)
    {
        err = varyNONCE("ERP_ATTESTATION", attestNONCE.NONCE, &(variedAttestationNONCE[0]));
    }
    if (err == ERP_ERR_SUCCESS)
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

TEST_F(ErpClusterTestFixture, AttestationSequencePart2)
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
            ErpClusterTestFixture::m_logonSession,
            Gen,
            savedTrustedEKBlob.get(),
            savedAKChallengeBlob.get(),
            reinterpret_cast<unsigned char*>(savedAKName.data()),
            savedAKPub.size() - 2,
            reinterpret_cast<unsigned char*>(savedAKPub.data() + 2),
            savedDecCred.size(),
            (unsigned char*)savedDecCred.data(),
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
            ErpClusterTestFixture::m_logonSession,
            Gen,
            pTrustedAK.get(),
            savedEnrollmentNONCE.get(),
            reinterpret_cast<unsigned char*>(savedAKName.data()),
            enrollQuote.size(), reinterpret_cast<unsigned char*>(enrollQuote.data()),
            enrollSig.size(), reinterpret_cast<unsigned char*>(enrollSig.data()),
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
            ErpClusterTestFixture::m_logonSession,
            pTrustedAK.get(),
            pTrustedQuote.get(),
            savedAttestationNONCE.get(),
            reinterpret_cast<unsigned char*>(savedAKName.data()),
            attestQuote.size(), reinterpret_cast<unsigned char*>(attestQuote.data()),
            attestSig.size(), reinterpret_cast<unsigned char*>(attestSig.data()),
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
        err = teststep_GenerateDerivationKey(ErpClusterTestFixture::m_logonSession, Gen, pDerivationKeyBlob.get());
    }
    // Save the Derivation Key for use in other tests.
    if (err == ERP_ERR_SUCCESS)
    {
        err = writeBlobResourceFile("saved/StaticDerivationKey.blob", pDerivationKeyBlob.get());
    }
    // 13. derive Task persistence Key for initial derivation
    unsigned char derivationData[] = "(Dummy Derivation Data) KVNR:Z123-45678";
    size_t derivationDataLength = strlen((const char*)derivationData) + 1;
    unsigned char usedDerivationData[MAX_BUFFER];
    size_t usedDerivationDataLength = 0;
    unsigned char initialDerivedKey[AES_256_LEN];
    if (err == ERP_ERR_SUCCESS)
    {
        err = teststep_deriveTaskPersistenceKey(
            ErpClusterTestFixture::m_logonSession,
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
        if (err == ERP_ERR_SUCCESS)
        {
            err = teststep_deriveTaskPersistenceKey(
                ErpClusterTestFixture::m_logonSession,
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
    // TODO.
    // Save the last TEEToken for anyone else who wants to use it.
    ErpClusterTestFixture::m_SavedTEEToken = *(pTEEToken.get());
    EXPECT_EQ(ERP_ERR_NOERROR, err);
}

// Test that the key derivation is possible with static data from previous test.
TEST_F(ErpClusterTestFixture, StaticKeyDerivation)
{
    unsigned int err = ERP_ERR_NOERROR;
    auto pAKName = readERPResourceFile("saved/h80000002.bin");
    std::unique_ptr<ERPBlob> teeToken = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/StaticTEETokenSaved.blob"));
    std::unique_ptr<ERPBlob> derivationKey = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/StaticDerivationKey.blob"));
    // 13. derive Task persistence Key for initial derivation
    unsigned char derivationData[] = "(Dummy Derivation Data) KVNR:Z123-45678";
    size_t derivationDataLength = strlen((const char*)derivationData) + 1;
    unsigned char usedDerivationData[MAX_BUFFER];
    size_t usedDerivationDataLength = 0;
    unsigned char initialDerivedKey[AES_256_LEN];
    if (err == ERP_ERR_SUCCESS)
    {
        err = teststep_deriveTaskPersistenceKey(
            ErpClusterTestFixture::m_logonSession,
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
TEST_F(ErpClusterTestFixture, UpdateUserTest)
{
    unsigned int Gen = THE_ANSWER;
    logoff();
    logonUpdate();
    auto pDerivationKeyBlob = getEmptyBlob(Gen);
    EXPECT_EQ(ERP_ERR_NOERROR, teststep_GenerateDerivationKey(
        ErpClusterTestFixture::m_logonSession, Gen, pDerivationKeyBlob.get()));
    logoff();
    logonSetup();
    EXPECT_EQ(ERP_ERR_NOERROR, teststep_GenerateDerivationKey(
        ErpClusterTestFixture::m_logonSession, Gen, pDerivationKeyBlob.get()));
    logoff();
    logonWorking();
    EXPECT_EQ(ERP_ERR_PERMISSION_DENIED, teststep_GenerateDerivationKey(
        ErpClusterTestFixture::m_logonSession, Gen, pDerivationKeyBlob.get()));
}

TEST_F(ErpClusterTestFixture, ConnectTests)
{ // TODO - add tests trying to reuse a disconnected session.
    // TODO - add tests for multi-threaded access.
    // TODO - Try using a disconnected session for a working command.
    EXPECT_EQ(HSMLoggedIn, ErpClusterTestFixture::m_logonSession.status);
    ErpClusterTestFixture::m_logonSession = ERP_Logoff(ErpClusterTestFixture::m_logonSession);
    EXPECT_EQ(HSMAnonymousOpen, ErpClusterTestFixture::m_logonSession.status);
    ErpClusterTestFixture::m_logonSession = ERP_Disconnect(ErpClusterTestFixture::m_logonSession);
    EXPECT_EQ(HSMClosed, ErpClusterTestFixture::m_logonSession.status);
    connect();
    EXPECT_EQ(HSMAnonymousOpen, ErpClusterTestFixture::m_logonSession.status);
    logonSetup();
    EXPECT_EQ(HSMLoggedIn, ErpClusterTestFixture::m_logonSession.status);
    ErpClusterTestFixture::m_logonSession = ERP_Logoff(ErpClusterTestFixture::m_logonSession);
    EXPECT_EQ(HSMAnonymousOpen, ErpClusterTestFixture::m_logonSession.status);
    logonWorking();
    EXPECT_EQ(HSMLoggedIn, ErpClusterTestFixture::m_logonSession.status);
}

TEST_F(ErpClusterTestFixture, ConnectionTestMethod)
{
    EXPECT_EQ(ERP_ERR_NOERROR, teststep_DumpHSMMemory(ErpClusterTestFixture::m_logonSession));
}
TEST_F(ErpClusterTestFixture, ConnectionTestDirect)
{
    unsigned int             err = ERP_ERR_NOERROR;

    printf("\nExecuting DumpHSMMemory command ...\n");

    EmptyOutput output = ERP_DumpHSMMemory(ErpClusterTestFixture::m_logonSession);
    EXPECT_EQ(ERP_ERR_NOERROR, output.returnCode);

    printf("Returned from DumpHSMMemory Command - Return Value: 0x%08x\n", output.returnCode);

    EXPECT_EQ(ERP_ERR_NOERROR, err);
}

TEST_F(ErpClusterTestFixture, GenerateBlobKey)
{
    EXPECT_EQ(ERP_ERR_NOERROR, teststep_GenerateBlobKey(ErpClusterTestFixture::m_logonSession, 0));
}

TEST_F(ErpClusterTestFixture, ListLoadedBlobKeys)
{
    EXPECT_EQ(ERP_ERR_NOERROR, teststep_ListLoadedBlobKeys(ErpClusterTestFixture::m_logonSession));
}

TEST_F(ErpClusterTestFixture, DeleteBlobKey)
{ // The number used in this test must not be the highest in the HSM or a repeat of the test suite might fails
    unsigned int genRet = teststep_GenerateBlobKey(ErpClusterTestFixture::m_logonSession, 3);
    EXPECT_TRUE((genRet == ERP_ERR_NOERROR) || (genRet == ERP_ERR_BAD_BLOB_GENERATION));
    EXPECT_EQ(ERP_ERR_NOERROR, teststep_ListLoadedBlobKeys(ErpClusterTestFixture::m_logonSession));
    EXPECT_EQ(ERP_ERR_NOERROR, teststep_DeleteBlobKey(ErpClusterTestFixture::m_logonSession, 3));
}

TEST_F(ErpClusterTestFixture, GenerateNONCE)
{
    // Use the STRIP_ERR_INDEX here to make sure it does not break the error code
    EXPECT_EQ(ERP_ERR_NOERROR, STRIP_ERR_INDEX(teststep_GenerateNONCE(ErpClusterTestFixture::m_logonSession, 0)));
}

// Test to exercise input parameter handling
TEST_F(ErpClusterTestFixture, Params_GenerateNONCE) {
    EXPECT_EQ(ERP_ERR_NOERROR, teststep_GenerateNONCE(ErpClusterTestFixture::m_logonSession, 0));
    // I am assuming that our tests setup will not generate blob generation keys beypnd 0x1000
    // Use the STRIP_ERR_INDEX here to make sure it does not break the error code
    EXPECT_EQ(ERP_ERR_BAD_BLOB_GENERATION, STRIP_ERR_INDEX(teststep_GenerateNONCE(ErpClusterTestFixture::m_logonSession, 0x1001)));
    EXPECT_EQ(ERP_ERR_BAD_BLOB_GENERATION, teststep_GenerateNONCE(ErpClusterTestFixture::m_logonSession, 0xffffffff));
    // Just in case of signed/unsigned problems
    EXPECT_EQ(ERP_ERR_BAD_BLOB_GENERATION, teststep_GenerateNONCE(ErpClusterTestFixture::m_logonSession, 0x7fffffff));
    teststep_ASN1IntegerInput(ErpClusterTestFixture::m_logonSession, ERP_SFC_GENERATE_NONCE);
}

// Test to check Permissions for GenerateNONCE command.
TEST_F(ErpClusterTestFixture, Permission_GenerateNONCE) {
    logoff();
    EXPECT_EQ(ERP_ERR_PERMISSION_DENIED, teststep_GenerateNONCE(ErpClusterTestFixture::m_logonSession, 0));
    logoff();
    logonWorking();
    EXPECT_EQ(ERP_ERR_NOERROR, teststep_GenerateNONCE(ErpClusterTestFixture::m_logonSession, 0));
    logoff();
    logonSetup();
    EXPECT_EQ(ERP_ERR_NOERROR, teststep_GenerateNONCE(ErpClusterTestFixture::m_logonSession, 0));
    logoff();
    logonSetup();
    logonWorking();
    EXPECT_EQ(ERP_ERR_NOERROR, teststep_GenerateNONCE(ErpClusterTestFixture::m_logonSession, 0));
}

TEST_F(ErpClusterTestFixture, GetRNDBytesTests)
{
    UIntInput desiredBytes = { 32 };
    RNDBytesOutput rndOut = ERP_GetRNDBytes(ErpClusterTestFixture::m_logonSession, desiredBytes);
    EXPECT_EQ(ERP_ERR_NOERROR, rndOut.returnCode);
    EXPECT_EQ(32, rndOut.RNDDataLen);
    // TODO log rnd data here...
    // 0 bytes - param err
    desiredBytes.intValue = 0;
    rndOut = ERP_GetRNDBytes(ErpClusterTestFixture::m_logonSession, desiredBytes);
    EXPECT_EQ(ERP_ERR_PARAM, rndOut.returnCode);
    // 1 byte - ok
    desiredBytes.intValue = 1;
    rndOut = ERP_GetRNDBytes(ErpClusterTestFixture::m_logonSession, desiredBytes);
    EXPECT_EQ(ERP_ERR_NOERROR, rndOut.returnCode);
    EXPECT_EQ(1, rndOut.RNDDataLen);
    // 42 bytes - not a multiple of 256 bits... - ok
    desiredBytes.intValue = 42;
    rndOut = ERP_GetRNDBytes(ErpClusterTestFixture::m_logonSession, desiredBytes);
    EXPECT_EQ(ERP_ERR_NOERROR, rndOut.returnCode);
    EXPECT_EQ(42, rndOut.RNDDataLen);
    // 64 bytes - ok
    desiredBytes.intValue = 64;
    rndOut = ERP_GetRNDBytes(ErpClusterTestFixture::m_logonSession, desiredBytes);
    EXPECT_EQ(ERP_ERR_NOERROR, rndOut.returnCode);
    EXPECT_EQ(64, rndOut.RNDDataLen);
    // 320 bytes - ok
    desiredBytes.intValue = MAX_RND_BYTES;
    rndOut = ERP_GetRNDBytes(ErpClusterTestFixture::m_logonSession, desiredBytes);
    EXPECT_EQ(ERP_ERR_NOERROR, rndOut.returnCode);
    EXPECT_EQ(MAX_RND_BYTES, rndOut.RNDDataLen);
    // 321 bytes - parm err.
    desiredBytes.intValue = MAX_RND_BYTES + 1;
    rndOut = ERP_GetRNDBytes(ErpClusterTestFixture::m_logonSession, desiredBytes);
    EXPECT_EQ(ERP_ERR_PARAM, rndOut.returnCode);
    // TODO - asn1 integer input tests - refactor from GenerateNONCE.
    teststep_ASN1IntegerInput(ErpClusterTestFixture::m_logonSession, ERP_SFC_GET_RND_BYTES, false);
}

// Test to check Permissions for GetRNDBytes command.
TEST_F(ErpClusterTestFixture, Permission_GetRNDBytes) {
    logoff();
    UIntInput desiredBytes = { 32 };
    RNDBytesOutput rndOut = ERP_GetRNDBytes(ErpClusterTestFixture::m_logonSession, desiredBytes);
    EXPECT_EQ(ERP_ERR_PERMISSION_DENIED, rndOut.returnCode);
    EXPECT_EQ(0, rndOut.RNDDataLen);
    logoff();
    logonWorking();
    rndOut = ERP_GetRNDBytes(ErpClusterTestFixture::m_logonSession, desiredBytes);
    EXPECT_EQ(ERP_ERR_NOERROR, rndOut.returnCode);
    EXPECT_EQ(32, rndOut.RNDDataLen);
    logoff();
    logonSetup();
    rndOut = ERP_GetRNDBytes(ErpClusterTestFixture::m_logonSession, desiredBytes);
    EXPECT_EQ(ERP_ERR_PERMISSION_DENIED, rndOut.returnCode);
    EXPECT_EQ(0, rndOut.RNDDataLen);
    logoff();
    logonSetup();
    logonWorking();
    rndOut = ERP_GetRNDBytes(ErpClusterTestFixture::m_logonSession, desiredBytes);
    EXPECT_EQ(ERP_ERR_NOERROR, rndOut.returnCode);
    EXPECT_EQ(32, rndOut.RNDDataLen);
}
