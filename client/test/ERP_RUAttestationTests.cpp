/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021, 2024
 * (C) Copyright IBM Corp. 2021, 2024
 *
 * non-exclusively licensed to gematik GmbH
 **************************************************************************************************/

// Test cases to generate static data set for new HSMs, including hardware HSMs.
// Read test/resources/SavedData.md
// Set devIP to correct HSM.

#include "ERP_Client.h"
#include "ERP_Error.h"
#include "ERP_TestParams.h"
#include "ERP_TestUtils.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <memory>
#include <vector>

class ErpRUAttestationTestFixture : public ::testing::Test {
public:
    HSMSession m_logonSession = { 0, 0, 0, HSMUninitialised, 0, ERP_ERR_NOERROR, 0 };
    static const std::string devIP;

    // This is the static set of generations that I want setup in the RU.
    // RFU.
    static const unsigned int reservedGeneration = 1;
    // Used for TPM and Enclave Enrollments with the SW TPM.
    static const unsigned int enrollmentGeneration = 2;
    // Used for derivation and hash key blobs linked to SW TPM
    static const unsigned int derivationKeyGeneration = 3;
    // Only used for the SW TPM VAUSIG Keypair - will remain once moved to real TPM,
    //    though value will be compromised and cannot be used live.
    static const unsigned int VAUSIGGeneration = 4;
    // Only used for the SW TPM ECIES Keypair - will remain once moved to real TPM,
    //    though value will be compromised and cannot be used live.
    static const unsigned int ECIESGeneration = 5;
    // Used for dynamic and transient blobs.
    static const unsigned int workingGeneration = 6;

    void connect()
    {
        // This method is intended to be invoked for each test just before the test starts
        m_logonSession = ERP_Connect(devIP.c_str(), TEST_CONNECT_TIMEOUT_MS, TEST_READ_TIMEOUT_MS);
    }

    void logonSetup()
    {
        // user ERP_SETUP with "password" and permissions 00000200
        const static std::string setupUsername = "ERP_SETUP";
        const static std::string password = "password";

        // For now, log in both tyes of user.
        m_logonSession = ERP_LogonPassword(m_logonSession, setupUsername.c_str(), password.c_str());
        ASSERT_EQ(HSMLoggedIn, m_logonSession.status);
    }
    void logonWorking() {
        // user ERP_WORK with "password" and permissions 00000020
        const static std::string workUsername = "ERP_WORK";
        const static std::string password = "password";

        m_logonSession = ERP_LogonPassword(m_logonSession, workUsername.c_str(), password.c_str());
        ASSERT_EQ(HSMLoggedIn, m_logonSession.status);
    }

    void logoff()
    {
        if (m_logonSession.status == HSMLoggedIn)
        {
            m_logonSession = ERP_Logoff(m_logonSession);
            ASSERT_EQ(HSMAnonymousOpen, m_logonSession.status);
        }
    }

    void forceCreateBlobGeneration(unsigned int generation)
    {
        unsigned int err = teststep_GenerateBlobKey(m_logonSession, generation);
        EXPECT_TRUE((err == ERP_ERR_NOERROR) || (err == ERP_ERR_BAD_BLOB_GENERATION));
    }

    void SetUp() override
    {
        // This method is intended to be invoked for each test just before the test starts
        connect();
        EXPECT_EQ(HSMAnonymousOpen, m_logonSession.status);
        logonSetup();
        logonWorking();
        forceCreateBlobGeneration(reservedGeneration); // = 1;
        forceCreateBlobGeneration(enrollmentGeneration); // = 2;
        forceCreateBlobGeneration(derivationKeyGeneration); // = 3;
        forceCreateBlobGeneration(VAUSIGGeneration); // = 4;
        forceCreateBlobGeneration(ECIESGeneration); // = 5;
        forceCreateBlobGeneration(workingGeneration); // = 6;
    }

    void TearDown() override
    {
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
        logoff();
        m_logonSession = ERP_Disconnect(m_logonSession);

        EXPECT_TRUE((m_logonSession.errorCode == ERP_ERR_NOERROR) ||
            (m_logonSession.errorCode == ERP_ERR_NO_CONNECTION));
    }
};

const std::string ErpRUAttestationTestFixture::devIP = HARDWARE_HSM;

TEST_F(ErpRUAttestationTestFixture, DISABLED_AttestationSequencePart1)
{
    unsigned int err = ERP_ERR_NOERROR;
    // Sequence:
    // 1. Trust Mfr Root CA Certificate
    auto pTrustedRoot = getEmptyBlob();
    auto MfrRootCert = readERPResourceFile("cacertecc.crt");

    err = teststep_TrustTPMMfr(
        ErpRUAttestationTestFixture::m_logonSession,
        enrollmentGeneration,
        pTrustedRoot.get(),
        MfrRootCert);

    if (err == ERP_ERR_SUCCESS)
    {
        // Save this in case we want to take a snapshot of a TPM decryption.
        err = writeBlobResourceFile("rusaved/trustedMfrRoot.blob", pTrustedRoot.get());
    }

    // 2. Missing Step to call TPM to get the EK Cert
    //    for now just use some certificate from a file.
    auto pEKCert = readERPResourceFile("EKCertECC.crt");

    // 3. Obsolete - Step to call TPM to sign the {EKPub | NONCE}

    // 4. Enroll EK
    auto pTrustedEK = getEmptyBlob();
    if (err == ERP_ERR_SUCCESS)
    {
        err = teststep_EnrollTPMEK(
            ErpRUAttestationTestFixture::m_logonSession,
            enrollmentGeneration,
            pTrustedRoot.get(),
            pTrustedEK.get(),
            pEKCert.size(),
            pEKCert.data());
    }
    if (err == ERP_ERR_SUCCESS)
    {
        // Save this in case we want to take a snapshot of a TPM decryption.
        err = writeBlobResourceFile("rusaved/trustedEK.blob", pTrustedEK.get());
    }

    // 5. getAKChallenge
    // Inputs:
    auto pAKName = readERPResourceFile("h80000002.bin");
    // AK Public key is now in TPMTPUBLIC format
    auto pAKPub = readERPResourceFile("AKPub.bin");
    // Outputs
    auto pCredChallengeBlob = getEmptyBlob();
    unsigned char encCredentialData[MAX_BUFFER] = "";
    size_t encCredentialLength = 0;
    unsigned char secretData[MAX_BUFFER] = "";
    size_t secretLength = 0;
    if (err == ERP_ERR_SUCCESS)
    {
        err = teststep_GetAKChallenge(
            ErpRUAttestationTestFixture::m_logonSession,
            workingGeneration,
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
    // 6. Go to TPM to answer challenge...
    // If done, this will create AKChallenge.blob and creddecHSM.bin.   If you wish to use these in the next steps copy
    //    then to  saved/AKChallengeSaved.blob and saved/credDecHSMSaved.bin
    // ---- MARKER ----
    // This is where to break the tests and generate e test response on the tpm.   If
    //    you do then copy the results into the saved directory.

    // The following step should be done after the AK attestation and before getting a quote, but if we do it here then
    //    the activateHSMCredential script will generate a quote using it.
    //
    // 8. getNONCE for TPM Quote
    UIntInput genIn = {workingGeneration};
    // 8. getNONCE for TPM Enrollment Quote - do this out of sequence to allow a single manual TPM step.
    NONCEOutput quoteNONCE = ERP_GenerateNONCE(ErpRUAttestationTestFixture::m_logonSession, genIn);
    writeBlobResourceFile("EnrollmentQuoteNONCE.blob", &(quoteNONCE.BlobOut));
    unsigned char variedEnrollmentNONCE[NONCE_LEN];
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
    NONCEOutput attestNONCE = ERP_GenerateNONCE(ErpRUAttestationTestFixture::m_logonSession, genIn);
    writeBlobResourceFile("AttestationQuoteNONCE.Blob", &(attestNONCE.BlobOut));
    unsigned char variedAttestationNONCE[NONCE_LEN];
    if (err == ERP_ERR_SUCCESS)
    {
        err = varyNONCE("ERP_ATTESTATION", &(attestNONCE.NONCE[0]), &(variedAttestationNONCE[0]));
    }
    if (err == ERP_ERR_SUCCESS)
    {
        writeERPResourceFile("AttestationQuoteNONCE.bin", std::vector<std::uint8_t>(&(variedAttestationNONCE[0]), &(variedAttestationNONCE[0]) + RND_256_LEN));
    }
    EXPECT_EQ(ERP_ERR_NOERROR, err);
}

// Run this test once static test data has been saved from AttestationSequencePart1 and going to the TPM for an
// Answer to the challenge.
TEST_F(ErpRUAttestationTestFixture, DISABLED_AttestationSequencePart2)
{
    auto err = ERP_ERR_NOERROR;
    // 7. Enroll AK
    // Use blob and decyrpted credential from a previous test run
    std::unique_ptr<ERPBlob> savedAKChallengeBlob = readBlobResourceFile("rusaved/AKChallengeSaved.blob");
    std::unique_ptr<ERPBlob> savedTrustedEKBlob = readBlobResourceFile("rusaved/trustedEKSaved.blob");
    auto savedDecCred = readERPResourceFile("rusaved/credDecHSMSaved.bin");
    auto savedAKPub = readERPResourceFile("rusaved/AKPub.bin");
    auto savedAKName = readERPResourceFile("rusaved/h80000002.bin");
    auto pTrustedAK = getEmptyBlob();

    err = teststep_EnrollAK(ErpRUAttestationTestFixture::m_logonSession,
                            enrollmentGeneration,
                            savedTrustedEKBlob.get(),
                            savedAKChallengeBlob.get(),
                            savedAKName.data(),
                            savedAKPub.size() - 2,
                            savedAKPub.data() + 2,
                            savedDecCred.size(),
                            savedDecCred.data(),
                            pTrustedAK.get());

    if (err == ERP_ERR_NOERROR)
    {
        writeBlobResourceFile("rusaved/trustedAk.blob", pTrustedAK.get());
    }

    // 8. getNONCE for TPM Quote
    //    We won't actually use the value that we get here, but we check that we can get a NONCE at the right time.
    //
    // The actual test will run with the saved value generated in part1.
    UIntInput genIn = { workingGeneration };
    NONCEOutput quoteNONCE = ERP_GenerateNONCE(ErpRUAttestationTestFixture::m_logonSession, genIn);
    EXPECT_EQ(ERP_ERR_NOERROR, err);
    // I want to generate the nonce at this point even if I actually use a different one in the next steps.
    (void)(quoteNONCE);
    // 9. get Quote from TPM.   Actually load previously saved...
    auto enrollQuote = readERPResourceFile("rusaved/EnrollmentQuoteSaved.bin");
    auto enrollSig = readERPResourceFile("rusaved/EnrollmentQuoteSigSaved.bin");
    std::unique_ptr<ERPBlob> enrollNONCE =
        readBlobResourceFile("rusaved/EnrollmentQuoteNONCESaved.blob");
    // 7. Enroll Enclave
    auto pTrustedQuote = getEmptyBlob();
    if (err == ERP_ERR_SUCCESS)
    {
        err = teststep_TrustQuote(
            ErpRUAttestationTestFixture::m_logonSession,
            enrollmentGeneration,
            pTrustedAK.get(),
            enrollNONCE.get(),
            savedAKName.data(),
            enrollQuote.size(), enrollQuote.data(),
            enrollSig.size(), enrollSig.data(),
            pTrustedQuote.get());
    }
    if (err == ERP_ERR_NOERROR)
    {
        writeBlobResourceFile("rusaved/trustedQuote.blob", pTrustedQuote.get());
    }
    // 10. get New NONCE for TEE Token request.   Actually load previously saved...
    auto attestQuote = readERPResourceFile("rusaved/AttestationQuoteSaved.bin");
    auto attestSig = readERPResourceFile("rusaved/AttestationQuoteSigSaved.bin");
    std::unique_ptr<ERPBlob> attestNONCE =
        readBlobResourceFile("rusaved/AttestationQuoteNONCESaved.blob");

    // 11. getTEEToken
    auto pTEEToken = getEmptyBlob();
    if (err == ERP_ERR_SUCCESS)
    {
        err = teststep_getTEEToken(
            ErpRUAttestationTestFixture::m_logonSession,
            pTrustedAK.get(),
            pTrustedQuote.get(),
            attestNONCE.get(),
            savedAKName.data(),
            attestQuote.size(), attestQuote.data(),
            attestSig.size(), attestSig.data(),
            pTEEToken.get());
    }
    // Save the TEEToken for use in other tests.
    if (err == ERP_ERR_SUCCESS)
    {
        err = writeBlobResourceFile("rusaved/staticTEEToken.blob", pTEEToken.get());
    }

    EXPECT_EQ(ERP_ERR_NOERROR, err);
}

// Run this test once static test data has been saved from AttestationSequencePart1 and going to the TPM for an
// Answer to the challenge.
// This test will create the static working keys if they are not already present.   It checks
//   for the existence of the rusaved/ blob files and only recreates them if they are not present.
TEST_F(ErpRUAttestationTestFixture, DISABLED_DeriveAESKeyBlobs)
{
    unsigned int err = ERP_ERR_NOERROR;

    // 12. Derive or retrieve a new Derivation Key Blobs.
    auto pTaskDerivationKeyBlob = getEmptyBlob();
    if (err == ERP_ERR_NOERROR)
    {
        err = deriveOrRetrieveDerivationKey(m_logonSession,
            derivationKeyGeneration,
            "rusaved/taskDerivationKeySaved.blob",
            pTaskDerivationKeyBlob.get() );
        EXPECT_EQ(ERP_ERR_NOERROR, err);
    }

    auto pAuditDerivationKeyBlob = getEmptyBlob();
    if (err == ERP_ERR_NOERROR)
    {
        err = deriveOrRetrieveDerivationKey(m_logonSession,
            derivationKeyGeneration,
            "rusaved/auditDerivationKeySaved.blob",
            pAuditDerivationKeyBlob.get() );
        EXPECT_EQ(ERP_ERR_NOERROR, err);
    }

    auto pCommsDerivationKeyBlob = getEmptyBlob();
    if (err == ERP_ERR_NOERROR)
    {
        err = deriveOrRetrieveDerivationKey(m_logonSession,
            derivationKeyGeneration,
            "rusaved/commsDerivationKeySaved.blob",
            pCommsDerivationKeyBlob.get() );
        EXPECT_EQ(ERP_ERR_NOERROR, err);
    }

    if (err == ERP_ERR_NOERROR)
    {
        static const char* filename = "rusaved/hashKeySaved.blob";
        auto pReadBlob = readBlobResourceFile(filename,false);

        if (pReadBlob == nullptr)
        {
            UIntInput in = { derivationKeyGeneration };
            SingleBlobOutput out = ERP_GenerateHashKey(m_logonSession, in);
            EXPECT_EQ(ERP_ERR_NOERROR, out.returnCode);
            if (out.returnCode == ERP_ERR_NOERROR)
            {
                writeBlobResourceFile(filename, &(out.BlobOut));
            }
        }
    }

    if (err == ERP_ERR_NOERROR)
    {
        static const char* filename = "rusaved/eciesKeyPairSaved.blob";
        auto pReadBlob = readBlobResourceFile(filename,false);

        if (pReadBlob == nullptr)
        {
            UIntInput in = { ECIESGeneration };
            SingleBlobOutput out = ERP_GenerateECIESKeyPair(m_logonSession, in);
            EXPECT_EQ(ERP_ERR_NOERROR, out.returnCode);
            if (out.returnCode == ERP_ERR_NOERROR)
            {
                writeBlobResourceFile(filename, &(out.BlobOut));
            }
        }
    }

    if (err == ERP_ERR_NOERROR)
    {
        static const char* filename = "rusaved/VAUSIGKeyPairSaved_UT.blob";
        auto pReadBlob = readBlobResourceFile(filename,false);

        if (pReadBlob == nullptr)
        {
            UIntInput in = { ECIESGeneration };
            SingleBlobOutput out = ERP_GenerateVAUSIGKeyPair(m_logonSession, in);
            EXPECT_EQ(ERP_ERR_NOERROR, out.returnCode);
            if (out.returnCode == ERP_ERR_NOERROR)
            {
                writeBlobResourceFile(filename, &(out.BlobOut));
            }
        }
    }

    EXPECT_EQ(ERP_ERR_NOERROR, err);
}

TEST_F(ErpRUAttestationTestFixture, DISABLED_DeriveKeyTest)
{
    auto err = ERP_ERR_NOERROR;

    std::unique_ptr<ERPBlob> savedTEEToken = readBlobResourceFile("rusaved/staticTEETokenSaved.blob");
    std::unique_ptr<ERPBlob> savedTaskDerivationKey = readBlobResourceFile("rusaved/taskDerivationKeySaved.blob");
    auto savedAKName = readERPResourceFile("rusaved/h80000002.bin");
    // 13. derive Task persistence Key for initial derivation
    auto derivationData = asciiToBuffer("(Dummy Derivation Data) KVNR:Z123-45678");
    unsigned char usedDerivationData[MAX_BUFFER];
    size_t usedDerivationDataLength = 0;
    unsigned char initialDerivedKey[AES_256_LEN];

    err = teststep_deriveTaskPersistenceKey(ErpRUAttestationTestFixture::m_logonSession,
                                            savedAKName.data(), // SHA_1_LEN...
                                            savedTEEToken.get(),
                                            savedTaskDerivationKey.get(),
                                            derivationData.size(),
                                            derivationData.data(),
                                            1, // 1 => Initial Derivation, 0 => subsequent Derivation.
                                            // Output
                                            &usedDerivationDataLength,
                                            &(usedDerivationData[0]), // MAX_BUFFER
                                            &(initialDerivedKey[0])); // AES_256_LEN

    // 14. Derive Task persistence key again for a non-initial derivation
    unsigned char subsequentDerivedKey[AES_256_LEN];
    for (int m = 0; m < SMALL_LOOP; m++)
    {
        if (err == ERP_ERR_SUCCESS)
        {
            err = teststep_deriveTaskPersistenceKey(
                ErpRUAttestationTestFixture::m_logonSession,
                savedAKName.data(), // SHA_1_LEN...
                savedTEEToken.get(),
                savedTaskDerivationKey.get(),
                usedDerivationDataLength,
                &(usedDerivationData[0]),
                0, // 1 => Initial Derivation, 0 => subsequent Derivation.
                // Output
                &usedDerivationDataLength,
                &(usedDerivationData[0]), // MAX_BUFFER
                &(subsequentDerivedKey[0])); // AES_256_LEN
        }
    }
    EXPECT_EQ(ERP_ERR_NOERROR, err);
}

TEST_F(ErpRUAttestationTestFixture, DISABLED_getVAUSIGPrivateKey)
{
    std::unique_ptr<ERPBlob> savedKeyPairBlob = readBlobResourceFile("rusaved/VAUSIGKeyPairSaved_UT.blob");
    ASSERT_NE(nullptr, savedKeyPairBlob);

    TwoBlobGetKeyInput vauSIG = { {0,0,{0}}, {0,0,{0}} };
    vauSIG.Key = *savedKeyPairBlob;
    // Take the TEEToken from a previous test run:
    auto teeToken = readBlobResourceFile("rusaved/staticTEETokenSaved.blob");
    ASSERT_NE(nullptr, teeToken);
    vauSIG.TEEToken = *teeToken;
    PrivateKeyOutput keyOut = ERP_GetVAUSIGPrivateKey(m_logonSession, vauSIG);
    ASSERT_EQ(ERP_ERR_NOERROR, keyOut.returnCode);

 /**
 // TODO(chris) - set up check of expected output.
    unsigned char expectedKey[] = { 0x30, 0x81, 0x95, 0x02, 0x01, 0x00, 0x30, 0x14, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
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
    **/
}

TEST_F(ErpRUAttestationTestFixture, DISABLED_generateVAUSIGCSR)
{
    std::unique_ptr<ERPBlob> savedKeyPairBlob{readBlobResourceFile("rusaved/VAUSIGKeyPairSaved_UT.blob")};
    ASSERT_NE(nullptr, savedKeyPairBlob);

    GetVAUCSRInput vauCSR{};
    vauCSR.KeyPair = *savedKeyPairBlob;
    // At the moment these candidate CSRs are from the ePA TU authn.
    auto candidateCSR = readERPResourceFile("candidateVAUSIG.csr");
    ASSERT_GT(candidateCSR.size(), 0);
    vauCSR.candidateCSRLength = candidateCSR.size();
    memcpy(&(vauCSR.candidateCSR[0]), candidateCSR.data(), candidateCSR.size());
    x509CSROutput keyOut = ERP_GenerateVAUSIGCSR(m_logonSession, vauCSR);
    ASSERT_EQ(ERP_ERR_NOERROR, keyOut.returnCode);

    writeERPResourceFile("rusaved/generatedVAUSIG.csr",
                         std::vector<std::uint8_t>(&(keyOut.CSRData[0]), &(keyOut.CSRData[0]) + keyOut.CSRDataLength));
}

// Cannot work without test data matching our ECIES KeyPair.
// This is really a DISABLED and FAIL
TEST_F(ErpRUAttestationTestFixture, DISABLED_doVAUECIES)
{
    std::unique_ptr<ERPBlob> savedKeyPairBlob{readBlobResourceFile("rusaved/eciesKeyPairSaved.blob")};
    ASSERT_NE(nullptr, savedKeyPairBlob);

    DoVAUECIESInput vauECIES = { {0,0,{0}}, {0,0,{0}},0, {0} };
    vauECIES.ECIESKeyPair = *savedKeyPairBlob;
    // Take the TEEToken from a previous test run:
    auto teeToken = std::unique_ptr<ERPBlob>(readBlobResourceFile("rusaved/staticTEETokenSaved.blob"));
    ASSERT_NE(nullptr, teeToken);
    vauECIES.TEEToken = *teeToken;
    auto clientPub = readERPResourceFile("rusaved/clientECIESPub.bin");
    //    auto clientPub = readERPResourceFile("saved/GemSpecClientECIESPub.bin");
    ASSERT_GT(clientPub.size(), 0);
    memcpy(&(vauECIES.clientPublicKeyData[0]), clientPub.data(), clientPub.size());
    vauECIES.clientPublicKeyLength = clientPub.size();
    AES128KeyOutput keyOut = ERP_DoVAUECIES128(m_logonSession, vauECIES);
    ASSERT_EQ(ERP_ERR_NOERROR, keyOut.returnCode);
    const unsigned char expectedKey[] = { 0xda, 0x7c, 0x96, 0x48, 0xf7, 0xab, 0xa4, 0x6d,
                                          0x6f, 0x7b, 0x98, 0x5e, 0xf8, 0xa9, 0x4b, 0x02 };
    ASSERT_TRUE(0 == memcmp(&(keyOut.AESKey[0]), &(expectedKey[0]), 16));
}

TEST_F(ErpRUAttestationTestFixture, DISABLED_generateECIESCSR)
{
    std::unique_ptr<ERPBlob> savedKeyPairBlob =
        std::unique_ptr<ERPBlob>(readBlobResourceFile("rusaved/eciesKeyPairSaved.blob"));
    ASSERT_NE(nullptr, savedKeyPairBlob);

    GetVAUCSRInput eciesCSR{};
    eciesCSR.KeyPair = *savedKeyPairBlob;
    // At the moment these candidate CSRs are from the ePA TU authn.
    auto candidateCSR = readERPResourceFile("candidateECIES.csr");
    ASSERT_GT(candidateCSR.size(), 0);
    eciesCSR.candidateCSRLength = candidateCSR.size();
    memcpy(&(eciesCSR.candidateCSR[0]), candidateCSR.data(), candidateCSR.size());
    x509CSROutput keyOut{};
    for (int i = 0; i < MEDIUM_LOOP; i++)
    {
        keyOut = ERP_GenerateECIESCSR(m_logonSession, eciesCSR);
        ASSERT_EQ(ERP_ERR_NOERROR, keyOut.returnCode);
    }

    writeERPResourceFile("rusaved/generatedECIES.csr",
                         std::vector<std::uint8_t>(&(keyOut.CSRData[0]), &(keyOut.CSRData[0]) + keyOut.CSRDataLength));
}

TEST_F(ErpRUAttestationTestFixture, DISABLED_UnwrapHashKey)
{
    std::unique_ptr<ERPBlob> savedKeyPairBlob =
        readBlobResourceFile("rusaved/hashKeySaved.blob");
    ASSERT_NE(nullptr, savedKeyPairBlob);

    TwoBlobGetKeyInput get{};
    get.Key = *savedKeyPairBlob;
    // Take the TEEToken from a previous test run:
    auto teeToken = readBlobResourceFile("rusaved/staticTEETokenSaved.blob");
    ASSERT_NE(nullptr, teeToken);
    get.TEEToken = *teeToken;
    AES256KeyOutput keyOut = ERP_UnwrapHashKey(m_logonSession, get);
    EXPECT_EQ(ERP_ERR_NOERROR, keyOut.returnCode);

    writeERPResourceFile("rusaved/ERPHashKey.bin",
                         std::vector<std::uint8_t>(&(keyOut.Key[0]), &(keyOut.Key[0]) + AES_256_LEN));
}
