// Test cases to generate static data set for new HSMs, including hardware HSMs.
// Read test/resources/SavedData.md
// Set devIP to correct HSM.

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

class ErpRUAttestationTestFixture : public ::testing::Test {
public:
    static HSMSession m_logonSession;
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

    ErpRUAttestationTestFixture() {
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

    void forceCreateBlobGeneration(unsigned int generation)
    {
        unsigned int err = teststep_GenerateBlobKey(m_logonSession, generation);
        EXPECT_TRUE((err == ERP_ERR_NOERROR) || (err == ERP_ERR_BAD_BLOB_GENERATION));
    }

    void SetUp() override {
        // code here will execute just before the test ensues 
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

    void TearDown() override {
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
        logoff();
        m_logonSession = ERP_Disconnect(m_logonSession);

        EXPECT_TRUE((m_logonSession.errorCode == ERP_ERR_NOERROR) ||
            (m_logonSession.errorCode == ERP_ERR_NO_CONNECTION));
    }
};

HSMSession ErpRUAttestationTestFixture::m_logonSession = { 0, 0, 0, HSMUninitialised, 0, ERP_ERR_NOERROR ,0 };
// 3001 is local simulator, 3021 is whatever you have mapped the 
//const std::string erpRUAttestationTestFixture::devIP = "3001@localhost";
const std::string ErpRUAttestationTestFixture::devIP = HARDWARE_HSM;

TEST_F(ErpRUAttestationTestFixture, DISABLED_AttestationSequencePart1)
{
    unsigned int err = 0;
    // Sequence:
    // 1. Trust Mfr Root CA Certificate
    auto pTrustedRoot = getEmptyBlob();
    auto MfrRootCert = readERPResourceFile("cacertecc.crt");

    err = teststep_TrustTPMMfr(
        ErpRUAttestationTestFixture::m_logonSession,
        enrollmentGeneration,
        pTrustedRoot.get(),
        MfrRootCert);

    if (err == 0)
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
    if (err == 0)
    {
        err = teststep_EnrollTPMEK(
            ErpRUAttestationTestFixture::m_logonSession,
            enrollmentGeneration,
            pTrustedRoot.get(),
            pTrustedEK.get(),
            pEKCert.size(),
            reinterpret_cast<unsigned char*>(pEKCert.data()));
    }
    if (err == 0)
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
    if (err == 0)
    {
        err = teststep_GetAKChallenge(
            ErpRUAttestationTestFixture::m_logonSession,
            workingGeneration,
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
    if (err == 0)
    {
        err = varyNONCE("ERP_ENROLLMENT", quoteNONCE.NONCE, &(variedEnrollmentNONCE[0]));
    }
    if (err == 0)
    {
        writeERPResourceFile("EnrollmentQuoteNONCE.bin", std::vector<char>(variedEnrollmentNONCE, variedEnrollmentNONCE + 0x20));
    }
    // 10. get New NONCE for TEE Token request - do this out of sequence to allow a single manual TPM step.
    NONCEOutput attestNONCE = ERP_GenerateNONCE(ErpRUAttestationTestFixture::m_logonSession, genIn);
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
    EXPECT_EQ(ERP_ERR_NOERROR, err);
}

// Run this test once static test data has been saved from AttestationSequencePart1 and going to the TPM for an
// Answer to the challenge.
TEST_F(ErpRUAttestationTestFixture, DISABLED_AttestationSequencePart2)
{
    unsigned int err = ERP_ERR_NOERROR;
    // 7. Enroll AK
    // Use blob and decyrpted credential from a previous test run
    std::unique_ptr<ERPBlob> savedAKChallengeBlob = std::unique_ptr<ERPBlob>(readBlobResourceFile("rusaved/AKChallengeSaved.blob"));
    std::unique_ptr<ERPBlob> savedTrustedEKBlob = std::unique_ptr<ERPBlob>(readBlobResourceFile("rusaved/trustedEKSaved.blob"));
    auto savedDecCred = readERPResourceFile("rusaved/credDecHSMSaved.bin");
    auto savedAKPub = readERPResourceFile("rusaved/AKPub.bin");
    auto savedAKName = readERPResourceFile("rusaved/h80000002.bin");
    auto pTrustedAK = getEmptyBlob();
    if (err == 0)
    {
        err = teststep_EnrollAK(
            ErpRUAttestationTestFixture::m_logonSession,
            enrollmentGeneration,
            savedTrustedEKBlob.get(),
            savedAKChallengeBlob.get(),
            reinterpret_cast<unsigned char*>(savedAKName.data()),
            savedAKPub.size() - 2,
            reinterpret_cast<unsigned char*>(savedAKPub.data() + 2),
            savedDecCred.size(),
            (unsigned char*)savedDecCred.data(),
            pTrustedAK.get());
    }

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
    std::unique_ptr<ERPBlob> enrollNONCE = std::unique_ptr<ERPBlob>(
        readBlobResourceFile("rusaved/EnrollmentQuoteNONCESaved.blob"));
    // 7. Enroll Enclave
    auto pTrustedQuote = getEmptyBlob();
    if (err == 0)
    {
        err = teststep_TrustQuote(
            ErpRUAttestationTestFixture::m_logonSession,
            enrollmentGeneration,
            pTrustedAK.get(),
            enrollNONCE.get(),
            reinterpret_cast<unsigned char*>(savedAKName.data()),
            enrollQuote.size(), reinterpret_cast<unsigned char*>(enrollQuote.data()),
            enrollSig.size(), reinterpret_cast<unsigned char*>(enrollSig.data()),
            pTrustedQuote.get());
    }
    if (err == ERP_ERR_NOERROR)
    {
        writeBlobResourceFile("rusaved/trustedQuote.blob", pTrustedQuote.get());
    }
    // 10. get New NONCE for TEE Token request.   Actually load previously saved...
    auto attestQuote = readERPResourceFile("rusaved/AttestationQuoteSaved.bin");
    auto attestSig = readERPResourceFile("rusaved/AttestationQuoteSigSaved.bin");
    std::unique_ptr<ERPBlob> attestNONCE = std::unique_ptr<ERPBlob>(
        readBlobResourceFile("rusaved/AttestationQuoteNONCESaved.blob"));

    // 11. getTEEToken
    auto pTEEToken = getEmptyBlob();
    if (err == 0)
    {
        err = teststep_getTEEToken(
            ErpRUAttestationTestFixture::m_logonSession,
            pTrustedAK.get(),
            pTrustedQuote.get(),
            attestNONCE.get(),
            reinterpret_cast<unsigned char*>(savedAKName.data()),
            attestQuote.size(), reinterpret_cast<unsigned char*>(attestQuote.data()),
            attestSig.size(), reinterpret_cast<unsigned char*>(attestSig.data()),
            pTEEToken.get());
    }
    // Save the TEEToken for use in other tests.
    if (err == 0)
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
        ERPBlob* pReadBlob = readBlobResourceFile(filename,false);

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
        if (pReadBlob != nullptr)
        {
            delete pReadBlob;
        }
    }
    if (err == ERP_ERR_NOERROR)
    {
        static const char* filename = "rusaved/eciesKeyPairSaved.blob";
        ERPBlob* pReadBlob = readBlobResourceFile(filename,false);

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
        if (pReadBlob != nullptr)
        {
            delete pReadBlob;
        }
    }
    if (err == ERP_ERR_NOERROR)
    {
        static const char* filename = "rusaved/vausigKeyPairSaved.blob";
        ERPBlob* pReadBlob = readBlobResourceFile(filename,false);

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
        if (pReadBlob != nullptr)
        {
            delete pReadBlob;
        }
    }

    EXPECT_EQ(ERP_ERR_NOERROR, err);
}
TEST_F(ErpRUAttestationTestFixture, DISABLED_DeriveKeyTest)
{
    unsigned int err = ERP_ERR_NOERROR;

    std::unique_ptr<ERPBlob> savedTEEToken = std::unique_ptr<ERPBlob>(readBlobResourceFile("rusaved/staticTEETokenSaved.blob"));
    std::unique_ptr<ERPBlob> savedTaskDerivationKey = std::unique_ptr<ERPBlob>(readBlobResourceFile("rusaved/taskDerivationKeySaved.blob"));
    auto savedAKName = readERPResourceFile("rusaved/h80000002.bin");
    // 13. derive Task persistence Key for initial derivation
    unsigned char derivationData[] = "(Dummy Derivation Data) KVNR:Z123-45678";
    size_t derivationDataLength = strlen((const char*)derivationData) + 1;
    unsigned char usedDerivationData[MAX_BUFFER];
    size_t usedDerivationDataLength = 0;
    unsigned char initialDerivedKey[AES_256_LEN];
    if (err == 0)
    {
        err = teststep_deriveTaskPersistenceKey(
            ErpRUAttestationTestFixture::m_logonSession,
            reinterpret_cast<unsigned char*>(savedAKName.data()), // SHA_1_LEN...
            savedTEEToken.get(),
            savedTaskDerivationKey.get(),
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
                ErpRUAttestationTestFixture::m_logonSession,
                reinterpret_cast<unsigned char*>(savedAKName.data()), // SHA_1_LEN...
                savedTEEToken.get(),
                savedTaskDerivationKey.get(),
                usedDerivationDataLength,
                usedDerivationData,
                0, // 1 => Initial Derivation, 0 => subsequent Derivation. 
                // Output
                &usedDerivationDataLength,
                usedDerivationData, // MAX_BUFFER
                subsequentDerivedKey); // AES_256_LEN
        }
    }
    EXPECT_EQ(ERP_ERR_NOERROR, err);
}

TEST_F(ErpRUAttestationTestFixture, DISABLED_getVAUSIGPrivateKey)
{
    std::unique_ptr<ERPBlob> savedKeyPairBlob =
        std::unique_ptr<ERPBlob>(readBlobResourceFile("rusaved/vausigKeyPairSaved.blob"));
    ASSERT_NE(nullptr, savedKeyPairBlob.get());

    TwoBlobGetKeyInput vauSIG = { {0,0,{0}}, {0,0,{0}} };
    vauSIG.Key = *savedKeyPairBlob;
    // Take the TEEToken from a previous test run:
    auto teeToken = std::unique_ptr<ERPBlob>(readBlobResourceFile("rusaved/staticTEETokenSaved.blob"));
    ASSERT_NE(nullptr, teeToken);
    vauSIG.TEEToken = *teeToken;
    PrivateKeyOutput keyOut = ERP_GetVAUSIGPrivateKey(m_logonSession, vauSIG);
    ASSERT_EQ(ERP_ERR_NOERROR, keyOut.returnCode);

 /**
 // TO DO - set up check of expected output.
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
    std::unique_ptr<ERPBlob> savedKeyPairBlob =
        std::unique_ptr<ERPBlob>(readBlobResourceFile("rusaved/vausigKeyPairSaved.blob"));
    ASSERT_NE(nullptr, savedKeyPairBlob.get());

    GetVAUCSRInput vauCSR = { {0,0,{0}} ,0, {0} };
    vauCSR.KeyPair = *savedKeyPairBlob;
    // At the moment these candidate CSRs are from the ePA TU authn.
    auto candidateCSR = readERPResourceFile("candidateVAUSIG.csr");
    ASSERT_GT(candidateCSR.size(), 0);
    vauCSR.candidateCSRLength = candidateCSR.size();
    memcpy(&(vauCSR.candidateCSR[0]), candidateCSR.data(), candidateCSR.size());
    x509CSROutput keyOut = ERP_GenerateVAUSIGCSR(m_logonSession, vauCSR);
    ASSERT_EQ(ERP_ERR_NOERROR, keyOut.returnCode);

    // TO DO - set up check of expected output.
//    unsigned char expectedKey[] = { 0x30, 0x81, 0x95, 0x02, 0x01, 0x00, 0x30, 0x14, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
//        0xdf, 0xd6, 0x5f, 0xf9, 0x73, 0xef, 0x0f, 0x9e };
//    ASSERT_EQ(sizeof(expectedKey), keyOut.keyLength);
//    ASSERT_TRUE(0 == memcmp(&(keyOut.keyData[0]), &(expectedKey[0]), sizeof(expectedKey)));
    // TO DO check CSR Signature?
    writeERPResourceFile("rusaved/generatedVAUSIG.csr",
        std::vector<char>(keyOut.CSRData, keyOut.CSRData + keyOut.CSRDataLength));
}

// Cannot work without test data matching our ECIES KeyPair.
// This is really a DISABLED and FAIL
TEST_F(ErpRUAttestationTestFixture, DISABLED_doVAUECIES)
{
    std::unique_ptr<ERPBlob> savedKeyPairBlob =
        std::unique_ptr<ERPBlob>(readBlobResourceFile("rusaved/eciesKeyPairSaved.blob"));
    ASSERT_NE(nullptr, savedKeyPairBlob.get());

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
    unsigned char expectedKey[] = { 0xda, 0x7c, 0x96, 0x48, 0xf7, 0xab, 0xa4, 0x6d
        , 0x6f, 0x7b, 0x98, 0x5e, 0xf8, 0xa9, 0x4b, 0x02 };
    ASSERT_TRUE(0 == memcmp(&(keyOut.AESKey[0]), &(expectedKey[0]), 16));
}

TEST_F(ErpRUAttestationTestFixture, DISABLED_generateECIESCSR)
{
    std::unique_ptr<ERPBlob> savedKeyPairBlob =
        std::unique_ptr<ERPBlob>(readBlobResourceFile("rusaved/eciesKeyPairSaved.blob"));
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
        keyOut = ERP_GenerateECIESCSR(m_logonSession, eciesCSR);
        ASSERT_EQ(ERP_ERR_NOERROR, keyOut.returnCode);
    }

    // TO DO - set up check of expected output.
//    unsigned char expectedKey[] = { 0x30, 0x81, 0x95, 0x02, 0x01, 0x00, 0x30, 0x14, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
//        0xdf, 0xd6, 0x5f, 0xf9, 0x73, 0xef, 0x0f, 0x9e };
//    ASSERT_EQ(sizeof(expectedKey), keyOut.keyLength);
//    ASSERT_TRUE(0 == memcmp(&(keyOut.keyData[0]), &(expectedKey[0]), sizeof(expectedKey)));
    // TO DO check CSR Signature?
    writeERPResourceFile("rusaved/generatedECIES.csr",
        std::vector<char>(keyOut.CSRData, keyOut.CSRData + keyOut.CSRDataLength));
}

TEST_F(ErpRUAttestationTestFixture, DISABLED_UnwrapHashKey)
{
    std::unique_ptr<ERPBlob> savedKeyPairBlob =
        std::unique_ptr<ERPBlob>(readBlobResourceFile("rusaved/hashKeySaved.blob"));
    ASSERT_NE(nullptr, savedKeyPairBlob.get());

    TwoBlobGetKeyInput get = { {0,0,{0}}, {0,0,{0}} };
    get.Key = *savedKeyPairBlob;
    // Take the TEEToken from a previous test run:
    auto teeToken = std::unique_ptr<ERPBlob>(readBlobResourceFile("rusaved/staticTEETokenSaved.blob"));
    ASSERT_NE(nullptr, teeToken.get());
    get.TEEToken = *teeToken;
    AES256KeyOutput keyOut = ERP_UnwrapHashKey(m_logonSession, get);
    EXPECT_EQ(ERP_ERR_NOERROR, keyOut.returnCode);
/**
unsigned char expectedKey[] = {
        0xa7, 0xab, 0xd1, 0x94, 0xe5, 0x0b, 0x14, 0x0c, 0x9b, 0xe7, 0xfe, 0xe7, 0xbb, 0x39, 0x07, 0xd9
        ,0xbe, 0xd8, 0xda, 0xdc, 0x2f, 0xc8, 0x3f, 0x9c, 0xaa, 0x41, 0x05, 0xa8, 0xc1, 0x1a, 0xc2, 0xf8
    };
    ASSERT_TRUE(0 == memcmp(&(keyOut.Key[0]), &(expectedKey[0]), 32));
**/
    writeERPResourceFile("rusaved/ERPHashKey.bin",
        std::vector<char>(keyOut.Key, keyOut.Key + AES_256_LEN));
}