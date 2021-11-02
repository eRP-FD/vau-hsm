#include "ERP_Client.h"
#include "ERP_SFC.h"
#include "ERP_Error.h"
#include "ERP_TestsBase.h"
#include "ERP_TestUtils.h"
#include <gtest/gtest.h>

class ErpPermissionTestsFixture : public ErpBaseTestsFixture {

public:

    // this blob key generation is only used for the create and delete calls.
    static const unsigned int generation = 0x55;

    // this blob key generation is used for the tests with the pre computed blobs
    static const unsigned int generationSaved = 0x42;

    static std::unique_ptr<ERPBlob> savedTrustedRoot;
    static std::unique_ptr<ERPBlob> savedTrustedEK;
    static std::unique_ptr<ERPBlob> savedTrustedAK;
    static std::unique_ptr<ERPBlob> savedAKChallengeBlob;

    static std::vector<char> savedAKName;
    static std::vector<char> savedAKPub;

    std::unique_ptr<ERPBlob> pTEEToken;

    static void SetUpTestSuite()
    {
        savedTrustedRoot = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/trustedRootSaved.blob"));
        savedTrustedEK = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/trustedEKSaved.blob"));
        savedTrustedAK = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/trustedAkSaved.blob"));
        savedAKChallengeBlob = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/AKChallengeSaved.blob"));

        savedAKName = readERPResourceFile("saved/h80000002.bin");
        savedAKPub = readERPResourceFile("saved/AKPub.bin");

    }

    void SetUp() override
    {
        ErpBaseTestsFixture::SetUp();

        unsigned int err = teststep_DeleteBlobKey(m_logonSession, generation);
        ASSERT_TRUE(err == ERP_ERR_NOERROR || err == ERP_ERR_UNKNOWN_BLOB_GENERATION);

        ASSERT_EQ(ERP_ERR_NOERROR, teststep_GenerateBlobKey(m_logonSession, generation));

        // Create a token for the test
        auto attestQuote = readERPResourceFile("saved/AttestationQuoteSaved.bin");
        auto attestQuoteSignature = readERPResourceFile("saved/AttestationQuoteSigSaved.bin");
        auto enrollQuote = readERPResourceFile("saved/EnrollmentQuoteSaved.bin");
        auto enrollQuoteSignature = readERPResourceFile("saved/EnrollmentQuoteSigSaved.bin");

        std::unique_ptr<ERPBlob> savedEnrollmentNONCE = std::unique_ptr<ERPBlob>(
            readBlobResourceFile("saved/EnrollmentQuoteNONCESaved.blob"));
        std::unique_ptr<ERPBlob> savedAttestationNONCE = std::unique_ptr<ERPBlob>(
            readBlobResourceFile("saved/AttestationQuoteNONCESaved.blob"));
        std::unique_ptr<ERPBlob> pTrustedQuote = std::unique_ptr<ERPBlob>(
                readBlobResourceFile("saved/trustedQuoteSaved.blob"));

        pTEEToken = getEmptyBlob(generationSaved);
        err = teststep_getTEEToken(
                m_logonSession,
                savedTrustedAK.get(),
                pTrustedQuote.get(),
                savedAttestationNONCE.get(),
                reinterpret_cast<unsigned char *>(savedAKName.data()),
                attestQuote.size(), reinterpret_cast<unsigned char *>(attestQuote.data()),
                attestQuoteSignature.size(), reinterpret_cast<unsigned char *>(attestQuoteSignature.data()),
                pTEEToken.get());

        ASSERT_EQ(ERP_ERR_NOERROR, err);
    }

};

std::unique_ptr<ERPBlob> ErpPermissionTestsFixture::savedTrustedRoot = std::make_unique<ERPBlob>();
std::unique_ptr<ERPBlob> ErpPermissionTestsFixture::savedTrustedEK = std::make_unique<ERPBlob>();
std::unique_ptr<ERPBlob> ErpPermissionTestsFixture::savedTrustedAK = std::make_unique<ERPBlob>();
std::unique_ptr<ERPBlob> ErpPermissionTestsFixture::savedAKChallengeBlob = std::make_unique<ERPBlob>();
std::vector<char> ErpPermissionTestsFixture::savedAKName;
std::vector<char> ErpPermissionTestsFixture::savedAKPub;


TEST_F(ErpPermissionTestsFixture, PermissionTrustTPMMfr)
{
    auto pNewTrustedRoot = getEmptyBlob(generationSaved);
    auto MfrRootCert = readERPResourceFile("cacertecc.crt");


    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        auto err = teststep_TrustTPMMfr(m_logonSession, generationSaved, pNewTrustedRoot.get(), MfrRootCert);
        EXPECT_EQ(expErr, err);
        EXPECT_EQ(pNewTrustedRoot->BlobGeneration, savedTrustedRoot->BlobGeneration);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Setup}, ERP_ERR_NOERROR);
    testFn({users::Set1}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1, users::Set2}, ERP_ERR_NOERROR);
    testFn({users::Update}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working, users::Setup}, ERP_ERR_NOERROR);

}

//ERP_EnrollTPMEK
TEST_F(ErpPermissionTestsFixture, PermissionEnrollTPMEK)
{
    // we need some dummy data. We just test for permissions
    auto pEKCert = readERPResourceFile("EKCertECC.crt");

    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        auto pNewTrustedEK = getEmptyBlob(generationSaved);
        auto err = teststep_EnrollTPMEK(
                m_logonSession,
                generationSaved,
                ErpPermissionTestsFixture::savedTrustedRoot.get(),
                pNewTrustedEK.get(),
                pEKCert.size(),
                reinterpret_cast<unsigned char *>(pEKCert.data()));
        EXPECT_EQ(expErr, err);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Setup}, ERP_ERR_NOERROR);
    testFn({users::Set1}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1, users::Set2}, ERP_ERR_NOERROR);
    testFn({users::Update}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working, users::Setup}, ERP_ERR_NOERROR);

}

//ERP_GetAKChallenge
TEST_F(ErpPermissionTestsFixture, PermissionGetAKChallenge)
{
    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        auto pCredChallengeBlob = getEmptyBlob(0);

        unsigned char encCredentialData[MAX_BUFFER] = "";
        size_t encCredentialLength = 0;
        unsigned char secretData[MAX_BUFFER] = "";
        size_t secretLength = 0;


        auto err = teststep_GetAKChallenge(
                m_logonSession,
                generation,
                savedTrustedEK.get(),
                reinterpret_cast<unsigned char *>(savedAKName.data()), // SHA_1_LEN...
                savedAKPub.size() - 2, // file includes two leading length bytes that we don't want.
                reinterpret_cast<unsigned char *>((savedAKPub.data() + 2)),
                pCredChallengeBlob.get(),
                &encCredentialLength,
                &(encCredentialData[0]),
                &secretLength,
                &(secretData[0]));

        EXPECT_EQ(expErr, err);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Setup}, ERP_ERR_NOERROR);
    testFn({users::Set1}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1, users::Set2}, ERP_ERR_NOERROR);
    testFn({users::Update}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working, users::Setup}, ERP_ERR_NOERROR);
}

//ERP_EnrollTPMAK
TEST_F(ErpPermissionTestsFixture, PermissionEnrollTPMAK)
{
    auto savedDecCred = readERPResourceFile("saved/credDecHSMSaved.bin");

    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        auto pTrustedAK = getEmptyBlob(generationSaved);

        auto err = teststep_EnrollAK(
                m_logonSession,
                generationSaved,
                savedTrustedEK.get(),
                savedAKChallengeBlob.get(),
                reinterpret_cast<unsigned char *>(savedAKName.data()),
                savedAKPub.size() - 2,
                reinterpret_cast<unsigned char *>(savedAKPub.data() + 2),
                savedDecCred.size(),
                (unsigned char *) savedDecCred.data(),
                pTrustedAK.get());

        EXPECT_EQ(expErr, err);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Setup}, ERP_ERR_NOERROR);
    testFn({users::Set1}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1, users::Set2}, ERP_ERR_NOERROR);
    testFn({users::Update}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working, users::Setup}, ERP_ERR_NOERROR);
}

//ERP_EnrollEnclave
TEST_F(ErpPermissionTestsFixture, PermissionEnrollEnclave)
{
    // Create a token for the test
    auto quote = readERPResourceFile("saved/EnrollmentQuoteSaved.bin");
    auto quoteSignature = readERPResourceFile("saved/EnrollmentQuoteSigSaved.bin");

    auto nonceForQuote = readBlobResourceFile("saved/EnrollmentQuoteNONCESaved.blob");
    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {

        logon(setOfUsers);

        EnrollEnclaveInput in = {
                generationSaved,
                "\0",
                *savedTrustedAK,
                *nonceForQuote,
                0,
                "",
                0,
                ""
        };

        memcpy(&(in.AKName[0]), savedAKName.data(), TPM_NAME_LEN);

        in.quoteLength = quote.size();
        memcpy(&(in.quoteData[0]), quote.data(), quote.size());

        in.signatureLength = quoteSignature.size();
        memcpy(&(in.signatureData[0]), quoteSignature.data(), quoteSignature.size());


        SingleBlobOutput out = ERP_EnrollEnclave(m_logonSession, in);

        EXPECT_EQ(expErr, out.returnCode);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Setup}, ERP_ERR_NOERROR);
    testFn({users::Set1}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1, users::Set2}, ERP_ERR_NOERROR);
    testFn({users::Update}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working, users::Setup}, ERP_ERR_NOERROR);

}

//ERP_GenerateECIESKeyPair
TEST_F(ErpPermissionTestsFixture, PermissionGenerateECIESKeyPair)
{
    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        UIntInput in = {
                generation
        };
        auto out = ERP_GenerateECIESKeyPair(m_logonSession, in);
        EXPECT_EQ(expErr, out.returnCode);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Setup}, ERP_ERR_NOERROR);
    testFn({users::Set1}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1, users::Set2}, ERP_ERR_NOERROR);
    testFn({users::Update}, ERP_ERR_NOERROR);
    testFn({users::Working}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working, users::Setup}, ERP_ERR_NOERROR);

}

//ERP_GenerateECIESCSR
TEST_F(ErpPermissionTestsFixture, PermissionGenerateECIESCSR)
{
    UIntInput in = {
            generationSaved
    };

    SingleBlobOutput outKP = ERP_GenerateECIESKeyPair(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, outKP.returnCode);

    auto savedCSR = readERPResourceFile("candidateECIES.csr");

    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        GetVAUCSRInput inCsr = {
                outKP.BlobOut,
                0,
                "\0"
        };

        inCsr.candidateCSRLength = savedCSR.size();
        memcpy(inCsr.candidateCSR, savedCSR.data(), savedCSR.size());

        auto out = ERP_GenerateECIESCSR(m_logonSession, inCsr);

        EXPECT_EQ(expErr, out.returnCode);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Setup}, ERP_ERR_NOERROR);
    testFn({users::Set1}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1, users::Set2}, ERP_ERR_NOERROR);
    testFn({users::Update}, ERP_ERR_NOERROR);
    testFn({users::Working}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working, users::Setup}, ERP_ERR_NOERROR);
}

//ERP_DoVAUECIES128
TEST_F(ErpPermissionTestsFixture, PermissionDoVAUECIES128)
{
    std::unique_ptr<ERPBlob> savedKeyPairBlob = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/ECIESKeyPairSaved.blob"));
    auto clientPub = readERPResourceFile("saved/clientECIESPub.bin");

    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        DoVAUECIESInput in = {
                *pTEEToken,
                *savedKeyPairBlob,
                0, {0}
        };
        ASSERT_GT(clientPub.size(),0);
        memcpy(&(in.clientPublicKeyData[0]),clientPub.data(),clientPub.size());
        in.clientPublicKeyLength = clientPub.size();

        AES128KeyOutput out = ERP_DoVAUECIES128(m_logonSession, in);
        EXPECT_EQ(expErr, out.returnCode);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Setup}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1, users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Update}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working}, ERP_ERR_NOERROR);
    testFn({users::Working, users::Setup}, ERP_ERR_NOERROR);
}

//ERP_GenerateVAUSIGKeyPair
TEST_F(ErpPermissionTestsFixture, PermissionGenerateVAUSIGKeyPair)
{
    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        UIntInput in = {
                generation
        };
        auto out = ERP_GenerateVAUSIGKeyPair(m_logonSession, in);
        EXPECT_EQ(expErr, out.returnCode);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Setup}, ERP_ERR_NOERROR);
    testFn({users::Set1}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1, users::Set2}, ERP_ERR_NOERROR);
    testFn({users::Update}, ERP_ERR_NOERROR);
    testFn({users::Working}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working, users::Setup}, ERP_ERR_NOERROR);
}

//ERP_GenerateVAUSIGCSR
TEST_F(ErpPermissionTestsFixture, PermissionGenerateVAUSIGCSR)
{
    UIntInput in = {
            generationSaved
    };

    SingleBlobOutput outKP = ERP_GenerateVAUSIGKeyPair(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, outKP.returnCode);

    auto savedCSR = readERPResourceFile("candidateVAUSIG.csr");

    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        GetVAUCSRInput inCsr = {
                outKP.BlobOut,
                0,
                "\0"
        };

        inCsr.candidateCSRLength = savedCSR.size();
        memcpy(inCsr.candidateCSR, savedCSR.data(), savedCSR.size());

        auto out = ERP_GenerateVAUSIGCSR(m_logonSession, inCsr);

        EXPECT_EQ(expErr, out.returnCode);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Setup}, ERP_ERR_NOERROR);
    testFn({users::Set1}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1, users::Set2}, ERP_ERR_NOERROR);
    testFn({users::Update}, ERP_ERR_NOERROR);
    testFn({users::Working}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working, users::Setup}, ERP_ERR_NOERROR);

}

//ERP_GetVAUSIGPrivateKey
TEST_F(ErpPermissionTestsFixture, GetVAUSIGPrivateKey)
{
    UIntInput in = {
            generationSaved
    };

    SingleBlobOutput outKP = ERP_GenerateVAUSIGKeyPair(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, outKP.returnCode);

    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {

        logon(setOfUsers);

        TwoBlobGetKeyInput twoBlobsIn = {
                *(pTEEToken.get()),
                outKP.BlobOut
        };
        auto out = ERP_GetVAUSIGPrivateKey(m_logonSession, twoBlobsIn);
        EXPECT_EQ(expErr, out.returnCode);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Setup}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1, users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Update}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working}, ERP_ERR_NOERROR);
    testFn({users::Working, users::Setup}, ERP_ERR_NOERROR);
}


//ERP_UnwrapHashKey
TEST_F(ErpPermissionTestsFixture, UnwrapHashKey)
{
    UIntInput in = {
            generationSaved
    };

    SingleBlobOutput outK = ERP_GenerateHashKey(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, outK.returnCode);

    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {

        logon(setOfUsers);

        TwoBlobGetKeyInput twoBlobsIn = {
                *(pTEEToken.get()),
                outK.BlobOut
        };
        auto out = ERP_UnwrapHashKey(m_logonSession, twoBlobsIn);
        EXPECT_EQ(expErr, out.returnCode);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Setup}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1, users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Update}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working}, ERP_ERR_NOERROR);
    testFn({users::Working, users::Setup}, ERP_ERR_NOERROR);
}


//ERP_DeriveTaskKey
TEST_F(ErpPermissionTestsFixture, PermissionDeriveTaskKey)
{
    auto pDerivationKeyBlob = getEmptyBlob(generationSaved);
    auto err = teststep_GenerateDerivationKey(m_logonSession, generationSaved, pDerivationKeyBlob.get());
    ASSERT_EQ(ERP_ERR_NOERROR, err);

    auto teeToken = pTEEToken.get();

    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        unsigned char derivationData[] = "(Dummy Derivation Data) KVNR:Z123-45678";
        size_t derivationDataLength = strlen((const char *) derivationData) + 1;
        unsigned char usedDerivationData[MAX_BUFFER];
        size_t usedDerivationDataLength = 0;
        unsigned char initialDerivedKey[AES_256_LEN];

        err = teststep_deriveTaskPersistenceKey(
                m_logonSession,
                reinterpret_cast<unsigned char *>(savedAKName.data()), // SHA_1_LEN...
                teeToken,
                pDerivationKeyBlob.get(),
                derivationDataLength,
                derivationData,
                1, // 1 => Initial Derivation, 0 => subsequent Derivation.
                // Output
                &usedDerivationDataLength,
                usedDerivationData, // MAX_BUFFER
                initialDerivedKey); // AES_256_LEN

        EXPECT_EQ(expErr, err);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Setup}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1, users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Update}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working}, ERP_ERR_NOERROR);

}

//ERP_DeriveAuditKey
TEST_F(ErpPermissionTestsFixture, PermissionDeriveAuditKey)
{
    auto pDerivationKeyBlob = getEmptyBlob(generationSaved);
    auto err = teststep_GenerateDerivationKey(m_logonSession, generationSaved, pDerivationKeyBlob.get());
    ASSERT_EQ(ERP_ERR_NOERROR, err);

    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        unsigned char derivationData[] = "(Dummy Derivation Data) KVNR:Z123-45678";
        size_t derivationDataLength = strlen((const char *) derivationData) + 1;
        unsigned char usedDerivationData[MAX_BUFFER];
        size_t usedDerivationDataLength = 0;
        unsigned char initialDerivedKey[AES_256_LEN];

        err = teststep_deriveAuditKey(
                m_logonSession,
                reinterpret_cast<unsigned char *>(savedAKName.data()), // SHA_1_LEN...
                pTEEToken.get(),
                pDerivationKeyBlob.get(),
                derivationDataLength,
                derivationData,
                1, // 1 => Initial Derivation, 0 => subsequent Derivation.
                // Output
                &usedDerivationDataLength,
                usedDerivationData, // MAX_BUFFER
                initialDerivedKey); // AES_256_LEN

        EXPECT_EQ(expErr, err);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Setup}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1, users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Update}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working}, ERP_ERR_NOERROR);
    testFn({users::Working, users::Setup}, ERP_ERR_NOERROR);

}

//ERP_DeriveCommsKey
TEST_F(ErpPermissionTestsFixture, PermissionDeriveCommsKey)
{
    auto pDerivationKeyBlob = getEmptyBlob(generationSaved);
    auto err = teststep_GenerateDerivationKey(m_logonSession, generationSaved, pDerivationKeyBlob.get());
    ASSERT_EQ(ERP_ERR_NOERROR, err);

    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        unsigned char derivationData[] = "(Dummy Derivation Data) KVNR:Z123-45678";
        size_t derivationDataLength = strlen((const char *) derivationData) + 1;
        unsigned char usedDerivationData[MAX_BUFFER];
        size_t usedDerivationDataLength = 0;
        unsigned char initialDerivedKey[AES_256_LEN];

        err = teststep_deriveCommsKey(
                m_logonSession,
                reinterpret_cast<unsigned char *>(savedAKName.data()), // SHA_1_LEN...
                pTEEToken.get(),
                pDerivationKeyBlob.get(),
                derivationDataLength,
                derivationData,
                1, // 1 => Initial Derivation, 0 => subsequent Derivation.
                // Output
                &usedDerivationDataLength,
                usedDerivationData, // MAX_BUFFER
                initialDerivedKey); // AES_256_LEN

        EXPECT_EQ(expErr, err);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Setup}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1, users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Update}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working}, ERP_ERR_NOERROR);
    testFn({users::Working, users::Setup}, ERP_ERR_NOERROR);
}


//ERP_GetTEEToken
TEST_F(ErpPermissionTestsFixture, PermissionGetTEEToken)
{
    auto quote = readERPResourceFile("saved/AttestationQuoteSaved.bin");
    auto quoteSignature = readERPResourceFile("saved/AttestationQuoteSigSaved.bin");

    std::unique_ptr<ERPBlob> savedNONCE = std::unique_ptr<ERPBlob>(
        readBlobResourceFile("saved/AttestationQuoteNONCESaved.blob"));
    std::unique_ptr<ERPBlob> pTrustedQuote = std::unique_ptr<ERPBlob>(
            readBlobResourceFile("saved/trustedQuoteSaved.blob"));

    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {

        logon(setOfUsers);

        auto pLocalTEEToken = getEmptyBlob(generationSaved);
        unsigned int err = teststep_getTEEToken(
                m_logonSession,
                savedTrustedAK.get(),
                pTrustedQuote.get(),
                savedNONCE.get(),
                reinterpret_cast<unsigned char *>(savedAKName.data()),
                quote.size(), reinterpret_cast<unsigned char *>(quote.data()),
                quoteSignature.size(), reinterpret_cast<unsigned char *>(quoteSignature.data()),
                pLocalTEEToken.get());
        EXPECT_EQ(expErr, err);

    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Setup}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1, users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Update}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working}, ERP_ERR_NOERROR);
    testFn({users::Working, users::Setup}, ERP_ERR_NOERROR);
}

//ERP_GetECPublicKey
TEST_F(ErpPermissionTestsFixture, PermissionGetECPublicKey)
{
    UIntInput in = {
            generationSaved
    };

    SingleBlobOutput outKP = ERP_GenerateVAUSIGKeyPair(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, outKP.returnCode);

    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {

        logon(setOfUsers);

        SingleBlobInput blobIn = {
                outKP.BlobOut
        };
        auto out = ERP_GetECPublicKey(m_logonSession, blobIn);
        EXPECT_EQ(expErr, out.returnCode);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Setup}, ERP_ERR_NOERROR);
    testFn({users::Set1}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1, users::Set2}, ERP_ERR_NOERROR);
    testFn({users::Update}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working, users::Setup}, ERP_ERR_NOERROR);
}

//ERP_GenerateBlobKey
TEST_F(ErpPermissionTestsFixture, PermissionGenerateBlobKey)
{
    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        auto err = teststep_GenerateBlobKey(m_logonSession, 0);
        EXPECT_EQ(expErr, err);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Setup}, ERP_ERR_NOERROR);
    testFn({users::Set1}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1, users::Set2}, ERP_ERR_NOERROR);
    testFn({users::Update}, ERP_ERR_NOERROR);
    testFn({users::Working}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working, users::Setup}, ERP_ERR_NOERROR);
}

//ERP_DeleteBlobKey
TEST_F(ErpPermissionTestsFixture, PermissionDeleteBlobKey)
{
    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {

        logonSetup();
        teststep_GenerateBlobKey(m_logonSession, generation);

        logon(setOfUsers);

        auto err = teststep_DeleteBlobKey(m_logonSession, generation);
        EXPECT_EQ(expErr, err);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Setup}, ERP_ERR_NOERROR);
    testFn({users::Set1}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1, users::Set2}, ERP_ERR_NOERROR);
    testFn({users::Update}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working, users::Setup}, ERP_ERR_NOERROR);
}


//ERP_GenerateHashKey
TEST_F(ErpPermissionTestsFixture, PermissionGenerateHashKey)
{
    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        UIntInput genKeyIn = {0};
        auto output = ERP_GenerateHashKey(m_logonSession, genKeyIn);

        EXPECT_EQ(expErr, output.returnCode);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Setup}, ERP_ERR_NOERROR);
    testFn({users::Set1}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1, users::Set2}, ERP_ERR_NOERROR);
    testFn({users::Update}, ERP_ERR_NOERROR);
    testFn({users::Working}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working, users::Setup}, ERP_ERR_NOERROR);
}

//ERP_GenerateDerivationKey
TEST_F(ErpPermissionTestsFixture, PermissionGenerateDerivationKey)
{
    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        auto keyBlob = getEmptyBlob(generation);
        auto err = teststep_GenerateDerivationKey(m_logonSession, generation, keyBlob.get());
        EXPECT_EQ(expErr, err);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Setup}, ERP_ERR_NOERROR);
    testFn({users::Set1}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1, users::Set2}, ERP_ERR_NOERROR);
    testFn({users::Update}, ERP_ERR_NOERROR);
    testFn({users::Working}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working, users::Setup}, ERP_ERR_NOERROR);
}



//ERP_ListLoadedBlobKeys
TEST_F(ErpPermissionTestsFixture, PermissionListLoadedBlobKeys)
{
    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        auto err = teststep_ListLoadedBlobKeys(m_logonSession);
        EXPECT_EQ(expErr, err);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Setup}, ERP_ERR_NOERROR);
    testFn({users::Set1}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1, users::Set2}, ERP_ERR_NOERROR);
    testFn({users::Update}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working}, ERP_ERR_NOERROR);
    testFn({users::Working, users::Setup}, ERP_ERR_NOERROR);
}

// Test to check Permissions for GenerateNONCE command.
TEST_F(ErpPermissionTestsFixture, PermissionGenerateNONCE)
{
    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        auto err = teststep_GenerateNONCE(m_logonSession, 0);
        EXPECT_EQ(expErr, err);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Setup}, ERP_ERR_NOERROR);
    testFn({users::Set1}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1, users::Set2}, ERP_ERR_NOERROR);
    testFn({users::Update}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working}, ERP_ERR_NOERROR);
    testFn({users::Working, users::Setup}, ERP_ERR_NOERROR);

}

//ERP_GetRNDBytes
TEST_F(ErpPermissionTestsFixture, PermissionGetRNDBytes)
{
    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        UIntInput desiredBytes = {32};

        auto rndOut = ERP_GetRNDBytes(m_logonSession, desiredBytes);
        EXPECT_EQ(expErr, rndOut.returnCode);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Setup}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Set1, users::Set2}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Update}, ERP_ERR_PERMISSION_DENIED);
    testFn({users::Working}, ERP_ERR_NOERROR);
    testFn({users::Working, users::Setup}, ERP_ERR_NOERROR);
}
