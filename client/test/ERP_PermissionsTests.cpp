/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021, 2024
 * (C) Copyright IBM Corp. 2021, 2024
 *
 * non-exclusively licensed to gematik GmbH
 **************************************************************************************************/

#include "ERP_Client.h"
#include "ERP_Error.h"
#include "ERP_TestUtils.h"
#include "ERP_TestsBase.h"

#include <gtest/gtest.h>

class ErpPermissionTestsFixture : public ErpBaseTestsFixture {

public:

    // this blob key generation is only used for the create and delete calls.
    static const unsigned int generation = 0x55;

    void SetUp() override
    {
        ErpBaseTestsFixture::SetUp();

        unsigned int err = teststep_DeleteBlobKey(m_logonSession, generation);
        ASSERT_TRUE(err == ERP_ERR_NOERROR || err == ERP_ERR_UNKNOWN_BLOB_GENERATION);
        err = teststep_GenerateBlobKey(m_logonSession, generation);
        ASSERT_EQ(ERP_ERR_NOERROR, err);
    }

};

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
                pEKCert.data());
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
                savedAKName.data(), // SHA_1_LEN...
                savedAKPub.size() - 2, // file includes two leading length bytes that we don't want.
                savedAKPub.data() + 2,
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
    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        auto pTrustedAK = getEmptyBlob(generationSaved);

        auto err = teststep_EnrollAK(
                m_logonSession,
                generationSaved,
                savedTrustedEK.get(),
                savedAKChallenge1Blob.get(),
                savedAKName.data(),
                savedAKPub.size() - 2,
                savedAKPub.data() + 2,
                savedDecCred.size(),
                savedDecCred.data(),
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
        memcpy(&(inCsr.candidateCSR[0]), savedCSR.data(), savedCSR.size());

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
    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        DoVAUECIESInput in = {
                *teeToken,
                *savedECIESKeyPairBlob,
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
        memcpy(&(inCsr.candidateCSR[0]), savedCSR.data(), savedCSR.size());

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
TEST_F(ErpPermissionTestsFixture, PermissionGetVAUSIGPrivateKey)
{
    UIntInput in = {
            generationSaved
    };

    SingleBlobOutput outKP = ERP_GenerateVAUSIGKeyPair(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, outKP.returnCode);

    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {

        logon(setOfUsers);

        TwoBlobGetKeyInput twoBlobsIn = {
                *(teeToken.get()),
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

//ERP_GenerateAUTCSR
TEST_F(ErpPermissionTestsFixture, PermissionGenerateAUTCSR)
{
    UIntInput in = {
        generationSaved
    };

    SingleBlobOutput outKP = ERP_GenerateVAUSIGKeyPair(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, outKP.returnCode);

    auto savedCSR = readERPResourceFile("candidateAUT.csr");

    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        GetVAUCSRInput inCsr = {
                outKP.BlobOut,
                0,
                "\0"
        };

        inCsr.candidateCSRLength = savedCSR.size();
        memcpy(&(inCsr.candidateCSR[0]), savedCSR.data(), savedCSR.size());

        auto out = ERP_GenerateAUTCSR(m_logonSession, inCsr);

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

//ERP_GenerateAUTKeyPair
TEST_F(ErpPermissionTestsFixture, PermissionGenerateAUTKeyPair)
{
    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        UIntInput in = {
                generation
        };
        auto out = ERP_GenerateAUTKeyPair(m_logonSession, in);
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

//ERP_SignVAUAUTToken
TEST_F(ErpPermissionTestsFixture, PermissionSignVAUAUTToken)
{
    AutSignatureInput in = {
        *(teeToken.get()),
        *savedVAUAUTKeyPairBlob,
        0,
        ""
    };
    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {
        logon(setOfUsers);
        auto out = ERP_SignVAUAUTToken(m_logonSession, in);
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
TEST_F(ErpPermissionTestsFixture, PermissionUnwrapHashKey)
{
    UIntInput in = {
            generationSaved
    };

    SingleBlobOutput outK = ERP_GenerateHashKey(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, outK.returnCode);

    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {

        logon(setOfUsers);

        TwoBlobGetKeyInput twoBlobsIn = {
                *(teeToken.get()),
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

//ERP_UnwrapPseudonameKey
TEST_F(ErpPermissionTestsFixture, PermissionUnwrapPseudonameKey)
{
    UIntInput in = {
            generationSaved
    };

    SingleBlobOutput outK = ERP_GeneratePseudonameKey(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, outK.returnCode);

    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users>& setOfUsers, unsigned int expErr) {

        logon(setOfUsers);

        TwoBlobGetKeyInput twoBlobsIn = {
                *(teeToken.get()),
                outK.BlobOut
        };
        auto out = ERP_UnwrapPseudonameKey(m_logonSession, twoBlobsIn);
        EXPECT_EQ(expErr, out.returnCode);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Setup }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Set1 }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Set2 }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Set1, users::Set2 }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Update }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Working }, ERP_ERR_NOERROR);
    testFn({ users::Working, users::Setup }, ERP_ERR_NOERROR);
}

//ERP_DeriveTaskKey
TEST_F(ErpPermissionTestsFixture, PermissionDeriveTaskKey)
{
    auto pDerivationKeyBlob = getEmptyBlob(generationSaved);
    auto err = teststep_GenerateDerivationKey(m_logonSession, generationSaved, pDerivationKeyBlob.get());
    ASSERT_EQ(ERP_ERR_NOERROR, err);

    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        auto derivationData = asciiToBuffer("(Dummy Derivation Data) KVNR:Z123-45678");
        unsigned char usedDerivationData[MAX_BUFFER];
        size_t usedDerivationDataLength = 0;
        unsigned char initialDerivedKey[AES_256_LEN];

        err = teststep_deriveTaskPersistenceKey(
                m_logonSession,
                savedAKName.data(), // SHA_1_LEN...
                ErpBaseTestsFixture::teeToken.get(),
                pDerivationKeyBlob.get(),
                derivationData.size(),
                derivationData.data(),
                1, // 1 => Initial Derivation, 0 => subsequent Derivation.
                // Output
                &usedDerivationDataLength,
                &(usedDerivationData[0]), // MAX_BUFFER
                &(initialDerivedKey[0])); // AES_256_LEN

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

        auto derivationData = asciiToBuffer("(Dummy Derivation Data) KVNR:Z123-45678");
        unsigned char usedDerivationData[MAX_BUFFER];
        size_t usedDerivationDataLength = 0;
        unsigned char initialDerivedKey[AES_256_LEN];

        err = teststep_deriveAuditKey(
                m_logonSession,
                savedAKName.data(), // SHA_1_LEN...
                ErpBaseTestsFixture::teeToken.get(),
                pDerivationKeyBlob.get(),
                derivationData.size(),
                derivationData.data(),
                1, // 1 => Initial Derivation, 0 => subsequent Derivation.
                // Output
                &usedDerivationDataLength,
                &(usedDerivationData[0]), // MAX_BUFFER
                &(initialDerivedKey[0])); // AES_256_LEN

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

        auto derivationData = asciiToBuffer("(Dummy Derivation Data) KVNR:Z123-45678");
        unsigned char usedDerivationData[MAX_BUFFER];
        size_t usedDerivationDataLength = 0;
        unsigned char initialDerivedKey[AES_256_LEN];

        err = teststep_deriveCommsKey(
                m_logonSession,
                savedAKName.data(), // SHA_1_LEN...
                ErpBaseTestsFixture::teeToken.get(),
                pDerivationKeyBlob.get(),
                derivationData.size(),
                derivationData.data(),
                1, // 1 => Initial Derivation, 0 => subsequent Derivation.
                // Output
                &usedDerivationDataLength,
                &(usedDerivationData[0]), // MAX_BUFFER
                &(initialDerivedKey[0])); // AES_256_LEN

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

//ERP_DeriveChargeItemKey
TEST_F(ErpPermissionTestsFixture, PermissionDeriveChargeItemKey)
{
    auto pDerivationKeyBlob = getEmptyBlob(generationSaved);
    auto err = teststep_GenerateDerivationKey(m_logonSession, generationSaved, pDerivationKeyBlob.get());
    ASSERT_EQ(ERP_ERR_NOERROR, err);

    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users>& setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        auto derivationData = asciiToBuffer("(Dummy Derivation Data) KVNR:Z123-45678");
        unsigned char usedDerivationData[MAX_BUFFER];
        size_t usedDerivationDataLength = 0;
        unsigned char initialDerivedKey[AES_256_LEN];

        err = teststep_deriveChargeItemKey(
            m_logonSession,
            savedAKName.data(), // SHA_1_LEN...
            ErpBaseTestsFixture::teeToken.get(),
            pDerivationKeyBlob.get(),
            derivationData.size(),
            derivationData.data(),
            1, // 1 => Initial Derivation, 0 => subsequent Derivation.
            // Output
            &usedDerivationDataLength,
            &(usedDerivationData[0]), // MAX_BUFFER
            &(initialDerivedKey[0])); // AES_256_LEN

        EXPECT_EQ(expErr, err);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Setup }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Set1 }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Set2 }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Set1, users::Set2 }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Update }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Working }, ERP_ERR_NOERROR);
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
                savedAKName.data(),
                quote.size(), quote.data(),
                quoteSignature.size(), quoteSignature.data(),
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
    testFn({users::Update}, ERP_ERR_NOERROR);
    testFn({users::Working}, ERP_ERR_NOERROR);
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


//ERP_GeneratePseudonameKey
TEST_F(ErpPermissionTestsFixture, PermissionGeneratePseudonameKey)
{
    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users>& setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        UIntInput genKeyIn = { 0 };
        auto output = ERP_GeneratePseudonameKey(m_logonSession, genKeyIn);

        EXPECT_EQ(expErr, output.returnCode);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Setup }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Set1 }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Set2 }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Set1, users::Set2 }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Setup, users::Update }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Update }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Working }, ERP_ERR_NOERROR);
    testFn({ users::Working, users::Setup }, ERP_ERR_NOERROR);
    testFn({ users::Working, users::Update }, ERP_ERR_NOERROR);
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
    testFn({users::Update}, ERP_ERR_NOERROR);
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

        UIntInput desiredBytes = {RND_256_LEN};

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

TEST_F(ErpPermissionTestsFixture, PermissionExportSingleBlobKey)
{
    unsigned int exportGeneration = TEST_BLOB_GEN;

    logonSetup();

    unsigned int err = teststep_DeleteBlobKey(m_logonSession, exportGeneration);
    ASSERT_TRUE(err == ERP_ERR_NOERROR || err == ERP_ERR_UNKNOWN_BLOB_GENERATION);

    err = teststep_GenerateBlobKey(m_logonSession, exportGeneration);
    ASSERT_EQ(ERP_ERR_NOERROR, err);

    logoff();

    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users>& setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        BUBlobOutput_t backupResult = { 0 , {0, {0}, {0},{0},{0},0,{0}} };
        UIntInput intIn;
        intIn.intValue = exportGeneration;

        // First backup an existing blob generation.
        backupResult = ERP_ExportSingleBlobKey(m_logonSession, intIn);
        EXPECT_EQ(expErr, backupResult.returnCode);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Setup }, ERP_ERR_NOERROR);
    testFn({ users::Set1 }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Set2 }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Set1, users::Set2 }, ERP_ERR_NOERROR);
    testFn({ users::Update }, ERP_ERR_NOERROR);
    testFn({ users::Working }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Working, users::Setup }, ERP_ERR_NOERROR);
}

TEST_F(ErpPermissionTestsFixture, PermissionImportSingleBlobKey)
{
    unsigned int exportGeneration = TEST_BLOB_GEN;

    logonSetup();

    unsigned int firstErr = teststep_DeleteBlobKey(m_logonSession, exportGeneration);
    ASSERT_TRUE(firstErr == ERP_ERR_NOERROR || firstErr == ERP_ERR_UNKNOWN_BLOB_GENERATION);

    firstErr = teststep_GenerateBlobKey(m_logonSession, exportGeneration);
    ASSERT_EQ(ERP_ERR_NOERROR, firstErr);

    BUBlobOutput_t backupResult = { 0 , {0, {0},{0},{0},{0},0,{0}} };
    UIntInput intIn;
    intIn.intValue = exportGeneration;

    // First backup an existing blob generation.
    backupResult = ERP_ExportSingleBlobKey(m_logonSession, intIn);

    logoff();

    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users>& setOfUsers, unsigned int expErr) {
        logonSetup();
        unsigned int err = teststep_DeleteBlobKey(m_logonSession, exportGeneration);
        ASSERT_TRUE(err == ERP_ERR_NOERROR || err == ERP_ERR_UNKNOWN_BLOB_GENERATION);

        logon(setOfUsers);

        EmptyOutput restoreResult = { 0 };
        BUBlobInput blobIn;
        blobIn.BUBlob = backupResult.BUBlob;

        // Another attempt to restore the blob generation should now work.
        restoreResult = ERP_ImportSingleBlobKey(m_logonSession, blobIn);
        EXPECT_EQ(expErr, restoreResult.returnCode);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Setup }, ERP_ERR_NOERROR);
    testFn({ users::Set1 }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Set2 }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Set1, users::Set2 }, ERP_ERR_NOERROR);
    testFn({ users::Update }, ERP_ERR_NOERROR);
    testFn({ users::Working }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Working, users::Setup }, ERP_ERR_NOERROR);
}

TEST_F(ErpPermissionTestsFixture, PermissionMigrateBlob)
{
    unsigned int exportGeneration = TEST_BLOB_GEN;  // 0x55

    logonSetup();

    unsigned int err = teststep_DeleteBlobKey(m_logonSession, exportGeneration);
    ASSERT_TRUE(err == ERP_ERR_NOERROR || err == ERP_ERR_UNKNOWN_BLOB_GENERATION);

    err = teststep_GenerateBlobKey(m_logonSession, exportGeneration);
    ASSERT_EQ(ERP_ERR_NOERROR, err);

    logoff();

    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users>& setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        SingleBlobOutput migrateResult = { 0 , {0, 0, {0}} };
        MigrateBlobInput_t migrateIn = { 0 , {0, 0, {0}} };
        migrateIn.NewBlobGeneration = exportGeneration;
        // Not really important which blob we take here...
        migrateIn.BlobIn = *(savedVAUSIGKeyPairBlob.get());

        // Another attempt to restore the blob generation should now work.
        migrateResult = ERP_MigrateBlob(m_logonSession, migrateIn);
        EXPECT_EQ(expErr, migrateResult.returnCode);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Setup }, ERP_ERR_NOERROR);
    testFn({ users::Set1 }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Set2 }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Set1, users::Set2 }, ERP_ERR_NOERROR);
    testFn({ users::Update }, ERP_ERR_NOERROR);
    testFn({ users::Working }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Working, users::Setup }, ERP_ERR_NOERROR);
}

TEST_F(ErpPermissionTestsFixture, PermissionGetBlobContentHash)
{
    unsigned int exportGeneration = TEST_BLOB_GEN; // 0x55;

    logonSetup();

    unsigned int err = teststep_DeleteBlobKey(m_logonSession, exportGeneration);
    ASSERT_TRUE(err == ERP_ERR_NOERROR || err == ERP_ERR_UNKNOWN_BLOB_GENERATION);

    err = teststep_GenerateBlobKey(m_logonSession, exportGeneration);
    ASSERT_EQ(ERP_ERR_NOERROR, err);

    logoff();

    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users>& setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        SHA256Output hashResult = { 0 , {0} };
        SingleBlobInput hashIn = { {0, 0, {0}} };
        // Not really important which blob we take here...
        hashIn.BlobIn = *(savedVAUSIGKeyPairBlob.get());

        // Another attempt to restore the blob generation should now work.
        hashResult = ERP_GetBlobContentHash(m_logonSession, hashIn);
        EXPECT_EQ(expErr, hashResult.returnCode);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Setup }, ERP_ERR_NOERROR);
    testFn({ users::Set1 }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Set2 }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Set1, users::Set2 }, ERP_ERR_NOERROR);
    testFn({ users::Update }, ERP_ERR_NOERROR);
    testFn({ users::Working }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Working, users::Setup }, ERP_ERR_NOERROR);
}

TEST_F(ErpPermissionTestsFixture, PermissionGetBlobContentHashWithToken)
{
    unsigned int exportGeneration = TEST_BLOB_GEN; // 0x55;

    logonSetup();

    unsigned int err = teststep_DeleteBlobKey(m_logonSession, exportGeneration);
    ASSERT_TRUE(err == ERP_ERR_NOERROR || err == ERP_ERR_UNKNOWN_BLOB_GENERATION);

    err = teststep_GenerateBlobKey(m_logonSession, exportGeneration);
    ASSERT_EQ(ERP_ERR_NOERROR, err);

    logoff();

    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users>& setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        SHA256Output hashResult = { 0 , {0} };
        TwoBlobGetKeyInput hashIn = { {0, 0, {0}}, {0, 0, {0}} };
        // Not really important which blob we take here...
        hashIn.Key = *(savedVAUSIGKeyPairBlob.get());
        hashIn.TEEToken = *(teeToken.get());

        // Another attempt to restore the blob generation should now work.
        hashResult = ERP_GetBlobContentHashWithToken(m_logonSession, hashIn);
        EXPECT_EQ(expErr, hashResult.returnCode);
    };

    testFn({}, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Setup }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Set1 }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Set2 }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Set1, users::Set2 }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Update }, ERP_ERR_PERMISSION_DENIED);
    testFn({ users::Working }, ERP_ERR_NOERROR);
    testFn({ users::Working, users::Setup }, ERP_ERR_NOERROR);
}

TEST_F(ErpPermissionTestsFixture, PermissionWrapPayload)
{
    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {
        logon(setOfUsers);

        RawPayloadInput input = {};
        input.desiredGeneration = THE_ANSWER;
        memcpy(input.rawPayload, "hello", 5);
        input.payloadLen = 5;

        auto rndOut = ERP_WrapRawPayload(m_logonSession, input);
        EXPECT_EQ(expErr, rndOut.returnCode);
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

TEST_F(ErpPermissionTestsFixture, PermissionWrapRawPayloadWithToken)
{
    const unsigned int Generation = THE_ANSWER;
    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {
        logon(setOfUsers);
        const char data[] = "hello";
        SingleBlobOutput out;

        auto err = teststep_WrapRawPayloadWithToken(m_logonSession, Generation, sizeof(data), (const unsigned char *)&data[0], &out);
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


TEST_F(ErpPermissionTestsFixture, PermissionUnwrapPayload)
{
    logonSetup();

    RawPayloadInput input = {};
    input.desiredGeneration = THE_ANSWER;
    memcpy(input.rawPayload, "hello", 5);
    input.payloadLen = 5;

    auto retBlob = ERP_WrapRawPayload(m_logonSession, input);
    ASSERT_EQ(ERP_ERR_NOERROR, retBlob.returnCode);

    logoff();

    auto testFn = [&](const std::vector<ErpBaseTestsFixture::users> &setOfUsers, unsigned int expErr) {
        logon(setOfUsers);
        RawPayloadOutput out;
        auto err = teststep_UnwrapRawPayload(m_logonSession, &retBlob.BlobOut, &out);
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
