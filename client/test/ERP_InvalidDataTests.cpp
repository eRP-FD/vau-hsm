/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021
 * (C) Copyright IBM Corp. 2021
 * SPDX-License-Identifier: CC BY-NC-ND 3.0 DE
 **************************************************************************************************/

#include "ERP_Client.h"
#include "ERP_Error.h"
#include "ERP_SFC.h"
#include "ERP_TestUtils.h"
#include "ERP_TestsBase.h"

#include <gtest/gtest.h>

#include <cstring>

class erpInvalidDataTestsFixture : public ErpBaseTestsFixture
{
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

#define EXPECTED_RESULT_UNKNOWN 1

TEST_F(erpInvalidDataTestsFixture, TrustTPMMfr)
{
    auto pNewTrustedRoot = getEmptyBlob(generationSaved);
    auto MfrRootCert = readERPResourceFile("cacertecc.crt");
    auto invalidMfrRootCert = readERPResourceFile("EKCertECC.crt");

    logonSetup();

    TrustTPMMfrInput in{};
    TrustTPMMfrInput inTest{};
    in.desiredGeneration = generationSaved;
    in.certLength = MfrRootCert.size();
    EXPECT_GT(MAX_BUFFER, in.certLength);
    std::memcpy(&(in.certData[0]), MfrRootCert.data(), in.certLength);

    SingleBlobOutput output;

    output = ERP_TrustTPMMfr(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, output.returnCode);

    // the inTest struct will be set to "good" values before the call to the mutation lambda
    const auto testFun = [&](const std::function<unsigned int(TrustTPMMfrInput&)>& f)
    {
        std::memcpy(&inTest, &in, sizeof(in));
        unsigned int expectedErr = f(inTest);
        output = ERP_TrustTPMMfr(m_logonSession, inTest);
        printf("Returned from ERP_EnrollTPMEK Command - Return Value: 0x%08x\n", output.returnCode);
        EXPECT_NE(ERP_ERR_NOERROR, output.returnCode) << "The return code is not an error";
        if (expectedErr != EXPECTED_RESULT_UNKNOWN)
        {
            EXPECT_EQ(expectedErr, output.returnCode);
        }
    };

    printf("Invalid key generation\n");
    testFun([&](TrustTPMMfrInput& input)
    {
        input.desiredGeneration = TEST_ABSENT_GEN;
        return ERP_ERR_BAD_BLOB_GENERATION;
    });

    printf("Invalid certificate length\n");
    testFun([&](TrustTPMMfrInput& input)
    {
        input.certLength = MfrRootCert.size() - TEST_LEN_CURTAILMENT; 
        return E_ASN1_DATASIZE;
    });

    printf("Invalid certificate data\n");
    testFun([&](TrustTPMMfrInput& input)
    {
        memset(&(input.certData[0]), BAD_BYTE, MAX_BUFFER);
        return E_ASN1_LENSIZE;
    });
}

//TODO(chris) This test is extracted from TrustTPMMfr, so it can be disabled
TEST_F(erpInvalidDataTestsFixture, TrustTPMMfrCertificateOnly)
{
    auto pNewTrustedRoot = getEmptyBlob(generationSaved);
    auto MfrRootCert = readERPResourceFile("cacertecc.crt");
    auto invalidMfrRootCert = readERPResourceFile("EKCertECC.crt");

    logonSetup();

    TrustTPMMfrInput in{};
    TrustTPMMfrInput inTest{};
    in.desiredGeneration = generationSaved;
    in.certLength = MfrRootCert.size();
    EXPECT_GT(MAX_BUFFER, in.certLength);
    std::memcpy(&(in.certData[0]), MfrRootCert.data(), in.certLength);

    SingleBlobOutput output;

    output = ERP_TrustTPMMfr(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, output.returnCode);

    // the inTest struct will be set to "good" values before the call to the mutation lambda
    const auto testFun = [&](const std::function<unsigned int(TrustTPMMfrInput&)>& f)
    {
        std::memcpy(&inTest, &in, sizeof(in));
        unsigned int expectedErr = f(inTest);
        output = ERP_TrustTPMMfr(m_logonSession, inTest);
        printf("Returned from ERP_EnrollTPMEK Command - Return Value: 0x%08x\n", output.returnCode);
        EXPECT_NE(ERP_ERR_NOERROR, output.returnCode) << "The return code is not an error";
        if (expectedErr != EXPECTED_RESULT_UNKNOWN)
        {
            EXPECT_EQ(expectedErr, output.returnCode);
        }
    };

    printf("Call with a non CA certificate\n");
    testFun([&](TrustTPMMfrInput& input)
    {
        // this is a non CA certificate
        input.certLength = invalidMfrRootCert.size();
        EXPECT_GT(MAX_BUFFER, input.certLength);
        std::memcpy(&(input.certData[0]), invalidMfrRootCert.data(), input.certLength);
        return EXPECTED_RESULT_UNKNOWN;
    });
}

//ERP_EnrollTPMEK
TEST_F(erpInvalidDataTestsFixture, EnrollTPMEK)
{
    auto pEKCert = readERPResourceFile("EKCertECC.crt");
    auto invalidEKCert = readERPResourceFile("cacertecc.crt");

    logonSetup();

    EnrollTPMEKInput in{};
    EnrollTPMEKInput inTest{};

    in.desiredGeneration = generationSaved;
    in.TPMMfrBlob = *savedTrustedRoot;
    in.EKCertLength = pEKCert.size();
    std::memcpy(&(in.EKCertData[0]), pEKCert.data(), pEKCert.size());

    SingleBlobOutput output;

    output = ERP_EnrollTPMEK(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, output.returnCode);

    // the inTest struct will be set to "good" values before the call to the mutation lambda
    const auto testFun = [&](const std::function<unsigned int(EnrollTPMEKInput&)>& f)
    {
        std::memcpy(&inTest, &in, sizeof(in));
        unsigned int expectedErr = f(inTest);

        output = ERP_EnrollTPMEK(m_logonSession, inTest);
        printf("Returned from ERP_EnrollTPMEK Command - Return Value: 0x%08x\n", output.returnCode);
        EXPECT_NE(ERP_ERR_NOERROR, output.returnCode) << "The return code is not an error";
        if (expectedErr != EXPECTED_RESULT_UNKNOWN)
        {
            EXPECT_EQ(expectedErr, output.returnCode);
        }
    };

    printf("Invalid key generation\n");
    testFun([&](EnrollTPMEKInput& input)
    {
        input.desiredGeneration = TEST_ABSENT_GEN;
        return ERP_ERR_BAD_BLOB_GENERATION;
    });

    printf("Invalid blob type\n");
    testFun([&](EnrollTPMEKInput& input)
    {
        input.TPMMfrBlob = *savedTrustedAK;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });

    printf("Invalid certificate length\n");
    testFun([&](EnrollTPMEKInput& input)
    {
        input.EKCertLength = pEKCert.size() - TEST_LEN_CURTAILMENT;
        return E_ASN1_DATASIZE;
    });

    printf("Invalid certificate data\n");
    testFun([&](EnrollTPMEKInput& input)
    {
        memset(&(input.EKCertData[0]), BAD_BYTE, MAX_BUFFER);
        return E_ASN1_LENSIZE;
    });
}

//ERP_EnrollTPMEK
//TODO(chris) This test is extracted from EnrollTPMEK, so it can be disabled
TEST_F(erpInvalidDataTestsFixture, EnrollTPMEKCertificateOnly)
{
    auto pEKCert = readERPResourceFile("EKCertECC.crt");
    auto invalidEKCert = readERPResourceFile("cacertecc.crt");

    logonSetup();

    EnrollTPMEKInput in{};
    EnrollTPMEKInput inTest{};

    in.desiredGeneration = generationSaved;
    in.TPMMfrBlob = *savedTrustedRoot;
    in.EKCertLength = pEKCert.size();
    std::memcpy(&(in.EKCertData[0]), pEKCert.data(), pEKCert.size());

    SingleBlobOutput output;

    output = ERP_EnrollTPMEK(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, output.returnCode);

    // the inTest struct will be set to "good" values before the call to the mutation lambda
    const auto testFun = [&](const std::function<unsigned int(EnrollTPMEKInput&)>& f)
    {
        std::memcpy(&inTest, &in, sizeof(in));
        unsigned int expectedErr = f(inTest);

        output = ERP_EnrollTPMEK(m_logonSession, inTest);
        printf("Returned from ERP_EnrollTPMEK Command - Return Value: 0x%08x\n", output.returnCode);
        EXPECT_NE(ERP_ERR_NOERROR, output.returnCode) << "The return code is not an error";
        if (expectedErr != EXPECTED_RESULT_UNKNOWN)
        {
            EXPECT_EQ(expectedErr, output.returnCode);
        }
    };

    printf("Call with a non EK certificate\n");
    testFun([&](EnrollTPMEKInput& input)
    {
        input.EKCertLength = invalidEKCert.size();
        EXPECT_GT(MAX_BUFFER, input.EKCertLength);
        std::memcpy(&(input.EKCertData[0]), invalidEKCert.data(), input.EKCertLength);
        return EXPECTED_RESULT_UNKNOWN;
    });
}

//ERP_GetAKChallenge
TEST_F(erpInvalidDataTestsFixture, GetAKChallenge)
{
    logonSetup();

    AKChallengeInput in{};
    AKChallengeInput inTest{};

    in.desiredGeneration = generationSaved;
    in.KnownEKBlob = *savedTrustedEK;
    std::memcpy(&(in.AKName[0]), savedAKName.data(), TPM_NAME_LEN);
    in.AKPubLength = savedAKPub.size() - 2; // file includes two leading length bytes that we don't want.
    std::memcpy(&(in.AKPubData[0]), savedAKPub.data() + 2, in.AKPubLength);

    AKChallengeOutput output;

    output = ERP_GetAKChallenge(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, output.returnCode);

    // the inTest struct will be set to "good" values before the call to the mutation lambda
    const auto testFun = [&](const std::function<unsigned int(AKChallengeInput&)>& f)
    {
        std::memcpy(&inTest, &in, sizeof(in));
        unsigned int expectedErr = f(inTest);
        output = ERP_GetAKChallenge(m_logonSession, inTest);
        printf("Returned from ERP_GetAKChallenge Command - Return Value: 0x%08x\n", output.returnCode);
        EXPECT_NE(ERP_ERR_NOERROR, output.returnCode) << "The return code is not an error";
        if (expectedErr != EXPECTED_RESULT_UNKNOWN)
        {
            EXPECT_EQ(expectedErr, output.returnCode);
        }
    };

    printf("Invalid key generation\n");
    testFun([&](AKChallengeInput& input)
    {
        input.desiredGeneration = TEST_ABSENT_GEN;
        return ERP_ERR_BAD_BLOB_GENERATION;
    });

    printf("Invalid blob type\n");
    testFun([&](AKChallengeInput& input)
    {
        input.KnownEKBlob = *savedTrustedAK;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });

    printf("Invalid public key length\n");
    testFun([&](AKChallengeInput& input)
    {
        input.AKPubLength -= TEST_LEN_CURTAILMENT;
        return ERP_ERR_BAD_TPMT_PUBLIC_LENGTH;
    });

    printf("Invalid public key data\n");
    testFun([&](AKChallengeInput& input)
    {
        memset(&(input.AKPubData[0]), BAD_BYTE, MAX_BUFFER);
        return ERP_ERR_TPM_NAME_MISMATCH;
    });

    printf("Invalid AK name data\n");
    testFun([&](AKChallengeInput& input)
    {
        memset(&(input.AKName[0]), BAD_BYTE, TPM_NAME_LEN);
        return ERP_ERR_BAD_TPM_NAME_ALGORITHM;
    });
}

//ERP_EnrollTPMAK
TEST_F(erpInvalidDataTestsFixture, EnrollTPMAK)
{
    EnrollTPMAKInput in{};
    EnrollTPMAKInput inTest{};

    in.desiredGeneration = generationSaved;
    in.KnownEKBlob = *savedTrustedEK;
    std::memcpy(&(in.AKName[0]), savedAKName.data(), TPM_NAME_LEN);
    in.AKPubLength = savedAKPub.size() - 2; // file includes two leading length bytes that we don't want.
    std::memcpy(&(in.AKPubData[0]), savedAKPub.data() + 2, in.AKPubLength);
    in.challengeBlob = *savedAKChallenge1Blob;
    in.decCredentialLength = savedDecCred.size();
    std::memcpy(&(in.decCredentialData[0]), savedDecCred.data(), savedDecCred.size());

    SingleBlobOutput output = ERP_EnrollTPMAK(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, output.returnCode);

    // the inTest struct will be set to "good" values before the call to the mutation lambda
    const auto testFun = [&](const std::function<unsigned int(EnrollTPMAKInput&)>& f)
    {
        std::memcpy(&inTest, &in, sizeof(in));
        unsigned int expectedErr = f(inTest);
        output = ERP_EnrollTPMAK(m_logonSession, inTest);
        printf("Returned from ERP_EnrollTPMAK Command - Return Value: 0x%08x\n", output.returnCode);
        EXPECT_NE(ERP_ERR_NOERROR, output.returnCode) << "The return code is not an error";
        if (expectedErr != EXPECTED_RESULT_UNKNOWN)
        {
            EXPECT_EQ(expectedErr, output.returnCode);
        }
    };

    printf("Invalid key generation\n");
    testFun([&](EnrollTPMAKInput& input)
    {
        input.desiredGeneration = TEST_ABSENT_GEN;
        return ERP_ERR_BAD_BLOB_GENERATION;
    });

    printf("Invalid blob type\n");
    testFun([&](EnrollTPMAKInput& input)
    {
        input.KnownEKBlob = *savedTrustedAK;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });

    printf("Invalid blob type\n");
    testFun([&](EnrollTPMAKInput& input)
    {
        input.challengeBlob = *savedTrustedAK;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });

    printf("Wrong challenge blob\n");
    testFun([&](EnrollTPMAKInput& input)
    {
        input.challengeBlob = *savedAKChallenge2Blob;
        return ERP_ERR_FAIL_AK_CREDENTIAL_MATCH;
    });

    printf("Invalid public key length\n");
    testFun([&](EnrollTPMAKInput& input)
    {
        input.AKPubLength -= TEST_LEN_CURTAILMENT;
        return ERP_ERR_BAD_TPMT_PUBLIC_LENGTH;
    });

    printf("Invalid public key data\n");
    testFun([&](EnrollTPMAKInput& input)
    {
        memset(&(input.AKPubData[0]), BAD_BYTE, MAX_BUFFER);
        return ERP_ERR_TPM_NAME_MISMATCH;
    });

    printf("Invalid AK name data\n");
    testFun([&](EnrollTPMAKInput& input)
    {
        memset(&(input.AKName[0]), BAD_BYTE, TPM_NAME_LEN);
        return ERP_ERR_BAD_TPM_NAME_ALGORITHM;
    });

    printf("Invalid credential length\n");
    testFun([&](EnrollTPMAKInput& input)
    {
        input.decCredentialLength -= TEST_LEN_CURTAILMENT;
        return ERP_ERR_FAIL_AK_CREDENTIAL_MATCH;
    });

    printf("Invalid credential data\n");
    testFun([&](EnrollTPMAKInput& input)
    {
        input.decCredentialLength = MAX_BUFFER + sizeof(ERPBlob);
        return ERP_ERR_FAIL_AK_CREDENTIAL_MATCH;
    });

    printf("Invalid credential data\n");
    testFun([&](EnrollTPMAKInput& input)
    {
        memset(&(input.decCredentialData[0]), BAD_BYTE, MAX_BUFFER);
        return ERP_ERR_FAIL_AK_CREDENTIAL_MATCH;
    });
}

//ERP_EnrollEnclave
TEST_F(erpInvalidDataTestsFixture, EnrollEnclave)
{
    // Create a token for the test
    UIntInput genIn = { generationSaved };
    NONCEOutput NONCE = ERP_GenerateNONCE(m_logonSession, genIn);
    ASSERT_EQ(ERP_ERR_NOERROR, NONCE.returnCode);

    EnrollEnclaveInput in = { generationSaved,
                              "\0",
                              *savedTrustedAK,
                              *savedEnrollmentNONCE,
                              0,
                              "",
                              0,
                              "" };

    EnrollEnclaveInput inTest{};

    std::memcpy(&(in.AKName[0]), savedAKName.data(), TPM_NAME_LEN);

    in.quoteLength = savedEnrollmentQuote.size();
    std::memcpy(&(in.quoteData[0]), savedEnrollmentQuote.data(), savedEnrollmentQuote.size());
    in.signatureLength = savedEnrollmentQuoteSignature.size();
    std::memcpy(&(in.signatureData[0]), savedEnrollmentQuoteSignature.data(), savedEnrollmentQuoteSignature.size());

    SingleBlobOutput output = ERP_EnrollEnclave(m_logonSession, in);

    ASSERT_EQ(ERP_ERR_NOERROR, output.returnCode);

    // the inTest struct will be set to "good" values before the call to the mutation lambda
    const auto testFun = [&](const std::function<unsigned int(EnrollEnclaveInput&)>& f)
    {
        std::memcpy(&inTest, &in, sizeof(in));
        unsigned int expectedErr = f(inTest);
        output = ERP_EnrollEnclave(m_logonSession, inTest);
        printf("Returned from ERP_EnrollEnclave Command - Return Value: 0x%08x\n", output.returnCode);
        EXPECT_NE(ERP_ERR_NOERROR, output.returnCode) << "The return code is not an error";
        if (expectedErr != EXPECTED_RESULT_UNKNOWN)
        {
            EXPECT_EQ(expectedErr, output.returnCode);
        }
    };

    printf("Invalid key generation\n");
    testFun([&](EnrollEnclaveInput& input)
    {
        input.desiredGeneration = TEST_ABSENT_GEN;
        return ERP_ERR_BAD_BLOB_GENERATION;
    });

    printf("Invalid blob type\n");
    testFun([&](EnrollEnclaveInput& input)
    {
        input.KnownAKBlob = *savedTrustedEK;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });

    printf("Invalid blob type\n");
    testFun([&](EnrollEnclaveInput& input)
    {
        input.NONCEBlob = *savedTrustedAK;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });

    printf("Wrong nonce blob\n");
    testFun([&](EnrollEnclaveInput& input)
    {
        input.NONCEBlob = NONCE.BlobOut;
        return ERP_ERR_QUOTE_NONCE_MISMATCH;
    });

    printf("Invalid quote length\n");
    testFun([&](EnrollEnclaveInput& input)
    {
        input.quoteLength = 2 * MAX_BUFFER;
        return E_ECDSA_VERIFY_FAILED;
    });

    printf("Invalid quote length\n");
    testFun([&](EnrollEnclaveInput& input)
    {
        input.quoteLength -= TEST_LEN_CURTAILMENT;
        return E_ECDSA_VERIFY_FAILED;
    });

    printf("Invalid quote data\n");
    testFun([&](EnrollEnclaveInput& input)
    {
        memset(&(input.quoteData[0]), BAD_BYTE, MAX_BUFFER);
        return E_ECDSA_VERIFY_FAILED;
    });

    printf("Invalid signature length\n");
    testFun([&](EnrollEnclaveInput& input)
    {
        input.signatureLength -= TEST_LEN_CURTAILMENT;
        return ERP_ERR_BAD_TPMT_SIGNATURE_FORMAT;
    });

    printf("Invalid signature length\n");
    testFun([&](EnrollEnclaveInput& input)
    {
        input.signatureLength = 0;
        return ERP_ERR_ASN1_CONTENT_ERROR;
    });

    printf("Invalid signature length\n");
    testFun([&](EnrollEnclaveInput& input)
    {
        input.signatureLength = MAX_BUFFER;
        return ERP_ERR_BAD_TPMT_SIGNATURE_FORMAT;
    });

    printf("Invalid signature length\n");
    testFun([&](EnrollEnclaveInput& input)
    {
        memset(&(input.signatureData[0]), BAD_BYTE, MAX_BUFFER);
        return ERP_ERR_BAD_TPMT_SIGNATURE_FORMAT;
    });
}

//ERP_GenerateECIESCSR
TEST_F(erpInvalidDataTestsFixture, GenerateECIESCSR)
{
    UIntInput inKp = { generationSaved };

    SingleBlobOutput outKPECIES = ERP_GenerateECIESKeyPair(m_logonSession, inKp);
    ASSERT_EQ(ERP_ERR_NOERROR, outKPECIES.returnCode);
    SingleBlobOutput outKPVAUSIG = ERP_GenerateVAUSIGKeyPair(m_logonSession, inKp);
    ASSERT_EQ(ERP_ERR_NOERROR, outKPVAUSIG.returnCode);

    auto savedCSR = readERPResourceFile("candidateECIES.csr");

    GetVAUCSRInput in = { outKPECIES.BlobOut, 0, "\0" };
    GetVAUCSRInput inTest{};

    in.candidateCSRLength = savedCSR.size();
    std::memcpy(&(in.candidateCSR[0]), savedCSR.data(), savedCSR.size());

    auto output = ERP_GenerateECIESCSR(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, outKPECIES.returnCode);

    // the inTest struct will be set to "good" values before the call to the mutation lambda
    const auto testFun = [&](const std::function<unsigned int(GetVAUCSRInput&)>& f)
    {
        std::memcpy(&inTest, &in, sizeof(in));
        unsigned int expectedErr = f(inTest);
        output = ERP_GenerateECIESCSR(m_logonSession, inTest);
        printf("Returned from ERP_GenerateECIESCSR Command - Return Value: 0x%08x\n", output.returnCode);
        EXPECT_NE(ERP_ERR_NOERROR, output.returnCode) << "The return code is not an error";
        if (expectedErr != EXPECTED_RESULT_UNKNOWN)
        {
            EXPECT_EQ(expectedErr, output.returnCode);
        }
    };

    printf("Invalid blob type\n");
    testFun([&](GetVAUCSRInput& input)
    {
        input.KeyPair = *savedTrustedAK;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });

    printf("Wrong key pair blob\n");
    testFun([&](GetVAUCSRInput& input)
    {
        input.KeyPair = outKPVAUSIG.BlobOut;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });

    printf("Invalid csr length\n");
    testFun([&](GetVAUCSRInput& input)
    {
        input.candidateCSRLength -= TEST_LEN_CURTAILMENT;
        return E_ASN1_DATASIZE;
    });

    printf("Invalid csr length\n");
    testFun([&](GetVAUCSRInput& input)
    {
        input.candidateCSRLength = 0;
        return ERP_ERR_ASN1_CONTENT_ERROR;
    });

    printf("Invalid csr length\n");
    testFun([&](GetVAUCSRInput& input)
    {
        memset(&(input.candidateCSR[0]), BAD_BYTE, MAX_BUFFER);
        return E_ASN1_LENSIZE;
    });
}

//ERP_DoVAUECIES128
TEST_F(erpInvalidDataTestsFixture, DoVAUECIES128)
{
    UIntInput inKp = {
            generationSaved
    };

    SingleBlobOutput outKP = ERP_GenerateECIESKeyPair(m_logonSession, inKp);
    ASSERT_EQ(ERP_ERR_NOERROR, outKP.returnCode);
    SingleBlobOutput outKPVAUSIG = ERP_GenerateVAUSIGKeyPair(m_logonSession, inKp);
    ASSERT_EQ(ERP_ERR_NOERROR, outKPVAUSIG.returnCode);

    DoVAUECIESInput in = {
            *teeToken,
            outKP.BlobOut,
            0,
            {0}
    };
    DoVAUECIESInput inTest = { {0,0,{0}} , {0,0,{0}} , 0, {0} };

    std::memcpy(&(in.clientPublicKeyData[0]), clientPub.data(), clientPub.size());
    in.clientPublicKeyLength = clientPub.size();

    AES128KeyOutput output;
    output = ERP_DoVAUECIES128(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, output.returnCode);
    // the inTest struct will be set to "good" values before the call to the mutation lambda
    const auto testFun = [&](const std::function<unsigned int(DoVAUECIESInput&)>& f) {
        std::memcpy(&inTest, &in, sizeof(in));
        unsigned int expectedErr = f(inTest);
        output = ERP_DoVAUECIES128(m_logonSession, inTest);
        printf("Returned from ERP_EnrollTPMAK Command - Return Value: 0x%08x\n", output.returnCode);
        EXPECT_NE(ERP_ERR_NOERROR, output.returnCode) << "The return code is not an error";
        if (expectedErr != EXPECTED_RESULT_UNKNOWN)
        {
            EXPECT_EQ(expectedErr, output.returnCode);
        }
    };

    printf("Invalid blob type\n");
    testFun([&](DoVAUECIESInput& input)
    {
        input.TEEToken = *savedTrustedAK;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });

    printf("Invalid blob type\n");
    testFun([&](DoVAUECIESInput& input)
    {
        input.ECIESKeyPair = *savedTrustedAK;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });

    printf("Wrong key pair blob\n");
    testFun([&](DoVAUECIESInput& input)
    {
        input.ECIESKeyPair = outKPVAUSIG.BlobOut;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });

    printf("Invalid publc key length\n");
    testFun([&](DoVAUECIESInput& input)
    {
        input.clientPublicKeyLength -= TEST_LEN_CURTAILMENT;
        return E_ASN1_DATASIZE;
    });

    printf("Invalid publc key length\n");
    testFun([&](DoVAUECIESInput& input)
    {
        input.clientPublicKeyLength = 0;
        return ERP_ERR_ASN1_CONTENT_ERROR;
    });

    printf("Invalid publc key data\n");
    testFun([&](DoVAUECIESInput& input)
    {
        memset(&(input.clientPublicKeyData[0]), BAD_BYTE, MAX_BUFFER);
        return E_ASN1_LENSIZE;
    });
}

//ERP_GenerateVAUSIGCSR
TEST_F(erpInvalidDataTestsFixture, GenerateVAUSIGCSR)
{
    UIntInput inKp = { generationSaved };

    SingleBlobOutput outKPVAUSIG = ERP_GenerateVAUSIGKeyPair(m_logonSession, inKp);
    ASSERT_EQ(ERP_ERR_NOERROR, outKPVAUSIG.returnCode);
    SingleBlobOutput outKPECIES = ERP_GenerateECIESKeyPair(m_logonSession, inKp);
    ASSERT_EQ(ERP_ERR_NOERROR, outKPECIES.returnCode);

    auto savedCSR = readERPResourceFile("candidateVAUSIG.csr");

    GetVAUCSRInput in = { outKPVAUSIG.BlobOut, 0, "\0" };
    GetVAUCSRInput inTest{};

    in.candidateCSRLength = savedCSR.size();
    std::memcpy(&(in.candidateCSR[0]), savedCSR.data(), savedCSR.size());

    auto output = ERP_GenerateVAUSIGCSR(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, output.returnCode);

    // the inTest struct will be set to "good" values before the call to the mutation lambda
    const auto testFun = [&](const std::function<unsigned int(GetVAUCSRInput&)>& f)
    {
        std::memcpy(&inTest, &in, sizeof(in));
        unsigned int expectedErr = f(inTest);
        output = ERP_GenerateVAUSIGCSR(m_logonSession, inTest);
        printf("Returned from ERP_GenerateVAUSIGCSR Command - Return Value: 0x%08x\n", output.returnCode);
        EXPECT_NE(ERP_ERR_NOERROR, output.returnCode) << "The return code is not an error";
        if (expectedErr != EXPECTED_RESULT_UNKNOWN)
        {
            EXPECT_EQ(expectedErr, output.returnCode);
        }
    };

    printf("Invalid blob type\n");
    testFun([&](GetVAUCSRInput& input)
    {
        input.KeyPair = *savedTrustedAK;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });

    printf("Wrong key pair blob\n");
    testFun([&](GetVAUCSRInput& input)
    {
        input.KeyPair = outKPECIES.BlobOut;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });

    printf("Invalid csr length\n");
    testFun([&](GetVAUCSRInput& input)
    {
        input.candidateCSRLength -= TEST_LEN_CURTAILMENT;
        return E_ASN1_DATASIZE;
    });

    printf("Invalid csr length\n");
    testFun([&](GetVAUCSRInput& input)
    {
        input.candidateCSRLength = 0;
        return ERP_ERR_ASN1_CONTENT_ERROR;
    });

    printf("Invalid csr length\n");
    testFun([&](GetVAUCSRInput& input)
    {
        memset(&(input.candidateCSR[0]), BAD_BYTE, MAX_BUFFER);
        return E_ASN1_LENSIZE;
    });
}

//ERP_GetVAUSIGPrivateKey
TEST_F(erpInvalidDataTestsFixture, GetVAUSIGPrivateKey)
{
    std::unique_ptr<ERPBlob> savedKeyPairBlob{readBlobResourceFile("saved/VAUSIGKeyPairSaved_UT.blob")};
    ASSERT_NE(nullptr, savedKeyPairBlob);

    UIntInput inKp = { generationSaved };
    SingleBlobOutput outKPECIES = ERP_GenerateECIESKeyPair(m_logonSession, inKp);
    ASSERT_EQ(ERP_ERR_NOERROR, outKPECIES.returnCode);

    TwoBlobGetKeyInput in{};
    TwoBlobGetKeyInput inTest{};

    in.Key = *savedKeyPairBlob;
    in.TEEToken = *teeToken;

    PrivateKeyOutput output = ERP_GetVAUSIGPrivateKey(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, output.returnCode);

    // the inTest struct will be set to "good" values before the call to the mutation lambda
    const auto testFun = [&](const std::function<unsigned int(TwoBlobGetKeyInput&)>& f)
    {
        std::memcpy(&inTest, &in, sizeof(in));
        unsigned int expectedErr = f(inTest);
        output = ERP_GetVAUSIGPrivateKey(m_logonSession, inTest);
        printf("Returned from ERP_GetVAUSIGPrivateKey Command - Return Value: 0x%08x\n", output.returnCode);
        EXPECT_NE(ERP_ERR_NOERROR, output.returnCode) << "The return code is not an error";
        if (expectedErr != EXPECTED_RESULT_UNKNOWN)
        {
            EXPECT_EQ(expectedErr, output.returnCode);
        }
    };


    printf("Invalid blob type\n");
    testFun([&](TwoBlobGetKeyInput& input)
    {
        input.TEEToken = *savedTrustedAK;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });

    printf("Invalid blob type\n");
    testFun([&](TwoBlobGetKeyInput& input)
    {
        input.Key = *savedTrustedAK;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });

    printf("Wrong key pair blob\n");
    testFun([&](TwoBlobGetKeyInput& input)
    {
        input.Key = outKPECIES.BlobOut;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });
}

//ERP_UnwrapHashKey
TEST_F(erpInvalidDataTestsFixture, UnwrapHashKey)
{
    UIntInput genKeyIn = { 0 };
    SingleBlobOutput outputKey = ERP_GenerateHashKey(m_logonSession, genKeyIn);
    ASSERT_EQ(ERP_ERR_NOERROR, outputKey.returnCode);

    UIntInput inKp = {generationSaved};
    SingleBlobOutput outKP = ERP_GenerateECIESKeyPair(m_logonSession, inKp);
    ASSERT_EQ(ERP_ERR_NOERROR, outKP.returnCode);

    TwoBlobGetKeyInput in{};
    TwoBlobGetKeyInput inTest{};

    in.Key = outputKey.BlobOut;
    in.TEEToken = *teeToken;

    auto output = ERP_UnwrapHashKey(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, output.returnCode);

    // the inTest struct will be set to "good" values before the call to the mutation lambda
    const auto testFun = [&](const std::function<unsigned int(TwoBlobGetKeyInput&)>& f) {
        std::memcpy(&inTest, &in, sizeof(in));
        unsigned int expectedErr = f(inTest);
        output = ERP_UnwrapHashKey(m_logonSession, inTest);
        printf("Returned from ERP_GetVAUSIGPrivateKey Command - Return Value: 0x%08x\n", output.returnCode);
        EXPECT_NE(ERP_ERR_NOERROR, output.returnCode) << "The return code is not an error";
        if (expectedErr != EXPECTED_RESULT_UNKNOWN)
        {
            EXPECT_EQ(expectedErr, output.returnCode);
        }
    };

    printf("Invalid blob type\n");
    testFun([&](TwoBlobGetKeyInput& input)
    {
        input.TEEToken = *savedTrustedAK;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });

    printf("Invalid blob type\n");
    testFun([&](TwoBlobGetKeyInput& input)
    {
        input.Key = *savedTrustedAK;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });

    printf("Wrong key pair blob\n");
    testFun([&](TwoBlobGetKeyInput& input)
    {
        input.Key = outKP.BlobOut;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });
}

//ERP_DeriveTaskKey
TEST_F(erpInvalidDataTestsFixture, DeriveTaskKey)
{
    auto pDerivationKeyBlob = getEmptyBlob(generationSaved);
    auto err = teststep_GenerateDerivationKey(m_logonSession, generationSaved, pDerivationKeyBlob.get());
    ASSERT_EQ(ERP_ERR_NOERROR, err);

    auto derivationData = asciiToBuffer("(Dummy Derivation Data) KVNR:Z123-45678");

    DeriveKeyInput in{};
    DeriveKeyInput inTest{};

    in.derivationDataLength = derivationData.size();
    std::memcpy(&(in.AKName[0]), savedAKName.data(), TPM_NAME_LEN);
    std::memcpy(&(in.derivationData), derivationData.data(), derivationData.size());
    in.TEEToken = *teeToken;
    in.derivationKey = *pDerivationKeyBlob;
    in.initialDerivation = 1;

    DeriveKeyOutput output = ERP_DeriveTaskKey(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, output.returnCode);


    // the inTest struct will be set to "good" values before the call to the mutation lambda
    const auto testFun = [&](const std::function<unsigned int(DeriveKeyInput&)>& f) {
        std::memcpy(&inTest, &in, sizeof(in));
        unsigned int expectedErr = f(inTest);
        output = ERP_DeriveTaskKey(m_logonSession, inTest);
        printf("Returned from ERP_DeriveTaskKey Command - Return Value: 0x%08x\n", output.returnCode);
        EXPECT_NE(ERP_ERR_NOERROR, output.returnCode) << "The return code is not an error";
        if (expectedErr != EXPECTED_RESULT_UNKNOWN)
        {
            EXPECT_EQ(expectedErr, output.returnCode);
        }
    };

    printf("Invalid blob type\n");
    testFun([&](DeriveKeyInput& input)
    {
        input.TEEToken = *savedTrustedAK;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });

    printf("Invalid blob type\n");
    testFun([&](DeriveKeyInput& input)
    {
        input.derivationKey = *savedTrustedAK;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });

    printf("Invalid derivation data length\n");
    testFun([&](DeriveKeyInput& input)
    {
        input.derivationDataLength = 0;
        return ERP_ERR_ASN1_CONTENT_ERROR;
    });
}

//ERP_DeriveAuditKey
TEST_F(erpInvalidDataTestsFixture, DeriveAuditKey)
{
    auto pDerivationKeyBlob = getEmptyBlob(generationSaved);
    auto err = teststep_GenerateDerivationKey(m_logonSession, generationSaved, pDerivationKeyBlob.get());
    ASSERT_EQ(ERP_ERR_NOERROR, err);

    auto derivationData = asciiToBuffer("(Dummy Derivation Data) KVNR:Z123-45678");

    DeriveKeyInput in{};
    DeriveKeyInput inTest{};

    in.derivationDataLength = derivationData.size();
    std::memcpy(&(in.AKName[0]), savedAKName.data(), TPM_NAME_LEN);
    std::memcpy(&(in.derivationData), derivationData.data(), derivationData.size());
    in.TEEToken = *teeToken;
    in.derivationKey = *pDerivationKeyBlob;
    in.initialDerivation = 1;

    DeriveKeyOutput output = ERP_DeriveAuditKey(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, output.returnCode);

    // the inTest struct will be set to "good" values before the call to the mutation lambda
    const auto testFun = [&](const std::function<unsigned int(DeriveKeyInput&)>& f) {
        std::memcpy(&inTest, &in, sizeof(in));
        unsigned int expectedErr = f(inTest);
        output = ERP_DeriveAuditKey(m_logonSession, inTest);
        printf("Returned from ERP_DeriveAuditKey Command - Return Value: 0x%08x\n", output.returnCode);
        EXPECT_NE(ERP_ERR_NOERROR, output.returnCode) << "The return code is not an error";
        if (expectedErr != EXPECTED_RESULT_UNKNOWN)
        {
            EXPECT_EQ(expectedErr, output.returnCode);
        }
    };

    printf("Invalid blob type\n");
    testFun([&](DeriveKeyInput& input)
    {
        input.TEEToken = *savedTrustedAK;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });

    printf("Invalid blob type\n");
    testFun([&](DeriveKeyInput& input)
    {
        input.derivationKey = *savedTrustedAK;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });

    printf("Invalid derivation data length\n");
    testFun([&](DeriveKeyInput& input)
    {
        input.derivationDataLength = 0;
        return ERP_ERR_ASN1_CONTENT_ERROR;
    });
}

//ERP_DeriveCommsKey
TEST_F(erpInvalidDataTestsFixture, DeriveCommsKey)
{
    auto pDerivationKeyBlob = getEmptyBlob(generationSaved);
    auto err = teststep_GenerateDerivationKey(m_logonSession, generationSaved, pDerivationKeyBlob.get());
    ASSERT_EQ(ERP_ERR_NOERROR, err);

    auto derivationData = asciiToBuffer("(Dummy Derivation Data) KVNR:Z123-45678");

    DeriveKeyInput in{};
    DeriveKeyInput inTest{};

    in.derivationDataLength = derivationData.size();
    std::memcpy(&(in.AKName[0]), savedAKName.data(), TPM_NAME_LEN);
    std::memcpy(&(in.derivationData), derivationData.data(), derivationData.size());
    in.TEEToken = *teeToken;
    in.derivationKey = *pDerivationKeyBlob;
    in.initialDerivation = 1;

    DeriveKeyOutput output = ERP_DeriveCommsKey(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, output.returnCode);

    // the inTest struct will be set to "good" values before the call to the mutation lambda
    const auto testFun = [&](const std::function<unsigned int(DeriveKeyInput&)>& f) {
        std::memcpy(&inTest, &in, sizeof(in));
        unsigned int expectedErr = f(inTest);
        output = ERP_DeriveCommsKey(m_logonSession, inTest);
        printf("Returned from ERP_DeriveCommsKey Command - Return Value: 0x%08x\n", output.returnCode);
        EXPECT_NE(ERP_ERR_NOERROR, output.returnCode) << "The return code is not an error";
        if (expectedErr != EXPECTED_RESULT_UNKNOWN)
        {
            EXPECT_EQ(expectedErr, output.returnCode);
        }
    };

    printf("Invalid blob type\n");
    testFun([&](DeriveKeyInput& input)
    {
        input.TEEToken = *savedTrustedAK;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });

    printf("Invalid blob type\n");
    testFun([&](DeriveKeyInput& input)
    {
        input.derivationKey = *savedTrustedAK;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });

    printf("Invalid derivation data length\n");
    testFun([&](DeriveKeyInput& input)
    {
        input.derivationDataLength = 0;
        return ERP_ERR_ASN1_CONTENT_ERROR;
    });
}

//ERP_DeriveChargeItemKey
TEST_F(erpInvalidDataTestsFixture, DeriveChargeItemKey)
{
    auto pDerivationKeyBlob = getEmptyBlob(generationSaved);
    auto err = teststep_GenerateDerivationKey(m_logonSession, generationSaved, pDerivationKeyBlob.get());
    ASSERT_EQ(ERP_ERR_NOERROR, err);

    auto derivationData = asciiToBuffer("(Dummy Derivation Data) KVNR:Z123-45678");

    DeriveKeyInput in{};
    DeriveKeyInput inTest{};

    in.derivationDataLength = derivationData.size();
    std::memcpy(&(in.AKName[0]), savedAKName.data(), TPM_NAME_LEN);
    std::memcpy(&(in.derivationData), derivationData.data(), derivationData.size());
    in.TEEToken = *teeToken;
    in.derivationKey = *pDerivationKeyBlob;
    in.initialDerivation = 1;

    DeriveKeyOutput output = ERP_DeriveChargeItemKey(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, output.returnCode);

    // the inTest struct will be set to "good" values before the call to the mutation lambda
    const auto testFun = [&](const std::function<unsigned int(DeriveKeyInput&)>& f) {
        std::memcpy(&inTest, &in, sizeof(in));
        unsigned int expectedErr = f(inTest);
        output = ERP_DeriveChargeItemKey(m_logonSession, inTest);
        printf("Returned from ERP_DeriveChargeItemKey Command - Return Value: 0x%08x\n", output.returnCode);
        EXPECT_NE(ERP_ERR_NOERROR, output.returnCode) << "The return code is not an error";
        if (expectedErr != EXPECTED_RESULT_UNKNOWN)
        {
            EXPECT_EQ(expectedErr, output.returnCode);
        }
    };

    printf("Invalid blob type\n");
    testFun([&](DeriveKeyInput& input)
        {
            input.TEEToken = *savedTrustedAK;
            return ERP_ERR_WRONG_BLOB_TYPE;
        });

    printf("Invalid blob type\n");
    testFun([&](DeriveKeyInput& input)
        {
            input.derivationKey = *savedTrustedAK;
            return ERP_ERR_WRONG_BLOB_TYPE;
        });

    printf("Invalid derivation data length\n");
    testFun([&](DeriveKeyInput& input)
        {
            input.derivationDataLength = 0;
            return ERP_ERR_ASN1_CONTENT_ERROR;
        });
}

// ERP_DeriveAuditKey
// This test collects the invalid AKName calls for the derived keys.
// Currently there are no checks on AK Name, so this test is disabled.
TEST_F(erpInvalidDataTestsFixture, DISABLED_DerivePersistenceKeyAKName)
{
    const auto pDerivationKeyBlob = getEmptyBlob(generationSaved);
    const auto err = teststep_GenerateDerivationKey(m_logonSession, generationSaved, pDerivationKeyBlob.get());
    ASSERT_EQ(ERP_ERR_NOERROR, err);

    auto derivationData = asciiToBuffer("(Dummy Derivation Data) KVNR:Z123-45678");

    DeriveKeyInput in{};
    DeriveKeyInput inTest{};

    in.derivationDataLength = derivationData.size();
    std::memcpy(&(in.AKName[0]), savedAKName.data(), TPM_NAME_LEN);
    std::memcpy(&(in.derivationData), derivationData.data(), derivationData.size());
    in.TEEToken = *teeToken;
    in.derivationKey = *pDerivationKeyBlob;
    in.initialDerivation = 1;

    DeriveKeyOutput output = ERP_DeriveAuditKey(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, output.returnCode);

    // the inTest struct will be set to "good" values before the call to the mutation lambda
    const auto testFun = [&](const std::function<unsigned int(DeriveKeyInput&)>& f)
    {
        std::memcpy(&inTest, &in, sizeof(in));
        unsigned int expectedErr = f(inTest);
        output = ERP_DeriveAuditKey(m_logonSession, inTest);
        printf("Returned from ERP_DeriveAuditKey Command - Return Value: 0x%08x\n", output.returnCode);
        EXPECT_NE(ERP_ERR_NOERROR, output.returnCode) << "The return code is not an error";
        if (expectedErr != EXPECTED_RESULT_UNKNOWN)
        {
            EXPECT_EQ(expectedErr, output.returnCode);
        }

        output = ERP_DeriveTaskKey(m_logonSession, inTest);
        printf("Returned from ERP_DeriveTaskKey Command - Return Value: 0x%08x\n", output.returnCode);
        EXPECT_NE(ERP_ERR_NOERROR, output.returnCode) << "The return code is not an error";
        if (expectedErr != EXPECTED_RESULT_UNKNOWN)
        {
            EXPECT_EQ(expectedErr, output.returnCode);
        }

        output = ERP_DeriveCommsKey(m_logonSession, inTest);
        printf("Returned from ERP_DeriveTaskKey Command - Return Value: 0x%08x\n", output.returnCode);
        EXPECT_NE(ERP_ERR_NOERROR, output.returnCode) << "The return code is not an error";
        if (expectedErr != EXPECTED_RESULT_UNKNOWN)
        {
            EXPECT_EQ(expectedErr, output.returnCode);
        }
    };

    printf("Invalid AK name\n");
    testFun([&](DeriveKeyInput& input)
    {
        memset(&(input.AKName[0]), BAD_BYTE, sizeof input.AKName);
        return EXPECTED_RESULT_UNKNOWN;
    });
}

//ERP_GetTEEToken
TEST_F(erpInvalidDataTestsFixture, GetTEEToken)
{
    UIntInput genIn = {generationSaved};
    NONCEOutput NONCE = ERP_GenerateNONCE(m_logonSession, genIn);
    ASSERT_EQ(ERP_ERR_NOERROR, NONCE.returnCode);

    TEETokenRequestInput in{};
    TEETokenRequestInput inTest{};

    std::memcpy(&(in.AKName[0]), savedAKName.data(), TPM_NAME_LEN);
    in.QuoteDataLength = savedAttestationQuote.size();
    std::memcpy(&(in.QuoteData[0]), savedAttestationQuote.data(), savedAttestationQuote.size());
    in.QuoteSignatureLength = savedAttestationQuoteSignature.size();
    std::memcpy(&(in.QuoteSignature[0]), savedAttestationQuoteSignature.data(), savedAttestationQuoteSignature.size());
    in.KnownAKBlob = *savedTrustedAK;
    in.NONCEBlob = *savedAttestationNONCE;
    in.KnownQuoteBlob = *savedTrustedQuote;

    SingleBlobOutput output = ERP_GetTEEToken(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, output.returnCode);

    // the inTest struct will be set to "good" values before the call to the mutation lambda
    const auto testFun = [&](const std::function<unsigned int(TEETokenRequestInput&)>& f) {
        std::memcpy(&inTest, &in, sizeof(in));
        unsigned int expectedErr = f(inTest);
        output = ERP_GetTEEToken(m_logonSession, inTest);
        printf("Returned from ERP_GetTEEToken Command - Return Value: 0x%08x\n", output.returnCode);
        EXPECT_NE(ERP_ERR_NOERROR, output.returnCode) << "The return code is not an error";
        if (expectedErr != EXPECTED_RESULT_UNKNOWN)
        {
            EXPECT_EQ(expectedErr, output.returnCode);
        }
    };

    printf("Invalid blob type\n");
    testFun([&](TEETokenRequestInput& input)
    {
        input.KnownAKBlob = *savedTrustedEK;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });

    printf("Invalid blob type\n");
    testFun([&](TEETokenRequestInput& input)
    {
        input.NONCEBlob = *savedTrustedEK;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });

    printf("Wrong nonce\n");
    testFun([&](TEETokenRequestInput& input)
    {
        input.NONCEBlob = *savedTrustedEK;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });

    printf("Invalid blob type\n");
    testFun([&](TEETokenRequestInput& input)
    {
        input.KnownQuoteBlob = *savedTrustedEK;
        return ERP_ERR_WRONG_BLOB_TYPE;
    });

    printf("Invalid quote data length\n");
    testFun([&](TEETokenRequestInput& input)
    {
        input.QuoteDataLength -= TEST_LEN_CURTAILMENT;
        return E_ECDSA_VERIFY_FAILED;
    });

    printf("Invalid quote data length\n");
    testFun([&](TEETokenRequestInput& input)
    {
        input.QuoteDataLength = 0;
        return ERP_ERR_ASN1_CONTENT_ERROR;
    });

    printf("Invalid quote data\n");
    testFun([&](TEETokenRequestInput& input)
    {
        memset(&(input.QuoteData[0]), BAD_BYTE, MAX_BUFFER);
        return E_ECDSA_VERIFY_FAILED;
    });

    printf("Invalid quote signature length\n");
    testFun([&](TEETokenRequestInput& input)
    {
        input.QuoteSignatureLength -= TEST_LEN_CURTAILMENT;
        return ERP_ERR_BAD_TPMT_SIGNATURE_FORMAT;
    });

    printf("Invalid quote signature length\n");
    testFun([&](TEETokenRequestInput& input)
    {
        input.QuoteSignatureLength = 0;
        return ERP_ERR_ASN1_CONTENT_ERROR;
    });

    printf("Invalid quote signature\n");
    testFun([&](TEETokenRequestInput& input)
    {
        memset(&(input.QuoteSignature[0]), BAD_BYTE, MAX_BUFFER);
        return ERP_ERR_BAD_TPMT_SIGNATURE_FORMAT;
    });

    printf("Invalid AK name\n");
    testFun([&](TEETokenRequestInput& input)
    {
        memset(&(input.AKName[0]), BAD_BYTE, sizeof input.AKName);
        return ERP_ERR_TPM_NAME_MISMATCH;
    });
}

//ERP_GetECPublicKey
TEST_F(erpInvalidDataTestsFixture, GetECPublicKey)
{
    UIntInput inKp = { generationSaved };

    SingleBlobOutput outKPVAUSIG = ERP_GenerateVAUSIGKeyPair(m_logonSession, inKp);
    ASSERT_EQ(ERP_ERR_NOERROR, outKPVAUSIG.returnCode);
    SingleBlobOutput outKPECIES = ERP_GenerateECIESKeyPair(m_logonSession, inKp);
    ASSERT_EQ(ERP_ERR_NOERROR, outKPECIES.returnCode);

    SingleBlobInput in = { outKPVAUSIG.BlobOut };
    SingleBlobInput inTest{};

    auto output = ERP_GetECPublicKey(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, output.returnCode);

    in.BlobIn = outKPECIES.BlobOut;
    output = ERP_GetECPublicKey(m_logonSession, in);
    ASSERT_EQ(ERP_ERR_NOERROR, output.returnCode);

    // the inTest struct will be set to "good" values before the call to the mutation lambda
    const auto testFun = [&](const std::function<unsigned int(SingleBlobInput&)>& f)
    {
        std::memcpy(&inTest, &in, sizeof(in));
        unsigned int expectedErr = f(inTest);
        output = ERP_GetECPublicKey(m_logonSession, inTest);
        printf("Returned from ERP_GetECPublicKey Command - Return Value: 0x%08x\n", output.returnCode);
        EXPECT_NE(ERP_ERR_NOERROR, output.returnCode) << "The return code is not an error";
        if (expectedErr != EXPECTED_RESULT_UNKNOWN) {
            EXPECT_EQ(expectedErr, output.returnCode);
        }
    };

    printf("Invalid blob type for key\n");
    testFun([&](SingleBlobInput& input)
    {
        input.BlobIn = *savedAKChallenge1Blob;

        // TODO(chris): check if this should be ERP_ERR_WRONG_BLOB_TYPE
        //
        return ERP_ERR_KEY_USAGE_ERROR;
    });
}
