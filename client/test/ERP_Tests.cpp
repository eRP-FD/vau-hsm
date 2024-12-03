/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021, 2024
 * (C) Copyright IBM Corp. 2021, 2024
 *
 * non-exclusively licensed to gematik GmbH
 **************************************************************************************************/

#include "ERP_Client.h"
#include "ERP_Error.h"
#include "ERP_SFC.h"
#include "ERP_TestParams.h"
#include "ERP_TestUtils.h"

#include <gtest/gtest.h>

#include <cstring>
#include <fstream>
#include <thread>
#include <vector>

class ErpCommonTestsFixture : public ::testing::TestWithParam<HSMParameterSetFactory> {
public:
    HSMSession m_logonSession{};
    HSMParameterSet parameters{};

    void connect()
    {
        HSMSessionFactory factory = parameters.SessionFactory;
        m_logonSession = factory();
    }

    void logonSetup()
    {
        m_logonSession = parameters.setupLogon(m_logonSession);
    }

    void logonWorking()
    {
        m_logonSession = parameters.workingLogon(m_logonSession);
    }

    void logoff()
    {
        if (m_logonSession.status == HSMLoggedIn)
        {
            m_logonSession = parameters.logoff(m_logonSession);
            ASSERT_EQ(HSMAnonymousOpen, m_logonSession.status);
        }
    }

    void SetUp() override
    {
        // This method is intended to be invoked for each test just before the test starts
        HSMParameterSetFactory factory = GetParam();
        parameters = factory();
        if (!parameters.TestEnabled)
        {
            return;
        }

        connect();
        EXPECT_EQ(HSMAnonymousOpen, m_logonSession.status);
        logonSetup();
        logonWorking();
    }

    void TearDown() override
    {
        if (!parameters.TestEnabled)
        {
            return;
        }

        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
        logoff();
        m_logonSession = ERP_Disconnect(m_logonSession);

        EXPECT_TRUE(m_logonSession.errorCode == ERP_ERR_NOERROR || m_logonSession.errorCode == ERP_ERR_NO_CONNECTION);
    }
};

TEST_P(ErpCommonTestsFixture, ConnectTests)
{
    ;
    // TODO(chris) - add tests trying to reuse a disconnected session.
    // TODO(chris) - add tests for multi-threaded access.
    // TODO(chris) - Try using a disconnected session for a working command.
    EXPECT_EQ(HSMLoggedIn, ErpCommonTestsFixture::m_logonSession.status);
    ErpCommonTestsFixture::m_logonSession = ERP_Logoff(ErpCommonTestsFixture::m_logonSession);
    EXPECT_EQ(HSMAnonymousOpen, ErpCommonTestsFixture::m_logonSession.status);
    ErpCommonTestsFixture::m_logonSession = ERP_Disconnect(ErpCommonTestsFixture::m_logonSession);
    EXPECT_EQ(HSMClosed, ErpCommonTestsFixture::m_logonSession.status);
    connect();
    EXPECT_EQ(HSMAnonymousOpen, ErpCommonTestsFixture::m_logonSession.status);
    logonSetup();
    EXPECT_EQ(HSMLoggedIn, ErpCommonTestsFixture::m_logonSession.status);
    ErpCommonTestsFixture::m_logonSession = ERP_Logoff(ErpCommonTestsFixture::m_logonSession);
    EXPECT_EQ(HSMAnonymousOpen, ErpCommonTestsFixture::m_logonSession.status);
    logonWorking();
    EXPECT_EQ(HSMLoggedIn, ErpCommonTestsFixture::m_logonSession.status);
}

TEST_P(ErpCommonTestsFixture, ConnectionTestMethod)
{
       EXPECT_EQ(ERP_ERR_NOERROR, teststep_DumpHSMMemory(ErpCommonTestsFixture::m_logonSession));
}
TEST_P(ErpCommonTestsFixture, ConnectionTestDirect)
{
    auto err = ERP_ERR_NOERROR;

    printf("\nExecuting DumpHSMMemory command ...\n");

    EmptyOutput output = ERP_DumpHSMMemory(ErpCommonTestsFixture::m_logonSession);
    EXPECT_EQ(ERP_ERR_NOERROR, output.returnCode);

    printf("Returned from DumpHSMMemory Command - Return Value: 0x%08x\n", output.returnCode);

    EXPECT_EQ(ERP_ERR_NOERROR, err);
}

TEST_P(ErpCommonTestsFixture, GenerateBlobKey)
{
    EXPECT_EQ(ERP_ERR_NOERROR, teststep_GenerateBlobKey(ErpCommonTestsFixture::m_logonSession, 0));
}

TEST_P(ErpCommonTestsFixture, ListLoadedBlobKeys)
{
    EXPECT_EQ(ERP_ERR_NOERROR, teststep_ListLoadedBlobKeys(ErpCommonTestsFixture::m_logonSession));
}

TEST_P(ErpCommonTestsFixture, DeleteBlobKey)
{ // The number used in this test must not be the highest in the HSM or a repeat of the test suite might fails
    unsigned int genRet = teststep_GenerateBlobKey(ErpCommonTestsFixture::m_logonSession, 3);
    EXPECT_TRUE((genRet == ERP_ERR_NOERROR) || (genRet == ERP_ERR_BAD_BLOB_GENERATION));
    EXPECT_EQ(ERP_ERR_NOERROR, teststep_ListLoadedBlobKeys(ErpCommonTestsFixture::m_logonSession));
    EXPECT_EQ(ERP_ERR_NOERROR, teststep_DeleteBlobKey(ErpCommonTestsFixture::m_logonSession, 3));
}

TEST_P(ErpCommonTestsFixture, GenerateNONCE)
{
    // Use the STRIP_ERR_INDEX here to make sure it does not break the error code
    EXPECT_EQ(ERP_ERR_NOERROR, STRIP_ERR_INDEX(teststep_GenerateNONCE(ErpCommonTestsFixture::m_logonSession, 0)));
}

// Test to exercise input parameter handling
TEST_P(ErpCommonTestsFixture, ParamsGenerateNONCE) {
    EXPECT_EQ(ERP_ERR_NOERROR, teststep_GenerateNONCE(ErpCommonTestsFixture::m_logonSession, 0));
    // I am assuming that our tests setup will not generate blob generation keys beypnd 0x1000
    // Use the STRIP_ERR_INDEX here to make sure it does not break the error code
    EXPECT_EQ(ERP_ERR_BAD_BLOB_GENERATION, STRIP_ERR_INDEX(teststep_GenerateNONCE(ErpCommonTestsFixture::m_logonSession, 0x1001)));
    EXPECT_EQ(ERP_ERR_BAD_BLOB_GENERATION, teststep_GenerateNONCE(ErpCommonTestsFixture::m_logonSession, TEST_MAX_UNSIGNED_GEN));
    // Just in case of signed/unsigned problems
    EXPECT_EQ(ERP_ERR_BAD_BLOB_GENERATION, teststep_GenerateNONCE(ErpCommonTestsFixture::m_logonSession, TEST_MAX_SIGNED_GEN));
    teststep_ASN1IntegerInput(ErpCommonTestsFixture::m_logonSession,ERP_SFC_GENERATE_NONCE);
}

// Test to check Permissions for GenerateNONCE command.
TEST_P(ErpCommonTestsFixture, PermissionGenerateNONCE) {
    logoff();
    EXPECT_EQ(ERP_ERR_PERMISSION_DENIED, teststep_GenerateNONCE(ErpCommonTestsFixture::m_logonSession, 0));
    logoff();
    logonWorking();
    EXPECT_EQ(ERP_ERR_NOERROR, teststep_GenerateNONCE(ErpCommonTestsFixture::m_logonSession, 0));
    logoff();
    logonSetup();
    EXPECT_EQ(ERP_ERR_NOERROR, teststep_GenerateNONCE(ErpCommonTestsFixture::m_logonSession, 0));
    logoff();
    logonSetup();
    logonWorking();
    EXPECT_EQ(ERP_ERR_NOERROR, teststep_GenerateNONCE(ErpCommonTestsFixture::m_logonSession, 0));
}

// Test to check behaviour after 15 minute HSM session timeout.
// Only run this test when explicitly wanting to check this functionality.   It takes too long.
// Cluster form of this test will not cause an error after the wait - the cluster impl automatically reconnects.
//TEST_P(ErpCommonTestsFixture, SessionTimeout) {
TEST_P(ErpCommonTestsFixture, DISABLED_SessionTimeout) {
    EXPECT_EQ(ERP_ERR_NOERROR, teststep_GenerateNONCE(ErpCommonTestsFixture::m_logonSession, 0));
    // 16 Minutes ....
    std::this_thread::sleep_for(std::chrono::minutes(16)); // NOLINT
    if (m_logonSession.bIsCluster != 0U)
    {
        EXPECT_EQ(ERP_ERR_NOERROR, teststep_GenerateNONCE(ErpCommonTestsFixture::m_logonSession, 0));
    }
    else {
        EXPECT_NE(ERP_ERR_NOERROR, teststep_GenerateNONCE(ErpCommonTestsFixture::m_logonSession, 0));
        m_logonSession = ERP_Disconnect(m_logonSession);
        connect();
        logonWorking();
    }
    EXPECT_EQ(ERP_ERR_NOERROR, teststep_GenerateNONCE(ErpCommonTestsFixture::m_logonSession, 0));
}

TEST_P(ErpCommonTestsFixture, GetRNDBytesTests)
{
    UIntInput desiredBytes = { RND_256_LEN };
    RNDBytesOutput rndOut = ERP_GetRNDBytes(ErpCommonTestsFixture::m_logonSession,desiredBytes);
    EXPECT_EQ(ERP_ERR_NOERROR, rndOut.returnCode);
    EXPECT_EQ(RND_256_LEN, rndOut.RNDDataLen);
    // 0 bytes - param err
    desiredBytes.intValue = 0;
    rndOut = ERP_GetRNDBytes(ErpCommonTestsFixture::m_logonSession, desiredBytes);
    EXPECT_EQ(ERP_ERR_PARAM, rndOut.returnCode);
    // 1 byte - ok
    desiredBytes.intValue = 1;
    rndOut = ERP_GetRNDBytes(ErpCommonTestsFixture::m_logonSession, desiredBytes);
    EXPECT_EQ(ERP_ERR_NOERROR, rndOut.returnCode);
    EXPECT_EQ(1, rndOut.RNDDataLen);
    // 42 bytes - not a multiple of 256 bits... - ok
    desiredBytes.intValue = THE_ANSWER;
    rndOut = ERP_GetRNDBytes(ErpCommonTestsFixture::m_logonSession, desiredBytes);
    EXPECT_EQ(ERP_ERR_NOERROR, rndOut.returnCode);
    EXPECT_EQ(THE_ANSWER, rndOut.RNDDataLen);
    // 64 bytes - ok
    const int Bytes64 = 64;
    desiredBytes.intValue = Bytes64;
    rndOut = ERP_GetRNDBytes(ErpCommonTestsFixture::m_logonSession, desiredBytes);
    EXPECT_EQ(ERP_ERR_NOERROR, rndOut.returnCode);
    EXPECT_EQ(Bytes64, rndOut.RNDDataLen);
    // 320 bytes - ok
    desiredBytes.intValue = MAX_RND_BYTES;
    rndOut = ERP_GetRNDBytes(ErpCommonTestsFixture::m_logonSession, desiredBytes);
    EXPECT_EQ(ERP_ERR_NOERROR, rndOut.returnCode);
    EXPECT_EQ(MAX_RND_BYTES, rndOut.RNDDataLen);
    // 321 bytes - parm err.
    desiredBytes.intValue = MAX_RND_BYTES + 1;
    rndOut = ERP_GetRNDBytes(ErpCommonTestsFixture::m_logonSession, desiredBytes);
    EXPECT_EQ(ERP_ERR_PARAM, rndOut.returnCode);
    // asn1 integer input tests - refactor from GenerateNONCE.
    teststep_ASN1IntegerInput(ErpCommonTestsFixture::m_logonSession, ERP_SFC_GET_RND_BYTES,false);
}

// Test to check Permissions for GetRNDBytes command.
TEST_P(ErpCommonTestsFixture, PermissionGetRNDBytes) {
    logoff();
    UIntInput desiredBytes = { RND_256_LEN };
    RNDBytesOutput rndOut = ERP_GetRNDBytes(ErpCommonTestsFixture::m_logonSession, desiredBytes);
    EXPECT_EQ(ERP_ERR_PERMISSION_DENIED, rndOut.returnCode);
    EXPECT_EQ(0, rndOut.RNDDataLen);
    logoff();
    logonWorking();
    rndOut = ERP_GetRNDBytes(ErpCommonTestsFixture::m_logonSession, desiredBytes);
    EXPECT_EQ(ERP_ERR_NOERROR, rndOut.returnCode);
    EXPECT_EQ(RND_256_LEN, rndOut.RNDDataLen);
    logoff();
    logonSetup();
    rndOut = ERP_GetRNDBytes(ErpCommonTestsFixture::m_logonSession, desiredBytes);
    EXPECT_EQ(ERP_ERR_PERMISSION_DENIED, rndOut.returnCode);
    EXPECT_EQ(0, rndOut.RNDDataLen);
    logoff();
    logonSetup();
    logonWorking();
    rndOut = ERP_GetRNDBytes(ErpCommonTestsFixture::m_logonSession, desiredBytes);
    EXPECT_EQ(ERP_ERR_NOERROR, rndOut.returnCode);
    EXPECT_EQ(RND_256_LEN, rndOut.RNDDataLen);
}

TEST_P(ErpCommonTestsFixture, FaultyCertificateTest1)
{
    const unsigned char certData[] =
    {
        0x30, 0x24,
        0x02, 0x01, THE_ANSWER,   // generation
        0x04, 0x1F,         // octet string
        0x30, 0x1d,         // cert
        0x30, 0x0a,         // tbsCertificate
        // ecdsaWithSHA256 (ANSI X9.62 ECDSA algorithm with SHA256)
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
        0x30, 0x09, // sigAlg
        // ecPublicKey (ANSI X9.62 public key type)
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
        0x03, 0x04, 0x00, 0x00, 0x00, 0x00  // sig
    };

    // for reference, a "real input"
    //  unsigned char certData[] = {0x30 ,0x82 ,0x01 ,0xEE ,0x02 ,0x01 ,0x00 ,0x04 ,0x82 ,0x01 ,0xE7 ,0x30 ,0x82 ,0x01 ,0xE3 ,0x30 ,0x82 ,0x01 ,0x89 ,0xA0 ,0x03 ,0x02 ,0x01 ,0x02 ,0x02 ,0x09 ,0x00 ,0xB5 ,0xFC ,0xF8 ,0xC5 ,0x4B ,0xDD ,0xD5 ,0xCF ,0x30 ,0x0A ,0x06 ,0x08 ,0x2A ,0x86 ,0x48 ,0xCE ,0x3D ,0x04 ,0x03 ,0x02 ,0x30 ,0x4E ,0x31 ,0x0B ,0x30 ,0x09 ,0x06 ,0x03 ,0x55 ,0x04 ,0x06 ,0x13 ,0x02 ,0x55 ,0x53 ,0x31 ,0x0B ,0x30 ,0x09 ,0x06 ,0x03 ,0x55 ,0x04 ,0x08 ,0x0C ,0x02 ,0x4E ,0x59 ,0x31 ,0x11 ,0x30 ,0x0F ,0x06 ,0x03 ,0x55 ,0x04 ,0x07 ,0x0C ,0x08 ,0x59 ,0x6F ,0x72 ,0x6B ,0x74 ,0x6F ,0x77 ,0x6E ,0x31 ,0x0C ,0x30 ,0x0A ,0x06 ,0x03 ,0x55 ,0x04 ,0x0A ,0x0C ,0x03 ,0x49 ,0x42 ,0x4D ,0x31 ,0x11 ,0x30 ,0x0F ,0x06 ,0x03 ,0x55 ,0x04 ,0x03 ,0x0C ,0x08 ,0x45 ,0x4B ,0x20 ,0x45 ,0x43 ,0x20 ,0x43 ,0x41 ,0x30 ,0x1E ,0x17 ,0x0D ,0x31 ,0x37 ,0x30 ,0x31 ,0x31 ,0x33 ,0x32 ,0x30 ,0x33 ,0x39 ,0x31 ,0x36 ,0x5A ,0x17 ,0x0D ,0x32 ,0x37 ,0x30 ,0x31 ,0x31 ,0x31 ,0x32 ,0x30 ,0x33 ,0x39 ,0x31 ,0x36 ,0x5A ,0x30 ,0x4E ,0x31 ,0x0B ,0x30 ,0x09 ,0x06 ,0x03 ,0x55 ,0x04 ,0x06 ,0x13 ,0x02 ,0x55 ,0x53 ,0x31 ,0x0B ,0x30 ,0x09 ,0x06 ,0x03 ,0x55 ,0x04 ,0x08 ,0x0C ,0x02 ,0x4E ,0x59 ,0x31 ,0x11 ,0x30 ,0x0F ,0x06 ,0x03 ,0x55 ,0x04 ,0x07 ,0x0C ,0x08 ,0x59 ,0x6F ,0x72 ,0x6B ,0x74 ,0x6F ,0x77 ,0x6E ,0x31 ,0x0C ,0x30 ,0x0A ,0x06 ,0x03 ,0x55 ,0x04 ,0x0A ,0x0C ,0x03 ,0x49 ,0x42 ,0x4D ,0x31 ,0x11 ,0x30 ,0x0F ,0x06 ,0x03 ,0x55 ,0x04 ,0x03 ,0x0C ,0x08 ,0x45 ,0x4B ,0x20 ,0x45 ,0x43 ,0x20 ,0x43 ,0x41 ,0x30 ,0x59 ,0x30 ,0x13 ,0x06 ,0x07 ,0x2A ,0x86 ,0x48 ,0xCE ,0x3D ,0x02 ,0x01 ,0x06 ,0x08 ,0x2A ,0x86 ,0x48 ,0xCE ,0x3D ,0x03 ,0x01 ,0x07 ,0x03 ,0x42 ,0x00 ,0x04 ,0x6A ,0x19 ,0xDF ,0xC6 ,0xE0 ,0x90 ,0xF8 ,0xDB ,0x0C ,0x70 ,0x32 ,0x1E ,0xF0 ,0x66 ,0x71 ,0x22 ,0x21 ,0x52 ,0x5F ,0xAE ,0x42 ,0x5C ,0x80 ,0xA4 ,0xEB ,0x37 ,0x37 ,0x34 ,0xB4 ,0x4F ,0x6C ,0xFB ,0xEA ,0x4E ,0x84 ,0x5D ,0x21 ,0xA9 ,0xDA ,0x3F ,0x5E ,0x13 ,0x4F ,0xA7 ,0xAE ,0xEF ,0xA1 ,0x64 ,0x34 ,0x3C ,0xDB ,0xB6 ,0xC6 ,0x3A ,0x3D ,0x23 ,0x20 ,0x54 ,0xD4 ,0xDE ,0x00 ,0x09 ,0xDF ,0x1A ,0xA3 ,0x50 ,0x30 ,0x4E ,0x30 ,0x1D ,0x06 ,0x03 ,0x55 ,0x1D ,0x0E ,0x04 ,0x16 ,0x04 ,0x14 ,0x01 ,0x64 ,0xA7 ,0x92 ,0xEE ,0xF1 ,0x9F ,0xA5 ,0x6B ,0x15 ,0x58 ,0x6A ,0x4F ,0x3F ,0x58 ,0x78 ,0x4B ,0xB0 ,0x6F ,0xA5 ,0x30 ,0x1F ,0x06 ,0x03 ,0x55 ,0x1D ,0x23 ,0x04 ,0x18 ,0x30 ,0x16 ,0x80 ,0x14 ,0x01 ,0x64 ,0xA7 ,0x92 ,0xEE ,0xF1 ,0x9F ,0xA5 ,0x6B ,0x15 ,0x58 ,0x6A ,0x4F ,0x3F ,0x58 ,0x78 ,0x4B ,0xB0 ,0x6F ,0xA5 ,0x30 ,0x0C ,0x06 ,0x03 ,0x55 ,0x1D ,0x13 ,0x04 ,0x05 ,0x30 ,0x03 ,0x01 ,0x01 ,0xFF ,0x30 ,0x0A ,0x06 ,0x08 ,0x2A ,0x86 ,0x48 ,0xCE ,0x3D ,0x04 ,0x03 ,0x02 ,0x03 ,0x48 ,0x00 ,0x30 ,0x45 ,0x02 ,0x20 ,0x43 ,0xD1 ,0x82 ,0x94 ,0x7D ,0xB8 ,0x63 ,0xD3 ,0x4F ,0xA4 ,0xA7 ,0x61 ,0xDC ,0x74 ,0xF0 ,0xB9 ,0xDA ,0xE3 ,0x60 ,0xF6 ,0x32 ,0x8C ,0xAF ,0x28 ,0xE4 ,0x74 ,0x3D ,0x73 ,0xC5 ,0xDC ,0xF5 ,0xE7 ,0x02 ,0x21 ,0x00 ,0xF4 ,0x36 ,0x02 ,0x23 ,0xD6 ,0x25 ,0x2F ,0x90 ,0x4C ,0xE0 ,0x36 ,0x85 ,0xD2 ,0xED ,0x43 ,0xF5 ,0x44 ,0x3D ,0x0C ,0xA4 ,0xA7 ,0x73 ,0xCB ,0x0A ,0x8C ,0xE5 ,0x1C ,0x8F ,0xD7 ,0x97 ,0x24 ,0x44};

    DirectIOInput rawInput;

    rawInput.SFCCode = ERP_SFC_TRUST_TPM_MFR;
    rawInput.DataLength = sizeof(certData);
    std::memcpy(&(rawInput.DataBody[0]), &(certData[0]), rawInput.DataLength);

    DirectIOOutput rawOutput = ERP_DirectIO(ErpCommonTestsFixture::m_logonSession, rawInput);

    /* this assumes that parsex509ECCertificate() fails after finding the both OIDs */
    EXPECT_EQ(ERP_ERR_CERT_BAD_SUBJECT_ALG, rawOutput.returnCode);

    /* also test this for  Enroll TPMEK */
    auto savedTrustedRoot = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/trustedRootSaved.blob"));
    auto savedTrustedEK = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/trustedEKSaved.blob"));
    EnrollTPMEKInput in = { 0,{0,0,""},0,"" };
    in.desiredGeneration = 0;
    in.TPMMfrBlob = *savedTrustedRoot;
    in.EKCertLength = sizeof(certData) - TEST_LEN_CURTAILMENT;
    memcpy(&(in.EKCertData[0]), &(certData[0]) + TEST_LEN_CURTAILMENT, in.EKCertLength);

    SingleBlobOutput output = ERP_EnrollTPMEK(ErpCommonTestsFixture::m_logonSession, in);
    EXPECT_EQ(ERP_ERR_CERT_BAD_SUBJECT_ALG, output.returnCode);
}

/* exchange both OIDs */
TEST_P(ErpCommonTestsFixture, FaultyCertificateTest2)
{
    const unsigned char certData[] =
    {
        0x30, 0x24,
        0x02, 0x01, THE_ANSWER,   // generation
        0x04, 0x1F,         // octet string
        0x30, 0x1d,         // cert
        0x30, 0x09,         // tbsCertificate
        // ecPublicKey (ANSI X9.62 public key type)
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
        0x30, 0x0a, // sigAlg
        // ecdsaWithSHA256 (ANSI X9.62 ECDSA algorithm with SHA256)
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
        0x03, 0x04, 0x00, 0x00, 0x00, 0x00  // sig
    };

    DirectIOInput rawInput;

    rawInput.SFCCode = ERP_SFC_TRUST_TPM_MFR;
    rawInput.DataLength = sizeof(certData);
    std::memcpy(&(rawInput.DataBody[0]), &(certData[0]), rawInput.DataLength);

    DirectIOOutput rawOutput = ERP_DirectIO(ErpCommonTestsFixture::m_logonSession, rawInput);

    /* this assumes that parsex509ECCertificate() fails after finding the both OIDs */
    EXPECT_EQ(ERP_ERR_CERT_BAD_SUBJECT_ALG, rawOutput.returnCode);

    /* also test this for  Enroll TPMEK */
    auto savedTrustedRoot = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/trustedRootSaved.blob"));
    auto savedTrustedEK = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/trustedEKSaved.blob"));
    EnrollTPMEKInput in = { 0,{0,0,""},0,"" };
    in.desiredGeneration = 0;
    in.TPMMfrBlob = *savedTrustedRoot;
    in.EKCertLength = sizeof(certData) - TEST_LEN_CURTAILMENT;
    memcpy(&(in.EKCertData[0]), &(certData[0]) + TEST_LEN_CURTAILMENT, in.EKCertLength);

    SingleBlobOutput output = ERP_EnrollTPMEK(ErpCommonTestsFixture::m_logonSession, in);
    EXPECT_EQ(ERP_ERR_CERT_BAD_SUBJECT_ALG, output.returnCode);
}

TEST_P(ErpCommonTestsFixture, FaultyCertificateTestInvalidASN1)
{
    const unsigned char certData[] =
    {
        0x30, 0x24,
        0x02, 0x01, THE_ANSWER,   // generation
        0x04, 0x1F,         // octet string
        // ERROR: changed length from 1d to 1c
        0x30, 0x1c,         // cert
        0x30, 0x0a,         // tbsCertificate
        // ecdsaWithSHA256 (ANSI X9.62 ECDSA algorithm with SHA256)
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
        0x30, 0x09, // sigAlg
        // ecPublicKey (ANSI X9.62 public key type)
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
        0x03, 0x04, 0x00, 0x00, 0x00, 0x00  // sig
    };

    DirectIOInput rawInput;

    rawInput.SFCCode = ERP_SFC_TRUST_TPM_MFR;
    rawInput.DataLength = sizeof(certData);
    std::memcpy(&(rawInput.DataBody[0]), &(certData[0]), rawInput.DataLength);

    DirectIOOutput rawOutput = ERP_DirectIO(ErpCommonTestsFixture::m_logonSession, rawInput);

    /* expect any Utimaco ASN1 Error Code (when decoding) */
    EXPECT_EQ(rawOutput.returnCode & E_ASN1_ALL, E_ASN1_ALL);

    /* also test this for  Enroll TPMEK */
    auto savedTrustedRoot = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/trustedRootSaved.blob"));
    auto savedTrustedEK = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/trustedEKSaved.blob"));
    EnrollTPMEKInput in = { 0,{0,0,""},0,"" };
    in.desiredGeneration = 0;
    in.TPMMfrBlob = *savedTrustedRoot;
    in.EKCertLength = sizeof(certData) - TEST_LEN_CURTAILMENT;
    memcpy(&(in.EKCertData[0]), &(certData[0]) + TEST_LEN_CURTAILMENT, in.EKCertLength);

    // expect ASN1 error as well
    SingleBlobOutput output = ERP_EnrollTPMEK(ErpCommonTestsFixture::m_logonSession, in);
    EXPECT_EQ(output.returnCode & E_ASN1_ALL, E_ASN1_ALL);
}

TEST_P(ErpCommonTestsFixture, FaultyCertificateTestInvalidASN12)
{
    const unsigned char certData[] =
    {
        0x30, 0x24,
        0x02, 0x01, THE_ANSWER,   // generation
        0x04, 0x1F,         // octet string
        0x30, 0x1d,         // cert
        0x30, 0x0a,         // tbsCertificate
        // ecdsaWithSHA256 (ANSI X9.62 ECDSA algorithm with SHA256)
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
        0x30, 0x09, // sigAlg
        // ecPublicKey (ANSI X9.62 public key type)
        // ERROR: Just cut if off somewhere
        0x06, 0x07, 0x2A, 0x86,// 0x48, 0xCE, 0x3D, 0x02, 0x01,
        0x03, 0x04, 0x00, 0x00, 0x00, 0x00  // sig*/
    };

    DirectIOInput rawInput;

    rawInput.SFCCode = ERP_SFC_TRUST_TPM_MFR;
    rawInput.DataLength = sizeof(certData);
    std::memcpy(&(rawInput.DataBody[0]), &(certData[0]), rawInput.DataLength);

    DirectIOOutput rawOutput = ERP_DirectIO(ErpCommonTestsFixture::m_logonSession, rawInput);

    /* expect any Utimaco ASN1 Error Code (when decoding) */
    EXPECT_EQ(rawOutput.returnCode & E_ASN1_ALL, E_ASN1_ALL);

    /* also test this for  Enroll TPMEK */
    auto savedTrustedRoot = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/trustedRootSaved.blob"));
    auto savedTrustedEK = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/trustedEKSaved.blob"));
    EnrollTPMEKInput in = { 0,{0,0,""},0,"" };
    in.desiredGeneration = 0;
    in.TPMMfrBlob = *savedTrustedRoot;
    in.EKCertLength = sizeof(certData) - TEST_LEN_CURTAILMENT;
    memcpy(&(in.EKCertData[0]), &(certData[0]) + TEST_LEN_CURTAILMENT, in.EKCertLength);

    // expect ASN1 error as well
    SingleBlobOutput output = ERP_EnrollTPMEK(ErpCommonTestsFixture::m_logonSession, in);
    EXPECT_EQ(output.returnCode & E_ASN1_ALL, E_ASN1_ALL);
}

// Test to check Maximum number of simultaneous sessions
TEST_P(ErpCommonTestsFixture, MaxSessionsSingleThread) {
    // There is already one session open due to the framework.
    HSMSession session[MAX_HSM_SESSIONS];
    int i = 0;
    for (i = 0; i < (MAX_HSM_SESSIONS - 1) ; i++)
    {
        session[i] = parameters.SessionFactory();
        session[i] = parameters.workingLogon(session[i]);
        static const UIntInput desiredBytes = { 32 };
        RNDBytesOutput rndOut = ERP_GetRNDBytes(session[i], desiredBytes);
        EXPECT_EQ(ERP_ERR_NOERROR, rndOut.returnCode);
    }
    for (i = 0; i < (MAX_HSM_SESSIONS - 1); i++)
    {
        session [i] = ERP_Disconnect(session[i]);
        EXPECT_TRUE((session[i].errorCode == ERP_ERR_NOERROR) ||
            (session[i].errorCode == ERP_ERR_NO_CONNECTION));
    }
}

// Test to check Maximum number of simultaneous sessions
TEST_P(ErpCommonTestsFixture, DISABLED_MaxSessionsMultithread) {
    // There is already one session open due to the framework.
    std::vector<std::thread> threads{};
    const auto testFactory = parameters.SessionTestFactory();
    for (int i = 0; i < (MAX_HSM_SESSIONS - 1) ; i++)
    {
        threads.emplace_back(testFactory(parameters));
        std::cerr << "Created SessionTest Thread ID: " << threads.back().get_id() << std::endl;
    }

    for (auto& thread : threads)
    {
        thread.join();
    }
}

INSTANTIATE_TEST_SUITE_P(
    SingleSimHSM,
    ErpCommonTestsFixture,
    testing::Values(createSingleSimHSMParameterSetFactory()),
    [](auto&) {return "SingleSimulatedHSM"; });

INSTANTIATE_TEST_SUITE_P(
    DISABLED_ClusteredSimHSM,
//    _ClusteredSimHSM,
    ErpCommonTestsFixture,
    testing::Values(createClusterSimHSMParameterSetFactory()),
    [](auto&) {return "ClusteredSimulatedHSM"; });

INSTANTIATE_TEST_SUITE_P(
    DISABLED_FailoverPairSimHSM,
//    FailoverPairSimHSM,
    ErpCommonTestsFixture,
    testing::Values(createFailoverPairSimHSMParameterSetFactory()),
    [](auto&) {return "FailoverPairOfSimulatedHSMs"; });
