#include "ERP_Client.h"
#include "ERP_SFC.h"
#include "ERP_Error.h"
#include "ERP_TestUtils.h"
#include "ERP_TestParams.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <fstream>
#include <thread>
#include <vector>

unsigned int teststep_GenerateBlobKey(HSMSession sesh, unsigned int gen);
unsigned int teststep_DeleteBlobKey(HSMSession sesh, unsigned int gen);

class ErpCommonTestsFixture : public ::testing::TestWithParam<HSMParameterSetFactory> {
public:
    HSMSession m_logonSession;
    static ERPBlob m_SavedTEEToken;

    ErpCommonTestsFixture() {
        // initialization code here
    }

    HSMParameterSet parameters;

    void connect(void)
    {
        HSMSessionFactory factory = parameters.SessionFactory;
        m_logonSession = factory();
    }
    void logonSetup() {
        m_logonSession = parameters.setupLogon(m_logonSession);
     }
    void logonWorking() {
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
    void SetUp() override {
        // code here will execute just before the test ensues 
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

    void TearDown() override {
        if (!parameters.TestEnabled)
        {
            return;
        }
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
        logoff();
        m_logonSession = ERP_Disconnect(m_logonSession);

        EXPECT_TRUE((m_logonSession.errorCode == ERP_ERR_NOERROR) ||
            (m_logonSession.errorCode == ERP_ERR_NO_CONNECTION));
    }
};

ERPBlob ErpCommonTestsFixture::m_SavedTEEToken = { 0,0,{'\0'} };

TEST_P(ErpCommonTestsFixture, ConnectTests)
{
    ;
    // TO DO - add tests trying to reuse a disconnected session.
    // TO DO - add tests for multi-threaded access.
    // TO DO - Try using a disconnected session for a working command.
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
    unsigned int             err = 0;

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
TEST_P(ErpCommonTestsFixture, Params_GenerateNONCE) {
    EXPECT_EQ(ERP_ERR_NOERROR, teststep_GenerateNONCE(ErpCommonTestsFixture::m_logonSession, 0));
    // I am assuming that our tests setup will not generate blob generation keys beypnd 0x1000
    // Use the STRIP_ERR_INDEX here to make sure it does not break the error code
    EXPECT_EQ(ERP_ERR_BAD_BLOB_GENERATION, STRIP_ERR_INDEX(teststep_GenerateNONCE(ErpCommonTestsFixture::m_logonSession, 0x1001)));
    EXPECT_EQ(ERP_ERR_BAD_BLOB_GENERATION, teststep_GenerateNONCE(ErpCommonTestsFixture::m_logonSession, 0xffffffff));
    // Just in case of signed/unsigned problems
    EXPECT_EQ(ERP_ERR_BAD_BLOB_GENERATION, teststep_GenerateNONCE(ErpCommonTestsFixture::m_logonSession, 0x7fffffff));
    teststep_ASN1IntegerInput(ErpCommonTestsFixture::m_logonSession,ERP_SFC_GENERATE_NONCE);
}

// Test to check Permissions for GenerateNONCE command.
TEST_P(ErpCommonTestsFixture, Permission_GenerateNONCE) {
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
    std::this_thread::sleep_for(std::chrono::minutes(16));
    if (m_logonSession.bIsCluster)
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
    UIntInput desiredBytes = { 32 };
    RNDBytesOutput rndOut = ERP_GetRNDBytes(ErpCommonTestsFixture::m_logonSession,desiredBytes);
    EXPECT_EQ(ERP_ERR_NOERROR, rndOut.returnCode);
    EXPECT_EQ(32, rndOut.RNDDataLen);
    // TO DO log rnd data here...
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
    desiredBytes.intValue = 42;
    rndOut = ERP_GetRNDBytes(ErpCommonTestsFixture::m_logonSession, desiredBytes);
    EXPECT_EQ(ERP_ERR_NOERROR, rndOut.returnCode);
    EXPECT_EQ(42, rndOut.RNDDataLen);
    // 64 bytes - ok
    desiredBytes.intValue = 64;
    rndOut = ERP_GetRNDBytes(ErpCommonTestsFixture::m_logonSession, desiredBytes);
    EXPECT_EQ(ERP_ERR_NOERROR, rndOut.returnCode);
    EXPECT_EQ(64, rndOut.RNDDataLen);
    // 320 bytes - ok
    desiredBytes.intValue = MAX_RND_BYTES;
    rndOut = ERP_GetRNDBytes(ErpCommonTestsFixture::m_logonSession, desiredBytes);
    EXPECT_EQ(ERP_ERR_NOERROR, rndOut.returnCode);
    EXPECT_EQ(MAX_RND_BYTES, rndOut.RNDDataLen);
    // 321 bytes - parm err.
    desiredBytes.intValue = MAX_RND_BYTES + 1;
    rndOut = ERP_GetRNDBytes(ErpCommonTestsFixture::m_logonSession, desiredBytes);
    EXPECT_EQ(ERP_ERR_PARAM, rndOut.returnCode);
    // to do - asn1 integer input tests - refactor from GenerateNONCE.
    teststep_ASN1IntegerInput(ErpCommonTestsFixture::m_logonSession, ERP_SFC_GET_RND_BYTES,false);
}

// Test to check Permissions for GetRNDBytes command.
TEST_P(ErpCommonTestsFixture, Permission_GetRNDBytes) {
    logoff();
    UIntInput desiredBytes = { 32 };
    RNDBytesOutput rndOut = ERP_GetRNDBytes(ErpCommonTestsFixture::m_logonSession, desiredBytes);
    EXPECT_EQ(ERP_ERR_PERMISSION_DENIED, rndOut.returnCode);
    EXPECT_EQ(0, rndOut.RNDDataLen);
    logoff();
    logonWorking();
    rndOut = ERP_GetRNDBytes(ErpCommonTestsFixture::m_logonSession, desiredBytes);
    EXPECT_EQ(ERP_ERR_NOERROR, rndOut.returnCode);
    EXPECT_EQ(32, rndOut.RNDDataLen);
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
    EXPECT_EQ(32, rndOut.RNDDataLen);
}

// Test to check MAximum number of simultaneous sessions
TEST_P(ErpCommonTestsFixture, MaxSessions) {
    // There is already one session open due to the framework.
    HSMSession session[MAX_HSM_SESSIONS];
    HSMSessionTestFactory testFactory = parameters.SessionTestFactory;
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

// Test to check MAximum number of simultaneous sessions
TEST_P(ErpCommonTestsFixture, MaxSessionsMultithread) {
    // There is already one session open due to the framework.
    std::vector<std::shared_ptr<std::thread>> threads = {};
    HSMSessionTestFactory testFactory = parameters.SessionTestFactory;
    for (int i = 0; i < (MAX_HSM_SESSIONS - 1) ; i++)
    {
        threads.push_back(testFactory()(parameters));
        std::cerr << "Created SessionTest Thread ID: " << threads.back()->get_id() << std::endl;
    }
    for (auto iter = threads.begin(); iter != threads.end() ; iter++)
    {
        (*(*iter)).join();
    }
    return;
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
