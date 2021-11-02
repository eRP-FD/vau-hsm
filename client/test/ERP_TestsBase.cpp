#include "ERP_Client.h"
#include "ERP_Error.h"
#include "ERP_TestsBase.h"
#include "ERP_TestUtils.h"
#include "ERP_TestParams.h"

#include <fstream>

const std::string ErpBaseTestsFixture::devIP = SINGLE_SIM_HSM;

ErpBaseTestsFixture::ErpBaseTestsFixture()
{
    m_logonSession = {0, 0, 0, HSMUninitialised, 0, ERP_ERR_NOERROR, 0};
}

void ErpBaseTestsFixture::connect()
{
    // code here will execute just before the test ensues
    m_logonSession = ERP_Connect(devIP.c_str(), 5000, 1800000);
}

void ErpBaseTestsFixture::logonSetup()
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

void ErpBaseTestsFixture::logonWorking()
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

void ErpBaseTestsFixture::logoff()
{
    if (m_logonSession.status == HSMLoggedIn) {
        m_logonSession = ERP_Logoff(m_logonSession);
        ASSERT_EQ(HSMAnonymousOpen, m_logonSession.status);
    }
}

void ErpBaseTestsFixture::SetUp()
{
    // code here will execute just before the test ensues
    connect();
    EXPECT_EQ(HSMAnonymousOpen, m_logonSession.status);
    logonSetup();
    logonWorking();
}


void ErpBaseTestsFixture::TearDown()
{
    // code here will be called just after the test completes
    // ok to through exceptions from here if need be
    logoff();
    m_logonSession = ERP_Disconnect(m_logonSession);

    EXPECT_TRUE((m_logonSession.errorCode == ERP_ERR_NOERROR) ||
                (m_logonSession.errorCode == ERP_ERR_NO_CONNECTION));
}

void ErpBaseTestsFixture::logon(const std::vector<ErpBaseTestsFixture::users> &setOfUsers)
{
    static const char *userNames[] =
            {"ERP_SETUP", "ERP_WORK", "ERP_SET1", "ERP_SET2", "ERP_UPDT"};

    const static std::string password = "password";

    logoff();

    for (ErpBaseTestsFixture::users u: setOfUsers) {
        auto userName = userNames[u];

        printf("Logon user %s\n", userName);
        m_logonSession = ERP_LogonPassword(m_logonSession, userName, password.c_str());
        ASSERT_EQ(HSMLoggedIn, m_logonSession.status);
    }
}

