#ifndef ERP_TEST_BASE_H
#define ERP_TEST_BASE_H

#include "ERP_Client.h"
#include <gtest/gtest.h>

class ErpBaseTestsFixture : public ::testing::Test {
public:

    enum users {
        Setup=0, Working=1, Set1=2, Set2=3, Update=4
    };

    HSMSession m_logonSession;
    static const std::string devIP;

    ErpBaseTestsFixture();

    void connect();

    void logonSetup();

    void logonWorking();

    void logon(const std::vector<ErpBaseTestsFixture::users>& setOfUsers);

    void logoff();

    void SetUp() override;

    void TearDown() override;
};
#endif