/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021
 * (C) Copyright IBM Corp. 2021
 * SPDX-License-Identifier: CC BY-NC-ND 3.0 DE
 **************************************************************************************************/

#include "ERP_TestParams.h"

#include "ERP_Client.h"
#include "ERP_Error.h"
#include "ERP_TestUtils.h"

#include <gtest/gtest.h>

#include <thread>

// return true here to enable tests for a single HW HSM.   The IP and other parameters must be set in 
// createSingleSimHSMParameterSetFactory()
bool isSingleSimulatedHSMConfigured()
{
    return true;
}

// return true here to enable tests for a cluster of simulated HSMs.   The IP and other parameters must be set in 
// createClusteredSimHSMParameterSetFactory()
// The hsm simulator setup for this can be found in firmware/HA/erp-hsm-ha.yaml
bool isClusteredSimulatedHSMConfigured()
{
    return false;
}

// return true here to enable tests for a single HW HSM.   The IP and other parameters must be set in 
// createSingleHardwareHSMParameterSetFactory()
// The hsm simulator setup for this can be found in firmware/HA/erp-two-hsms.yaml
bool isFailoverPairSimulatedHSMConfigured()
{
    return false;
}

// return true here to enable tests for a single HW HSM.   The IP and other parameters must be set in 
// createSingleHardwareHSMParameterSetFactory()
bool isSingleHardwareHSMConfigured()
{
    // Not Supported yet.
    return false;
}

// return true here to enable tests for a Cluster of HW HSMs.   The IP and other parameters must be set in 
// createSingleHardwareHSMParameterSetFactory()
bool isClusteredHardwareHSMConfigured()
{
    // Not Supported yet.
    return false;
}

HSMSession parametrisedLogon(HSMSession sesh,
                             bool bUsePassword,
                             const std::string& workUsername,
                             const std::string& keySpec,
                             const std::string& password)
{
    HSMSession retVal{};
    if (bUsePassword)
    {
        retVal = ERP_LogonPassword(sesh, workUsername.c_str(), password.c_str());
    }
    else
    {
        retVal = ERP_LogonKeySpec(sesh, workUsername.c_str(), keySpec.c_str(), password.c_str());
    }

    EXPECT_EQ(ERP_ERR_NOERROR, retVal.errorCode);
    EXPECT_EQ(HSMLoggedIn, retVal.status);

    return retVal;
}

HSMSession parametrisedLogoff(const HSMSession& sesh)
{
    HSMSession retVal = ERP_Logoff(sesh);
    EXPECT_EQ(HSMAnonymousOpen, retVal.status);

    return retVal;
}

// This utility method is designed to be a thread entry point to talk to the session 
//   passed in and do a minimal set of functions repeated a few times then exit.
std::thread::id threadedSessionTest(const HSMParameterSet& parameters)
{
    static const int testLoops = 10;

    HSMSession thisSesh = parameters.SessionFactory();
 
    thisSesh = parameters.workingLogon(thisSesh);
    // Cannot use ASSERT_EQ because it doesn't work in subsidiary functions
    EXPECT_EQ(HSMLoggedIn, thisSesh.status);
    EXPECT_EQ(ERP_ERR_NOERROR, thisSesh.errorCode);

    for (int i = 0; i < testLoops; i++)
    {
        // Just a few non-data dependent tests
        std::cerr << "ThreadedSessionTest Thread ID: "
                  << std::this_thread::get_id()
                  << " Starting Loop Iteration: "
                  << i << std::endl;
        
        EmptyOutput output = ERP_DumpHSMMemory(thisSesh);
        EXPECT_EQ(ERP_ERR_NOERROR, output.returnCode);

        // Use the STRIP_ERR_INDEX here to make sure it does not break the error code
        EXPECT_EQ(ERP_ERR_NOERROR, STRIP_ERR_INDEX(teststep_GenerateNONCE(thisSesh, 0)));
        static const UIntInput desiredBytes = { 32 };
        RNDBytesOutput rndOut = ERP_GetRNDBytes(thisSesh, desiredBytes);
        EXPECT_EQ(ERP_ERR_NOERROR, rndOut.returnCode);
        EXPECT_EQ(32, rndOut.RNDDataLen);
    }

    ERP_Disconnect(thisSesh);
    return std::this_thread::get_id();
}

HSMParameterSetFactory createSingleSimHSMParameterSetFactory()
{
    return []()
    {
        HSMParameterSet parameters{};

        parameters.ConfigName = "SingleSimulatedHSM";
        parameters.TestEnabled = isSingleSimulatedHSMConfigured();
        parameters.TestDataDirectory = "resources";
        parameters.StaticBlobDataDirectory = "saved";

        parameters.SessionFactory = []()
        {
            return ERP_Connect(SINGLE_SIM_HSM, TEST_CONNECT_TIMEOUT_MS, TEST_READ_TIMEOUT_MS);
        };

        parameters.SessionTestFactory = []()
        {
            return [](const auto& parameterSet)
            {
                return std::thread{threadedSessionTest, parameterSet};
            };
        };

        parameters.workingLogon = [](const HSMSession& sesh)
        {
            // user with permissions 00000020
            return parametrisedLogon(sesh, false, "ERP_KWRK", "resources/ERP_KWRK_keyfile.key", "RUTU");
        };

        parameters.setupLogon = [](const HSMSession& sesh)
        {
            // user with permissions 00000200
            return parametrisedLogon(sesh, true, "ERP_SETUP", "", "password");
        };

        parameters.logoff = [](const auto& sesh)
        {
            return parametrisedLogoff(sesh);
        };

        return parameters;
    };
}

HSMParameterSetFactory createClusterSimHSMParameterSetFactory()
{
    return []()
    {
        HSMParameterSet parameters{};

        parameters.ConfigName = "ClusteredSimulatedHSM";
        parameters.TestEnabled = isClusteredSimulatedHSMConfigured();
        parameters.TestDataDirectory = "resources";
        parameters.StaticBlobDataDirectory = "saved";

        parameters.SessionFactory = []()
        {
            // code here will execute just before the test ensues
            const char* devArray[] = CLUSTER_HSM; // 10 is maximum

            int NDevices = 0;
            while (devArray[NDevices] != nullptr && NDevices < MAX_CLUSTER_HSMS)
            {
                NDevices++;
            }

            EXPECT_LT(NDevices, MAX_CLUSTER_HSMS);
            devArray[NDevices] = nullptr;

            return ERP_ClusterConnect(&(devArray[0]),
                                      TEST_CONNECT_TIMEOUT_MS,
                                      TEST_READ_TIMEOUT_MS,
                                      TEST_RECONNECT_INTERVAL_MS);
        };

        parameters.SessionTestFactory = []()
        {
            return [](const auto& parameterSet)
            {
                return std::thread{threadedSessionTest, parameterSet};
            };
        };

        parameters.workingLogon = [](const auto& sesh)
        {
            // user with permissions 00000020
            return parametrisedLogon(sesh,
                                     false,
                                     "ERP_KWRK",
                                     "resources/ERP_KWRK_keyfile.key",
                                     "RUTU");
        };

        parameters.setupLogon = [](const auto& sesh)
        {
            // user with permissions 00000200
            return parametrisedLogon(sesh, true, "ERP_SETUP", "", "password");
        };

        parameters.logoff = [](const auto& sesh)
        {
            return parametrisedLogoff(sesh);
        };

        return parameters;
    };
}

HSMParameterSetFactory createFailoverPairSimHSMParameterSetFactory()
{
    return []()
    {
        HSMParameterSet parameters{};

        parameters.ConfigName = "FailoverPairOfSimulatedHSMs";
        parameters.TestEnabled = isFailoverPairSimulatedHSMConfigured();
        parameters.TestDataDirectory = "resources";
        parameters.StaticBlobDataDirectory = "saved";

        parameters.SessionFactory = []()
        {
            // code here will execute just before the test ensues
            const char* devArray[] = FAILOVER_PAIR_HSM; // 10 is maximum

            int NDevices = 0;
            while (devArray[NDevices] != nullptr && NDevices < MAX_CLUSTER_HSMS)
            {
                NDevices++;
            }

            EXPECT_LT(NDevices, 10);
            devArray[NDevices] = nullptr;

            return ERP_ClusterConnect(&(devArray[0]),
                                      TEST_CONNECT_TIMEOUT_MS,
                                      TEST_READ_TIMEOUT_MS,
                                      TEST_RECONNECT_INTERVAL_MS);
        };

        parameters.SessionTestFactory = []()
        {
            return [](const auto& parameterSet)
            {
                return std::thread{threadedSessionTest, parameterSet};
            };
        };

        parameters.workingLogon = [](const auto& sesh)
        {
            // user with permissions 00000020
            return parametrisedLogon(sesh, false, "ERP_KWRK", "resources/ERP_KWRK_keyfile.key", "RUTU");
        };

        parameters.setupLogon = [](const auto& sesh)
        {
            // user with permissions 00000200
            return parametrisedLogon(sesh, true, "ERP_SETUP", "", "password");
        };

        parameters.logoff = [](const auto& sesh)
        {
            return parametrisedLogoff(sesh);
        };

        return parameters;
    };
}
