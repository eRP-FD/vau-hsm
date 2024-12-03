/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021, 2024
 * (C) Copyright IBM Corp. 2021, 2024
 *
 * non-exclusively licensed to gematik GmbH
 **************************************************************************************************/

#ifndef ERP_TEST_PARAMS_H
#define ERP_TEST_PARAMS_H

#include "ERP_Client.h"

#include <string>
#include <functional>
#include <thread>

// Some useful device specs collected into a central location for easy customisation.
// Use 3001 if running simulator locally, 3103 to use one of the failover pair on kubernetes.
#define SINGLE_SIM_HSM "3001@localhost"
//#define SINGLE_SIM_HSM "3103@localhost"
#define CLUSTER_HSM {"3101@localhost","3102@localhost",NULL}
#define FAILOVER_PAIR_HSM {"3103@localhost","3104@localhost",NULL}
// I am assuming this will be a local port forward from whereves the HSM is actually located,
//   but it could be a direct IP if it is reachable.
#define HARDWARE_HSM "3021@localhost"

using HSMSessionFactory = std::function<HSMSession(void)>;

class HSMParameterSet;

// This is a test that will start a new thread, connect a session in it and
//   do some minimal HSM calls then disconnect the session
// The thread returned should not be destroyed until the thread has termianted - chaeck with join().
using HSMSessionTest = std::function<std::thread(HSMParameterSet &)>;
using HSMSessionTestFactory = std::function<HSMSessionTest()>;
using HSMLoggerOn = std::function<HSMSession(HSMSession &)>;
using HSMLoggerOff = std::function<HSMSession(HSMSession &)>;
class HSMParameterSet
{
public:
    std::string TestDataDirectory;
    std::string StaticBlobDataDirectory;
    std::string ConfigName;
    bool TestEnabled;
    HSMSessionFactory SessionFactory;
    HSMSessionTestFactory SessionTestFactory;
    HSMLoggerOn workingLogon;
    HSMLoggerOn setupLogon;
    HSMLoggerOff logoff;
};

using HSMParameterSetFactory = std::function<HSMParameterSet()>;
HSMParameterSetFactory createSingleSimHSMParameterSetFactory();
HSMParameterSetFactory createClusterSimHSMParameterSetFactory();
HSMParameterSetFactory createFailoverPairSimHSMParameterSetFactory();

#endif // ERP_TEST_PARAMS_H