HA Testing (High Availability) is done with parameterised versions of the base test suite.
There are three configurations supported in the testing:
1. A Single HSM Simulator on port 3001.   This can be running locally.   The checked in version on master should always only enable this configuration
2. A kubernetes cluster running a load balancer on port 3101 and 3102 connecting to a replica set of three HSM Simulators running in docker.
3. A kubernetes cluster running a pair of HSM simulators (dockerised), both individually available as services on 3103 and 3104 respectively.

These three configurations can be enabled or disabled using the following methods in ERP_TestParams.cpp
- isSingleSimulatedHSMConfigured()
- isClusteredSimulatedHSMConfigured()
- isFailoverPairSimulatedHSMConfigured()

Running with minikube on Windows, applying th eabove two yaml files and then starting minikube tunnl will set up the test environment for the second two configurations.
