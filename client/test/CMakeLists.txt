# (C) Copyright IBM Deutschland GmbH 2021
# (C) Copyright IBM Corp. 2021
# SPDX-License-Identifier: CC BY-NC-ND 3.0 DE

########################################################################################################################

# define the name of a new test target
#
set(TARGET_NAME "hsmclient-test")

# list its source files
#
set(SOURCE_FILES "ERP_AttestTests.cpp"
                 "ERP_ECIESTests.cpp"
                 "ERP_Tests.cpp"
                 "ERP_TestsBase.cpp"
                 "ERP_PermissionsTests.cpp"
                 "ERP_InvalidDataTests.cpp"
                 "ERP_TestUtils.cpp"
                 "ERP_BasicInputTests.cpp"
                 "ERP_VAUSIGTests.cpp"
                 "ERP_HashKeyTests.cpp"
                 "ERP_RUAttestationTests.cpp"
                 "ERP_SingleBlobKeyBackupTests.cpp"
                 "ERP_BlobMigrationAndIdentityTests.cpp"
                 "ERP_TestParams.cpp"
                 "ERP_PseudonameKeyTests.cpp" )

# also list the targets under test (that the test target depends on)
#
set(TARGETS_UNDER_TEST "hsmclient")

########################################################################################################################

# define and configure the test target by specifying its name,
# list of targets that it tests and list of its own source files
#
configure_test_target(${TARGET_NAME} "${TARGETS_UNDER_TEST}" "${SOURCE_FILES}")

# make the resources needed by the test available at runtime
#
copy_test_resources(${TARGET_NAME})

########################################################################################################################
