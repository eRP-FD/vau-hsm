# (C) Copyright IBM Deutschland GmbH 2021, 2024
# (C) Copyright IBM Corp. 2021, 2024
#
# non-exclusively licensed to gematik GmbH

########################################################################################################################

find_package(csxapi REQUIRED)
find_package(asn1c REQUIRED)
find_package(GTest REQUIRED)
find_package(OpenSSL REQUIRED)

# list its source files
#
set(SOURCE_FILES "ERP_AttestTests.cpp"
                 "ERP_AUTTests.cpp"
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
                 "ERP_PseudonameKeyTests.cpp"
                 "ERP_WrapRawPayloadTests.cpp"
                 ERP_PseudonymLogKeyTests.cpp
                 ERP_ClusterTests.cpp
                 )

########################################################################################################################

add_executable(hsmclient-test ${SOURCE_FILES})
target_link_libraries(hsmclient-test
     PRIVATE GTest::gtest GTest::gtest_main OpenSSL::SSL OpenSSL::Crypto hsmclient
)
# define and configure the test target by specifying its name,
# list of targets that it tests and list of its own source files
#
configure_test_target(hsmclient-test hsmclient "${SOURCE_FILES}")


# make the resources needed by the test available at runtime
#
copy_test_resources(hsmclient-test)

########################################################################################################################
