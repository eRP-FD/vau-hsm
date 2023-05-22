/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021, 2023
 * (C) Copyright IBM Corp. 2021, 2023
 *
 * non-exclusively licensed to gematik GmbH
 **************************************************************************************************/

#include "ERP_Client.h"
#include "ERP_Error.h"
#include "ERP_SFC.h"
#include "ERP_TestUtils.h"
#include "ERP_TestsBase.h"

#include <gtest/gtest.h>

class erpBlobMigrationAndIdentityTestsFixture : public ErpBaseTestsFixture {

public:

    // this blob key generation is only used for the create and delete calls.
    static const unsigned int generation = 0x55;
    static std::unique_ptr<ERPBlob> savedStarterBlob;
    // For these tests we need one generation that we know is free to manipulate and
    //   at least one blob created for that generation
    void SetUp() override
    {
        ErpBaseTestsFixture::SetUp();

        unsigned int err = teststep_DeleteBlobKey(m_logonSession, generation);
        ASSERT_TRUE(err == ERP_ERR_NOERROR || err == ERP_ERR_UNKNOWN_BLOB_GENERATION);

        err = teststep_GenerateBlobKey(m_logonSession, generation);
        ASSERT_EQ(ERP_ERR_NOERROR, err);
        // Generation 0x42 is present in the standard startup HSM simulator.   We will not
        //   change it in these tests.
        UIntInput intIn = { THE_ANSWER };
        SingleBlobOutput blobOut = { 0, {0,0,{}} };

        blobOut = ERP_GenerateDerivationKey(m_logonSession, intIn);
        ASSERT_EQ(ERP_ERR_NOERROR, blobOut.returnCode);

        savedStarterBlob = std::make_unique<ERPBlob>();
        *savedStarterBlob = blobOut.BlobOut;

        ASSERT_NE(nullptr, savedStarterBlob.get());
    }
};

std::unique_ptr<ERPBlob> erpBlobMigrationAndIdentityTestsFixture::savedStarterBlob;

#define EXPECTED_RESULT_UNKNOWN 1

// This test does a basic backup and restore using the MBK which is assumed to be loaded into the HSM.
TEST_F(erpBlobMigrationAndIdentityTestsFixture, MigrateAndCheck)
{
    logonSetup();

    // First get a hash of our original blob
    SHA256Output firstHash = { 0,{0} };
    SingleBlobInput firstBlobIn = { 0,0,{} };
    firstBlobIn.BlobIn = *savedStarterBlob;
    firstHash = ERP_GetBlobContentHash(m_logonSession, firstBlobIn);
    ASSERT_EQ(ERP_ERR_NOERROR,firstHash.returnCode);

    SingleBlobOutput migratedOut = { 0,{0,0,{0}} };
    MigrateBlobInput_t migrateIn = { generation,{0,0,{0}} };
    migrateIn.BlobIn = *savedStarterBlob;
    migratedOut = ERP_MigrateBlob(m_logonSession, migrateIn);
    ASSERT_EQ(ERP_ERR_NOERROR, migratedOut.returnCode);

    // Now get a hash of our migrated blob
    SHA256Output migratedHash = { 0,{0} };
    SingleBlobInput migratedBlobIn = { 0,0,{} };
    migratedBlobIn.BlobIn = migratedOut.BlobOut;
    migratedHash = ERP_GetBlobContentHash(m_logonSession, migratedBlobIn);
    ASSERT_EQ(ERP_ERR_NOERROR, migratedHash.returnCode);
    ASSERT_EQ(0, memcmp(&(firstHash.hash[0]), &(migratedHash.hash[0]), SHA_256_LEN));

    logoff();
    logonWorking();
    SHA256Output workingHash = { 0,{0} };
    TwoBlobGetKeyInput workingBlobIn = {{ 0,0,{} },{ 0,0,{} }};
    workingBlobIn.Key = migratedOut.BlobOut;
    workingBlobIn.TEEToken = *teeToken;
    workingHash = ERP_GetBlobContentHashWithToken(m_logonSession, workingBlobIn);
    ASSERT_EQ(ERP_ERR_NOERROR, workingHash.returnCode);
    ASSERT_EQ(0, memcmp(&(firstHash.hash[0]), &(workingHash.hash[0]), SHA_256_LEN));

}
