/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021, 2024
 * (C) Copyright IBM Corp. 2021, 2024
 *
 * non-exclusively licensed to gematik GmbH
 **************************************************************************************************/

#include "ERP_Client.h"
#include "ERP_Error.h"
#include "ERP_SFC.h"
#include "ERP_TestUtils.h"
#include "ERP_TestsBase.h"

#include <gtest/gtest.h>

class erpSingleBlobKeyBackupTestsFixture : public ErpBaseTestsFixture {

public:

    // this blob key generation is only used for the create and delete calls.
    static const unsigned int generation = 0x55;

    void SetUp() override
    {
        ErpBaseTestsFixture::SetUp();

        unsigned int err = teststep_DeleteBlobKey(m_logonSession, generation);
        ASSERT_TRUE(err == ERP_ERR_NOERROR || err == ERP_ERR_UNKNOWN_BLOB_GENERATION);

        err = teststep_GenerateBlobKey(m_logonSession, generation);
        ASSERT_EQ(ERP_ERR_NOERROR, err);
    }

};

#define EXPECTED_RESULT_UNKNOWN 1

// This test does a basic backup and restore using the MBK which is assumed to be loaded into the HSM.
TEST_F(erpSingleBlobKeyBackupTestsFixture, BackupRestore)
{
    logonSetup();
    BUBlobOutput_t backupResult = { 0 , {0, {0},{0},{0},{0},0,{0}} };
    UIntInput intIn;
    intIn.intValue = generation;

    // First backup an existing blob generation.
    backupResult = ERP_ExportSingleBlobKey(m_logonSession, intIn);
    ASSERT_EQ(ERP_ERR_NOERROR, backupResult.returnCode);

    // Then try to restore it.
    EmptyOutput restoreResult = { 0 };
    BUBlobInput blobIn;
    blobIn.BUBlob = backupResult.BUBlob;

    restoreResult = ERP_ImportSingleBlobKey(m_logonSession, blobIn);
    // Should fail because Blob generation is already present in HSM.
    ASSERT_EQ(ERP_ERR_BAD_BLOB_GENERATION, restoreResult.returnCode);

    // Now delete the Blob Generation in the HSM and try to restore again.
    unsigned int err = teststep_DeleteBlobKey(m_logonSession, generation);
    ASSERT_TRUE(err == ERP_ERR_NOERROR);

    // Another attempt to restore the blob generation should now work.
    restoreResult = ERP_ImportSingleBlobKey(m_logonSession, blobIn);
    // Should fail because Blob generation is already present in HSM.
    ASSERT_EQ(ERP_ERR_NOERROR, restoreResult.returnCode);

    err = teststep_ListLoadedBlobKeys(m_logonSession);
    ASSERT_EQ(ERP_ERR_NOERROR, err);
    // To Do, add check that key is present again and has same hash as previously.
}
TEST_F(erpSingleBlobKeyBackupTestsFixture, UseRestoredKey)
{
    logonSetup();
    BUBlobOutput_t backupResult = { 0 , {0, {0},{0},{0},{0},0,{0}} };
    UIntInput intIn;
    intIn.intValue = generation;
    SingleBlobOutput hashBlobOut = { 0, {0,0,{}} };

    // Generate a blob using the key we are backing up.
    teststep_GenerateHashKey(m_logonSession, generation, &hashBlobOut);

    // Now we try to unwrap the hash key - it should fail.
    AES256KeyOutput firstKeyOut = { 0, {0} };
    teststep_UnwrapHashKey(m_logonSession, &hashBlobOut.BlobOut, &firstKeyOut);
    ASSERT_EQ(ERP_ERR_NOERROR, firstKeyOut.returnCode);

    // First backup an existing blob generation.
    backupResult = ERP_ExportSingleBlobKey(m_logonSession, intIn);
    ASSERT_EQ(ERP_ERR_NOERROR, backupResult.returnCode);

    // Then try to restore it.
    EmptyOutput restoreResult = { 0 };
    BUBlobInput blobIn;
    blobIn.BUBlob = backupResult.BUBlob;

    restoreResult = ERP_ImportSingleBlobKey(m_logonSession, blobIn);
    // Should fail because Blob generation is already present in HSM.
    ASSERT_EQ(ERP_ERR_BAD_BLOB_GENERATION, restoreResult.returnCode);

    // Now delete the Blob Generation in the HSM and try to restore again.
    unsigned int err = teststep_DeleteBlobKey(m_logonSession, generation);
    ASSERT_TRUE(err == ERP_ERR_NOERROR);

    // Now we try to unwrap the hash key - it should fail.
    AES256KeyOutput secondKeyOut = { 0, {0} };
    teststep_UnwrapHashKey(m_logonSession, &hashBlobOut.BlobOut, &secondKeyOut);
    ASSERT_EQ(ERP_ERR_BAD_BLOB_GENERATION, secondKeyOut.returnCode);

    // Another attempt to restore the blob generation should now work.
    restoreResult = ERP_ImportSingleBlobKey(m_logonSession, blobIn);
    ASSERT_EQ(ERP_ERR_NOERROR, restoreResult.returnCode);

    // Now we try to unwrap the hash key - it should work.
    AES256KeyOutput thirdKeyOut = { 0, {0} };
    teststep_UnwrapHashKey(m_logonSession, &hashBlobOut.BlobOut, &thirdKeyOut);
    ASSERT_EQ(ERP_ERR_NOERROR, thirdKeyOut.returnCode);
    ASSERT_EQ(0, memcmp(&(firstKeyOut.Key[0]), &(thirdKeyOut.Key[0]), AES_256_LEN));

    err = teststep_ListLoadedBlobKeys(m_logonSession);
    ASSERT_EQ(ERP_ERR_NOERROR, err);
    // To Do, add check that key is present again and has same hash as previously.
}
