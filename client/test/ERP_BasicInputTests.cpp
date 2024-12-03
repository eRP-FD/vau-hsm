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

#include "ERP_SealedBlobManipulator.h"

#include <cstring>

/*
 * Basic tests that test the API for correct behaviour in case of valid and invalid input.
 * This mostly entails tests for expected error codes and some sanity checks.
 * Does not test more complex behaviour (e.g. in-depth crypto tests).
 */
class ErpBasicInputTestsFixture : public ErpBaseTestsFixture
{
  public:

  void SetUp() override
  {
    ErpBaseTestsFixture::SetUp();
  }
};

TEST_F(ErpBasicInputTestsFixture, GetNonceInputTest)
{
  /* generate SMALL_LOOP Nonces for newest generation */
  NONCEOutput output;
  for(int i = 0; i < SMALL_LOOP; i++)
  {
    output = ERP_GenerateNONCE(ErpBasicInputTestsFixture::m_logonSession, {0});
    EXPECT_EQ(ERP_ERR_NOERROR, output.returnCode);
  }

  /* now check that the generation is really the newest generation in the HSM */
  BlobKeyListOutput blobKeyList = ERP_ListLoadedBlobKeys(ErpBasicInputTestsFixture::m_logonSession);
  bool foundBlobGeneration = false;
  for (int i = 0; i < blobKeyList.NumKeys; i++)
  {
    if(blobKeyList.Generations[i].Generation == output.BlobOut.BlobGeneration)
    {
      foundBlobGeneration = true;
    }
    EXPECT_LE(blobKeyList.Generations[i].Generation, output.BlobOut.BlobGeneration);
  }
  EXPECT_EQ(foundBlobGeneration, true);

  /* now generate a blob with an invalid generation */
  output = ERP_GenerateNONCE(ErpBasicInputTestsFixture::m_logonSession, {output.BlobOut.BlobGeneration + 1});
  EXPECT_EQ(ERP_ERR_BAD_BLOB_GENERATION, output.returnCode);
}

/*
 * This tests the firmware's parseSingleIntInput-method
 */
TEST_F(ErpBasicInputTestsFixture, GetNonceRawInputTests)
{
  DirectIOInput rawInput;
  rawInput.SFCCode = ERP_SFC_GENERATE_NONCE;

  const unsigned char invalidASN1Input1[] = { 0x30, 0x03, 0x08, 0x01, THE_ANSWER };
  std::memcpy(&(rawInput.DataBody[0]), &(invalidASN1Input1[0]), sizeof(invalidASN1Input1));
  rawInput.DataLength = sizeof(invalidASN1Input1);
  DirectIOOutput rawOutput = ERP_DirectIO(ErpBasicInputTestsFixture::m_logonSession, rawInput);
  EXPECT_EQ(rawOutput.returnCode, ERP_ERR_ASN1_CONTENT_ERROR);

  const unsigned char invalidASN1Input2[] = { 0x30, 0x06, 0x02, 0x01, THE_ANSWER, 0x02, 0x01, THE_ANSWER };
  std::memcpy(&(rawInput.DataBody[0]), &(invalidASN1Input2[0]), sizeof(invalidASN1Input2));
  rawInput.DataLength = sizeof(invalidASN1Input2);
  rawOutput = ERP_DirectIO(ErpBasicInputTestsFixture::m_logonSession, rawInput);
  EXPECT_EQ(rawOutput.returnCode, ERP_ERR_ASN1_CONTENT_ERROR);
}


TEST_F(ErpBasicInputTestsFixture, GenerateBlobKeyInputTests)
{
  /* generate 10 new generations */
  BlobKeyListOutput blobKeyListStart = ERP_ListLoadedBlobKeys(ErpBasicInputTestsFixture::m_logonSession);
  for(int i = 1; i <= SMALL_LOOP; i++)
  {
    UIntOutput genBlobKeyOutput = ERP_GenerateBlobKey(ErpBasicInputTestsFixture::m_logonSession, {0});
    EXPECT_EQ(ERP_ERR_NOERROR, genBlobKeyOutput.returnCode);

    /* check that it is created */
    BlobKeyListOutput blobKeyListCur = ERP_ListLoadedBlobKeys(ErpBasicInputTestsFixture::m_logonSession);
    EXPECT_EQ(blobKeyListCur.NumKeys, blobKeyListStart.NumKeys + i);

    /* check that key is not in the old list already */
    for(int j = 0; j < blobKeyListStart.NumKeys; j++)
    {
      EXPECT_NE(blobKeyListStart.Generations[j].Generation, genBlobKeyOutput.intValue);
    }
  }

  /* now generate invalid (existing) generation */
  EXPECT_EQ(ERP_ERR_BAD_BLOB_GENERATION, ERP_GenerateBlobKey(ErpBasicInputTestsFixture::m_logonSession, {blobKeyListStart.Generations[0].Generation}).returnCode);
}


TEST_F(ErpBasicInputTestsFixture, GenerateBlobKeyInputTestsFillMax)
{
  UIntOutput output = {ERP_ERR_NOERROR, 0};
  std::vector<unsigned int> added_generations = {};
  while(output.returnCode == ERP_ERR_NOERROR)
  {
    output = ERP_GenerateBlobKey(ErpBasicInputTestsFixture::m_logonSession, {0});
    if(output.returnCode == ERP_ERR_NOERROR)
    {
      added_generations.push_back(output.intValue);
    }
  }

  EXPECT_EQ(output.returnCode, ERP_ERR_MAX_BLOB_GENERATIONS);

  for(unsigned gen : added_generations)
  {
    // remove the keys again s.t. future tests remain functional
    UIntInput deleteGen = {gen};
    EmptyOutput delOut = ERP_DeleteBlobKey(ErpBasicInputTestsFixture::m_logonSession, deleteGen);
    EXPECT_EQ(delOut.returnCode, ERP_ERR_NOERROR);
  }

  printf("number of keys added and deleted: %u\n", static_cast<unsigned int>(added_generations.size()));
}


TEST_F(ErpBasicInputTestsFixture, deleteBlobKeyInputTests)
{
  const unsigned int ERR_E_ERP_UNKNOWN_BLOB_GENERATION = 0xB101000B;      // Blob Generation does not match any loaded key.

  /* make sure there are at least SMALL_LOOP keys */
  BlobKeyListOutput blobKeyList = ERP_ListLoadedBlobKeys(ErpBasicInputTestsFixture::m_logonSession);
  while(blobKeyList.NumKeys < SMALL_LOOP)
  {
    ERP_GenerateBlobKey(ErpBasicInputTestsFixture::m_logonSession, {0});
  }

  /* delete the first SMALL_LOOP keys */
  BlobKeyListOutput blobKeyListStart = ERP_ListLoadedBlobKeys(ErpBasicInputTestsFixture::m_logonSession);
  for(int i = 0; i < SMALL_LOOP; i++)
  {
    UIntInput deleteGen = {blobKeyListStart.Generations[i].Generation};

    EmptyOutput output = ERP_DeleteBlobKey(ErpBasicInputTestsFixture::m_logonSession, deleteGen);
    EXPECT_EQ(output.returnCode, ERP_ERR_NOERROR);

    /* check that it is deleted  */
    BlobKeyListOutput blobKeyListCur = ERP_ListLoadedBlobKeys(ErpBasicInputTestsFixture::m_logonSession);
    EXPECT_EQ(blobKeyListCur.NumKeys, blobKeyListStart.NumKeys - (i+1));

    /* check that the key really is not present in the new list */
    for(int j = 0; j < blobKeyListCur.NumKeys; j++)
    {
      EXPECT_NE(blobKeyListCur.Generations[j].Generation, deleteGen.intValue);
    }
  }

  /* now delete an invalid (non-existing) generation */
  EXPECT_EQ(ERR_E_ERP_UNKNOWN_BLOB_GENERATION, ERP_DeleteBlobKey(ErpBasicInputTestsFixture::m_logonSession, {blobKeyListStart.Generations[0].Generation}).returnCode);
}


/*
 * some functions are the same on an abstract level:
 * here the tests get the generation as input and output a (key) blob.
 */
TEST_F(ErpBasicInputTestsFixture, generateBlobWithGenerationInputBlobOutput)
{
  /*
   * Generate Blobs for the 10 first generations
   */

  std::vector<SingleBlobOutput(*)(HSMSession, UIntInput)> funcs =
    {
      &ERP_GenerateHashKey,
      &ERP_GenerateDerivationKey,
      &ERP_GenerateECIESKeyPair,
      &ERP_GenerateVAUSIGKeyPair
    };

  for(auto ERP_toTestFunc : funcs)
  {
    /* make sure there are at least SMALL_LOOP keys */
    BlobKeyListOutput blobKeyList = ERP_ListLoadedBlobKeys(ErpBasicInputTestsFixture::m_logonSession);
    while(blobKeyList.NumKeys < SMALL_LOOP)
    {
      ERP_GenerateBlobKey(ErpBasicInputTestsFixture::m_logonSession, {0});
    }

    UIntInput inGen;
    for(int i = 0; i < SMALL_LOOP; i++)
    {
      inGen.intValue = blobKeyList.Generations[i].Generation;

      SingleBlobOutput output = ERP_toTestFunc(m_logonSession, inGen);
      ASSERT_EQ(output.returnCode, ERP_ERR_NOERROR);
      ASSERT_EQ(output.BlobOut.BlobGeneration, inGen.intValue);
    }

    /* generate hash key for invalid generation */
    for(int i = 0; i < blobKeyList.NumKeys; i++)
    {
      inGen.intValue = std::max(inGen.intValue, blobKeyList.Generations[i].Generation + 1);
    }
    EXPECT_EQ(ERP_ERR_BAD_BLOB_GENERATION, ERP_toTestFunc(ErpBasicInputTestsFixture::m_logonSession, inGen).returnCode);
  }
}

TEST_F(ErpBasicInputTestsFixture, ERPGenerateECCSRInputTests) // DISABLED until Github Issue 72 is resolved
{
  /* valid inputs */
  GetVAUCSRInput eciesCSR = { {0,0,{0}}, 0, {0} };
  eciesCSR.KeyPair = *savedECIESKeyPairBlob;

  auto candidateCSR = readERPResourceFile("candidateECIES.csr");
  ASSERT_GT(candidateCSR.size(), 0);
  eciesCSR.candidateCSRLength = candidateCSR.size();
  memcpy(&(eciesCSR.candidateCSR[0]), candidateCSR.data(), candidateCSR.size());

  x509CSROutput keyOut = { 0,0,{0} };

  /* first do a run with valid input */
  keyOut = ERP_GenerateECIESCSR(ErpBasicInputTestsFixture::m_logonSession, eciesCSR);
  ASSERT_EQ(ERP_ERR_NOERROR, keyOut.returnCode);

  /* now tests invalid sealed blobs */
  GetVAUCSRInput eciesCSR_sealedBlobs = eciesCSR;
  SealedBlobManipulator sealedBlobManipulator(eciesCSR_sealedBlobs.KeyPair);
  std::vector<SealedBlobManipulator::sealedBlobManipulation_t> manipulationOutput = sealedBlobManipulator.getManipulations();
  for (const auto& manipulation : manipulationOutput)
  {
    SCOPED_TRACE("SealedBlobManipulator test failed: " + manipulation.TestName);
    eciesCSR_sealedBlobs.KeyPair = manipulation.blob;
    x509CSROutput out = ERP_GenerateECIESCSR(ErpBasicInputTestsFixture::m_logonSession, eciesCSR_sealedBlobs);
    if(manipulation.expectErrVar == SealedBlobManipulator::EXPECT_ERR_EQ)
    {
      EXPECT_EQ(out.returnCode, manipulation.expectErr);
    }
    else
    {
      EXPECT_NE(out.returnCode, manipulation.expectErr);
    }
  }

  /* try invalid inputs
   * It's not necessary to check everything,
   * for example SealedBlobs or invalid ASN.1 Certificate structures are already checked in other tests
   */
  GetVAUCSRInput eciesCSR_invalid;

  eciesCSR_invalid = eciesCSR;
  eciesCSR_invalid.KeyPair.BlobGeneration += 999; // NOLINT
  keyOut = ERP_GenerateECIESCSR(ErpBasicInputTestsFixture::m_logonSession, eciesCSR_invalid);
  EXPECT_NE(ERP_ERR_BAD_BLOB_GENERATION, keyOut.returnCode);

  eciesCSR_invalid = eciesCSR;
  eciesCSR_invalid.candidateCSRLength = 0;
  keyOut = ERP_GenerateECIESCSR(ErpBasicInputTestsFixture::m_logonSession, eciesCSR_invalid);
  EXPECT_EQ(ERP_ERR_ASN1_CONTENT_ERROR, keyOut.returnCode);
}


// ERP_GenerateVAUSIGCSR: ERP_GenerateECCSR_InputTests

// ERP_TrustTPMMfr: Mostly Checked with other tests, can do raw/crypto tests

TEST_F(ErpBasicInputTestsFixture, ERPEnrollTPMEKInputTests) // DISABLED until Github Issue 72 is resolved
{
  /* first, valid test */
  auto pEKCert = readERPResourceFile("EKCertECC.crt");
  auto pNewTrustedEK = getEmptyBlob(generationSaved);
  auto err = teststep_EnrollTPMEK(
    m_logonSession,
    generationSaved,
    ErpBasicInputTestsFixture::savedTrustedRoot.get(),
    pNewTrustedEK.get(),
    pEKCert.size(),
    pEKCert.data());
  ASSERT_EQ(ERP_ERR_NOERROR, err);

  /* now tests invalid sealed blobs */
  ERPBlob trustedRoot = *ErpBasicInputTestsFixture::savedTrustedRoot;
  SealedBlobManipulator sealedBlobManipulator(trustedRoot);
  std::vector<SealedBlobManipulator::sealedBlobManipulation_t> manipulationOutput = sealedBlobManipulator.getManipulations();
  for (const auto& manipulation : manipulationOutput)
  {
    SCOPED_TRACE("SealedBlobManipulator test failed: " + manipulation.TestName);
    trustedRoot = manipulation.blob;
    err = teststep_EnrollTPMEK(
      m_logonSession,
      generationSaved,
      &trustedRoot,
      pNewTrustedEK.get(),
      pEKCert.size(),
      pEKCert.data());
    if(manipulation.expectErrVar == SealedBlobManipulator::EXPECT_ERR_EQ)
    {
      EXPECT_EQ(err, manipulation.expectErr);
    }
    else
    {
      EXPECT_NE(err, manipulation.expectErr);
    }
  }

  /* wrong generation */
  err = teststep_EnrollTPMEK(
    m_logonSession,
    999, // NOLINT
    ErpBasicInputTestsFixture::savedTrustedRoot.get(),
    pNewTrustedEK.get(),
    pEKCert.size(),
    pEKCert.data());
  EXPECT_EQ(ERP_ERR_BAD_BLOB_GENERATION, err);
}

TEST_F(ErpBasicInputTestsFixture, ERPGetAKChallengeInputTests) // DISABLED until Github Issue 72 is resolved
{
  std::vector<unsigned char> AKname;
  AKChallengeInput in = { 0,{0},{0,0,{0}},0,{0} };
  AKChallengeOutput output;

  // inputs
  auto pAKName = savedAKName;
  auto pAKPub = savedAKPub;

  /* valid data */
  AKname.clear();
  std::copy(pAKName.begin(), pAKName.end(), std::back_inserter(AKname));
  in = { 0,{0},{0,0,{0}},0,{0} };
  in.desiredGeneration = generationSaved;
  in.KnownEKBlob = *savedTrustedEK;
  in.AKPubLength = pAKPub.size()-2;
  std::memcpy(&(in.AKName[0]), AKname.data(), TPM_NAME_LEN);
  std::memcpy(&(in.AKPubData[0]), pAKPub.data()+2, in.AKPubLength);
  output = ERP_GetAKChallenge(ErpBasicInputTestsFixture::m_logonSession, in);
  EXPECT_EQ(ERP_ERR_NOERROR, output.returnCode);
  EXPECT_EQ(output.ChallengeBlob.BlobGeneration, in.desiredGeneration);

  /* now tests invalid sealed blobs */
  AKChallengeInput in_sealedBlobTest = in;
  SealedBlobManipulator sealedBlobManipulator(in_sealedBlobTest.KnownEKBlob);
  std::vector<SealedBlobManipulator::sealedBlobManipulation_t> manipulationOutput = sealedBlobManipulator.getManipulations();
  for (const auto& manipulation : manipulationOutput)
  {
    SCOPED_TRACE("SealedBlobManipulator test failed: " + manipulation.TestName);
    in_sealedBlobTest.KnownEKBlob = manipulation.blob;
    output = ERP_GetAKChallenge(ErpBasicInputTestsFixture::m_logonSession, in_sealedBlobTest);
    if(manipulation.expectErrVar == SealedBlobManipulator::EXPECT_ERR_EQ)
    {
      EXPECT_EQ(output.returnCode, manipulation.expectErr);
    }
    else
    {
      EXPECT_NE(output.returnCode, manipulation.expectErr);
    }
  }


  /* valid data (2): check newest generation */
  BlobKeyListOutput blobKeyList = ERP_ListLoadedBlobKeys(ErpBasicInputTestsFixture::m_logonSession);
  unsigned maxBlobGen = 0;
  for(int i = 0; i < blobKeyList.NumKeys; i++)
  {
    maxBlobGen = std::max(blobKeyList.Generations[i].Generation, maxBlobGen);
  }
  AKname.clear();
  std::copy(pAKName.begin(), pAKName.end(), std::back_inserter(AKname));
  in = { 0,{0},{0,0,{0}},0,{0} };
  in.desiredGeneration = 0;
  in.KnownEKBlob = *savedTrustedEK;
  in.AKPubLength = pAKPub.size()-2;
  std::memcpy(&(in.AKName[0]), AKname.data(), TPM_NAME_LEN);
  std::memcpy(&(in.AKPubData[0]), pAKPub.data()+2, in.AKPubLength);
  output = ERP_GetAKChallenge(ErpBasicInputTestsFixture::m_logonSession, in);
  EXPECT_EQ(ERP_ERR_NOERROR, output.returnCode);
  EXPECT_EQ(output.ChallengeBlob.BlobGeneration, maxBlobGen);


  /* invalid generation */
  AKname.clear();
  std::copy(pAKName.begin(), pAKName.end(), std::back_inserter(AKname));
  in = { 0,{0},{0,0,{0}},0,{0} };
  in.desiredGeneration = generationSaved + 999; // NOLINT
  in.KnownEKBlob = *savedTrustedEK;
  in.AKPubLength = pAKPub.size()-2;
  std::memcpy(&(in.AKName[0]), AKname.data(), TPM_NAME_LEN);
  std::memcpy(&(in.AKPubData[0]), pAKPub.data()+2, in.AKPubLength);
  output = ERP_GetAKChallenge(ErpBasicInputTestsFixture::m_logonSession, in);
  EXPECT_EQ(ERP_ERR_BAD_BLOB_GENERATION, output.returnCode);


  /* invalid AK Name: Hash bytes wrong */
  AKname.clear();
  std::copy(pAKName.begin(), pAKName.end(), std::back_inserter(AKname));
  AKname[0] += 1;
  in = { 0,{0},{0,0,{0}},0,{0} };
  in.desiredGeneration = generationSaved;
  in.KnownEKBlob = *savedTrustedEK;
  in.AKPubLength = pAKPub.size()-2;
  std::memcpy(&(in.AKName[0]), AKname.data(), TPM_NAME_LEN);
  std::memcpy(&(in.AKPubData[0]), pAKPub.data()+2, in.AKPubLength);
  output = ERP_GetAKChallenge(ErpBasicInputTestsFixture::m_logonSession, in);
  EXPECT_EQ(ERP_ERR_BAD_TPM_NAME_ALGORITHM, output.returnCode);

  /* invalid AK Name: wrong hash  */
  AKname.clear();
  std::copy(pAKName.begin(), pAKName.end(), std::back_inserter(AKname));
  AKname[3] += 1;
  in = { 0,{0},{0,0,{0}},0,{0} };
  in.desiredGeneration = generationSaved;
  in.KnownEKBlob = *savedTrustedEK;
  in.AKPubLength = pAKPub.size()-2;
  std::memcpy(&(in.AKName[0]), AKname.data(), TPM_NAME_LEN);
  std::memcpy(&(in.AKPubData[0]), pAKPub.data()+2, in.AKPubLength);
  output = ERP_GetAKChallenge(ErpBasicInputTestsFixture::m_logonSession, in);
  EXPECT_EQ(ERP_ERR_TPM_NAME_MISMATCH, output.returnCode);


  /* invalid AK Name: wrong hash (2) */
  AKname.clear();
  std::copy(pAKName.begin(), pAKName.end(), std::back_inserter(AKname));
  AKname[33] = 0x00; // NOLINT
  in = { 0,{0},{0,0,{0}},0,{0} };
  in.desiredGeneration = generationSaved;
  in.KnownEKBlob = *savedTrustedEK;
  in.AKPubLength = pAKPub.size() - 2;
  std::memcpy(&(in.AKName[0]), AKname.data(), TPM_NAME_LEN);
  std::memcpy(&(in.AKPubData[0]), pAKPub.data()+2, in.AKPubLength);
  output = ERP_GetAKChallenge(ErpBasicInputTestsFixture::m_logonSession, in);
  EXPECT_EQ(ERP_ERR_TPM_NAME_MISMATCH, output.returnCode);
}

/* TODO(chris): "raw" (DirectIO) ERP_GetAKChallenge_InputTests? e.g. send too short AKName, mess with AKPub etc */

// ERP_EnrollTPMAK: Mostly Checked with other tests, can do raw/crypto tests

// ERP_EnrollTPMEK: Mostly Checked with other tests, can do raw/crypto tests

// ERP_EnrollEnclave: Mostly checked with other tests, can do raw/crypto tests

TEST_F(ErpBasicInputTestsFixture, ERPGetTEETokenInputTests) // DISABLED until Github Issue 72 is resolved
{
  TEETokenRequestInput in = { {'\0'},{0,0,{'\0'}},{0,0,{'\0'}},{0,0,{'\0'}},0,{'\0'} ,0,{'\0'} };

  /* valid */
  memcpy(&(in.AKName[0]), savedAKName.data(), TPM_NAME_LEN);
  in.QuoteDataLength = savedAttestationQuote.size();
  memcpy(&(in.QuoteData[0]), savedAttestationQuote.data(), savedAttestationQuote.size());
  in.QuoteSignatureLength = savedAttestationQuoteSignature.size();
  memcpy(&(in.QuoteSignature[0]), savedAttestationQuoteSignature.data(), savedAttestationQuoteSignature.size());
  in.KnownAKBlob = *savedTrustedAK;
  in.NONCEBlob = *savedAttestationNONCE;
  in.KnownQuoteBlob = *savedTrustedQuote;
  SingleBlobOutput output = ERP_GetTEEToken(ErpBasicInputTestsFixture::m_logonSession, in);
  EXPECT_EQ(ERP_ERR_NOERROR, output.returnCode);

  /* check that the returned blob has newest generation */
  BlobKeyListOutput blobKeyList = ERP_ListLoadedBlobKeys(ErpBasicInputTestsFixture::m_logonSession);
  unsigned maxBlobGen = 0;
  for(int i = 0; i < blobKeyList.NumKeys; i++)
  {
    maxBlobGen = std::max(blobKeyList.Generations[i].Generation, maxBlobGen);
  }
  EXPECT_EQ(output.BlobOut.BlobGeneration, maxBlobGen);

  /* now tests invalid sealed blobs */
  // TODO(chris): probably best to use a lambda function for 3 times copied code
  TEETokenRequestInput in_sealedBlobTest = in;
  SealedBlobManipulator sealedBlobManipulator(in_sealedBlobTest.KnownAKBlob);
  std::vector<SealedBlobManipulator::sealedBlobManipulation_t> manipulationOutput = sealedBlobManipulator.getManipulations();
  for (const auto& manipulation : manipulationOutput)
  {
    SCOPED_TRACE("SealedBlobManipulator test failed: " + manipulation.TestName);
    in_sealedBlobTest.KnownAKBlob = manipulation.blob;
    output = ERP_GetTEEToken(ErpBasicInputTestsFixture::m_logonSession, in_sealedBlobTest);
    if(manipulation.expectErrVar == SealedBlobManipulator::EXPECT_ERR_EQ)
    {
      EXPECT_EQ(output.returnCode, manipulation.expectErr);
    }
    else
    {
      EXPECT_NE(output.returnCode, manipulation.expectErr);
    }
  }
  in_sealedBlobTest = in;
  sealedBlobManipulator = SealedBlobManipulator(in_sealedBlobTest.KnownQuoteBlob);
  manipulationOutput = sealedBlobManipulator.getManipulations();
  for (const auto& manipulation : manipulationOutput)
  {
    SCOPED_TRACE("SealedBlobManipulator test failed: " + manipulation.TestName);
    in_sealedBlobTest.KnownQuoteBlob = manipulation.blob;
    output = ERP_GetTEEToken(ErpBasicInputTestsFixture::m_logonSession, in_sealedBlobTest);
    if(manipulation.expectErrVar == SealedBlobManipulator::EXPECT_ERR_EQ)
    {
      EXPECT_EQ(output.returnCode, manipulation.expectErr);
    }
    else
    {
      EXPECT_NE(output.returnCode, manipulation.expectErr);
    }
  }
  in_sealedBlobTest = in;
  sealedBlobManipulator = SealedBlobManipulator(in_sealedBlobTest.NONCEBlob);
  manipulationOutput = sealedBlobManipulator.getManipulations();
  for (const auto& manipulation : manipulationOutput)
  {
    SCOPED_TRACE("SealedBlobManipulator test failed: " + manipulation.TestName);
    in_sealedBlobTest.NONCEBlob = manipulation.blob;
    output = ERP_GetTEEToken(ErpBasicInputTestsFixture::m_logonSession, in_sealedBlobTest);
    if(manipulation.expectErrVar == SealedBlobManipulator::EXPECT_ERR_EQ)
    {
      EXPECT_EQ(output.returnCode, manipulation.expectErr);
    }
    else
    {
      EXPECT_NE(output.returnCode, manipulation.expectErr);
    }
  }

  /* invalid AKname */
  std::vector<unsigned char> AKname;
  std::copy(savedAKName.begin(), savedAKName.end(), std::back_inserter(AKname));
  AKname[0]++;
  memcpy(&(in.AKName[0]), AKname.data(), TPM_NAME_LEN);
  in.QuoteDataLength = savedAttestationQuote.size();
  memcpy(&(in.QuoteData[0]), savedAttestationQuote.data(), savedAttestationQuote.size());
  in.QuoteSignatureLength = savedAttestationQuoteSignature.size();
  memcpy(&(in.QuoteSignature[0]), savedAttestationQuoteSignature.data(), savedAttestationQuoteSignature.size());
  in.KnownAKBlob = *savedTrustedAK;
  in.NONCEBlob = *savedAttestationNONCE;
  in.KnownQuoteBlob = *savedTrustedQuote;
  output = ERP_GetTEEToken(ErpBasicInputTestsFixture::m_logonSession, in);
  EXPECT_EQ(ERP_ERR_TPM_NAME_MISMATCH, output.returnCode);
}


TEST_F(ErpBasicInputTestsFixture,ERPDeriveKeysInputTests)
{
  /* Same function with different key prefixes
   * ERP_DeriveTaskKey, ERP_DeriveAuditKey, ERP_DeriveCommsKey
   */
  auto pDerivationKeyBlob = getEmptyBlob(generationSaved);
  teststep_GenerateDerivationKey(ErpBasicInputTestsFixture::m_logonSession, generationSaved, pDerivationKeyBlob.get());

  std::vector<DeriveKeyOutput(*)(HSMSession, DeriveKeyInput)> funcs =
    {
      &ERP_DeriveTaskKey,
      &ERP_DeriveAuditKey,
      &ERP_DeriveCommsKey,
      &ERP_DeriveChargeItemKey,
    };

  const unsigned NUM_FUNCS = 4;
  const unsigned NUM_ITERATIONS = 100;
  std::vector<std::vector<unsigned char>> savedKeysList;
  for(auto ERP_toTestFunc : funcs)
  {
    for(unsigned int i = 0; i < NUM_ITERATIONS; i++)
    {
      DeriveKeyInput in = { {'\0'} ,{0,0,{'\0'}},{0,0,{'\0'}},0,0,{'\0'} };

      /* valid */
      std::vector<unsigned char> derivationData = {0x00, 0x01, 0x02};
      memcpy(&(in.AKName[0]), savedAKName.data(), TPM_NAME_LEN);
      in.derivationDataLength = derivationData.size();
      memcpy(&(in.derivationData), derivationData.data(), in.derivationDataLength);
      in.TEEToken = *teeToken;
      in.derivationKey = *pDerivationKeyBlob;
      in.initialDerivation = 1;
      DeriveKeyOutput output = ERP_toTestFunc(ErpBasicInputTestsFixture::m_logonSession, in);
      ASSERT_EQ(ERP_ERR_NOERROR, output.returnCode);
      EXPECT_EQ(output.derivationDataLength, 2 + 32 + in.derivationDataLength); /* check that the used derivation data is correct */
      savedKeysList.emplace_back(&(output.derivedKey[0]), &(output.derivedKey[0]) + AES_256_LEN);

      /* valid with initialDerivation false */
      // Too short - Derivation Data must be at least as long as the derivation variation prefix
      derivationData = { 0x00 };
      memcpy(&(in.AKName[0]), savedAKName.data(), TPM_NAME_LEN);
      in.derivationDataLength = derivationData.size();
      memcpy(&(in.derivationData), derivationData.data(), in.derivationDataLength);
      in.TEEToken = *teeToken;
      in.derivationKey = *pDerivationKeyBlob;
      in.initialDerivation = 0;
      output = ERP_toTestFunc(ErpBasicInputTestsFixture::m_logonSession, in);
      ASSERT_EQ(ERP_ERR_DERIVATION_DATA_LENGTH, output.returnCode);

      // Ok, Derivation Data must be at least as long as the derivation variation prefix
      derivationData = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a }; // NOLINT
      memcpy(&(in.AKName[0]), savedAKName.data(), TPM_NAME_LEN);
      in.derivationDataLength = derivationData.size();
      memcpy(&(in.derivationData), derivationData.data(), in.derivationDataLength);
      in.TEEToken = *teeToken;
      in.derivationKey = *pDerivationKeyBlob;
      in.initialDerivation = 0;
      output = ERP_toTestFunc(ErpBasicInputTestsFixture::m_logonSession, in);
      ASSERT_EQ(ERP_ERR_NOERROR, output.returnCode);
      EXPECT_EQ(output.derivationDataLength, in.derivationDataLength); /* check that the used derivation data is correct */
      savedKeysList.emplace_back(&(output.derivedKey[0]), &(output.derivedKey[0]) + AES_256_LEN);

      /* valid, different derivation Data */
      derivationData.clear();
      for(unsigned int j = 0; j < (MAX_BUFFER - 2 - 64); j++) // NOLINT /* max size if we don't want the output buffer to overflow */
      {
        derivationData.push_back(rand() % 255); // NOLINT just put in some pseudorandom numbers, we don't care
      }
      memcpy(&(in.AKName[0]), savedAKName.data(), TPM_NAME_LEN);
      in.derivationDataLength = derivationData.size();
      memcpy(&(in.derivationData), derivationData.data(), in.derivationDataLength);
      in.TEEToken = *teeToken;
      in.derivationKey = *pDerivationKeyBlob;
      in.initialDerivation = 1;
      output = ERP_toTestFunc(ErpBasicInputTestsFixture::m_logonSession, in);
      ASSERT_EQ(ERP_ERR_NOERROR, output.returnCode);
      EXPECT_EQ(output.derivationDataLength, 2 + 32 + in.derivationDataLength); /* check that the used derivation data is correct */
      savedKeysList.emplace_back(&(output.derivedKey[0]), &(output.derivedKey[0]) + AES_256_LEN);

      /* empty derivation data (OCTET STRING is checked for 0, expect ERP_ERR_ASN1_CONTENT_ERROR */
      derivationData.clear();
      memcpy(&(in.AKName[0]), savedAKName.data(), TPM_NAME_LEN);
      in.derivationDataLength = derivationData.size();
      in.TEEToken = *teeToken;
      in.derivationKey = *pDerivationKeyBlob;
      in.initialDerivation = 1;
      output = ERP_toTestFunc(ErpBasicInputTestsFixture::m_logonSession, in);
      ASSERT_EQ(ERP_ERR_ASN1_CONTENT_ERROR, output.returnCode);

      /* TODO(chris): Some other incorrect inputs to trigger the respective errors */
    }

    /* now test invalid sealed blobs (outer loop to test only once) */
    DeriveKeyInput in = { {'\0'} ,{0,0,{'\0'}},{0,0,{'\0'}},0,0,{'\0'} };
    std::vector<unsigned char> derivationData = {0x00, 0x01, 0x02};
    memcpy(&(in.AKName[0]), savedAKName.data(), TPM_NAME_LEN);
    in.derivationDataLength = derivationData.size();
    memcpy(&(in.derivationData), derivationData.data(), in.derivationDataLength);
    in.TEEToken = *teeToken;
    in.derivationKey = *pDerivationKeyBlob;
    in.initialDerivation = 1;
    DeriveKeyInput in_sealedBlobTest = in;
    SealedBlobManipulator sealedBlobManipulator(in_sealedBlobTest.TEEToken);
    std::vector<SealedBlobManipulator::sealedBlobManipulation_t> manipulationOutput = sealedBlobManipulator.getManipulations();
    for (const auto& manipulation : manipulationOutput)
    {
      SCOPED_TRACE("SealedBlobManipulator test failed: " + manipulation.TestName);
      in_sealedBlobTest.TEEToken = manipulation.blob;
      DeriveKeyOutput output = ERP_toTestFunc(ErpBasicInputTestsFixture::m_logonSession, in_sealedBlobTest);
      if(manipulation.expectErrVar == SealedBlobManipulator::EXPECT_ERR_EQ)
      {
        EXPECT_EQ(output.returnCode, manipulation.expectErr);
      }
      else
      {
        EXPECT_NE(output.returnCode, manipulation.expectErr);
      }
    }
  }

  /* test that every key has only been derived once in our tests
   * we expect that the calls with initialDerivation = false only add one new unique derived key per different function called
   * since they should add their own prefix somehow.
   */
  std::set<std::vector<unsigned char>> testUniqueness(savedKeysList.begin(), savedKeysList.end());
  unsigned expectDifference = (NUM_ITERATIONS * NUM_FUNCS) - NUM_FUNCS;
  EXPECT_EQ(testUniqueness.size() + expectDifference, savedKeysList.size());
}

// ERP_GetRNDBytes: already checked in other tests


TEST_F(ErpBasicInputTestsFixture, ERPGetECPublicKeyInputTests) // DISABLED until Github Issue 72 is resolved
{
  SingleBlobInput get = { {0,0,{0}} };
  get.BlobIn = *savedECIESKeyPairBlob;

  /* valid. Also check that always the same key is returned */
  PublicKeyOutput tmpKeyOut;
  for(int i = 0; i < MEDIUM_LOOP; i++)
  {
    PublicKeyOutput keyOut = ERP_GetECPublicKey(ErpBasicInputTestsFixture::m_logonSession, get);
    EXPECT_EQ(ERP_ERR_NOERROR, keyOut.returnCode);
    if(i > 0)
    {
      EXPECT_EQ(std::memcmp(&keyOut, &tmpKeyOut, sizeof(keyOut)), 0);
    }
    tmpKeyOut = keyOut;
  }

  /* now test invalid sealed blobs */
  SingleBlobInput in_sealedBlobTest = get;
  in_sealedBlobTest = get;
  SealedBlobManipulator sealedBlobManipulator = SealedBlobManipulator(in_sealedBlobTest.BlobIn);
  std::vector<SealedBlobManipulator::sealedBlobManipulation_t> manipulationOutput = sealedBlobManipulator.getManipulations();
  for (const auto& manipulation : manipulationOutput)
  {
    SCOPED_TRACE("SealedBlobManipulator test failed: " + manipulation.TestName);
    in_sealedBlobTest.BlobIn = manipulation.blob;
    PublicKeyOutput output = ERP_GetECPublicKey(ErpBasicInputTestsFixture::m_logonSession, in_sealedBlobTest);
    if(manipulation.expectErrVar == SealedBlobManipulator::EXPECT_ERR_EQ)
    {
      EXPECT_EQ(output.returnCode, manipulation.expectErr);
    }
    else
    {
      EXPECT_NE(output.returnCode, manipulation.expectErr);
    }
  }
}


TEST_F(ErpBasicInputTestsFixture, ERPDoECIES128InputTests) // DISABLED until Github Issue 72 is resolved
{

  DoVAUECIESInput in = {
    *teeToken,
    *savedECIESKeyPairBlob,
    0, {0}
  };

  /* valid */
  ASSERT_GT(clientPub.size(),0);
  memcpy(&(in.clientPublicKeyData[0]),clientPub.data(),clientPub.size());
  in.clientPublicKeyLength = clientPub.size();
  AES128KeyOutput out = ERP_DoVAUECIES128(m_logonSession, in);
  EXPECT_EQ(ERP_ERR_NOERROR, out.returnCode);

  /* now test invalid sealed blobs */
  DoVAUECIESInput in_sealedBlobTest = in;
  SealedBlobManipulator sealedBlobManipulator(in_sealedBlobTest.TEEToken);
  std::vector<SealedBlobManipulator::sealedBlobManipulation_t> manipulationOutput = sealedBlobManipulator.getManipulations();
  for (const auto& manipulation : manipulationOutput)
  {
    SCOPED_TRACE("SealedBlobManipulator test failed: " + manipulation.TestName);
    in_sealedBlobTest.TEEToken = manipulation.blob;
    AES128KeyOutput output = ERP_DoVAUECIES128(ErpBasicInputTestsFixture::m_logonSession, in_sealedBlobTest);
    if(manipulation.expectErrVar == SealedBlobManipulator::EXPECT_ERR_EQ)
    {
      EXPECT_EQ(output.returnCode, manipulation.expectErr);
    }
    else
    {
      EXPECT_NE(output.returnCode, manipulation.expectErr);
    }
  }
  in_sealedBlobTest = in;
  sealedBlobManipulator = SealedBlobManipulator(in_sealedBlobTest.ECIESKeyPair);
  manipulationOutput = sealedBlobManipulator.getManipulations();
  for (const auto& manipulation : manipulationOutput)
  {
    SCOPED_TRACE("SealedBlobManipulator test failed: " + manipulation.TestName);
    in_sealedBlobTest.ECIESKeyPair = manipulation.blob;
    AES128KeyOutput output = ERP_DoVAUECIES128(ErpBasicInputTestsFixture::m_logonSession, in_sealedBlobTest);
    if(manipulation.expectErrVar == SealedBlobManipulator::EXPECT_ERR_EQ)
    {
      EXPECT_EQ(output.returnCode, manipulation.expectErr);
    }
    else
    {
      EXPECT_NE(output.returnCode, manipulation.expectErr);
    }
  }
}


/* test giving in wrong blobs. Tested for ERP_GetVAUSIGPrivateKey
 * One test should suffice since the same functions for unsealing get called by every test
 */
TEST_F(ErpBasicInputTestsFixture, ERPTestWrongBlobInputs)
{
  TwoBlobGetKeyInput vauSIG = { {0,0,{0}}, {0,0,{0}} };

  /* input "swapped" */
  vauSIG.TEEToken = *savedVAUSIGKeyPairBlob;
  vauSIG.Key = *teeToken;

  PrivateKeyOutput keyOut = ERP_GetVAUSIGPrivateKey(ErpBasicInputTestsFixture::m_logonSession, vauSIG);
  ASSERT_EQ(ERP_ERR_WRONG_BLOB_TYPE, keyOut.returnCode);
}


TEST_F(ErpBasicInputTestsFixture, ERPGetVAUSIGPrivateKeyInputTests) // DISABLED until Github Issue 72 is resolved
{
  TwoBlobGetKeyInput vauSIG = { {0,0,{0}}, {0,0,{0}} };

  vauSIG.TEEToken = *teeToken;
  vauSIG.Key = *savedVAUSIGKeyPairBlob;

  /* valid */
  PrivateKeyOutput keyOut = ERP_GetVAUSIGPrivateKey(ErpBasicInputTestsFixture::m_logonSession, vauSIG);
  ASSERT_EQ(ERP_ERR_NOERROR, keyOut.returnCode);

  /* now test invalid sealed blobs */
  TwoBlobGetKeyInput in_sealedBlobTest = vauSIG;
  SealedBlobManipulator sealedBlobManipulator(in_sealedBlobTest.TEEToken);
  std::vector<SealedBlobManipulator::sealedBlobManipulation_t> manipulationOutput = sealedBlobManipulator.getManipulations();
  for (const auto& manipulation : manipulationOutput)
  {
    SCOPED_TRACE("SealedBlobManipulator test failed: " + manipulation.TestName);
    in_sealedBlobTest.TEEToken = manipulation.blob;
    PrivateKeyOutput output = ERP_GetVAUSIGPrivateKey(ErpBasicInputTestsFixture::m_logonSession, in_sealedBlobTest);
    if(manipulation.expectErrVar == SealedBlobManipulator::EXPECT_ERR_EQ)
    {
      EXPECT_EQ(output.returnCode, manipulation.expectErr);
    }
    else
    {
      EXPECT_NE(output.returnCode, manipulation.expectErr);
    }
  }
  in_sealedBlobTest = vauSIG;
  sealedBlobManipulator = SealedBlobManipulator(in_sealedBlobTest.Key);
  manipulationOutput = sealedBlobManipulator.getManipulations();
  for (const auto& manipulation : manipulationOutput)
  {
    SCOPED_TRACE("SealedBlobManipulator test failed: " + manipulation.TestName);
    in_sealedBlobTest.Key = manipulation.blob;
    PrivateKeyOutput output = ERP_GetVAUSIGPrivateKey(ErpBasicInputTestsFixture::m_logonSession, in_sealedBlobTest);
    if(manipulation.expectErrVar == SealedBlobManipulator::EXPECT_ERR_EQ)
    {
      EXPECT_EQ(output.returnCode, manipulation.expectErr);
    }
    else
    {
      EXPECT_NE(output.returnCode, manipulation.expectErr);
    }
  }
}

TEST_F(ErpBasicInputTestsFixture, ERPUnwrapHashKeyInputTests) // DISABLED until Github Issue 72 is resolved
{
  SingleBlobOutput outputGenKey = ERP_GenerateHashKey(ErpBasicInputTestsFixture::m_logonSession, {0});
  EXPECT_EQ(ERP_ERR_NOERROR, outputGenKey.returnCode);

  TwoBlobGetKeyInput in = { {0,0,{0}}, {0,0,{0}} };
  in.Key = outputGenKey.BlobOut;
  in.TEEToken = *teeToken;

  /* valid */
  AES256KeyOutput out = ERP_UnwrapHashKey(ErpBasicInputTestsFixture::m_logonSession, in);
  EXPECT_EQ(ERP_ERR_NOERROR, out.returnCode);

  /* now test invalid sealed blobs */
  TwoBlobGetKeyInput in_sealedBlobTest = in;
  SealedBlobManipulator sealedBlobManipulator(in_sealedBlobTest.TEEToken);
  std::vector<SealedBlobManipulator::sealedBlobManipulation_t> manipulationOutput = sealedBlobManipulator.getManipulations();
  for (const auto& manipulation : manipulationOutput)
  {
    SCOPED_TRACE("SealedBlobManipulator test failed: " + manipulation.TestName);
    in_sealedBlobTest.TEEToken = manipulation.blob;
    AES256KeyOutput output = ERP_UnwrapHashKey(ErpBasicInputTestsFixture::m_logonSession, in_sealedBlobTest);
    if(manipulation.expectErrVar == SealedBlobManipulator::EXPECT_ERR_EQ)
    {
      EXPECT_EQ(output.returnCode, manipulation.expectErr);
    }
    else
    {
      EXPECT_NE(output.returnCode, manipulation.expectErr);
    }
  }
  in_sealedBlobTest = in;
  sealedBlobManipulator = SealedBlobManipulator(in_sealedBlobTest.Key);
  manipulationOutput = sealedBlobManipulator.getManipulations();
  for (const auto& manipulation : manipulationOutput)
  {
    SCOPED_TRACE("SealedBlobManipulator test failed: " + manipulation.TestName);
    in_sealedBlobTest.Key = manipulation.blob;
    AES256KeyOutput output = ERP_UnwrapHashKey(ErpBasicInputTestsFixture::m_logonSession, in_sealedBlobTest);
    if(manipulation.expectErrVar == SealedBlobManipulator::EXPECT_ERR_EQ)
    {
      EXPECT_EQ(output.returnCode, manipulation.expectErr);
    }
    else
    {
      EXPECT_NE(output.returnCode, manipulation.expectErr);
    }
  }
}

TEST_F(ErpBasicInputTestsFixture, ERPExportSingleBlobKeyInputTests)
{
    const unsigned int exportGeneration = TEST_BLOB_GEN;

    unsigned int err = teststep_DeleteBlobKey(m_logonSession, exportGeneration);
    ASSERT_TRUE(err == ERP_ERR_NOERROR || err == ERP_ERR_UNKNOWN_BLOB_GENERATION);

    err = teststep_GenerateBlobKey(m_logonSession, exportGeneration);

    ASSERT_EQ(ERP_ERR_NOERROR, err);
    UIntInput intIn = {exportGeneration};
    BUBlobOutput_t outputBlob = ERP_ExportSingleBlobKey(ErpBasicInputTestsFixture::m_logonSession, intIn);
    EXPECT_EQ(ERP_ERR_NOERROR, outputBlob.returnCode);

    intIn.intValue = TEST_MAX_SIGNED_GEN;
    outputBlob = ERP_ExportSingleBlobKey(ErpBasicInputTestsFixture::m_logonSession, intIn);
    EXPECT_EQ(ERP_ERR_BAD_BLOB_GENERATION, outputBlob.returnCode);

    intIn.intValue = 0;
    outputBlob = ERP_ExportSingleBlobKey(ErpBasicInputTestsFixture::m_logonSession, intIn);
    EXPECT_EQ(ERP_ERR_BAD_BLOB_GENERATION, outputBlob.returnCode);

    DirectIOInput rawInput;
    rawInput.SFCCode = ERP_SFC_EXPORT_SINGLE_BLOB_KEY;

    unsigned char invalidASN1Input1[] = { 0x30, 0x03, 0x08, 0x01, 0x42 }; // NOLINT
    std::memcpy(&(rawInput.DataBody[0]), &(invalidASN1Input1[0]), sizeof(invalidASN1Input1));
    rawInput.DataLength = sizeof(invalidASN1Input1);
    DirectIOOutput rawOutput = ERP_DirectIO(ErpBasicInputTestsFixture::m_logonSession, rawInput);
    EXPECT_EQ(rawOutput.returnCode, ERP_ERR_ASN1_CONTENT_ERROR);

    unsigned char invalidASN1Input2[] = { 0x30, 0x06, 0x02, 0x01, 0x42, 0x02, 0x01, 0x42 }; // NOLINT
    std::memcpy(&(rawInput.DataBody[0]), &(invalidASN1Input2[0]), sizeof(invalidASN1Input2));
    rawInput.DataLength = sizeof(invalidASN1Input2);
    rawOutput = ERP_DirectIO(ErpBasicInputTestsFixture::m_logonSession, rawInput);
    EXPECT_EQ(rawOutput.returnCode, ERP_ERR_ASN1_CONTENT_ERROR);
}

TEST_F(ErpBasicInputTestsFixture, ERPImportSingleBlobKeyInputTests)
{
    const unsigned int exportGeneration = TEST_BLOB_GEN;

    logonSetup();

    unsigned int err = teststep_DeleteBlobKey(m_logonSession, exportGeneration);
    ASSERT_TRUE(err == ERP_ERR_NOERROR || err == ERP_ERR_UNKNOWN_BLOB_GENERATION);

    err = teststep_GenerateBlobKey(m_logonSession, exportGeneration);
    ASSERT_EQ(ERP_ERR_NOERROR, err);

    BUBlobOutput_t backupResult = { 0 , {0, {0},{0},{0},{0},0,{0}} };
    UIntInput intIn;
    intIn.intValue = exportGeneration;

    // First backup an existing blob generation.
    backupResult = ERP_ExportSingleBlobKey(m_logonSession, intIn);
    ASSERT_EQ(ERP_ERR_NOERROR,backupResult.returnCode);

    auto testFn = [&](const BUBlobInput & blobIn, unsigned int expErr) {
        unsigned int lambdaErr = teststep_DeleteBlobKey(m_logonSession, exportGeneration);
        ASSERT_TRUE(lambdaErr == ERP_ERR_NOERROR || lambdaErr == ERP_ERR_UNKNOWN_BLOB_GENERATION);

        EmptyOutput restoreResult = { 0 };

        // Another attempt to restore the blob generation should now work.
        restoreResult = ERP_ImportSingleBlobKey(m_logonSession, blobIn);
        EXPECT_EQ(expErr, restoreResult.returnCode);
    };

    BUBlobInput variedBlobIn = { backupResult.BUBlob };
    // All of the Metadata Manipulations should fail with ERP_ERR_BAD_BLAB_AD
    //    unless the specific error is caight before the decrpytion.
    // Generation already present
    variedBlobIn.BUBlob.Generation = THE_ANSWER;
    testFn(variedBlobIn, ERP_ERR_BAD_BLOB_GENERATION);
    // Zero explicitly not allowed for backups.
    variedBlobIn.BUBlob.Generation = 0;
    testFn(variedBlobIn, ERP_ERR_BAD_BLOB_GENERATION);

    // Generation good, but wrong for blob.
    variedBlobIn.BUBlob.Generation = TEST_HIGH_VALID_GENERATION;
    testFn(variedBlobIn, ERP_ERR_BAD_BLOB_AD);

    // Copy the original blob back in.
    variedBlobIn.BUBlob = backupResult.BUBlob;
    memcpy(&(variedBlobIn.BUBlob.Domain[0]),"NODM",sizeof(variedBlobIn.BUBlob.Domain)); //NOLINT
    testFn(variedBlobIn, ERP_ERR_BAD_BLOB_DOMAIN);

    // Copy the original blob back in.
    variedBlobIn.BUBlob = backupResult.BUBlob;
    variedBlobIn.BUBlob.encDataLength = 0;
    testFn(variedBlobIn, ERP_ERR_ASN1_CONTENT_ERROR);

    variedBlobIn.BUBlob = backupResult.BUBlob;
    variedBlobIn.BUBlob.encDataLength++;
    testFn(variedBlobIn, ERP_ERR_BACKUP_WRONG_DATA_LEN);

    variedBlobIn.BUBlob = backupResult.BUBlob;
    variedBlobIn.BUBlob.encDataLength--;
    testFn(variedBlobIn, ERP_ERR_BACKUP_WRONG_DATA_LEN);

    variedBlobIn.BUBlob = backupResult.BUBlob;
    variedBlobIn.BUBlob.encDataLength = MAX_BUFFER;
    testFn(variedBlobIn, ERP_ERR_BACKUP_WRONG_DATA_LEN);

    variedBlobIn.BUBlob = backupResult.BUBlob;
    variedBlobIn.BUBlob.BlobKeyKCV[0] ^= XOR_CHANGE_BYTE; // %10101010;
    testFn(variedBlobIn, ERP_ERR_BAD_BLOB_AD);

    variedBlobIn.BUBlob = backupResult.BUBlob;
    variedBlobIn.BUBlob.BlobKeyKCV[SHA_256_LEN-1] ^= XOR_CHANGE_BYTE; // %10101010;
    testFn(variedBlobIn, ERP_ERR_BAD_BLOB_AD);

    variedBlobIn.BUBlob = backupResult.BUBlob;
    variedBlobIn.BUBlob.MBKName[0] ^= XOR_CHANGE_BYTE; // %10101010;
    testFn(variedBlobIn, ERP_ERR_BACKUP_WRONG_MBK_NAME);

    variedBlobIn.BUBlob = backupResult.BUBlob;
    variedBlobIn.BUBlob.MBKName[MBK_NAME_LEN-1] ^= XOR_CHANGE_BYTE; // %10101010;
    testFn(variedBlobIn, ERP_ERR_BACKUP_WRONG_MBK_NAME);

    variedBlobIn.BUBlob = backupResult.BUBlob;
    variedBlobIn.BUBlob.MBKKCV[0] ^= XOR_CHANGE_BYTE; // %10101010;
    testFn(variedBlobIn, ERP_ERR_BACKUP_WRONG_MBK_KCV);

    variedBlobIn.BUBlob = backupResult.BUBlob;
    variedBlobIn.BUBlob.MBKKCV[MBK_KCV_LEN - 1] ^= XOR_CHANGE_BYTE; // %10101010;
    testFn(variedBlobIn, ERP_ERR_BACKUP_WRONG_MBK_KCV);

    variedBlobIn.BUBlob = backupResult.BUBlob;
    variedBlobIn.BUBlob.encData[0] ^= XOR_CHANGE_BYTE; // %10101010;
    testFn(variedBlobIn, ERP_ERR_BAD_BLOB_AD);

    variedBlobIn.BUBlob = backupResult.BUBlob;
    variedBlobIn.BUBlob.encData[BLOB_IV_LEN] ^= XOR_CHANGE_BYTE; // %10101010;
    testFn(variedBlobIn, ERP_ERR_BAD_BLOB_AD);

    variedBlobIn.BUBlob = backupResult.BUBlob;
    variedBlobIn.BUBlob.encData[variedBlobIn.BUBlob.encDataLength - 1] ^= XOR_CHANGE_BYTE; // %10101010;
    testFn(variedBlobIn, ERP_ERR_BAD_BLOB_AD);
}

TEST_F(ErpBasicInputTestsFixture, ERPGetBlobContentHashInputTests)
{
    SingleBlobInput in = { {0,0,{0}} };
    SHA256Output out = { 0 ,{0} };
    // Not really important which blob we take here...
    in.BlobIn = *(savedVAUSIGKeyPairBlob.get());

    /* valid */
    out = ERP_GetBlobContentHash(ErpBasicInputTestsFixture::m_logonSession, in);
    EXPECT_EQ(ERP_ERR_NOERROR, out.returnCode);

    /* now test invalid sealed blobs */
    SingleBlobInput in_sealedBlobTest = in;
    SealedBlobManipulator sealedBlobManipulator(in_sealedBlobTest.BlobIn);
    for (const auto & manipulation : sealedBlobManipulator.getManipulations())
    {
        SCOPED_TRACE("SealedBlobManipulator test failed: " + manipulation.TestName);
        in_sealedBlobTest.BlobIn = manipulation.blob;
        SHA256Output output = ERP_GetBlobContentHash(ErpBasicInputTestsFixture::m_logonSession, in_sealedBlobTest);
        if (manipulation.expectErrVar == SealedBlobManipulator::EXPECT_ERR_EQ)
        {
            EXPECT_EQ(output.returnCode, manipulation.expectErr);
        }
        else
        {
            EXPECT_NE(output.returnCode, manipulation.expectErr);
        }
    }
}

TEST_F(ErpBasicInputTestsFixture, ERPGetBlobContentHashWithTokenInputTests)
{
    TwoBlobGetKeyInput in = { {0,0,{0}}, {0,0,{0}} };
    SHA256Output out = { 0 ,{0} };
    // Not really important which blob we take here...
    in.Key = *(savedVAUSIGKeyPairBlob.get());
    in.TEEToken = *(teeToken.get());

    /* valid */
    out = ERP_GetBlobContentHashWithToken(ErpBasicInputTestsFixture::m_logonSession, in);
    EXPECT_EQ(ERP_ERR_NOERROR, out.returnCode);

    /* now test invalid sealed blobs */
    TwoBlobGetKeyInput in_sealedBlobTest = in;
    SealedBlobManipulator sealedBlobManipulator(in_sealedBlobTest.TEEToken);
    for (const auto & manipulation : sealedBlobManipulator.getManipulations())
    {
        SCOPED_TRACE("SealedBlobManipulator test failed: " + manipulation.TestName);
        in_sealedBlobTest.TEEToken = manipulation.blob;
        SHA256Output output = ERP_GetBlobContentHashWithToken(ErpBasicInputTestsFixture::m_logonSession, in_sealedBlobTest);
        if (manipulation.expectErrVar == SealedBlobManipulator::EXPECT_ERR_EQ)
        {
            EXPECT_EQ(output.returnCode, manipulation.expectErr);
        }
        else
        {
            EXPECT_NE(output.returnCode, manipulation.expectErr);
        }
    }
    in_sealedBlobTest = in;
    sealedBlobManipulator = SealedBlobManipulator(in_sealedBlobTest.Key);
    for (const auto & manipulation : sealedBlobManipulator.getManipulations())
    {
        SCOPED_TRACE("SealedBlobManipulator test failed: " + manipulation.TestName);
        in_sealedBlobTest.Key = manipulation.blob;
        SHA256Output output = ERP_GetBlobContentHashWithToken(ErpBasicInputTestsFixture::m_logonSession, in_sealedBlobTest);
        if (manipulation.expectErrVar == SealedBlobManipulator::EXPECT_ERR_EQ)
        {
            EXPECT_EQ(output.returnCode, manipulation.expectErr);
        }
        else
        {
            EXPECT_NE(output.returnCode, manipulation.expectErr);
        }
    }
}

TEST_F(ErpBasicInputTestsFixture, ERPMigrateBlobInputTests)
{
    unsigned int exportGeneration = TEST_BLOB_GEN;

    logonSetup();

    unsigned int err = teststep_DeleteBlobKey(m_logonSession, exportGeneration);
    ASSERT_TRUE(err == ERP_ERR_NOERROR || err == ERP_ERR_UNKNOWN_BLOB_GENERATION);

    err = teststep_GenerateBlobKey(m_logonSession, exportGeneration);
    ASSERT_EQ(ERP_ERR_NOERROR, err);

    // Valid existing generation: 0x55  (TEST_BLOB_GEN)
    SingleBlobOutput migratedOut = { 0,{0,0,{0}} };
    MigrateBlobInput_t migrateIn = { exportGeneration,{0,0,{0}} };
    // Not really important which blob we take here...
    migrateIn.BlobIn = *(savedVAUSIGKeyPairBlob.get());
    migratedOut = ERP_MigrateBlob(m_logonSession, migrateIn);
    ASSERT_EQ(ERP_ERR_NOERROR, migratedOut.returnCode);

    // Valid Generation: 0
    migrateIn.NewBlobGeneration = 0;
    migratedOut = ERP_MigrateBlob(m_logonSession, migrateIn);
    ASSERT_EQ(ERP_ERR_NOERROR, migratedOut.returnCode);

    // Invalid Generation: 0x1fff
    migrateIn.NewBlobGeneration = TEST_HIGH_VALID_GENERATION;
    migratedOut = ERP_MigrateBlob(m_logonSession, migrateIn);
    ASSERT_EQ(ERP_ERR_BAD_BLOB_GENERATION, migratedOut.returnCode);

    // Now work through the blob mangling.
    migrateIn.NewBlobGeneration = exportGeneration;
    MigrateBlobInput_t in_sealedBlobTest = migrateIn;
    SealedBlobManipulator sealedBlobManipulator = SealedBlobManipulator(in_sealedBlobTest.BlobIn);
    for (const auto & manipulation : sealedBlobManipulator.getManipulations())
    {
        SCOPED_TRACE("SealedBlobManipulator test failed: " + manipulation.TestName);
        in_sealedBlobTest.BlobIn = manipulation.blob;
        SingleBlobOutput output = ERP_MigrateBlob(ErpBasicInputTestsFixture::m_logonSession, in_sealedBlobTest);
        if (manipulation.expectErrVar == SealedBlobManipulator::EXPECT_ERR_EQ)
        {
            EXPECT_EQ(output.returnCode, manipulation.expectErr);
        }
        else
        {
            EXPECT_NE(output.returnCode, manipulation.expectErr);
        }
    }
}