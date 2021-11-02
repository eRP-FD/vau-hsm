#include "ERP_TestUtils.h"

#include "ERP_SFC.h"
#include "ERP_Error.h"

#include <gtest/gtest.h>
#include <openssl/hmac.h>

#include <cstring>

namespace
{
    const std::string testDataDir{"resources/"};

    constexpr const size_t ERPBlobHeader = sizeof(ERPBlob) - MAX_BUFFER;
}

std::unique_ptr<ERPBlob> getEmptyBlob(unsigned int Gen)
{
    auto pBlob = std::make_unique<ERPBlob>();
    *(pBlob.get()) = { Gen, 0, {0} };
    std::memset(pBlob->BlobData, 0, sizeof(pBlob->BlobData));
    return pBlob;
}
// Utility method to read a file form the resources directory, allocates a pointer to a buffer to it and return that pointer 
// for the caller to own and be responsible for deletion.
std::vector<char> readERPResourceFile(const std::string& filename, bool bMustExist)
{
    const std::string fullFileName = testDataDir + filename;
    std::ifstream readFile = std::ifstream(fullFileName, std::ios::in | std::ios::binary);;
    if (bMustExist)
    {
        EXPECT_TRUE(readFile.is_open());
        if(!readFile.is_open())
        {
            fprintf(stderr,"Test resource file missing: %s\n",filename.c_str());
        }
    }

    auto eos = std::istreambuf_iterator<char>();
    auto retVal = std::vector<char>(std::istreambuf_iterator<char>(readFile), eos);

    return retVal;
}

// Caller must delete returned object.
ERPBlob* readBlobResourceFile(const std::string& filename, bool bMustExist)
{
    std::vector<char> data = readERPResourceFile(filename,bMustExist);
    if (bMustExist)
    {
        EXPECT_LE(data.size(), MAX_BUFFER);
    }
    if ((data.size() == 0) || (data.size() > MAX_BUFFER))
    {
        return nullptr;
    }
    ERPBlob* retVal = new ERPBlob;
    EXPECT_NE(nullptr, retVal);
    if (retVal != nullptr)
    {
        std::copy(data.begin(), data.end(), (char*)retVal);
        retVal->BlobLength = data.size() - ERPBlobHeader;
    }
    return retVal;
}

unsigned int writeERPResourceFile(const std::string& filename, const std::vector<char>& data) 
{
    unsigned int err = ERP_ERR_NOERROR;

    const std::string fullFileName = testDataDir + filename;
    std::ofstream writeFile = std::ofstream(fullFileName, std::ios::out | std::ios::binary);;
    EXPECT_TRUE(writeFile.is_open());
    std::copy(data.begin(), data.end(), std::ostreambuf_iterator<char>(writeFile));
    writeFile.close();

    return err;
}

// Caller must delete returned object.
unsigned int writeBlobResourceFile(const std::string& filename, const ERPBlob *pBlob)
{
    unsigned int err = ERP_ERR_NOERROR;
    size_t blobSize = pBlob->BlobLength + ERPBlobHeader;

    const std::string fullFileName = testDataDir + filename;
    std::ofstream writeFile = std::ofstream(fullFileName, std::ios::out | std::ios::binary);;
    EXPECT_TRUE(writeFile.is_open());
    unsigned char* blobBegin = (unsigned char*)pBlob;
    std::copy(blobBegin,blobBegin+blobSize, std::ostreambuf_iterator<char>(writeFile));
    writeFile.close();

    return err;
}

void printHex(const std::string& message, const std::vector<char>& data)
{
    std::cerr << message << ": ";
    for (std::size_t i = 0; i < data.size(); ++i)
    {
        unsigned int a = reinterpret_cast<const uint8_t&>(data.at(i));
        if ((i > 0) && ((i % 16) == 0))
        {
            std::cerr << std::endl;
        }
        std::cerr << std::hex << std::setfill('0') <<
            std::setw(2) << std::setprecision(2) << a << " ";
    }
    std::cerr << std::endl;
}  

unsigned int deriveOrRetrieveDerivationKey(HSMSession sesh,
    unsigned int generation, 
    const char* filename,
    ERPBlob * pOutBlob )
{
    unsigned int err = ERP_ERR_NOERROR;
    ERPBlob* pReadBlob = readBlobResourceFile(filename,false);

    if (pReadBlob == nullptr)
    {
         err = teststep_GenerateDerivationKey(
                sesh, generation, pOutBlob);
         // Save the Derivation Key for use in other tests.
         if (err == 0)
         {
             err = writeBlobResourceFile(filename, pOutBlob);
         }
    }
    else {
        *pOutBlob = *pReadBlob;
    }
    if (pReadBlob != nullptr)
    {
        delete pReadBlob;
    }
    return err;
}

unsigned int teststep_DumpHSMMemory(HSMSession sesh)
{
    unsigned int             err = 0;

    fprintf(stderr,"\nExecuting DumpHSMMemory command ...\n");

    EmptyOutput output = ERP_DumpHSMMemory(sesh);
    EXPECT_EQ(ERP_ERR_NOERROR, output.returnCode);

    fprintf(stderr,"Returned from DumpHSMMemory Command - Return Value: 0x%08x\n", output.returnCode);

    return err;
}

unsigned int teststep_GenerateBlobKey(HSMSession sesh, unsigned int gen)
{
    unsigned int             err = 0;

    fprintf(stderr,"\nExecuting GenerateBlobKey command ...\n");
    // zero will ask for next new generation.
    UIntInput genKeyIn = { gen };
    UIntOutput output = ERP_GenerateBlobKey(sesh, genKeyIn);
    err = output.returnCode;

    fprintf(stderr,"Returned from GenerateBlobKey Command - Return Value: 0x%08x\n", output.returnCode);

    return err;
}

unsigned int teststep_ListLoadedBlobKeys(HSMSession sesh)
{
    unsigned int             err = 0;

    fprintf(stderr,"\nExecuting ListLoadedBlobKeys command ...\n");

    BlobKeyListOutput output = ERP_ListLoadedBlobKeys(sesh);
    err = output.returnCode;

    fprintf(stderr,"Returned from ListLoadedBlobKeys Command - Return Value: 0x%08x\n", output.returnCode);
    fprintf(stderr,"Number of loaded Blob Keys: %i", output.NumKeys);
//    for (int i = 0; i < output.NumKeys; i++)
//    {
//        fprintf(stderr, "\n KeyGeneration: %08x, SHA256 of Key",
//            output.Generations[i].Generation);
//        printHex("", std::vector<char>( &(output.Generations[i].KeyHash[0]), &(output.Generations[i].KeyHash[0]) + SHA_256_LEN));
//    }
    return err;
}

unsigned int teststep_DeleteBlobKey(HSMSession sesh, unsigned int gen)
{
    int             err = 0;

    fprintf(stderr,"\nExecuting DeleteBlobKey command ...\n");
    // zero will ask for next new generation.
    UIntInput genKeyIn = { gen };
    EmptyOutput output = ERP_DeleteBlobKey(sesh, genKeyIn);
    err = output.returnCode;

    fprintf(stderr,"Returned from DeleteBlobKey Command - Return Value: 0x%08x\n", output.returnCode);

    return err;
}

unsigned int teststep_GenerateNONCE(HSMSession sesh, unsigned int gen)
{
    int             err = 0;

    fprintf(stderr,"\nExecuting GenerateNONCE command ...\n");
    // zero will ask for next new generation.
    UIntInput genKeyIn = { gen };
    NONCEOutput output = ERP_GenerateNONCE(sesh, genKeyIn);
    err = output.returnCode;
    fprintf(stderr,"Returned from GenerateNONCE Command - Return Value: 0x%08x\n", output.returnCode);
    fprintf(stderr,"Blob Generation: %08x\n", output.BlobOut.BlobGeneration);

    return err;
}

unsigned int teststep_TrustTPMMfr(HSMSession sesh, unsigned int generation, ERPBlob* pOutBlob, const std::vector<char>& certFile)
{
    unsigned int err = 0;
    TrustTPMMfrInput in = { 0, 0,{0} };
    in.desiredGeneration = generation;
    in.certLength = certFile.size();
    EXPECT_GT(MAX_BUFFER, in.certLength);
    memcpy(&(in.certData[0]), certFile.data(), in.certLength);
    printHex("\nExecuting TrustTPMMfr command with certificate", certFile);
    // zero will ask for next new generation.
    SingleBlobOutput output = ERP_TrustTPMMfr(sesh, in);

    fprintf(stderr,"Returned from TrustTPMMFr Command - Return Value: 0x%08x\n", output.returnCode);
    if (output.returnCode == 0)
    {
        fprintf(stderr,"Blob Generation: %08x\n", output.BlobOut.BlobGeneration);
        pOutBlob->BlobGeneration = output.BlobOut.BlobGeneration;
        pOutBlob->BlobLength = output.BlobOut.BlobLength;
        memcpy(&(pOutBlob->BlobData[0]), &(output.BlobOut.BlobData[0]), output.BlobOut.BlobLength);
    }
    else {
        err = output.returnCode;
    }
    return err;
}

unsigned int teststep_EnrollTPMEK(
    HSMSession sesh,
    unsigned int generation,
    ERPBlob* pTrustedRoot,
    ERPBlob* pTrustedEK, // Output
    size_t EKCertLen,
    unsigned char* pEKCertData)
{
    unsigned int err = 0;
    EnrollTPMEKInput in = { 0,{0,0,""},0,"" };

    in.desiredGeneration = generation;
    in.TPMMfrBlob = *pTrustedRoot;
    in.EKCertLength = EKCertLen;
    memcpy(&(in.EKCertData[0]), pEKCertData, EKCertLen);

    fprintf(stderr,"\nExecuting EnrollTPMEK command...\n");
    // zero will ask for next new generation.
    SingleBlobOutput output = ERP_EnrollTPMEK(sesh, in);

    fprintf(stderr,"Returned from EnrollTPMEK Command - Return Value: 0x%08x\n", output.returnCode);
    if (output.returnCode == 0)
    {
        fprintf(stderr,"Blob Generation: %08x\n", output.BlobOut.BlobGeneration);
        pTrustedEK->BlobGeneration = output.BlobOut.BlobGeneration;
        pTrustedEK->BlobLength = output.BlobOut.BlobLength;
        memcpy(&(pTrustedEK->BlobData[0]), &(output.BlobOut.BlobData[0]), output.BlobOut.BlobLength);
    }
    else {
        err = output.returnCode;
    }
    return err;
}

unsigned int teststep_GetAKChallenge(
    HSMSession sesh,
    // Input
    unsigned int desiredGeneration,
    ERPBlob* pTrustedEK,
    unsigned char* pAKName, // TPM_NAME_LEN...
    size_t AKPubLength,
    unsigned char* AKPubData,
    // output
    ERPBlob* pCredChallengeBlob,
    size_t* pEncCredentialLength,
    unsigned char* pEncCredentialData, // MAX_BUFFER
    size_t* pSecretLength,
    unsigned char* pSecretData) // MAX_BUFFER
{
    unsigned int err = 0;
    AKChallengeInput in = { 0,{0},{0,0,{0}},0,{0} };

    in.desiredGeneration = desiredGeneration;
    in.KnownEKBlob = *pTrustedEK;
    in.AKPubLength = AKPubLength;
    memcpy(&(in.AKName[0]), pAKName, TPM_NAME_LEN);
    memcpy(&(in.AKPubData[0]), AKPubData, AKPubLength);

    fprintf(stderr,"\nExecuting GetAKChallenge command...\n");
    // zero will ask for next new generation.
    AKChallengeOutput output = ERP_GetAKChallenge(sesh, in);

    fprintf(stderr,"Returned from GetAKChallenge Command - Return Value: 0x%08x\n", output.returnCode);
    if (output.returnCode == 0)
    {
        fprintf(stderr,"ChallengeBlob Generation: %08x\n", output.ChallengeBlob.BlobGeneration);
        pCredChallengeBlob->BlobGeneration = output.ChallengeBlob.BlobGeneration;
        pCredChallengeBlob->BlobLength = output.ChallengeBlob.BlobLength;
        memcpy(&(pCredChallengeBlob->BlobData[0]),
            &(output.ChallengeBlob.BlobData[0]),
            output.ChallengeBlob.BlobLength);
        (*pEncCredentialLength) = output.encCredentialLength;
        memcpy(pEncCredentialData, output.encCredentialData, output.encCredentialLength);
        (*pSecretLength) = output.secretLength;
        memcpy(pSecretData, output.secretData, output.secretLength);
    }
    else {
        err = output.returnCode;
    }
    return err;
}

unsigned int teststep_EnrollAK(
    HSMSession sesh,
    unsigned int desiredGeneration,
    ERPBlob* pTrustedEK,
    ERPBlob* pChallengeBlob,
    unsigned char* pAKName, // TPM_NAME_LEN
    size_t AKPubLength,
    unsigned char* AKPubData,
    size_t decCredLength,
    unsigned char* decCredData,
    ERPBlob* pOutBlob)
{
    unsigned int err = 0;
    EnrollTPMAKInput in = { 0,{'\0'},{0,0,{'\0'}},0,{'\0'},0,{'\0'}, {0,0,{'\0'}} };

    in.desiredGeneration = desiredGeneration;
    in.KnownEKBlob = *pTrustedEK;
    memcpy(&(in.AKName[0]), pAKName, TPM_NAME_LEN);
    in.AKPubLength = AKPubLength;
    memcpy(&(in.AKPubData[0]), AKPubData, AKPubLength);
    in.challengeBlob = *pChallengeBlob;
    in.decCredentialLength = decCredLength;
    memcpy(&(in.decCredentialData[0]), decCredData, decCredLength);

    fprintf(stderr,"\nExecuting EnrollTPMAK command...\n");
    // zero will ask for next new generation.
    SingleBlobOutput output = ERP_EnrollTPMAK(sesh, in);

    fprintf(stderr,"Returned from EnrollTPMAK Command - Return Value: 0x%08x\n", output.returnCode);

    if (output.returnCode == 0)
    {
        fprintf(stderr,"Output Blob Generation: %08x\n", output.BlobOut.BlobGeneration);
        pOutBlob->BlobGeneration = output.BlobOut.BlobGeneration;
        pOutBlob->BlobLength = output.BlobOut.BlobLength;
        memcpy(&(pOutBlob->BlobData[0]), &(output.BlobOut.BlobData[0]), output.BlobOut.BlobLength);
    }
    else {
        err = output.returnCode;
    }
    return err;
}

unsigned int teststep_TrustQuote(
    HSMSession sesh,
    unsigned int desiredGeneration,
    ERPBlob* pTrustedAK,
    ERPBlob* pNONCEBlob,
    unsigned char* pAKName, // TPM_NAME_LEN
    size_t quoteLength,
    unsigned char* quoteData,
    size_t sigLength,
    unsigned char* sigData,
    ERPBlob* pOutBlob)
{
    unsigned int err = 0;
    EnrollEnclaveInput in = { 0,{'\0'},{0,0,{'\0'}},{0,0,{'\0'}},0,{'\0'},0,{'\0'} };

    in.desiredGeneration = desiredGeneration;
    memcpy(&(in.AKName[0]), pAKName, TPM_NAME_LEN);
    in.quoteLength = quoteLength;
    memcpy(&(in.quoteData[0]), quoteData, quoteLength);
    in.signatureLength = sigLength;
    memcpy(&(in.signatureData[0]), sigData, sigLength);
    in.KnownAKBlob = *pTrustedAK;
    in.NONCEBlob = *pNONCEBlob;

    fprintf(stderr,"\nExecuting EnrollEnclave command...\n");
    // zero will ask for next new generation.
    SingleBlobOutput output = ERP_EnrollEnclave(sesh, in);

    fprintf(stderr,"Returned from EnrollEnclave Command - Return Value: 0x%08x\n", output.returnCode);

    if (output.returnCode == 0)
    {
        fprintf(stderr,"Output Blob Generation: %08x\n", output.BlobOut.BlobGeneration);
        pOutBlob->BlobGeneration = output.BlobOut.BlobGeneration;
        pOutBlob->BlobLength = output.BlobOut.BlobLength;
        memcpy(&(pOutBlob->BlobData[0]), &(output.BlobOut.BlobData[0]), output.BlobOut.BlobLength);
    }
    else {
        err = output.returnCode;
    }
    return err;
}

unsigned int teststep_getTEEToken(
    HSMSession sesh,
    ERPBlob* pTrustedAK,
    ERPBlob* pTrustedQuote,
    ERPBlob* pNONCEBlob,
    unsigned char* pAKName, // TPM_NAME_LEN
    size_t quoteLength,
    unsigned char* quoteData,
    size_t sigLength,
    unsigned char* sigData,
    ERPBlob* pOutBlob)
{
    unsigned int err = 0;
    TEETokenRequestInput in = { {'\0'},{0,0,{'\0'}},{0,0,{'\0'}},{0,0,{'\0'}},0,{'\0'} ,0,{'\0'} };

    memcpy(&(in.AKName[0]), pAKName, TPM_NAME_LEN);
    in.QuoteDataLength = quoteLength;
    memcpy(&(in.QuoteData[0]), quoteData, quoteLength);
    in.QuoteSignatureLength = sigLength;
    memcpy(&(in.QuoteSignature[0]), sigData, sigLength);
    in.KnownAKBlob = *pTrustedAK;
    in.NONCEBlob = *pNONCEBlob;
    in.KnownQuoteBlob = *pTrustedQuote;

    fprintf(stderr,"\nExecuting getTEEToken command...\n");
    // zero will ask for next new generation.
    SingleBlobOutput output = ERP_GetTEEToken(sesh, in);

    fprintf(stderr,"Returned from getTEEToke Command - Return Value: 0x%08x\n", output.returnCode);

    if (output.returnCode == 0)
    {
        fprintf(stderr,"Output Blob Generation: %08x\n", output.BlobOut.BlobGeneration);
        pOutBlob->BlobGeneration = output.BlobOut.BlobGeneration;
        pOutBlob->BlobLength = output.BlobOut.BlobLength;
        memcpy(&(pOutBlob->BlobData[0]), &(output.BlobOut.BlobData[0]), output.BlobOut.BlobLength);
    }
    else {
        err = output.returnCode;
    }
    return err;
}

unsigned int teststep_GenerateDerivationKey(HSMSession sesh, unsigned int desiredGeneration, ERPBlob* pOutBlob)
{
    unsigned int err = 0;

    fprintf(stderr,"\nExecuting GenerateDerivationKey command ...\n");
    // zero will ask for next new generation.
    UIntInput genKeyIn = { desiredGeneration };
    SingleBlobOutput output = ERP_GenerateDerivationKey(sesh, genKeyIn);

    fprintf(stderr,"Returned from GenerateDerivationKey Command - Return Value: 0x%08x\n", output.returnCode);
    if (output.returnCode == 0)
    {
        fprintf(stderr,"Blob Generation: %08x\n", output.BlobOut.BlobGeneration);
        pOutBlob->BlobGeneration = output.BlobOut.BlobGeneration;
        pOutBlob->BlobLength = output.BlobOut.BlobLength;
        memcpy(&(pOutBlob->BlobData[0]), &(output.BlobOut.BlobData[0]), output.BlobOut.BlobLength);
    }
    else {
        err = output.returnCode;
    }
    return err;
}

unsigned int teststep_deriveTaskPersistenceKey(
    HSMSession sesh,
    unsigned char* pAKName, // TPM_NAME_LEN
    ERPBlob* pTEEToken,
    ERPBlob* pDerivationKey,
    size_t derivationDataLength,
    unsigned char* derivationData,
    unsigned int isInitial, // 1 => Initial Derivation, 0 => subsequent Derivation. 
    // Output
    size_t* pUsedDerivationDataLength,
    unsigned char* usedDerivationData, // MAX_BUFFER
    unsigned char* derivedKey) // AES_256_LEN
{
    unsigned int err = 0;
    DeriveKeyInput in = { {'\0'} ,{0,0,{'\0'}},{0,0,{'\0'}},0,0,{'\0'} };

    in.derivationDataLength = derivationDataLength;
    memcpy(&(in.AKName[0]), pAKName, TPM_NAME_LEN);
    memcpy(&(in.derivationData), derivationData, derivationDataLength);
    in.TEEToken = *pTEEToken;
    in.derivationKey = *pDerivationKey;
    in.initialDerivation = isInitial;
    fprintf(stderr,"\nExecuting DeriveTaskKey command...\n");
    // zero will ask for next new generation.
    DeriveKeyOutput output = ERP_DeriveTaskKey(sesh, in);

    fprintf(stderr,"Returned from deriveTaskKey Command - Return Value: 0x%08x\n", output.returnCode);

    if (output.returnCode == 0)
    {
        (*pUsedDerivationDataLength) = output.derivationDataLength;
        memcpy(usedDerivationData, output.derivationData, output.derivationDataLength);
        memcpy(derivedKey, output.derivedKey, AES_256_LEN);
    }
    else {
        err = output.returnCode;
    }
    return err;
}

unsigned int teststep_deriveAuditKey(
    HSMSession sesh,
    unsigned char* pAKName, // TPM_NAME_LEN
    ERPBlob* pTEEToken,
    ERPBlob* pDerivationKey,
    size_t derivationDataLength,
    unsigned char* derivationData,
    unsigned int isInitial, // 1 => Initial Derivation, 0 => subsequent Derivation.
    // Output
    size_t* pUsedDerivationDataLength,
    unsigned char* usedDerivationData, // MAX_BUFFER
    unsigned char* derivedKey) // AES_256_LEN
{
    unsigned int err = 0;
    DeriveKeyInput in = { {'\0'} ,{0,0,{'\0'}},{0,0,{'\0'}},0,0,{'\0'} };

    in.derivationDataLength = derivationDataLength;
    memcpy(&(in.AKName[0]), pAKName, TPM_NAME_LEN);
    memcpy(&(in.derivationData), derivationData, derivationDataLength);
    in.TEEToken = *pTEEToken;
    in.derivationKey = *pDerivationKey;
    in.initialDerivation = isInitial;
    fprintf(stderr,"\nExecuting DeriveTaskKey command...\n");
    // zero will ask for next new generation.
    DeriveKeyOutput output = ERP_DeriveAuditKey(sesh, in);

    fprintf(stderr,"Returned from deriveTaskKey Command - Return Value: 0x%08x\n", output.returnCode);

    if (output.returnCode == 0)
    {
        (*pUsedDerivationDataLength) = output.derivationDataLength;
        memcpy(usedDerivationData, output.derivationData, output.derivationDataLength);
        memcpy(derivedKey, output.derivedKey, AES_256_LEN);
    }
    else {
        err = output.returnCode;
    }
    return err;
}

unsigned int teststep_deriveCommsKey(
    HSMSession sesh,
    unsigned char* pAKName, // TPM_NAME_LEN
    ERPBlob* pTEEToken,
    ERPBlob* pDerivationKey,
    size_t derivationDataLength,
    unsigned char* derivationData,
    unsigned int isInitial, // 1 => Initial Derivation, 0 => subsequent Derivation.
    // Output
    size_t* pUsedDerivationDataLength,
    unsigned char* usedDerivationData, // MAX_BUFFER
    unsigned char* derivedKey) // AES_256_LEN
{
    unsigned int err = 0;
    DeriveKeyInput in = { {'\0'} ,{0,0,{'\0'}},{0,0,{'\0'}},0,0,{'\0'} };

    in.derivationDataLength = derivationDataLength;
    memcpy(&(in.AKName[0]), pAKName, TPM_NAME_LEN);
    memcpy(&(in.derivationData), derivationData, derivationDataLength);
    in.TEEToken = *pTEEToken;
    in.derivationKey = *pDerivationKey;
    in.initialDerivation = isInitial;
    fprintf(stderr,"\nExecuting DeriveTaskKey command...\n");
    // zero will ask for next new generation.
    DeriveKeyOutput output = ERP_DeriveCommsKey(sesh, in);

    fprintf(stderr,"Returned from deriveTaskKey Command - Return Value: 0x%08x\n", output.returnCode);

    if (output.returnCode == 0)
    {
        (*pUsedDerivationDataLength) = output.derivationDataLength;
        memcpy(usedDerivationData, output.derivationData, output.derivationDataLength);
        memcpy(derivedKey, output.derivedKey, AES_256_LEN);
    }
    else {
        err = output.returnCode;
    }
    return err;
}

void teststep_ASN1IntegerInput(HSMSession sesh, unsigned int SFCCode, bool bZeroOk)
{
    DirectIOInput rawInput = { SFCCode,5,{0x30, 0x03, 0x02, 0x01, 0x00} };
    DirectIOOutput rawOutput = ERP_DirectIO(sesh, rawInput);
    if (bZeroOk)
    {
        EXPECT_EQ(ERP_ERR_NOERROR, rawOutput.returnCode);
    }
    else {
        EXPECT_EQ(ERP_ERR_PARAM, rawOutput.returnCode);
    }
    rawInput = { SFCCode,5,{0x30, 0x01, 0x02, 0x01, 0x00} };
    rawOutput = ERP_DirectIO(sesh, rawInput);
    EXPECT_EQ(E_ASN1_DATASIZE, rawOutput.returnCode);
    rawInput = { SFCCode,5,{0x30, 0x06, 0x02, 0x01, 0x00} };
    rawOutput = ERP_DirectIO(sesh, rawInput);
    EXPECT_EQ(E_ASN1_DATASIZE, rawOutput.returnCode);
    rawInput = { SFCCode,5,{0x30, 0x03, 0x02, 0x00, 0x00} };
    rawOutput = ERP_DirectIO(sesh, rawInput);
    EXPECT_EQ(E_ASN1_DECODE_ERR, rawOutput.returnCode);
    rawInput = { SFCCode,5,{0x30, 0x03, 0x02, 0x02, 0x00} };
    rawOutput = ERP_DirectIO(sesh, rawInput);
    EXPECT_EQ(E_ASN1_DATASIZE, rawOutput.returnCode);
    rawInput = { SFCCode,6,{0x30, 0x03, 0x02, 0x01, 0x00, 0x00} };
    rawOutput = ERP_DirectIO(sesh, rawInput);
    EXPECT_EQ(ERP_ERR_PARAM_LEN, rawOutput.returnCode);
    rawInput = { SFCCode,6,{0x30, 0x04, 0x02, 0x01, 0x00, 0xFF} };
    rawOutput = ERP_DirectIO(sesh, rawInput);
    EXPECT_EQ(E_ASN1_DATASIZE, rawOutput.returnCode);
    rawInput = { SFCCode,5,{0x30, 0x03, 0x04, 0x01, 0x00} };
    rawOutput = ERP_DirectIO(sesh, rawInput);
    EXPECT_EQ(ERP_ERR_ASN1_CONTENT_ERROR, rawOutput.returnCode);
    rawInput = { SFCCode,8,{0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00} };
    rawOutput = ERP_DirectIO(sesh, rawInput);
    EXPECT_EQ(ERP_ERR_ASN1_CONTENT_ERROR, rawOutput.returnCode);
    rawInput = { SFCCode,4,{0x30, 0x03, 0x02, 0x01, 0x00} };
    rawOutput = ERP_DirectIO(sesh, rawInput);
    EXPECT_EQ(E_ASN1_DATASIZE, rawOutput.returnCode);
    rawInput = { SFCCode,6,{0x30, 0x03, 0x02, 0x01, 0x00} };
    rawOutput = ERP_DirectIO(sesh, rawInput);
    EXPECT_EQ(ERP_ERR_PARAM_LEN, rawOutput.returnCode);
    rawInput = { SFCCode,MAX_BUFFER,{0x30, 0x03, 0x02, 0x01, 0x00} };
    rawOutput = ERP_DirectIO(sesh, rawInput);
    EXPECT_EQ(ERP_ERR_PARAM_LEN, rawOutput.returnCode);
}

// This function will produce a one way variation of the NONCE value using a variation parameter to
//   enforce a purpose restriction on the NONCE.
// The variation function is out = HMAC_SHA256(nonceIn,variation data) where nonceIn is used as the HMAC key.
// This function does not do error checking on its' input - it is assumed that the caller did that.
extern unsigned int varyNONCE(const char* variation, unsigned char* nonceDataIn, unsigned char* variedNONCEOut)
{
    int err = ERP_ERR_NOERROR;
    size_t outputLength = NONCE_LEN;
    unsigned char* pOut = HMAC(EVP_sha256(),
        nonceDataIn, NONCE_LEN,
        (const unsigned char *)variation, strlen(variation),
        variedNONCEOut, (unsigned int *)&outputLength);
    if (pOut == NULL)
    {
        err = ERP_ERR_FILE_IO;
    }
    return err;
}