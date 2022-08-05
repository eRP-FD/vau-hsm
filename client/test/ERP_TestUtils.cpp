/**************************************************************************************************
 * (C) Copyright IBM Deutschland GmbH 2021
 * (C) Copyright IBM Corp. 2021
 * SPDX-License-Identifier: CC BY-NC-ND 3.0 DE
 **************************************************************************************************/

#include "ERP_TestUtils.h"

#include "ERP_Error.h"

#include <gtest/gtest.h>
#include <openssl/hmac.h>

#include <cstring>

namespace
{
    constexpr std::string_view testDataDir = "resources/";
    constexpr std::size_t ERPBlobHeader = sizeof(ERPBlob) - MAX_BUFFER;

    using Buffer = std::vector<std::uint8_t>;
} // namespace

// Utility Method for byte arrays initialised from strings.
Buffer asciiToBuffer(std::string_view in)
{
    return Buffer(std::make_move_iterator(in.begin()), std::make_move_iterator(in.end()));
}

std::unique_ptr<ERPBlob> getEmptyBlob(unsigned int Gen)
{
    auto pBlob = std::make_unique<ERPBlob>();
    pBlob->BlobGeneration = Gen;
    pBlob->BlobLength = 0;
    std::memset(&(pBlob->BlobData[0]), 0, sizeof(pBlob->BlobData));

    return pBlob;
}

// Utility method to read a file form the resources directory, allocates a pointer to a buffer to it and return that pointer 
// for the caller to own and be responsible for deletion.
Buffer readERPResourceFile(const std::string& filename, bool bMustExist)
{
    const std::string fullFileName = testDataDir.data() + filename;
    std::ifstream readFile = std::ifstream(fullFileName, std::ios::in | std::ios::binary);;
    if (bMustExist)
    {
        EXPECT_TRUE(readFile.is_open());
        if (!readFile.is_open())
        {
            std::cerr << "Test resource file missing: " << filename.c_str() << "\n";
        }
    }

    return Buffer(std::istreambuf_iterator<char>(readFile), std::istreambuf_iterator<char>());
}

// Caller must delete returned object.
ERPBlob* readBlobResourceFile(const std::string& filename, bool bMustExist)
{
    const auto data = readERPResourceFile(filename, bMustExist);
    if (bMustExist)
    {
        EXPECT_LE(data.size(), MAX_BUFFER);
    }

    if (data.empty() || data.size() > MAX_BUFFER)
    {
        return nullptr;
    }

    auto* retVal = new ERPBlob{};
    EXPECT_NE(nullptr, retVal);

    std::copy(data.cbegin(), data.cend(), reinterpret_cast<unsigned char*>(retVal));
    retVal->BlobLength = data.size() - ERPBlobHeader;

    return retVal;
}

unsigned int writeERPResourceFile(const std::string& filename, const std::vector<uint8_t>& data) 
{
    const std::string fullFileName = testDataDir.data() + filename;
    std::ofstream writeFile = std::ofstream(fullFileName, std::ios::out | std::ios::binary);;
    EXPECT_TRUE(writeFile.is_open());
    // The uint8 to int8 conversion has to be done somewhere - this is it.
    writeFile.write(reinterpret_cast<const char*>(data.data()), data.size() * sizeof(data.front()));
    writeFile.close();

    return ERP_ERR_NOERROR;
}

// Caller must delete returned object.
unsigned int writeBlobResourceFile(const std::string& filename, const ERPBlob *pBlob)
{
    auto blobSize = static_cast<std::streamsize>(pBlob->BlobLength + ERPBlobHeader);

    const std::string fullFileName = testDataDir.data() + filename;
    std::ofstream writeFile = std::ofstream(fullFileName, std::ios::out | std::ios::binary);;
    EXPECT_TRUE(writeFile.is_open());
    // The uint8 to int8 conversion has to be done somewhere - this is it.
    const char* blobBegin = reinterpret_cast<const char*>(pBlob); // NOLINT
    writeFile.write(blobBegin, blobSize);
    writeFile.close();

    return ERP_ERR_NOERROR;
}

void printHex(const std::string& message, const std::vector<uint8_t>& data)
{
    std::cerr << message << ": ";
    for (std::size_t i = 0; i < data.size(); ++i)
    {
        unsigned int a = data.at(i);
        if ((i > 0) && ((i % NIBBLE_SIZE) == 0))
        {
            std::cerr << std::endl;
        }

        std::cerr << std::hex
                  << std::setfill('0')
                  << std::setw(2)
                  << std::setprecision(2)
                  << a
                  << " ";
    }

    std::cerr << std::endl;
}

unsigned int deriveOrRetrieveDerivationKey(HSMSession sesh,
                                           unsigned int generation,
                                           const char* filename,
                                           ERPBlob* pOutBlob)
{
    auto err = ERP_ERR_NOERROR;
    ERPBlob* pReadBlob = readBlobResourceFile(filename, false);

    if (pReadBlob == nullptr)
    {
         err = teststep_GenerateDerivationKey(sesh, generation, pOutBlob);

         // Save the Derivation Key for use in other tests.
         if (err == ERP_ERR_SUCCESS)
         {
             err = writeBlobResourceFile(filename, pOutBlob);
         }
    }
    else
    {
        *pOutBlob = *pReadBlob;
    }

    delete pReadBlob;

    return err;
}

unsigned int teststep_DumpHSMMemory(HSMSession sesh)
{
    std::cerr << "Executing DumpHSMMemory command...\n";

    EmptyOutput output = ERP_DumpHSMMemory(sesh);
    EXPECT_EQ(ERP_ERR_NOERROR, output.returnCode);

    std::cerr << "Returned from DumpHSMMemory Command - Return Value: " << output.returnCode << "\n";

    return output.returnCode;
}

unsigned int teststep_GenerateBlobKey(HSMSession sesh, unsigned int gen)
{
    std::cerr << "Executing GenerateBlobKey command...\n";
    // zero will ask for next new generation.
    UIntInput genKeyIn = { gen };
    UIntOutput output = ERP_GenerateBlobKey(sesh, genKeyIn);

    std::cerr << "Returned from GenerateBlobKey Command - Return Value: " << output.returnCode << "\n";

    return output.returnCode;
}

unsigned int teststep_ListLoadedBlobKeys(HSMSession sesh)
{
    std::cerr << "Executing ListLoadedBlobKeys command...\n";

    BlobKeyListOutput output = ERP_ListLoadedBlobKeys(sesh);

    std::cerr << "Returned from ListLoadedBlobKeys Command - Return Value: " << output.returnCode << "\n";
    std::cerr << "Number of loaded Blob Keys: " << output.NumKeys << "\n";

    return output.returnCode;
}

unsigned int teststep_DeleteBlobKey(HSMSession sesh, unsigned int gen)
{
    std::cerr << "Executing DeleteBlobKey command...\n";
    // zero will ask for next new generation.
    UIntInput genKeyIn = { gen };
    EmptyOutput output = ERP_DeleteBlobKey(sesh, genKeyIn);

    std::cerr << "Returned from DeleteBlobKey Command - Return Value: " << output.returnCode << "\n";

    return output.returnCode;
}

unsigned int teststep_GenerateNONCE(HSMSession sesh, unsigned int gen)
{
    std::cerr << "Executing GenerateNONCE command...\n";
    // zero will ask for next new generation.
    UIntInput genKeyIn = { gen };
    NONCEOutput output = ERP_GenerateNONCE(sesh, genKeyIn);
    std::cerr << "Returned from GenerateNONCE Command - Return Value: " << output.returnCode << "\n";
    std::cerr << "Blob Generation: " << output.BlobOut.BlobGeneration << "\n";

    return output.returnCode;
}

unsigned int teststep_TrustTPMMfr(HSMSession sesh, unsigned int generation, ERPBlob* pOutBlob, const std::vector<uint8_t>& certFile)
{
    TrustTPMMfrInput in = { 0, 0,{0} };
    in.desiredGeneration = generation;
    in.certLength = certFile.size();
    EXPECT_GT(MAX_BUFFER, in.certLength);
    memcpy(&(in.certData[0]), certFile.data(), in.certLength);
    printHex("\nExecuting TrustTPMMfr command with certificate", certFile);
    // zero will ask for next new generation.
    SingleBlobOutput output = ERP_TrustTPMMfr(sesh, in);

    std::cerr << "Returned from TrustTPMMFr Command - Return Value: " << output.returnCode << "\n";
    if (output.returnCode == 0)
    {
        std::cerr << "Blob Generation: " << output.BlobOut.BlobGeneration << "\n";
        pOutBlob->BlobGeneration = output.BlobOut.BlobGeneration;
        pOutBlob->BlobLength = output.BlobOut.BlobLength;
        memcpy(&(pOutBlob->BlobData[0]), &(output.BlobOut.BlobData[0]), output.BlobOut.BlobLength);
    }

    return output.returnCode;
}

unsigned int teststep_EnrollTPMEK(
    HSMSession sesh,
    unsigned int generation,
    ERPBlob* pTrustedRoot,
    ERPBlob* pTrustedEK, // Output
    size_t EKCertLen,
    unsigned char* pEKCertData)
{
    EnrollTPMEKInput in = { 0,{0,0,""},0,"" };

    in.desiredGeneration = generation;
    in.TPMMfrBlob = *pTrustedRoot;
    in.EKCertLength = EKCertLen;
    memcpy(&(in.EKCertData[0]), pEKCertData, EKCertLen);

    std::cerr << "Executing EnrollTPMEK command...\n";
    // zero will ask for next new generation.
    SingleBlobOutput output = ERP_EnrollTPMEK(sesh, in);

    std::cerr << "Returned from EnrollTPMEK Command - Return Value: " << output.returnCode << "\n";
    if (output.returnCode == 0)
    {
        std::cerr << "Blob Generation: " << output.BlobOut.BlobGeneration << "\n";
        pTrustedEK->BlobGeneration = output.BlobOut.BlobGeneration;
        pTrustedEK->BlobLength = output.BlobOut.BlobLength;
        memcpy(&(pTrustedEK->BlobData[0]), &(output.BlobOut.BlobData[0]), output.BlobOut.BlobLength);
    }

    return output.returnCode;
}

unsigned int teststep_GetAKChallenge(
    HSMSession sesh,
    // Input
    unsigned int desiredGeneration,
    ERPBlob* pTrustedEK,
    unsigned char* pAKName, // TPM_NAME_LEN...
    size_t AKCertLength,
    unsigned char* AKCertData,
    // output
    ERPBlob* pCredChallengeBlob,
    size_t* pEncCredentialLength,
    unsigned char* pEncCredentialData, // MAX_BUFFER
    size_t* pSecretLength,
    unsigned char* pSecretData) // MAX_BUFFER
{
    AKChallengeInput in{};

    in.desiredGeneration = desiredGeneration;
    in.KnownEKBlob = *pTrustedEK;
    in.AKPubLength = AKCertLength;
    memcpy(&(in.AKName[0]), pAKName, TPM_NAME_LEN);
    memcpy(&(in.AKPubData[0]), AKCertData, AKCertLength);

    std::cerr << "Executing GetAKChallenge command...\n" << "\n";
    // zero will ask for next new generation.
    AKChallengeOutput output = ERP_GetAKChallenge(sesh, in);

    std::cerr << "Returned from GetAKChallenge Command - Return Value: " << output.returnCode << "\n";
    if (output.returnCode == 0)
    {
        std::cerr << "ChallengeBlob Generation: " << output.ChallengeBlob.BlobGeneration << "\n";
        pCredChallengeBlob->BlobGeneration = output.ChallengeBlob.BlobGeneration;
        pCredChallengeBlob->BlobLength = output.ChallengeBlob.BlobLength;
        memcpy(&(pCredChallengeBlob->BlobData[0]),
            &(output.ChallengeBlob.BlobData[0]),
            output.ChallengeBlob.BlobLength);
        (*pEncCredentialLength) = output.encCredentialLength;
        memcpy(pEncCredentialData, &(output.encCredentialData[0]), output.encCredentialLength);
        (*pSecretLength) = output.secretLength;
        memcpy(pSecretData, &(output.secretData[0]), output.secretLength);
    }

    return output.returnCode;
}

unsigned int teststep_EnrollAK(
    HSMSession sesh,
    unsigned int desiredGeneration,
    ERPBlob* pTrustedEK,
    ERPBlob* pChallengeBlob,
    unsigned char* pAKName, // TPM_NAME_LEN
    size_t AKCertLength,
    unsigned char* AKCertData,
    size_t decCredLength,
    unsigned char* decCredData,
    ERPBlob* pOutBlob)
{
    EnrollTPMAKInput in{};

    in.desiredGeneration = desiredGeneration;
    in.KnownEKBlob = *pTrustedEK;
    memcpy(&(in.AKName[0]), pAKName, TPM_NAME_LEN);
    in.AKPubLength = AKCertLength;
    memcpy(&(in.AKPubData[0]), AKCertData, AKCertLength);
    in.challengeBlob = *pChallengeBlob;
    in.decCredentialLength = decCredLength;
    memcpy(&(in.decCredentialData[0]), decCredData, decCredLength);

    std::cerr << "Executing EnrollTPMAK command...\n";
    // zero will ask for next new generation.
    SingleBlobOutput output = ERP_EnrollTPMAK(sesh, in);

    std::cerr << "Returned from EnrollTPMAK Command - Return Value: " << output.returnCode << "\n";

    if (output.returnCode == 0)
    {
        std::cerr << "Output Blob Generation: " << output.BlobOut.BlobGeneration << "\n";
        pOutBlob->BlobGeneration = output.BlobOut.BlobGeneration;
        pOutBlob->BlobLength = output.BlobOut.BlobLength;
        memcpy(&(pOutBlob->BlobData[0]), &(output.BlobOut.BlobData[0]), output.BlobOut.BlobLength);
    }

    return output.returnCode;
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
    EnrollEnclaveInput in{};

    in.desiredGeneration = desiredGeneration;
    memcpy(&(in.AKName[0]), pAKName, TPM_NAME_LEN);
    in.quoteLength = quoteLength;
    memcpy(&(in.quoteData[0]), quoteData, quoteLength);
    in.signatureLength = sigLength;
    memcpy(&(in.signatureData[0]), sigData, sigLength);
    in.KnownAKBlob = *pTrustedAK;
    in.NONCEBlob = *pNONCEBlob;

    std::cerr << "Executing EnrollEnclave command...\n";
    // zero will ask for next new generation.
    SingleBlobOutput output = ERP_EnrollEnclave(sesh, in);

    std::cerr << "Returned from EnrollEnclave Command - Return Value: " << output.returnCode << "\n";

    if (output.returnCode == 0)
    {
        std::cerr << "Output Blob Generation: " << output.BlobOut.BlobGeneration << "\n";
        pOutBlob->BlobGeneration = output.BlobOut.BlobGeneration;
        pOutBlob->BlobLength = output.BlobOut.BlobLength;
        memcpy(&(pOutBlob->BlobData[0]), &(output.BlobOut.BlobData[0]), output.BlobOut.BlobLength);
    }

    return output.returnCode;
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
    TEETokenRequestInput in{};

    memcpy(&(in.AKName[0]), pAKName, TPM_NAME_LEN);
    in.QuoteDataLength = quoteLength;
    memcpy(&(in.QuoteData[0]), quoteData, quoteLength);
    in.QuoteSignatureLength = sigLength;
    memcpy(&(in.QuoteSignature[0]), sigData, sigLength);
    in.KnownAKBlob = *pTrustedAK;
    in.NONCEBlob = *pNONCEBlob;
    in.KnownQuoteBlob = *pTrustedQuote;

    std::cerr << "Executing getTEEToken command...\n";
    // zero will ask for next new generation.
    SingleBlobOutput output = ERP_GetTEEToken(sesh, in);

    std::cerr << "Returned from getTEEToke Command - Return Value: " << output.returnCode << "\n";

    if (output.returnCode == 0)
    {
        std::cerr << "Output Blob Generation: " << output.BlobOut.BlobGeneration << "\n";
        pOutBlob->BlobGeneration = output.BlobOut.BlobGeneration;
        pOutBlob->BlobLength = output.BlobOut.BlobLength;
        memcpy(&(pOutBlob->BlobData[0]), &(output.BlobOut.BlobData[0]), output.BlobOut.BlobLength);
    }

    return output.returnCode;
}

unsigned int teststep_GenerateDerivationKey(HSMSession sesh, unsigned int desiredGeneration, ERPBlob* pOutBlob)
{
    std::cerr << "Executing GenerateDerivationKey command...\n";
    // zero will ask for next new generation.
    UIntInput genKeyIn = { desiredGeneration };
    SingleBlobOutput output = ERP_GenerateDerivationKey(sesh, genKeyIn);

    std::cerr << "Returned from GenerateDerivationKey Command - Return Value: " <<output.returnCode << "\n";
    if (output.returnCode == 0)
    {
        std::cerr << "Blob Generation: " << output.BlobOut.BlobGeneration << "\n";
        pOutBlob->BlobGeneration = output.BlobOut.BlobGeneration;
        pOutBlob->BlobLength = output.BlobOut.BlobLength;
        memcpy(&(pOutBlob->BlobData[0]), &(output.BlobOut.BlobData[0]), output.BlobOut.BlobLength);
    }

    return output.returnCode;
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
    DeriveKeyInput in{};

    in.derivationDataLength = derivationDataLength;
    memcpy(&(in.AKName[0]), pAKName, TPM_NAME_LEN);
    memcpy(&(in.derivationData), derivationData, derivationDataLength);
    in.TEEToken = *pTEEToken;
    in.derivationKey = *pDerivationKey;
    in.initialDerivation = isInitial;
    std::cerr << "Executing DeriveTaskKey command...\n";
    // zero will ask for next new generation.
    DeriveKeyOutput output = ERP_DeriveTaskKey(sesh, in);

    std::cerr << "Returned from deriveTaskKey Command - Return Value: " << output.returnCode << "\n";

    if (output.returnCode == 0)
    {
        (*pUsedDerivationDataLength) = output.derivationDataLength;
        memcpy(&(usedDerivationData[0]), &(output.derivationData[0]), output.derivationDataLength);
        memcpy(&(derivedKey[0]), &(output.derivedKey[0]), AES_256_LEN);
    }

    return output.returnCode;
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
    DeriveKeyInput in{};

    in.derivationDataLength = derivationDataLength;
    memcpy(&(in.AKName[0]), pAKName, TPM_NAME_LEN);
    memcpy(&(in.derivationData), derivationData, derivationDataLength);
    in.TEEToken = *pTEEToken;
    in.derivationKey = *pDerivationKey;
    in.initialDerivation = isInitial;
    printf("\nExecuting DeriveAuditKey command...\n");
    // zero will ask for next new generation.
    DeriveKeyOutput output = ERP_DeriveAuditKey(sesh, in);

    printf("Returned from deriveAuditKey Command - Return Value: 0x%08x\n", output.returnCode);

    if (output.returnCode == 0)
    {
        (*pUsedDerivationDataLength) = output.derivationDataLength;
        memcpy(&(usedDerivationData[0]), &(output.derivationData[0]), output.derivationDataLength);
        memcpy(&(derivedKey[0]), &(output.derivedKey[0]), AES_256_LEN);
    }

    return output.returnCode;
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
    DeriveKeyInput in{};

    in.derivationDataLength = derivationDataLength;
    memcpy(&(in.AKName[0]), pAKName, TPM_NAME_LEN);
    memcpy(&(in.derivationData), derivationData, derivationDataLength);
    in.TEEToken = *pTEEToken;
    in.derivationKey = *pDerivationKey;
    in.initialDerivation = isInitial;
    printf("\nExecuting DeriveCommsKey command...\n");
    // zero will ask for next new generation.
    DeriveKeyOutput output = ERP_DeriveCommsKey(sesh, in);

    printf("Returned from DeriveCommsKey Command - Return Value: 0x%08x\n", output.returnCode);

    if (output.returnCode == 0)
    {
        (*pUsedDerivationDataLength) = output.derivationDataLength;
        memcpy(&(usedDerivationData[0]), &(output.derivationData[0]), output.derivationDataLength);
        memcpy(&(derivedKey[0]), &(output.derivedKey[0]), AES_256_LEN);
    }

    return output.returnCode;
}

unsigned int teststep_deriveChargeItemKey(
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
    DeriveKeyInput in{};

    in.derivationDataLength = derivationDataLength;
    memcpy(&(in.AKName[0]), pAKName, TPM_NAME_LEN);
    memcpy(&(in.derivationData), derivationData, derivationDataLength);
    in.TEEToken = *pTEEToken;
    in.derivationKey = *pDerivationKey;
    in.initialDerivation = isInitial;
    printf("\nExecuting DeriveChargeItemKey command...\n");
    // zero will ask for next new generation.
    DeriveKeyOutput output = ERP_DeriveChargeItemKey(sesh, in);

    printf("Returned from DeriveChargeItemKey Command - Return Value: 0x%08x\n", output.returnCode);

    if (output.returnCode == 0)
    {
        (*pUsedDerivationDataLength) = output.derivationDataLength;
        memcpy(&(usedDerivationData[0]), &(output.derivationData[0]), output.derivationDataLength);
        memcpy(&(derivedKey[0]), &(output.derivedKey[0]), AES_256_LEN);
    }

    return output.returnCode;
}

void teststep_ASN1IntegerInput(HSMSession sesh, unsigned int SFCCode, bool bZeroOk)
{
    // the nolint comments are for the clang-tody readability - magic numbers checks which ado not
    //   result in an improvement. 
    DirectIOInput rawInput = { SFCCode,5,{0x30, 0x03, 0x02, 0x01, 0x00} }; // NOLINT
    DirectIOOutput rawOutput = ERP_DirectIO(sesh, rawInput);
    if (bZeroOk)
    {
        EXPECT_EQ(ERP_ERR_NOERROR, rawOutput.returnCode);
    }
    else
    {
        EXPECT_EQ(ERP_ERR_PARAM, rawOutput.returnCode);
    }
    rawInput = { SFCCode, 5, {0x30, 0x01, 0x02, 0x01, 0x00} }; // NOLINT
    rawOutput = ERP_DirectIO(sesh, rawInput);
    EXPECT_EQ(E_ASN1_DATASIZE, rawOutput.returnCode);
    rawInput = { SFCCode, 5, {0x30, 0x06, 0x02, 0x01, 0x00} }; // NOLINT
    rawOutput = ERP_DirectIO(sesh, rawInput);
    EXPECT_EQ(E_ASN1_DATASIZE, rawOutput.returnCode);
    rawInput = { SFCCode, 5, {0x30, 0x03, 0x02, 0x00, 0x00} }; // NOLINT
    rawOutput = ERP_DirectIO(sesh, rawInput);
    EXPECT_EQ(E_ASN1_DECODE_ERR, rawOutput.returnCode);
    rawInput = { SFCCode, 5, {0x30, 0x03, 0x02, 0x02, 0x00} }; // NOLINT
    rawOutput = ERP_DirectIO(sesh, rawInput);
    EXPECT_EQ(E_ASN1_DATASIZE, rawOutput.returnCode);
    rawInput = { SFCCode, 6, {0x30, 0x03, 0x02, 0x01, 0x00, 0x00} }; // NOLINT
    rawOutput = ERP_DirectIO(sesh, rawInput);
    EXPECT_EQ(ERP_ERR_PARAM_LEN, rawOutput.returnCode);
    rawInput = { SFCCode, 6, {0x30, 0x04, 0x02, 0x01, 0x00, 0xFF} }; // NOLINT
    rawOutput = ERP_DirectIO(sesh, rawInput);
    EXPECT_EQ(E_ASN1_DATASIZE, rawOutput.returnCode);
    rawInput = { SFCCode, 5, {0x30, 0x03, 0x04, 0x01, 0x00} }; // NOLINT
    rawOutput = ERP_DirectIO(sesh, rawInput);
    EXPECT_EQ(ERP_ERR_ASN1_CONTENT_ERROR, rawOutput.returnCode);
    rawInput = { SFCCode, 8, {0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00} }; // NOLINT
    rawOutput = ERP_DirectIO(sesh, rawInput);
    EXPECT_EQ(ERP_ERR_ASN1_CONTENT_ERROR, rawOutput.returnCode);
    rawInput = { SFCCode, 4, {0x30, 0x03, 0x02, 0x01, 0x00} }; // NOLINT
    rawOutput = ERP_DirectIO(sesh, rawInput);
    EXPECT_EQ(E_ASN1_DATASIZE, rawOutput.returnCode);
    rawInput = { SFCCode, 6, {0x30, 0x03, 0x02, 0x01, 0x00} }; // NOLINT
    rawOutput = ERP_DirectIO(sesh, rawInput);
    EXPECT_EQ(ERP_ERR_PARAM_LEN, rawOutput.returnCode);
    rawInput = { SFCCode,MAX_BUFFER,{0x30, 0x03, 0x02, 0x01, 0x00} }; // NOLINT
    rawOutput = ERP_DirectIO(sesh, rawInput);
    EXPECT_EQ(ERP_ERR_PARAM_LEN, rawOutput.returnCode);
}

// This function will produce a one way variation of the NONCE value using a variation parameter to
//   enforce a purpose restriction on the NONCE.
// The variation function is out = HMAC_SHA256(nonceIn,variation data) where nonceIn is used as the HMAC key.
// This function does not do error checking on its' input - it is assumed that the caller did that.
extern unsigned int varyNONCE(const char* variation, unsigned char* nonceDataIn, unsigned char* variedNONCEOut)
{
    auto err = ERP_ERR_NOERROR;
    auto varVector = asciiToBuffer(variation);
    unsigned int outputLength = NONCE_LEN;
    unsigned char* pOut = HMAC(EVP_sha256(),
                               nonceDataIn,
                               NONCE_LEN,
                               varVector.data(),
                               varVector.size()-1,
                               variedNONCEOut,
                               &outputLength);

    if (pOut == nullptr)
    {
        err = ERP_ERR_FILE_IO;
    }

    return err;
}

extern unsigned int teststep_GenerateHashKey(HSMSession sesh, unsigned int Generation, SingleBlobOutput* pHashBlobOut)
{
    UIntInput in = { Generation };
    *pHashBlobOut = ERP_GenerateHashKey(sesh, in);
    return pHashBlobOut->returnCode;
}

extern unsigned int teststep_GeneratePseudonameKey(HSMSession sesh, unsigned int Generation, SingleBlobOutput* pPseudonameBlobOut)
{
    UIntInput in = { Generation };
    *pPseudonameBlobOut = ERP_GeneratePseudonameKey(sesh, in);
    return pPseudonameBlobOut->returnCode;
}

extern unsigned int teststep_UnwrapHashKey(HSMSession sesh, ERPBlob* hashBlob, AES256KeyOutput* pKeyOut)
{
    TwoBlobGetKeyInput get{};
    get.Key = *hashBlob;
    // Take the TEEToken from a previous test run:
    auto teeToken = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/StaticTEETokenSaved.blob"));
    EXPECT_NE(nullptr, teeToken);
    get.TEEToken = *teeToken;
    *pKeyOut = ERP_UnwrapHashKey(sesh, get);
    return pKeyOut->returnCode;
}

extern unsigned int teststep_GoodKeyDerivation(HSMSession sesh,
    ERPBlob* pTEEToken, unsigned char* pAKName,
    deriveFunc_t* pGoodTestFunc, // Will be checked for consistent derivation
    deriveFunc_t* pOtherTestFunc // Will be checked that it DOES NOT prpoduce the same result.
)
{
    unsigned int err = ERP_ERR_NOERROR;
    // 12. Derive or retrieve a new Derivation Key Blob.
    ERPBlob derivationKeyBlob = {};
    if (err == ERP_ERR_SUCCESS)
    {
        err = teststep_GenerateDerivationKey(sesh, 0, &derivationKeyBlob);
        // Alternatively - Fill derivationKeyBlob from previously generated data...
    }
    // derive good persistence Key for initial derivation
    auto derivationData = asciiToBuffer("(Dummy Derivation Data) KVNR:Z123-45678");
    std::uint8_t usedDerivationData[MAX_BUFFER];
    size_t usedDerivationDataLength = 0;
    std::uint8_t initialDerivedKey[AES_256_LEN];
    if (err == ERP_ERR_SUCCESS)
    {
        err = (*pGoodTestFunc)(
            sesh,
            pAKName, // SHA_1_LEN...
            pTEEToken,
            &derivationKeyBlob,
            derivationData.size(),
            derivationData.data(),
            1, // 1 => Initial Derivation, 0 => subsequent Derivation. 
            // Output
            &usedDerivationDataLength,
            &(usedDerivationData[0]), // MAX_BUFFER
            &(initialDerivedKey[0])); // AES_256_LEN
    }
    EXPECT_EQ(ERP_ERR_NOERROR, err);
    EXPECT_EQ(usedDerivationDataLength, 2 + 32 + derivationData.size()); /* check that the used derivation data is correct */
    // Derive good persistence key again for a non-initial derivation
    std::uint8_t subsequentDerivedKey[AES_256_LEN];
    for (int m = 0; m < SMALL_LOOP; m++)
    {
        if (err == ERP_ERR_SUCCESS)
        {
            err = (*pGoodTestFunc)(
                sesh,
                pAKName, // SHA_1_LEN...
                pTEEToken,
                &derivationKeyBlob,
                usedDerivationDataLength,
                &(usedDerivationData[0]),
                0, // 1 => Initial Derivation, 0 => subsequent Derivation. 
                // Output
                &usedDerivationDataLength,
                &(usedDerivationData[0]), // MAX_BUFFER
                &(subsequentDerivedKey[0])); // AES_256_LEN
        }
    }
    // Compare the two keys from the good derivation:
    EXPECT_EQ(0, memcmp(&(initialDerivedKey[0]), &(subsequentDerivedKey[0]), AES_256_LEN));

    // Derive a different class of persistence key for a non-initial derivation
    std::uint8_t otherDerivedKey[AES_256_LEN];
    if (err == ERP_ERR_SUCCESS)
    {
        err = (*pOtherTestFunc)(
            sesh,
            pAKName, // SHA_1_LEN...
            pTEEToken,
            &derivationKeyBlob,
            usedDerivationDataLength,
            &(usedDerivationData[0]),
            0, // 1 => Initial Derivation, 0 => subsequent Derivation. 
            // Output
            &usedDerivationDataLength,
            &(usedDerivationData[0]), // MAX_BUFFER
            &(otherDerivedKey[0])); // AES_256_LEN
    }
    // Now check that the other class of key derivation did NOT match the good one:
    EXPECT_FALSE(0 == memcmp(&(initialDerivedKey[0]), &(otherDerivedKey[0]), AES_256_LEN));

    return err;
}

extern unsigned int teststep_UnwrapPseudonameKey(HSMSession sesh, ERPBlob* hashBlob, AES256KeyOutput* pKeyOut)
{
    TwoBlobGetKeyInput get{};
    get.Key = *hashBlob;
    // Take the TEEToken from a previous test run:
    auto teeToken = std::unique_ptr<ERPBlob>(readBlobResourceFile("saved/StaticTEETokenSaved.blob"));
    EXPECT_NE(nullptr, teeToken);
    get.TEEToken = *teeToken;
    *pKeyOut = ERP_UnwrapPseudonameKey(sesh, get);
    return pKeyOut->returnCode;
}
