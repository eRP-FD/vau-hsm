This file contains instructions to generate a new set of stastic test data for a newly initialised TPM.
To create saved data on RU (or anywhere else - replace target directory as appropriate...):
- start the sw tpm running in its' own window.
- go to the test/resources directory before CMAKE and run GenerateTPMTestData.bat or the unix equivalent.
- Change the RUAttestationSequencePart1 and 2 tests to not be disabled.
- During all of this, the tests will write to a copy of the resources directory inside the build folder and 
   to persist data beyond a single cmake generation, these must be duplicated in the main repo resources folder.
- Make sure that the EKCertificate (generated during the above batch...) is in EKCertECC.crt 
   and the TPM Manufacturer root CA certificate is in cacertecc.crt
- set the devIP in eRPRUAttestationTests to point to the target HSM.
- run eRPRUAttestationSequencePart1.   This will write into rusaved:
    - trustedMfrRoot.blob
    - trustedEK.blob
    and the following into the resources directory:
    - encCredHSM.bin
    - secretHSM.bin
    - AKChallenge.blob
    - EnrolmentQuoteNONCE.bin
    - EnrollmentQuoteNONCE.blob
    - AttestationQuoteNONCE.bin
    - AttestationQuoteNONCE.blob
- Go back to the command prompt in the resources directory.
- if this is a completely new TPM installation then run GenerateTPMTestData.bat once only.   This
   will require copying and saving of a number of files and will invalidate and saved data alread generated using this tpm.
- run the script gentleTPMStartup.bat followed by ActivateHSMCredential.bat   This will take the encCredHSM.bin and secretHSM.bin
   from the previous test and calculate the decrypted challenge to be returned to the HSM   This will save:
   - credDecHSM.bin.
   - AttestationQuote.bin
   - AttestationQuoteSig.bin
   - EnrollmentQuote.bin
   - EnrollmentQuoteSig.bin
- Copy the following files from the resources directory into the saved directory.   Pay attention to whether this is the 
   cmake build copy of the resources or the actual saved copy in the main repo.
   - encCredHSM.bin -> rusaved/encCredHSMSaved.bin
   - secretHSM.bin -> rusaved/secretHSMSaved.bin
   - AKChallenge.blob -> rusaved/AKChallengeSaved.blob
   - credDecHSM.bin -> rusaved/credDecHSMSaved.bin
   - AKPub.bin -> rusaved/AKPub.bin
   - h80000002.bin -> rusaved/h80000002.bin;
   - AttestationQuote.bin -> rusaved/AttestationQuoteSaved.bin
   - AttestationQuoteSig.bin -> AttestationQuoteSigSaved.bin
   - EnrollmentQuote.bin -> rusaved/EnrollmentQuoteSaved.bin
   - EnrollmentQuoteSig.bin -> rusaved/EnrollmentQuoteSigSaved.bin
   - AttestationQuoteNONCE.bin -> rusaved/AttestationQuoteNONCESaved.bin
   - AttestationQuoteNONCE.blob -> rusaved/AttestationQuoteNONCESaved.blob
   - EnrollmentQuoteNONCE.bin -> rusaved/EnrollmentQuoteNONCESaved.bin
   - EnrollmentQuoteNONCE.blob -> rusaved/EnrollmentQuoteNONCESaved.blob
   - trustedEK.blob -> rusaved/trustedEKSaved.blob
- run eRPRUAttestationSequenceTestPart2   This will write the following files whih need to be renamed 
   if they are to be saved:
   - rusaved/trustedAK.blob -> rusaved/trustedAKSaved.blob
   - rusaved/trustedQuote.blob -> rusaved/trustedQuoteSaved.blob
   - rusaved/staticTEEToken.blob -> rusaved/StaticTEETokenSaved.blob




