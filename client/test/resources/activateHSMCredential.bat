REM Script to activate credential created by HSM Unit Tests Attestation  Sequence test.
%TPM_EXE_PATH%flushcontext -ha 03000000
%TPM_EXE_PATH%flushcontext -ha 03000001
%TPM_EXE_PATH%flushcontext -ha 03000002

 REM Start a policy session
%TPM_EXE_PATH%startauthsession -se p 
 REM Returns Handle 03000000
 REM Policy command code - activatecredential
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 00000147 
 REM Start a second policy session
%TPM_EXE_PATH%startauthsession -se p 
 REM REturns Handle 03000001
 REM -pwde "..." if an endorsement password has been set..
%TPM_EXE_PATH%policysecret -hs 03000001 -ha 4000000b
 REM
 REM Check the two policies:
%TPM_EXE_PATH%policygetdigest -ha 03000000
%TPM_EXE_PATH%policygetdigest -ha 03000001
echo "Activate credential"
%TPM_EXE_PATH%activatecredential -ha 80000002 -hk 80000001 -icred encCredHSM.bin -is secretHSM.bin -ocred credDecHSM.bin -pwdk erpek -se0 03000000 0 -se1 03000001 0
REM
REM now get a workable quote for the enrollment.
REM assume QuoteNONCE.bin has the rnd nonce in it.
%TPM_EXE_PATH%quote -hp 0 -hp 1 -hp 2 -hp 3 -hk 80000002 -pwdk erpsign -halg sha256 -salg ecc -palg sha256 -os EnrollmentQuoteSig.bin -oa EnrollmentQuote.bin -qd EnrollmentQuoteNONCE.bin
 REM Verify the signature
%TPM_EXE_PATH%verifysignature -hk 80000002 -halg sha256 -if EnrollmentQuote.bin -is EnrollmentQuoteSig.bin
REM
REM And another for the Attestation
%TPM_EXE_PATH%quote -hp 0 -hp 1 -hp 2 -hp 3 -hk 80000002 -pwdk erpsign -halg sha256 -salg ecc -palg sha256 -os AttestationQuoteSig.bin -oa AttestationQuote.bin -qd AttestationQuoteNONCE.bin
 REM Verify the signature
%TPM_EXE_PATH%verifysignature -hk 80000002 -halg sha256 -if AttestationQuote.bin -is AttestationQuoteSig.bin
