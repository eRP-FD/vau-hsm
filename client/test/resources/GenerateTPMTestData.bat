# batch file to generate ERP test keys and other data in simulated software TPM 
 REM 
 REM You must already have run the init_tpm script from the TSS Utils Regtests directory.
 REM Also, you must have openssl installed on your path.
 REM
 REM Create Primary key.   This would normally be created and managed by the Manufacturer?
call inittpm.bat
 REM
%TPM_EXE_PATH%createprimary -hi p -pwdk erpprim -pol zeroSHA256.pol -tk erpprimtk.bin -ch erpprimch.bin -opu erpprimpub.bin -opem erpprimpub.pem -ecc nistp256
 REM This should return Handle 80000000
 REM
 REM Read name hash of primary key:
%TPM_EXE_PATH%readpublic -ho 80000000 -ns
 REM
 REM Now create a storage key under the primary key.   This is EK.
 REM%TPM_EXE_PATH%create -hp 80000000 -ecc nistp256 -halg sha256 -st -kt f -kt p -opr erpstorepriv.bin -opu erpstorepub.bin -opem erpstorepub.pem -pwdp erpprim -pwdk erpstore
 REM returns Handle 80000001
 REM
 REM Now do it for real EK template
%TPM_EXE_PATH%CreateEK -pwdk erpek -ecc nistp256 -cp
 REM
 REM Create EK Cert signed by cakeyecc
%TPM_EXE_PATH%CreateEKCert -ecc nistp256 -cakey cakeyecc.pem -capwd rrrr -caalg ec -v
 REM
 REM Check the certificate under 0x01c0000a
 REM If you do this then you have to manually edit EKCertECC.crt to correct size.
  You only need TODO this the first time on a new TPM.
REM %TPM_EXE_PATH%nvread -ha 01c0000a -cert -of EKCertECC.crt
 REM
 REM Now load and check the EK against the certificate and this time leave it loaded
%TPM_EXE_PATH%CreateEK -pwdk erpek -ecc nistp256 -cp -noflush
 REM Returns that certificate check has passed and that EK HAndle is 80000001
 REM
 REM Load the storage key under the primary key
 REM%TPM_EXE_PATH%load -hp 80000000 -ipr erpstorepriv.bin -ipu erpstorepub.bin -pwdp erpprim
 REM
 REM Create restricted signing key under primary key.   This is AK.
 REM The policy is that the command code is activate credential.
%TPM_EXE_PATH%create -hp 80000000 -ecc nistp256 -sir -kt f -kt p -opr erpsignpriv.bin -opu erpsignpub.bin -opem erpsignpub.pem -pwdp erpprim -pwdk erpsign -pol policyccactivate.pol
 REM
 REM Load the signing key under the primary key
%TPM_EXE_PATH%load -hp 80000000 -ipr erpsignpriv.bin -ipu erpsignpub.bin -pwdp erpprim
 REM returns handle 80000002
 REM
 REM Read out the AK Pub 
%TPM_EXE_PATH%readpublic -ho 80000002 -opem AKPub.pem -ns -opu AKPub.bin
 REM After this the AKName is in h80000002.bin, starting with 0x000b as a tag for hash (00) with sha256 (0b)
 REM This is the sha256 hash over the contents of the AKPub.bin file WITHOUT The first two length bytes.
 REM
 REM Convert to DER
openssl ec -pubin -in AKPub.pem -outform DER -out AKPub.der
 REM
 REMextract the EKPub as well for comparison with tpm2scratch
openssl x509 -inform der -in EKCertECC.crt -pubkey -noout -outform der -out EKPub.pem
openssl ec -pubin -in EKPub.pem -outform DER -out EKPub.der
 REM
rem Generate the credential to be encrypted:   This will be a NONCE.
rem For now take thr RND from the TPM.
%TPM_EXE_PATH%getrandom -by 32 -of credin.bin
 REM
 REM h80000002.bin contains the sha1 hash of the key stored in 80000002
%TPM_EXE_PATH%makecredential -ha 80000001 -icred credin.bin -in h80000002.bin -ocred credenc.bin -os secret.bin
 REM 
 REM Now the decryption:
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
%TPM_EXE_PATH%activatecredential -ha 80000002 -hk 80000001 -icred credenc.bin -is secret.bin -ocred creddec.bin -pwdk erpek -se0 03000000 0 -se1 03000001 0
 REM
 REM Compare credin and creddec.
 REM 
 REM#########################
 REM
 REM Now do the quote:
 REM
%TPM_EXE_PATH%getrandom -by 32 -of QuoteNONCE.bin
 REM
%TPM_EXE_PATH%quote -hp 0 -hk 80000002 -pwdk erpsign -halg sha256 -salg ecc -palg sha256 -os quotesig.bin -oa attest.bin -qd quoteNONCE.bin
 REM Verify the signature
%TPM_EXE_PATH%verifysignature -hk 80000002 -halg sha256 -if attest.bin -is quotesig.bin
 REM
 REM see attestparsed for attestation data structure.   Defined in:
 REM Trusted Platform Module Library - Part 2: Structures
 REM TPMS_ATTEST with TPMI_ST_ATTEST_QUOTE




