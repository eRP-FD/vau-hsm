This directory contains files needed to run the Unit tests.
GenerateTPMTestData.bat will re-initialise a software TPM with a new AK and create the various data files needed to setup the tests.
GentleTPMStartup will startup a software TPM that has already been initialised, but will not change the value of any keys already created.
ActivateHSMCredential.bat will activate (decrpyt) a credential challenge based on the files currently stored in this directory.   It will also generate a quote for pcr 0 using the QuoteNONCE.bin file as the quote
The saved directory contains blobs and tpm answer data from a manually run complete attestation session.   This can be used to run replays for HSM Unit tests with static data as shown in the UT AttestationSequence.   These replays only work as long as the firmware has been built with DISABLE_BLOB_EXPIRY defined.

Password for the keyfile working user logon is RUTU, so LogonKeySpec (ERP_KWRK,"ERP_KWRK_keyfile.key","RUTU") should work.