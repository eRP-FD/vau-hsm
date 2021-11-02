#ifndef ERP_CLIENT_H_
#define ERP_CLIENT_H_

#include <stddef.h>
#include <stdint.h>

// Use this for maximum size of any statically defined buffers.
#define MAX_BUFFER (unsigned int) 2048

// This is not the maximum value, but the maximum number of simultaneously
//    loaded generations.   It affects the size of the structure passed over the client API.
// The similar definition in the firmware enforces a limit on blob generation at this number.
#define MAX_BLOB_GENERATIONS 200

// This is binary length in bytes
#define SHA_256_LEN 32
// TPM Name is 2 bytes 0x000B plus SHA256 hash of public key.
#define TPM_NAME_LEN 34
// This is length of NONCE in binary Bytes
#define NONCE_LEN 32
#define AES_256_LEN 32
#define AES_128_LEN 16
#define RND_256_LEN 32

// Life time of the TEE token in seconds (1800 = 30 minutes * 60 seconds)
#define TEE_TOKEN_LIFE_TIME 1800

// A structure to hold the HSM connection and login status.
//	Generated in the ERP_Connect call.
//	Modified bny the ERP_Login/ERP_Logoff calls 
//	Invalidated by the ERP_Disconnect call.
//	Used by all calls that communicate with the HSM
typedef enum HSMSessionStatus_t{ 
	HSMUninitialised,
	HSMClosed, 
	HSMAnonymousOpen,
	HSMLoggedIn,
	HSMLoginFailed,
	HSMError } HSMSessionStatus;

typedef struct HSMSession_s{
	int h_cs;		// Connection Handle
	// handle to structure holding login and comms channel information for the session.
	// The actual handle is stored inside the C library.
	unsigned int hSessionContext; // Not used in Cluster mode
    // Time in seconds after a failover until connection to the original device is retried.
    unsigned int reconnectInterval; // Not used in single connection mode.
	HSMSessionStatus status;
	unsigned int LogonCount;
	unsigned int errorCode; // Last Error code from Firmware.
    unsigned int bIsCluster;
} HSMSession;

// Structure for returns from functions with no return data.
typedef struct {
	unsigned int returnCode; // Return code from firmware call -> 0 == good.
} EmptyOutput;

// DirectIO is only intended to be used for unit testing of the HSM interface
//   formal handling of parameters.   i.e. bouncing it with invalid inputs.
// It may be removed for the final build, or not - it rpesents no security risk
//   since the security is provided inside the HSM.
typedef struct {
	unsigned int SFCCode; // Firmware function command code.
	size_t DataLength;
	unsigned char DataBody[MAX_BUFFER * 2];
} DirectIOInput;

typedef struct {
	unsigned int returnCode; // Return code from firmware call -> 0 == good.
	size_t DataLength;
	unsigned char DataBody[MAX_BUFFER * 2];
} DirectIOOutput;

// Structure for commands with a single int as input data.
typedef struct {
	unsigned int intValue; 
} UIntInput;

// Structure for commands with a single int as output data.
typedef struct {
	unsigned int returnCode; // Return code from firmware call -> 0 == good.
	unsigned int intValue; // Returned Data
} UIntOutput;

typedef struct {
	uint32_t Generation;
	char KeyHash[SHA_256_LEN]; // in hex
}BlobKeyInfo_if_t;

typedef struct {
	unsigned int returnCode; // Return code from firmware call -> 0 == good.
	int NumKeys;
	// If more than Generations than this are returned by the firmware 
	//    then the excess will be discarded.
	// Note: The firmware should be blocking th creation of more blab keys than this anyway.
	BlobKeyInfo_if_t Generations[MAX_BLOB_GENERATIONS];
} BlobKeyListOutput;

typedef struct ERPBlob_s {
	uint32_t BlobGeneration;
	size_t BlobLength;   // length
	char BlobData[MAX_BUFFER]; // binary
} ERPBlob;

typedef struct SingleBlobInput_s {
    ERPBlob BlobIn;
} SingleBlobInput;

typedef struct SingleBlobOutput_s {
    unsigned int returnCode; // Return code from firmware call -> 0 == good.
    ERPBlob BlobOut;
} SingleBlobOutput;

typedef struct {
	unsigned int returnCode; // Return code from firmware call -> 0 == good.
	unsigned char NONCE[NONCE_LEN]; // Binary NONCE Value
	ERPBlob BlobOut;
} NONCEOutput;

typedef struct {
	unsigned int returnCode; // Return code from firmware call -> 0 == good.
	const char hash [SHA_256_LEN]; 
} SHA256Output;

typedef struct {
	unsigned int returnCode; // Return code from firmware call -> 0 == good.
	size_t CSRDataLength;
	char CSRData[MAX_BUFFER];
} x509CSROutput;

typedef struct {
	uint32_t desiredGeneration; // For the output Blob
	size_t certLength;
	unsigned char certData[MAX_BUFFER];
} TrustTPMMfrInput;

typedef struct {
	uint32_t desiredGeneration; // For the output Blob
	ERPBlob TPMMfrBlob;
	size_t EKCertLength;
	unsigned char EKCertData[MAX_BUFFER];
} EnrollTPMEKInput;

typedef struct{
	uint32_t desiredGeneration; // For the output Blob
	unsigned char AKName[TPM_NAME_LEN]; // 0x000b + SHA256 hash of AK Public - used by TPM as name
	ERPBlob KnownEKBlob;
	size_t AKPubLength;
	unsigned char AKPubData[MAX_BUFFER]; // Attestation Key public key in TPMT_PUBLIC format.
} AKChallengeInput;

typedef struct {
	unsigned int returnCode; // Return code from firmware call -> 0 == good.
	ERPBlob ChallengeBlob;
	size_t secretLength;
	unsigned char secretData[MAX_BUFFER];
	size_t encCredentialLength;
	unsigned char encCredentialData[MAX_BUFFER];
} AKChallengeOutput;

typedef struct {
	uint32_t desiredGeneration; // For the output Blob
	unsigned char AKName[TPM_NAME_LEN]; // 0x000b + SHA256 hash of AK Public - used by TPM as name
	ERPBlob KnownEKBlob;
	size_t AKPubLength; // Attestation Key in TPMT_PUBLIC format.
	unsigned char AKPubData[MAX_BUFFER];
	size_t decCredentialLength; 
	unsigned char decCredentialData[MAX_BUFFER];
	ERPBlob challengeBlob;
} EnrollTPMAKInput;

typedef struct {
	uint32_t desiredGeneration; // For the output Blob
	unsigned char AKName[TPM_NAME_LEN]; // 0x000b + SHA256 hash of AK Public - used by TPM as name
	ERPBlob	KnownAKBlob;
	ERPBlob NONCEBlob; // Blob related to HSM NONCE used to generate the quote (see below).
	size_t quoteLength; 
    // The quote data will include a NONCE-derived value of HMAC(HSM NONCE,"ERP_ENROLLMENT")
	unsigned char quoteData[MAX_BUFFER]; // TPMS_ATTEST with TPMI_ST_ATTEST_QUOTE
	size_t signatureLength;
	unsigned char signatureData[MAX_BUFFER]; // TPMT_SIGNATURE with TPMI_ALG_ECDSA
} EnrollEnclaveInput;

typedef struct {
	unsigned char AKName[TPM_NAME_LEN]; // 0x000b + SHA256 hash of AK Public - used by TPM as name
	ERPBlob	KnownAKBlob;
	ERPBlob	KnownQuoteBlob;
	ERPBlob	NONCEBlob; // Blob related to HSM NONCE used to generate the quote (see below).
	size_t QuoteDataLength;
    //        The quote data will include a NONCE-derived value of HMAC(HSM NONCE,"ERP_ATTESTATION")
	unsigned char QuoteData[MAX_BUFFER]; // TPMS_ATTEST with TPMI_ST_ATTEST_QUOTE
	size_t QuoteSignatureLength;
	unsigned char QuoteSignature[MAX_BUFFER]; // TPMT_SIGNATURE with TPMI_ALG_ECDSA
} TEETokenRequestInput;

typedef struct {
	unsigned char AKName[TPM_NAME_LEN]; // 0x000b + SHA256 hash of AK Public - used by TPM as name
	ERPBlob TEEToken;
	ERPBlob derivationKey;
	unsigned int initialDerivation; // 0 = false, 1 = true.
	size_t derivationDataLength;
	unsigned char derivationData[MAX_BUFFER];
} DeriveKeyInput;

typedef struct {
    unsigned int returnCode; // Return code from firmware call -> 0 == good.
    size_t derivationDataLength;
    unsigned char derivationData[MAX_BUFFER];
    char derivedKey[AES_256_LEN]; // ASCII Hex:   Derived key.
} DeriveKeyOutput;

typedef struct {
    unsigned int returnCode; // Return code from firmware call -> 0 == good.
    char Key[AES_256_LEN]; // ASCII Hex:   Derived key.
} AES256KeyOutput;

// Used to request either a public, private key or symmetric key
// For a private key the keypair must be a VAUSIG Keypair
// For a smmetric key the key blob must be a Hash_Key blob
typedef struct {
	ERPBlob TEEToken;
	ERPBlob Key;
} TwoBlobGetKeyInput;

typedef struct {
    unsigned int returnCode; // Return code from firmware call -> 0 == good.
    size_t keyLength;
    // Key encoding is ANSI X9.62, / RFC 5480
    unsigned char keyData[MAX_BUFFER]; // ASN1 DER encoded public key.
} PublicKeyOutput;

typedef struct {
    unsigned int returnCode; // Return code from firmware call -> 0 == good.
    size_t keyLength;
    // Key Encoding is PKCS#8 (RFC 5208) wrapping an EC Private key RFC 5915
    //   and including the optional (RFC 5480) public key.
    unsigned char keyData[MAX_BUFFER]; // ASN1 DER encoded private key.
} PrivateKeyOutput;

typedef struct {
	ERPBlob TEEToken;
	ERPBlob ECIESKeyPair;
	size_t clientPublicKeyLength;
	unsigned char clientPublicKeyData[MAX_BUFFER]; // ASN1.DER encoded.
} DoVAUECIESInput;

typedef struct {
	unsigned int returnCode; // Return code from firmware call -> 0 == good.
	char AESKey[AES_128_LEN];
} AES128KeyOutput;

#define MAX_RND_BYTES 320
typedef struct { // MAximum Number of returned byes is 320 - 10*256 bits.
	unsigned int returnCode; // Return code from firmware call -> 0 == good.
	size_t RNDDataLen; // Number of bytes in returned RND Data.
	unsigned char RNDData[MAX_RND_BYTES]; // RND Data.
} RNDBytesOutput;

typedef struct {
    ERPBlob KeyPair;
    size_t candidateCSRLength;
    unsigned char candidateCSR[MAX_BUFFER]; // ASN1.DER encoded.
} GetVAUCSRInput;

#ifdef __cplusplus
#define ERP_API_FUNC extern "C"
#else
#define ERP_API_FUNC extern
#endif
#define MAX_HSM_SESSIONS 20

// ERP_Connect establishes a connection to an HSM - the definition of the device parameter is 
//    taken from the utimaco documentation.   Usually <port>@<ip> e.g. 288@192.168.1.1
// The returned session object contains no dynamically allocated data and must be passed into 
//    ERP_ methods that require it - These are methods that deal with connection, Disconnection, 
//    logon, logoff, et.c.
// Every ERP_Connect call must be paired eventually with a call to ERP_Disconnect.
// ERP_Connect is a relatively costly operation in performance terms and should not be performed too often.
// There cannot be more than MAX_HSM_SESSIONS sessions connected at any given time.
ERP_API_FUNC HSMSession ERP_Connect(
	const char    *device,          // I: device specifier (e.g. PCI:0 / 192.168.1.1)
	unsigned int  connect_timeout,  // I: connection timeout [ms]
	unsigned int  read_timeout     // I: read (command) timeout [ms]
	);

// ERP_ClusterConnect establishes a connection to a cluster of HSMs.
// devices is a null terminated list of pointers to null terminated strings describing individual HSMs
//  - the definition of the device parameter for each HSM is 
//    taken from the utimaco documentation.   Usually <port>@<ip> e.g. 288@192.168.1.1
//  - There may formally be no more than 10 devices in the list, though the normal and tested mode will be with 2.
// The returned session object contains no dynamically allocated data and must be passed into 
//    ERP_ methods that require it - These are methods that deal with connection, Disconnection, 
//    logon, logoff, et.c.
// Every ERP_ClusterConnect call must be paired eventually with a call to ERP_Disconnect.   One 
//    disconnect per cluster connection session.
// ERP_ClusterConnect is a relatively costly operation in performance terms and should not be performed too often.
// There cannot be more than MAX_HSM_SESSIONS sessions connected at any given time.
// ReconnectInterval is the time in seconds after which the API will try to reconnect to the primary HSM following a failover.
//   A value of 0 means that the API will remain on the current device without trying to fallback to the primary one.
ERP_API_FUNC HSMSession ERP_ClusterConnect(
    const char** devices,          // I: Null terminated array of device specifiers (e.g. PCI:0 / 192.168.1.1)
    unsigned int  connect_timeout,  // I: connection timeout [ms]
    unsigned int  read_timeout,     // I: read (command) timeout [ms]
    unsigned int  reconnect_interval // I: interval after a failover before retrying a connection to the orignal HSM 
);

// Logs on a user with a password.
// The HSMSession value returned replaces the one passed in as an argument - typical invocation
//   might look like this:
//       mySesh = ERP_LogonPassword(mySesh,...);
ERP_API_FUNC HSMSession ERP_LogonPassword(
	HSMSession sesh,
	const char * user,
	const char * password
	);

// Logs on a user with akey spec - these are defined in the Utimaco documentation and may be
//   key files or smart card readers.
// Session is for a cluster connection then the smartcard logon will probably not work,
// The HSMSession value returned replaces the one passed in as an argument - typical invocation
//   might look like this:
//       mySesh = ERP_LogonPassword(mySesh,...);
ERP_API_FUNC HSMSession ERP_LogonKeySpec(
    HSMSession sesh,
    const char* user,
    const char* KeySpec, // e.g. ":cs2:auto:usb0" or "myfile.key"
    const char* password
);

// Logs off all currently logged on users
// The HSMSession value returned replaces the one passed in as an argument - typical invocation
//   might look like this:
//       mySesh = ERP_LogonPassword(mySesh,...);
ERP_API_FUNC HSMSession ERP_Logoff(HSMSession sesh);

// Disconnects the session from the HSM.   The returned session object will show a session in status HSMClosed
//   and meaning-free values for the rest of the structure.   It does not need to be kept and can be discarded.
// The HSMSession value returned replaces the one passed in as an argument - typical invocation
//   might look like this:
//       mySesh = ERP_LogonPassword(mySesh,...);
ERP_API_FUNC HSMSession ERP_Disconnect(HSMSession sesh);

// DirectIO is only intended to be used for unit testing of the HSM interface
//   formal handling of parameters.   i.e. bouncing it with invalid inputs.
// It may be removed for the final build, or not - it rpesents no security risk
//   since the security is provided inside the HSM.
// For the production build, this will return  E_ERP_DEV_FUNCTION_ONLY.
ERP_API_FUNC DirectIOOutput ERP_DirectIO(HSMSession sesh,
	DirectIOInput input); // input for the command.

// DumpHSMMemory will cause the HSM to dump diagnostic information for HSM Memory allocations
// This will go to the serial port on the real HSM or to the screen on the simulated HSM.
// For the production build, this will return  E_ERP_DEV_FUNCTION_ONLY.
ERP_API_FUNC EmptyOutput ERP_DumpHSMMemory(
	HSMSession sesh);			// HSM Session

ERP_API_FUNC UIntOutput ERP_GenerateBlobKey(
	HSMSession sesh,			// HSM Session
	UIntInput input); // input for command.   Desired Generation

ERP_API_FUNC EmptyOutput ERP_DeleteBlobKey(
	HSMSession sesh,			// HSM Session
	UIntInput input); // input for command.   Undesired Generation

ERP_API_FUNC BlobKeyListOutput ERP_ListLoadedBlobKeys(
	HSMSession sesh);			// HSM Session

ERP_API_FUNC SingleBlobOutput ERP_GenerateDerivationKey(
	HSMSession sesh,			// HSM Session
	UIntInput input); // input for command.   Desired Generation

ERP_API_FUNC SingleBlobOutput ERP_GenerateHashKey(
	HSMSession sesh,			// HSM Session
	UIntInput input); // input for command.   Desired Generation

ERP_API_FUNC SingleBlobOutput ERP_GenerateECIESKeyPair(
    HSMSession sesh,			// HSM Session
    UIntInput input); // input for command.   Desired Generation

ERP_API_FUNC x509CSROutput ERP_GenerateECIESCSR(
    HSMSession sesh,			// HSM Session
    GetVAUCSRInput input); // input for command.

ERP_API_FUNC SingleBlobOutput ERP_GenerateVAUSIGKeyPair(
    HSMSession sesh,			// HSM Session
    UIntInput input); // input for command.   Desired Generation

ERP_API_FUNC x509CSROutput ERP_GenerateVAUSIGCSR(
    HSMSession sesh,			// HSM Session
    GetVAUCSRInput input); // input for command.

ERP_API_FUNC NONCEOutput ERP_GenerateNONCE(
	HSMSession sesh,			// HSM Session
	UIntInput input); // input for command.   Desired Generation

ERP_API_FUNC SingleBlobOutput ERP_TrustTPMMfr(
	HSMSession sesh,			// HSM Session
	TrustTPMMfrInput input); // input for command.

ERP_API_FUNC SingleBlobOutput ERP_EnrollTPMEK(
	HSMSession sesh,			// HSM Session
	EnrollTPMEKInput input); // input for command.

ERP_API_FUNC AKChallengeOutput ERP_GetAKChallenge(
	HSMSession sesh,			// HSM Session
	AKChallengeInput input); // input for command.

ERP_API_FUNC SingleBlobOutput ERP_EnrollTPMAK(
	HSMSession sesh,			// HSM Session
	EnrollTPMAKInput input); // input for command.

ERP_API_FUNC SingleBlobOutput ERP_EnrollEnclave(
	HSMSession sesh,			// HSM Session
	EnrollEnclaveInput input); // input for command.

/**
 * Call once on application startup to obtain the TEE token that is to be used with most other calls
 * to authenticate and authorize the caller.
 * The returned token can be used in multiple threads.
 *
 * The token's life time is TEE_TOKEN_LIFE_TIME seconds (30 minutes) and should be renewed before that to
 * avoid ERP_ERR_BLOB_EXPIRED errors. If an ERP_ERR_BLOB_EXPIRED error is encountered (when calling another
 * function), the token should be renewed synchronously and the call be repeated.
 * Note that obtaining a new token does not invalidate the old one.
 *
 * Some of the input values can be found in the blob database where they are stored during enrollment.
 * Other values can be obtained from the TPM.
 *
 * @param sesh                          a valid HSM session, i.e. sesh.status == logged in, user erp working
 * @param input.AKName                  SHA1 hash of public attestation key - used by TPM as name
 *                                      stored during enrollment process in blob db
 * @param input.KnownAKBlob             stored during enrollment process in blob db
 * @param input.KnownQuoteBlob          stored during enrollment process in blob db
 * @param input.NONCEBlob               returned by the HSM's ERP_GenerateNONCE()
 * @param input.QuoteDataLength         must be <= MAX_BUFFER
 * @param input.QuoteData               provided by the TPM
 * @param input.QuoteSignatureLength    must be <= MAX_BUFFER
 * @param input.QuoteSignature          provided by the TPM
 * @return SingleBlobOutput.returnCode  0 for no error, error code otherwise
 * 	       SingleBlobOutput.BlobOut     the TEE token.
 */
ERP_API_FUNC SingleBlobOutput ERP_GetTEEToken(
	HSMSession sesh,
	TEETokenRequestInput input);

/**
 * Derive a symmetric AES 256 key from the HSM's private key and the given derivation data.
 * The returned key is intended to be used for encrypting Task resources and uses a private key with a suitable life time.
 *
 * This function has the convenience feature to add random data as salt to the derivationData. This happens when the
 * initialDerivation flag is 1. The concatenation of the given derivationData and the random bytes is returned in the
 * derivationData output.
 *
 * For subsequent calls, set initialDerivation to 0 and pass back in the derivationData output from the first call.
 * Otherwise another set of random bytes is added and the generated key is different from the one returned by the first call.
 *
 * @param sesh                                    a valid HSM session, i.e. sesh.status == HSMLoggedIn
 * @param input.AKName                            SHA1 hash of AK Public - used by TPM as name
 * @param input.TEEToken                          the TEE token from a previous call to ERP_GetTEEToken()
 * @param input.derivationKey                     blob that contains the encrypted derivation key, opaque to the caller.
 * @param input.initialDerivation                 when 1 (true) then derivationData must be empty in the input
 *                                                    and will be returned in the output
 *                                                when 0 (false then derivationData must contain the output from the initial call
 * @param input.derivationDataLength              <= MAX_BUFFER
 * @param input.derivationData                    application specific derivation data
 * @return DeriveKeyOutput.returnCode             0 for no error, error code otherwise
 *         DeriveKeyOutput.derivationDataLength   <= MAX_BUFFER
 *         DeriveKeyOutput.derivationData         has to be persisted on the initial call and passed back in on subsequent calls
 *         DeriveKeyOutput.derivedKey             the requested symmetric AES 256 key
 *
 */
ERP_API_FUNC DeriveKeyOutput ERP_DeriveTaskKey(
    HSMSession sesh,
    DeriveKeyInput input);

/**
 * Derive a symmetric AES 256 key from the HSM's private key and the given derivation data.
 * The returned key is intended to be used for encrypting Audito Log entries and uses a private key with a suitable life time.
 *
 * See ERP_DeriveTaskKey for details and a description of input and output parameters.
 */
ERP_API_FUNC DeriveKeyOutput ERP_DeriveAuditKey(
    HSMSession sesh,
    DeriveKeyInput input);

/**
 * Derive a symmetric AES 256 key from the HSM's private key and the given derivation data.
 * The returned key is intended to be used for encrypting Communication resources and uses a private key with a suitable life time.
 *
 * See ERP_DeriveTaskKey for details and a description of input and output parameters.
 */
ERP_API_FUNC DeriveKeyOutput ERP_DeriveCommsKey(
    HSMSession sesh,
    DeriveKeyInput input);

/**
 * Return the public key of a VAU KeyPair (ID.FD.AUT or ID-FD.-IG) as diagnostic to verify that the public key that is obtained by the TEE processing
 * context via independent process is compatible with the private/public key pair that is obtained in the same process.
 * Typically called once during startup.
 *
 * The public key is either:
 *    an ECIES KeyPair can be used for ECIES key derivation according to requirement A_20161-01, or
 *    a VAUSIG KeyPair for which the private key can be recovered by an attested VAU and used for signatures.
 * The public key will be exposed as certificate via the FD's / VAUCertificate endpoint.
 *
 * @param sesh                                    a valid HSM session, i.e. sesh.status == HSMLoggedIn with erp working or erp setup
 * @param input.KeyPair                           encrypted private public key pair which is provided by independent configuration process.

 * @return PublicKeyOutput.returnCode             0 for no error, error code otherwise
 *         PublicKeyOutput.keyLength              <= MAX_BUFFER
 *         PublicKeyOutput.keyData                ASN.1 DER encoded public key with a format according to RFC 5480, sections 2 and 2.2
 */
ERP_API_FUNC PublicKeyOutput ERP_GetECPublicKey(
	HSMSession sesh,
	SingleBlobInput input);

/**
 * Return the private key of a VAU Signautre KeyPair (ID-FD.-IG).   This requires a valid TEE Token and
 *
 * The public key is either:
 *    an ECIES KeyPair can be used for ECIES key derivation according to requirement A_20161-01, or
 *    a VAUSIG KeyPair for which the private key can be recovered by an attested VAU and used for signatures.
 * The public key will be exposed as certificate via the FD's / VAUCertificate endpoint.
 *
 * @param sesh                                    a valid HSM session, i.e. sesh.status == HSMLoggedIn with erp working or erp setup
 * @param input.TEEToken                          currently valid TEE Token
 * @param input.KeyPair                           ERP Blob containing a VAUSIG encrypted private public key pair which is provided by independent configuration process.
 * @return PublicKeyOutput.returnCode             0 for no error, error code otherwise
 *         PublicKeyOutput.keyLength              <= MAX_BUFFER
 *         PublicKeyOutput.keyData                ASN.1 DER encoded PKCS#8/RFC5208/5915/5240 private Key info including public key
 */
ERP_API_FUNC PrivateKeyOutput ERP_GetVAUSIGPrivateKey(
    HSMSession sesh,
    TwoBlobGetKeyInput input);

/**
 * Perform elliptic curve key derivation (IES or integrated encryption scheme) based on Diffie-Hellman algorithm and SHA-256
 * according to A_20161-01 (ECIES according to [SEC1-2009], ECDH according to [NIST-800-56-A], HKDF according to [RFC-5869],
 * see gemSpec_Krypt_V2.18.0 for details and the references.) Produces an AES 128 symmetric key.
 *
 * regarding elliptic curve: ask Andrea
 *
 * @param sesh                                    a valid HSM session, i.e. sesh.status == HSMLoggedIn erp working
 * @param input.TEEToken                          the TEE token from a previous call to ERP_GetTEEToken()
 * @param input.ECIESKeyPair                      ERP Blob containing a VAUSIG encrypted private public key pair which is provided by independent configuration process.
 * @param input.clientPublicKeyLength             <= MAX_BUFFER, length of the client public key data
 * @param input.clientPublicKeyData               ASN.1 DER encoded public key with a format according to RFC 5480, sections 2 and 2.2
 * @return AES128Output.returnCode                0 for no error, error code otherwise
 *         AES128Output.AESKey                    AES 128 symmetric key
 */
ERP_API_FUNC AES128KeyOutput ERP_DoVAUECIES128(
    HSMSession sesh,
    DoVAUECIESInput input);

/**
 * Returns the requested number of bytes of hardware generated random data.  Intended for seeding of software PRNGs.
 *
 * @param sesh                                    a valid HSM session, i.e. sesh.status == HSMLoggedIn erp working
 * @param input                                   <= MAX_RND_BYTES (320) number of requested random bytes
 * @param RNDBytesOutput.returnCode               0 for no error, error code otherwise
 *        RNDBytesOutput.RNDDataLen               <= input <= MAX_RND_BYTES number of returned random bytes
 *        RNDBytesOutput.RNDData                  the requested random data
 */
ERP_API_FUNC RNDBytesOutput ERP_GetRNDBytes(
    HSMSession sesh,
    UIntInput input);

/**
 * Return the secret value of a Hash Key to be used for HMAC ID calculation in the VAU.   This requires a valid TEE Token.
 *
 * @param sesh                                    a valid HSM session, i.e. sesh.status == HSMLoggedIn with erp working or erp setup
 * @param input.TEEToken                          currently valid TEE Token
 * @param input.KeyPair                           ERP Blob containing a Hash Key encrypted AES 256 key which is provided by independent configuration process.
 * @return PublicKeyOutput.returnCode             0 for no error, error code otherwise
 *         PublicKeyOutput.keyLength              AES 256 key length
 *         PublicKeyOutput.keyData                AES 256 Key length of binary data containing the raw key value
 */
ERP_API_FUNC AES256KeyOutput ERP_UnwrapHashKey(
    HSMSession sesh,
    TwoBlobGetKeyInput input);

#endif
