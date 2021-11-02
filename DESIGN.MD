## eRezept HSM-VAU Design Considerations

This file captures design decisions made in the vau-hsm firmware and hsm access client for the IBM eRezept project.

#### Constraints
- HSM Firmware must be implemented in C and will be compiled differently for real hardware and for the simulated HSM.
- Texas Instruments provides the compiler for the real Hardware.   It compiles for a 32 bit big endian architecture with 4 byte alignement for addressability of structures.
- The Utimaco libraries providing client side access to HSMs provide a C interface.
- The ultimate consumers of the client library will be either C++ or java with JNI.

#### Languages
- It was decided that both client and firmware woudl be implemented in C.   This was mandatory for the firmware.   For the client it was decided not to implement a C++ wrapper at the level of the Utimaco csxapi, but to keep the API in C to simplify a JNI wrapper at a higher level.

#### Client API
- The HSM Access Client API is a C API and all parameters are passed or returned by value, including relatively large buffers (with a size parameter) in some places.   There is a maximum size  of these buffers, currently set at 2048 bytes.   This was a conscious tradeoff between the inefficiency of passing more data than needed versus the complexity of memory management between caller and API.
- The Client API has a mechanism to log ALL data at the level of the binary protocol to the HSM.   This can be explicitly enabled at compile time and MUST NOT be used in production.   To enable it, define TRACE_HSM_API when building the client.

#### Binary Protocol for communication between client and firmware
- The client and hsm custom firmware communicate with an input of a command code and buffer and respond with a 4 byte response code and a buffer.   The buffers can be empty.   The response codes can include codes returned by other firmware modules in the HSM, making it hard to provide definitive lists of possible error codes to firmware calls.
- It was decided to use ASN1/DER for the encoding of data in both directions.   This allows a formal specification of the interface simplifying verification and testing of compliance.   In practice, the interface only uses the ASNB1 types INTEGER, OCTET_STRING and SEQUENCES built of these types.
- On the client side an open source library was selected to generate ASN1/DER code for our interface - This is asn1c.   The input to this is a file defining our types which is client/src/ERP_Types.asn1
- On the firmware side, the Utimaco support for ASN1 is used, though this is limited to simple parsing into ASN Items and all further processing needs to be done by walking the list of extracted items.   There are memory management issues associated with using this library which means that reading ASN1 Buffers and writing them need to be handle ddifferently.   The code does this.

#### Firmware and error handling
- The firmware uses an error handling pattern of always using function return codes for error status.   Input and output parameters are both handled as passed parameters.
- Within a function, the firmware uses a chain of if clauses, where every step is preceeded by a check whether the current status of the function call is SUCCESS and the step skipped if there is an error.   By extension, this will apply to all following steps in the method as well, until the cleanup code and function exit are reached.   This mechanism is preferred (compared to if...else... stacking) because it is easy to insert or remove steps without counting {}.   In almost all cases, the functions only have a single return point at the end - where this is not the case, it is for a reason, documented in the code.
- The convention is used that a local or global pointer with a non-NULL value points to some memory that needs to be deleted.   This allows memory cleanup at the end of functions that may have only partially completed.
- Pointers passed into functions do not transfer ownership of the memory pointed to.
- Pointers returned from functions may or may not transfer a responsibility to delete the memory - this is documented in the individual functions on a case by case basis.
- The allocator of memory is ultimately responsible for ensuring that the memory is deleted, either explicitly or by explicitly handing over responsibility to another part of the code that accepts it.
- Utimaco provide a debug memory manager which can be used to report allocated blocks.   The API Function ERP_DumpHSMMemory will log current usage to the console of a simulated HSM.   On a real HSM this will go the serial output of the HSM and on a release build the method will return an error E_ERP_DEV_FUNCTION_ONLY.   This memory manager is used exclusively throughout the firmware and is used to detect and identify memory leaks.
