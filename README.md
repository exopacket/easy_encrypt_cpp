# easy_encrypt_cpp

Easy one line function calls for AES Encryption, SHA hashes, MD5 hashes, key generation, encoding and other utilities using the OpenSSL 3 library.

# current problems

  - PKCS#5 (for java interop) & PKCS#7 padding
  - Using binary data (without passing the size) 

Pretty close to figuring this out. This will require adding static fields in order to set the padding and other parameters. Binary data and strings will not need the size. There will be an extra function call for binary data, in order to prepare it for encryption (which does require the size). This prepare function call for binary data is optional for the AES `char*` returning functions since you can enter the size with these functions using the `int* len` parameter. It is required to call that function, however, if you want to encrypt binary data using the AES Hex or Base64 functions as well as all of the one way hash functions. Decryption with the `char*` returning functions does not require the prepare function even though the input data is binary (one less step & without knowing the size).<br>
I know this complicates things. This will only add support for and change the way you encrypt binary data. Strings remain the same as it is currently. Im sure you can tell I write code in Java primarily, where passing the size doesn't always matter. ;) Anyways, my goal is to provide the easiest to use encryption and one way hash functions, along with encrypting data with multiple null terminators. I'll post usage to help out.

# the EasyEncrypt class

The source code for the EasyEncrypt class is available in this repo and contains five inner classes: AES, SHA, MD5, Random and Utils.<br><br>
AES includes CBC-256 & CBC-128 for key + iv encryption/decrypiton as well as EBC-256 & EBC-128 for key only encryption/decryption. AES uses PKCS#5 padding for compatibility with Java. PKCS#7 can be used by removing the set_padding function call within the AES functions (the default). SHA contains the SHA hashing algorithms in both 256 bit and 512 bit as well as an HMAC 256 & 512 bit hash function that accepts a key of any length. MD5 contains one function to get the 128 bit MD5 result of the input. <br><br>Each of the AES and one way hash functions have inner classes for easy use with Hex/Base64 parameters and return types. During <b>encryption</b> (encrypt == true), input data is recognized as regular characters. During <b>decryption</b> (encrypt == false), input data is recognized as the return type (base64 or hex) of the encryption call. It's important to note that this source is meant for encrypting and hashing strings only. It uses strlen() to calculate the size of the input which ends the data at the first null terminator.<br><br>There are multiple utility functions that support encryption, decryption, and the hashing of data as well as encoding functions to convert between bytes, hex, and base64 as well as hex->base64 & base64->hex. Secure random functions are also available for use to generate keys, ivs, and random numbers.
<br>

# building and installation

<b>Don't forget to edit the variables in the CMakeLists.txt file to build and install the library as well as installing the openssl library.</b><br>

To build the library with cmake run the following within the directory of the EasyEncrypt source files:<br>
`cmake .`<br>
`cmake --build .`<br>

To install the library (optional) with cmake run:<br>
`cmake --install .`
