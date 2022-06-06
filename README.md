# easy_encrypt_cpp

<b>Latest update untested.</b>
- Freed variables
- Added GCM support
- Created AESData class and functions

Easy one line function calls for AES Encryption, SHA hashes, MD5 hashes, RSA Public Key encryption with Private Key decryption, key generation, encoding and other utilities using the OpenSSL 3 library.<br><br>This branch differs from the 'past' branch due to the fact that it has been cleaned up and that most of the Hex and Base64 functions take the string type. This is for data with multiple null terminator characters (string type is not terminated by `'\0'` like char array strings). To create a string from a char array with multiple `'\0'` characters call the arrToStr utility function.

# the EasyEncrypt class

The source code for the EasyEncrypt class is available in this repo and contains five inner classes: AES, AESData, SHA, MD5, PublicKey (with KeyPair), Random and Utils.<br><br>
AES includes GCM-256/192/128 for key, iv (92 bits preferred), additional authenticated data (optional: pass NULL), and tag verification encryption/decryption. Plus CBC-256/192/128 for key + iv encryption/decrypiton as well as EBC-256/192/128 for key only encryption/decryption. AES uses PKCS#7 padding. SHA contains the SHA hashing algorithms in both 256 bit and 512 bit as well as an HMAC 256 & 512 bit hash function that accepts a key of any length. MD5 contains one function to get the 128 bit MD5 result of the input. <br><br>Each of the AES and one way hash functions have inner classes for easy use with Hex/Base64 parameters and return types. During <b>encryption</b> (encrypt == true), input data is recognized as regular characters. During <b>decryption</b> (encrypt == false), input data is recognized the same as the return type (base64 or hex) of the encryption call. PublicKey consists of functions that support Public Key encryption and Private Key decryption plus a KeyPair class to create new Public and Private keys. If you do not wish to use a password for the private key, simply pass NULL for the password param. <br><br>There are multiple utility functions that support encryption, decryption, and the hashing of data as well as encoding functions to convert between bytes, hex, and base64 as well as hex->base64 & base64->hex. Secure random functions are also available for use to generate keys, ivs, and random numbers.
<br>
