# easy_encrypt_cpp

<b>Important note<br>
Went a little to quick with posting this.
<br>
Working on some changes too make it as easy as possible to use this class. (return values, calculating the size, and encoding conversions).
<br>
Currently untested and not cleaned up all the way yet. Some functions may not work as expected or at all (builds okay). C implementation coming as well.</b>

Easy one line function calls for AES Encryption, SHA hashes, MD5 hashes, key generation, encoding and other utilities using the OpenSSL 3 library.

# the EasyEncrypt class

The source code for the EasyEncrypt class is available in this repo and contains four inner classes: AES, SHA, MD5, and Utils.<br><br>
AES includes CBC-256 & CBC-128 for key + iv encryption/decrypiton as well as EBC-256 & EBC-128 for key only encryption/decryption. AES uses PKCS#5 padding for compatibility with Java. PKCS#7 can be used by removing the set_padding function call within the AES functions (the default). SHA contains the SHA hashing algorithms in both 256 bit and 512 bit as well as an HMAC 256 & 512 bit hash function that accepts a key of any length. MD5 contains one function to get the 128 bit MD5 result of the input. There are multiple utility functions that support encryption, decryption, and the hashing of data as well as encoding functions to convert between bytes, hex, and base64 as well as hex->base64 & base64->hex. Secure random functions are also available for use to generate keys, ivs, and random numbers. The goodRandom function can also be used as a secure random key/iv generator (shown in usage).<br>

# usage

<b>AES (CBC-256) Encryption Examples</b><br>
Encrypting with a 32 character key string. <i>To decrypt, simply change the encrypt boolean to false with the data input as your encrypted content.</i>
```
std::string myData = "My secret information.";            //A string containing your data to be encrypted.
const char* myKey = "E5oj9lJjuiqFs5SzO2W71NODtozsjSRU";   //A string containing your 32 byte key.
const char* myIv = "elwJ8WSZTUNjueSX";                    //A string containing your 16 byte IV.
std::string encryptedResult;                              //A c++ string for the return value.

encryptedResult = EasyEncrypt::AES::cbc256(               //The actual function call.
                          (char*) myData.c_str(),         //Converting the c++ string to a c string and casting it as a pointer to a char array.
                          (char*) myKey,                  //Casting the key c string as a char array.
                          (char*) myIv,                   //Casting the iv c string as a char array.
                          true                            //Are you encrypting? Yes: true, otherwise: false.
                        );
```

Encrypting with a 32 byte hex key and 16 byte hex iv. <i>To decrypt, simply change the encrypt boolean to false with the data input as your encrypted content.</i>

```
std::string myData = "My secret information.";            //A string containing your data to be encrypted.
const char* myKey = "7c0e8cf56067bab4c5c014a73c7ba93b58223fb5c5280c285c18724c6b1757e4";   //A string containing your 32 byte key as hexadecimal.
const char* myIv = "cdd9fe8202f5f66f4620991daff11ba2";    //A string containing your 16 byte IV as hexadecimal.

std::string encryptedResult;                              //A c++ string for the return value.

encryptedResult = EasyEncrypt::AES::cbc256(               //The actual function call.
                          (char*) myData.c_str(),         //Converting the c++ string to a c string and casting it as a pointer to a char array.
                          EasyEncrypt::Utils::fromHex(    //Calling the fromHex utility function.
                                      (char*) myKey       //Casting the c string to char array.
                          ),
                          EasyEncrypt::Utils::fromHex(    //Calling the fromHex utility function.
                                      (char*) myIv        //Casting the c string to char array.
                          ),
                          true                            //Are you encrypting? Yes: true, otherwise: false.
                        );
```

<b>Generating Hashes Examples</b><br>

Generating hashes with the SHA and MD5 functions.

```
std::string myData = "My secret information.";            //A string containing your data to be hashed.
std::string myHmacKey = "You can't see this."             //A string containing your key for the HMAC hash.


std::string md5Result = EasyEncrypt::MD5::get((char*) myData.c_str());       //The function call with converting to c string & casting the data as char array.

std::string sha256Result = EasyEncrypt::SHA::hash256((char*) myData.c_str());       //The function call with converting to c string & casting the data as char array.

std::string sha512Result = EasyEncrypt::SHA::hash512((char*) myData.c_str());       //The function call with converting to c string & casting the data as char array.

std::string hmac256Result = EasyEncrypt::SHA::hmac256(                //The function call
                                    (char*) myData.c_str(),           // Converting to c string & casting the data as char array.
                                    (char*) myHmacKey.c_str()         // Converting the key to a c string and casting the data as a char array.
                            );
```

<b>Generating Keys Examples</b><br>

Generating keys and initialization vectors.

```
//New Key and IV for AES-CBC-256.
unsigned char* key;                         //pointer to unsigned char array for key
unsigned char* iv;                          //pointer to unsinged char array for key

EasyEncrypt::Utils::secureRandom(           //function call
                            key,            //char array pointer from above
                            32              //key size (32 bytes for 256 bit encryption/decryption or 16 for 128 bit)
                       );
                       
EasyEncrypt::Utils::secureRandom(           //function call
                            iv,             //char array pointer from above
                            16              //iv size (16 bytes for 256 AND 128 bit encryption/decryption)
                       );
                       
                       
// Optional key generation using the goodRandom function.

int keySize = 32;                           //key size int value
unsigned char key[keySize];                 //unsigned char array for key with correct size

int mySeed = 123;                           //my seed value

for(int i=0; i<keySize; i++) {              //for loop iterating 32 times beginning from 0.

    int x = EasyEncrypt::Utils::goodRandom(0, 255, i + mySeed);     //generate random number between 0 and 255 (inclusive) with mySeed.
    key[i] = (unsigned char) x;             //cast the int value to an unsigned char and place it in array.

}

```

# building and installation

<b>Don't forget to edit the variables in the CMakeLists.txt file to build and install the library as well as installing the openssl library.</b><br>

To build the library with cmake run the following within the directory of the EasyEncrypt source files:<br>
`cmake .`<br>
`cmake --build .`<br>

To install the library (optional) with cmake run:<br>
`cmake --install .`
