//
// Created by ryanfitzgerald on 6/6/22.
//

#include <iostream>
#include "EasyEncrypt.h"

int main() {

    //Creating a HEX key and iv (256 bit & 128 bit == 256 bit encryption)
    std::string hex_key = EasyEncrypt::Random::secureEncoded(EasyEncrypt::HEX, 32);
    std::string hex_iv = EasyEncrypt::Random::secureEncoded(EasyEncrypt::HEX, 16);

    //creating a message string to encrypt
    std::string msg = "My Encrypted Message";

    //Calling the hex encryption function, setting encrypt to true
    std::string hex_result = EasyEncrypt::AES::Hex::ecb256(msg, hex_key, true);

    //Printing the encrypted result encoded as a hex string
    std::cout << "Encrypted Result 1: " << hex_result << std::endl;

    //Calling the hex decryption function, setting encrypt to false
    std::string str_result = EasyEncrypt::AES::Hex::ecb256(hex_result, hex_key, false);

    //Printing the decrypted result encoded as a hex string
    std::cout << "Decrypted Result 1: " << str_result << std::endl;

    /*
     * --------------------------------------------------------------------------------
     */

    //This example uses the AESData object to encrypt and decrypt data

    std::string input = "My Other Encrypted Message";

    //Creating an AESData object using the ecb_hex_create;
    //std::string input, std::string key, std::string iv,  std::string aad, bool encrypt
    EasyEncrypt::AESData* aes_obj2 = EasyEncrypt::AESData::ecb_hex_create(input, hex_key,
                                                                 true);

    //ALTERNATIVELY, you can call the AESData constructor
    EasyEncrypt::AESData* aes_obj_construct =
            new EasyEncrypt::AESData(
                    EasyEncrypt::ECB, EasyEncrypt::HEX,
                    input, hex_key, true);

    //encrypting and storing in a new object
    EasyEncrypt::AESData ecb_res = EasyEncrypt::AES::Hex::ecb(*aes_obj2);

    //Printing the encrypted result encoded as a hex string
    std::cout << "Encrypted Result 2: " << ecb_res.encrypted << std::endl;

    //Setting the object to decryption
    //** this step is not required if you keep a copy of the AESData object
    //   after encryption, the do_encrypt variable is changed to false.
    ecb_res.do_encrypt = false;

    //Decrypting and storing in previously created result object
    ecb_res = EasyEncrypt::AES::Hex::ecb(ecb_res);

    //Printing the encrypted result encoded as a hex string
    std::cout << "Decrypted Result 2 " << ecb_res.plaintext << std::endl;

    return 0;

}