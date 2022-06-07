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
    std::string hex_result = EasyEncrypt::AES::Hex::cbc256(msg, hex_key, hex_iv, true);

    //Printing the encrypted result encoded as a hex string
    std::cout << "Encrypted Result 1: " << hex_result << std::endl;

    //Calling the hex decryption function, setting encrypt to false
    std::string str_result = EasyEncrypt::AES::Hex::cbc256(hex_result, hex_key, hex_iv, false);

    //Printing the decrypted result encoded as a hex string
    std::cout << "Decrypted Result 1: " << str_result << std::endl;

    /*
     * --------------------------------------------------------------------------------
     */

    //This example uses the AESData object to encrypt and decrypt data

    std::string input = "My Other Encrypted Message";

    //Creating an AESData object using the cbc_hex_create;
    //std::string input, std::string key, std::string iv,  std::string aad, bool encrypt
    EasyEncrypt::AESData* aes_obj2 = EasyEncrypt::AESData::cbc_hex_create(input, hex_key,
                                                                hex_iv,  true);

    //ALTERNATIVELY, you can call the AESData constructor
    EasyEncrypt::AESData* aes_obj_construct =
            new EasyEncrypt::AESData(
                    EasyEncrypt::CBC, EasyEncrypt::HEX,
                    input, hex_key, hex_iv, true);

    //encrypting and storing in a new object
    EasyEncrypt::AESData cbc_res = EasyEncrypt::AES::Hex::cbc(*aes_obj2);

    //Printing the encrypted result encoded as a hex string
    std::cout << "Encrypted Result 2: " << cbc_res.encrypted << std::endl;

    //Setting the object to decryption
    //** this step is not required if you keep a copy of the AESData object
    //   after encryption, the do_encrypt variable is changed to false.
    cbc_res.do_encrypt = false;

    //Decrypting and storing in previously created result object
    cbc_res = EasyEncrypt::AES::Hex::cbc(cbc_res);

    //Printing the encrypted result encoded as a hex string
    std::cout << "Decrypted Result 2 " << cbc_res.plaintext << std::endl;

    return 0;

}