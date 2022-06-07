//
// Created by ryanfitzgerald on 6/6/22.
//

#include <iostream>
#include "EasyEncrypt.h"

int main() {

    //creating a message string to encrypt
    std::string msg = "My Encrypted Message";

    //Calling the hex hash function, setting encrypt to true
    std::string hex_result = EasyEncrypt::SHA::Hex::hash512(msg);

    //Printing the hashed result encoded as a hex string
    std::cout << "Hashed Result 1 (SHA 512 Hash): " << hex_result << std::endl;

    /*
     * --------------------------------------------------------------------------------
     */

    //This example uses the AESData object to encrypt and decrypt data

    std::string input = "My Other Encrypted Message";

    //creating a key string for the hmac functions;
    std::string key = "My Secret Sentence.";

    //Calling the hex hash function, setting encrypt to true
    std::string hex_result2 = EasyEncrypt::SHA::Hex::hmac512(input, key);

    //Printing the hashed result encoded as a hex string
    std::cout << "Hashed Result 2 (SHA 512 HMAC): " << hex_result2 << std::endl;

    return 0;

}