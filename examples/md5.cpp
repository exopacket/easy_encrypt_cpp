//
// Created by ryanfitzgerald on 6/6/22.
//

#include <iostream>
#include "EasyEncrypt.h"

int main() {

    //creating a message string to encrypt
    std::string msg = "My Encrypted Message";

    //Calling the hex hash function, setting encrypt to true
    std::string hex_result = EasyEncrypt::MD5::Hex::get(msg);

    //Printing the hashed result encoded as a hex string
    std::cout << "Hashed Result 1 (MD5 Hash): " << hex_result << std::endl;

    return 0;

}