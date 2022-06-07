//
// Created by ryanfitzgerald on 6/7/22.
//

#include <iostream>
#include "EasyEncrypt.h"

int main() {

    //Creating a password for the Private Key
    std::string private_key_pass = "My Secret Sentence.";

    //Creating a new KeyPair (Public Key & Private Key) with Password
    EasyEncrypt::PublicKey::KeyPair* keyPair =
            new EasyEncrypt::PublicKey::KeyPair(private_key_pass.c_str(), 2048);

    //Getting the public and private key as string values
    std::string public_key = keyPair->getPublicKey();
    std::string private_key = keyPair->getPrivateKey();

    //Creating a message to encrypt with the public key
    std::string msg = "My Encrypted Message";

    //Encrypting using the public key with Base64 encoding
    std::string encrypted =
            EasyEncrypt::PublicKey::Base64::encrypt(msg, (char*) public_key.c_str());

    //Printing the encrypted result encoded as a hex string
    std::cout << "Public Key Encrypted Result: " << encrypted << std::endl;

    //Decrypting using the private key with message input as a base64 encoded string
    std::string decrypted =
            EasyEncrypt::PublicKey::Base64::decrypt(encrypted,
                                                        (char*) private_key.c_str(),
                                                        private_key_pass.c_str());

    //Printing the encrypted result encoded as a hex string
    std::cout << "Private Key Decrypted Result: " << decrypted << std::endl;


}