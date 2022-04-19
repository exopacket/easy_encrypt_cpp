//
// Created by ryan on 10/17/21.
//

#include <random>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <string>
#include "openssl/conf.h"
#include "openssl/evp.h"
#include "openssl/aes.h"
#include "openssl/sha.h"
#include "openssl/hmac.h"
#include "openssl/rand.h"
#include "stdio.h"
#include "stdlib.h"
#include "EasyEncrypt.h"
#include "Base64.h"

std::vector<std::string> EasyEncrypt::Utils::explode(const std::string &str, const char &c) {

    std::string next;
    std::vector<std::string> result;

    for(std::string::const_iterator it = str.begin(); it != str.end(); it++) {

        if(*it == c) {

            if(!next.empty()) {
                result.push_back(next);
                next.clear();
            }

        } else {

            next += *it;

        }

    }

    if(!next.empty()) {
        result.push_back(next);
    }

    return result;

}

int EasyEncrypt::Utils::strToInt(std::string val) {

    int _val;

    try {
        _val = std::stoi(val);
    } catch (std::exception ex) {
        _val = INT32_MAX;
    }

    return _val;

}

int EasyEncrypt::Utils::goodRandom(int start, int end, int seed) {

    std::mt19937 rng;

    auto now = std::chrono::system_clock::now();
    auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch());

    int randBite;
    memset(&randBite, 0, 1);
    secureRandom((unsigned char*) &randBite, 1);

    int seedVal = (nanos.count() - (randBite^randBite)) + seed;

    rng.seed(seedVal);
    std::uniform_int_distribution<uint32_t> uint_dist10(start,end);

    return uint_dist10(rng);

}

std::string EasyEncrypt::Utils::toUpperCase(std::string input) {

    std::string output;

    for(int i=0; i<input.size(); i++) {

        char c = std::toupper(input.at(i));
        output += c;

    }

    return output;

}

std::string EasyEncrypt::Utils::toLowerCase(std::string input) {

    std::string output;

    for(int i=0; i<input.size(); i++) {

        char c = std::tolower(input.at(i));
        output += c;

    }

    return output;

}

std::string EasyEncrypt::Utils::toHex(unsigned char* source, ssize_t size) {

    std::stringstream ss;

    ss << std::hex << std::setfill('0');

    for (int i=0;i<size;i++)
    {

        ss << std::setw(2) << static_cast<unsigned>(source[i]);
    }

    std::string outputStr = ss.str();

    char *out = new char[outputStr.length()];
    strcpy(out, outputStr.c_str());

    std::string data = ss.str();

    std::transform(data.begin(), data.end(), data.begin(), [](unsigned char c){return std::toupper(c);});

    return data;

}

std::vector<unsigned char> EasyEncrypt::Utils::toVector(char* source, size_t size) {

    std::vector<unsigned char> returnVal;

    for(int i=0; i<size; i++) {

        returnVal.push_back((unsigned) source[i]);

    }

    return returnVal;

}

std::vector<unsigned char> EasyEncrypt::Utils::hexToVector(const char* source, ssize_t size) {

    int _size = (size) / 2;

    std::string input = source;
    int x=0;
    int i;

    std::vector<unsigned char> returnVal;

    for(i=0;i<_size; i++) {

        std::string ret = "";
        for(int y=0; y<2; y++) {
            ret += input.at(x);
            x++;
        }

        std::stringstream  ss;
        ss << std::hex << ret;
        unsigned int j;
        ss >> j;

        returnVal.push_back((unsigned char) j);

    }

    return returnVal;

}

std::string EasyEncrypt::AES::cbc256(char* _data, ssize_t data_len, char* _key, char* _iv, bool encrypt) {

    std::vector<unsigned char> data = EasyEncrypt::Utils::toVector(_data, data_len);
    std::vector<unsigned char> key = EasyEncrypt::Utils::toVector(_key, 32);
    std::vector<unsigned char> iv = EasyEncrypt::Utils::toVector(_iv, 16);

    size_t inputLength = data.size();

    unsigned char aes_input[inputLength];
    unsigned char aes_key[32];

    memset(aes_input, 0, inputLength);
    memset(aes_key, 0, sizeof(aes_key));

    memcpy(aes_input, data.data(), data.size());
    memcpy(aes_key, key.data(), key.size());

    unsigned char aes_iv[16];
    memset(aes_iv, 0x00, AES_BLOCK_SIZE);
    memcpy(aes_iv, iv.data(), iv.size());

    if(encrypt) {

        unsigned char res[inputLength];

        EVP_CIPHER_CTX *ctx;

        int len;
        int ciphertext_len;

        ctx = EVP_CIPHER_CTX_new();

        EVP_CIPHER_CTX_set_padding(ctx, 5);

        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
        EVP_EncryptUpdate(ctx, res, &len, aes_input, sizeof(aes_input));
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, res + len, &len);
        ciphertext_len += len;

        EVP_CIPHER_CTX_free(ctx);
        return EasyEncrypt::Utils::toHex(res, ciphertext_len);

    } else {

        unsigned char res[inputLength];

        EVP_CIPHER_CTX *ctx;

        int len;
        int plaintext_len;

        ctx = EVP_CIPHER_CTX_new();

        EVP_CIPHER_CTX_set_padding(ctx, 5);

        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
        EVP_DecryptUpdate(ctx, res, &len, aes_input, sizeof(aes_input));
        plaintext_len = len;
        EVP_DecryptFinal_ex(ctx, res + len, &len);
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        return EasyEncrypt::Utils::toHex(res, plaintext_len);

    }

}

std::string EasyEncrypt::AES::cbc128(char* _data, ssize_t data_len,  char* _key, char* _iv, bool encrypt) {

    std::vector<unsigned char> data = EasyEncrypt::Utils::toVector(_data, data_len);
    std::vector<unsigned char> key = EasyEncrypt::Utils::toVector(_key, 16);
    std::vector<unsigned char> iv = EasyEncrypt::Utils::toVector(_iv, 16);

    size_t inputLength = data.size();

    unsigned char aes_input[inputLength];
    unsigned char aes_key[16];

    memset(aes_input, 0, inputLength);
    memset(aes_key, 0, sizeof(aes_key));

    memcpy(aes_input, data.data(), data.size());
    memcpy(aes_key, key.data(), key.size());

    unsigned char aes_iv[16];
    memset(aes_iv, 0x00, AES_BLOCK_SIZE);
    memcpy(aes_iv, iv.data(), iv.size());

    if(encrypt) {

        unsigned char res[inputLength];

        EVP_CIPHER_CTX *ctx;

        int len;
        int ciphertext_len;

        ctx = EVP_CIPHER_CTX_new();

        EVP_CIPHER_CTX_set_padding(ctx, 5);

        EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aes_key, aes_iv);
        EVP_EncryptUpdate(ctx, res, &len, aes_input, sizeof(aes_input));
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, res + len, &len);
        ciphertext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        return EasyEncrypt::Utils::toHex(res, ciphertext_len);

    } else {

        unsigned char res[inputLength];

        EVP_CIPHER_CTX *ctx;

        int len;
        int plaintext_len;

        ctx = EVP_CIPHER_CTX_new();

        EVP_CIPHER_CTX_set_padding(ctx, 5);

        EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aes_key, aes_iv);
        EVP_DecryptUpdate(ctx, res, &len, aes_input, sizeof(aes_input));
        plaintext_len = len;
        EVP_DecryptFinal_ex(ctx, res + len, &len);
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        return EasyEncrypt::Utils::toHex(res, plaintext_len);

    }

}

std::string EasyEncrypt::AES::ecb256(char* _data, ssize_t data_len, char* _key, bool encrypt) {

    std::vector<unsigned char> data = EasyEncrypt::Utils::toVector(_data, data_len);
    std::vector<unsigned char> key = EasyEncrypt::Utils::toVector(_key, 32);

    size_t inputLength = data.size();

    unsigned char aes_input[inputLength];
    unsigned char aes_key[32];

    memset(aes_input, 0, inputLength);
    memset(aes_key, 0, sizeof(aes_key));

    memcpy(aes_input, data.data(), data.size());
    memcpy(aes_key, key.data(), key.size());

    if(encrypt) {

        unsigned char res[inputLength];

        EVP_CIPHER_CTX *ctx;

        int len;
        int ciphertext_len;

        ctx = EVP_CIPHER_CTX_new();

        EVP_CIPHER_CTX_set_padding(ctx, 5);

        EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, aes_key, NULL);
        EVP_EncryptUpdate(ctx, res, &len, aes_input, sizeof(aes_input));
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, res + len, &len);
        ciphertext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        return EasyEncrypt::Utils::toHex(res, ciphertext_len);

    } else {

        unsigned char res[inputLength];

        EVP_CIPHER_CTX *ctx;

        int len;
        int plaintext_len;

        ctx = EVP_CIPHER_CTX_new();

        EVP_CIPHER_CTX_set_padding(ctx, 5);

        EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, aes_key, NULL);
        EVP_DecryptUpdate(ctx, res, &len, aes_input, sizeof(aes_input));
        plaintext_len = len;
        EVP_DecryptFinal_ex(ctx, res + len, &len);
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        return EasyEncrypt::Utils::toHex(res, plaintext_len);

    }

}

std::string EasyEncrypt::AES::ecb128(char* _data, ssize_t data_len, char* _key, bool encrypt) {

    std::vector<unsigned char> data = EasyEncrypt::Utils::toVector(_data, data_len);
    std::vector<unsigned char> key = EasyEncrypt::Utils::toVector(_key, 16);

    size_t inputLength = data.size();

    unsigned char aes_input[inputLength];
    unsigned char aes_key[16];

    memset(aes_input, 0, inputLength);
    memset(aes_key, 0, sizeof(aes_key));

    memcpy(aes_input, data.data(), data.size());
    memcpy(aes_key, key.data(), key.size());

    if(encrypt) {

        unsigned char res[inputLength];

        EVP_CIPHER_CTX *ctx;

        int len;
        int ciphertext_len;

        ctx = EVP_CIPHER_CTX_new();

        EVP_CIPHER_CTX_set_padding(ctx, 5);

        EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, aes_key, NULL);
        EVP_EncryptUpdate(ctx, res, &len, aes_input, sizeof(aes_input));
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, res + len, &len);
        ciphertext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        return EasyEncrypt::Utils::toHex(res, ciphertext_len);

    } else {

        unsigned char res[inputLength];

        EVP_CIPHER_CTX *ctx;

        int len;
        int plaintext_len;

        ctx = EVP_CIPHER_CTX_new();

        EVP_CIPHER_CTX_set_padding(ctx, 5);

        EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, aes_key, NULL);
        EVP_DecryptUpdate(ctx, res, &len, aes_input, sizeof(aes_input));
        plaintext_len = len;
        EVP_DecryptFinal_ex(ctx, res + len, &len);
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        return EasyEncrypt::Utils::toHex(res, plaintext_len);

    }

}

std::string EasyEncrypt::SHA::hash512(char *source, ssize_t data_len) {

    unsigned char hash[EVP_MD_size(EVP_sha512())];

    std::vector<unsigned char> data = EasyEncrypt::Utils::toVector(source, data_len);

    const EVP_MD *md = EVP_get_digestbyname("sha512");
    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data.data(), data.size());
    unsigned int digest_len;
    EVP_DigestFinal_ex(mdctx, hash, &digest_len);
    std::stringstream ss;

    for(int i=0; i<sizeof(hash); i++) {

        ss << std::hex << std::setw(2) << std::setfill('0') << (int) hash[i];

    }

    EVP_MD_CTX_free(mdctx);

    return EasyEncrypt::Utils::toLowerCase(ss.str());

}

std::string EasyEncrypt::SHA::hash256(char *source, ssize_t data_len) {

    unsigned char hash[EVP_MD_size(EVP_sha256())];

    std::vector<unsigned char> data = EasyEncrypt::Utils::toVector(source, data_len);

    const EVP_MD *md = EVP_get_digestbyname("sha256");
    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data.data(), data.size());
    unsigned int digest_len;
    EVP_DigestFinal_ex(mdctx, hash, &digest_len);
    std::stringstream ss;

    for(int i=0; i<sizeof(hash); i++) {

        ss << std::hex << std::setw(2) << std::setfill('0') << (int) hash[i];

    }

    EVP_MD_CTX_free(mdctx);

    return EasyEncrypt::Utils::toLowerCase(ss.str());

}

std::string EasyEncrypt::SHA::hmac256(char * _data, ssize_t data_len, char* _key, ssize_t key_len) {

    size_t len;
    unsigned char hash[SHA256_DIGEST_LENGTH];

    std::vector<unsigned char> key = EasyEncrypt::Utils::toVector(_key, key_len);
    std::vector<unsigned char> data = EasyEncrypt::Utils::toVector(_data, data_len);

    unsigned char key_input[key.size()];

    memset(key_input, 0, sizeof(key_input));
    memcpy(key_input, key.data(), key.size());

    OSSL_PARAM params[2];
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *mac_ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);

    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char*) "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    EVP_MAC_init(mac_ctx, key_input, sizeof(key_input), params);
    EVP_MAC_update(mac_ctx, data.data(), data.size());
    EVP_MAC_final(mac_ctx, hash, &len, sizeof(hash));

    std::stringstream ss;

    for(int i=0; i<sizeof(hash); i++) {

        ss << std::hex << std::setw(2) << std::setfill('0') << (int) hash[i];

    }

    EVP_MAC_CTX_free(mac_ctx);

    return EasyEncrypt::Utils::toLowerCase(ss.str());

}

std::string EasyEncrypt::SHA::hmac512(char * _data, ssize_t data_len, char* _key, ssize_t key_len) {

    size_t len;
    unsigned char hash[SHA512_DIGEST_LENGTH];

    std::vector<unsigned char> key = EasyEncrypt::Utils::toVector(_key, key_len);
    std::vector<unsigned char> data = EasyEncrypt::Utils::toVector(_data, data_len);

    unsigned char key_input[key.size()];

    memset(key_input, 0, sizeof(key_input));
    memcpy(key_input, key.data(), key.size());

    OSSL_PARAM params[2];
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *mac_ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);

    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char*) "SHA512", 0);
    params[1] = OSSL_PARAM_construct_end();

    EVP_MAC_init(mac_ctx, key_input, sizeof(key_input), params);
    EVP_MAC_update(mac_ctx, data.data(), data.size());
    EVP_MAC_final(mac_ctx, hash, &len, sizeof(hash));

    std::stringstream ss;

    for(int i=0; i<sizeof(hash); i++) {

        ss << std::hex << std::setw(2) << std::setfill('0') << (int) hash[i];

    }

    EVP_MAC_CTX_free(mac_ctx);

    return EasyEncrypt::Utils::toLowerCase(ss.str());

}

std::string EasyEncrypt::MD5::get(char *_data) {

    std::vector<unsigned char> data = EasyEncrypt::Utils::toVector(_data, sizeof(_data));

    unsigned char hash[EVP_MD_size(EVP_md5())];

    const EVP_MD *md = EVP_get_digestbyname("md5");
    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data.data(), data.size());
    unsigned int digest_len;
    EVP_DigestFinal_ex(mdctx, hash, &digest_len);
    std::stringstream ss;

    for(int i=0; i<sizeof(hash); i++) {

        ss << std::hex << std::setw(2) << std::setfill('0') << (int) hash[i];

    }

    EVP_DigestFinal_ex(mdctx, hash, &digest_len);

    return EasyEncrypt::Utils::toLowerCase(ss.str());

}

void EasyEncrypt::Utils::fromHex(const char *source, ssize_t size, char** destination) {

    std::vector<unsigned char> input = hexToVector(source, size);
    *destination = (char*) input.data();

}

std::vector<unsigned char> EasyEncrypt::Utils::base64ToVector(const char* source) {

    std::string decoded;
    Base64::Decode(source, decoded);

    return EasyEncrypt::Utils::toVector((char*) decoded.c_str(), decoded.size());

}

std::string EasyEncrypt::Utils::toBase64(unsigned char *source, ssize_t size) {

    std::string input = (char*) source;

    return Base64::Encode(input);

}

std::string EasyEncrypt::Utils::base64ToHex(const char *input) {

    return toHex(
            EasyEncrypt::Utils::base64ToVector(input).data(),
            EasyEncrypt::Utils::base64ToVector(input).size()
            );

}

std::string EasyEncrypt::Utils::hexToBase64(const char *input) {

    std::vector<unsigned char> data = hexToVector(input, sizeof(input));

    std::string output = EasyEncrypt::Utils::toBase64(data.data(), data.size());

    return output;

}

void EasyEncrypt::Utils::secureRandom(unsigned char *dest, ssize_t count) {

    memset(dest, 0, count);
    RAND_bytes(dest, count);

}
