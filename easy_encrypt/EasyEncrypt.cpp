//
// Created by ryan on 10/17/21.
//

#include <random>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include "openssl/conf.h"
#include "openssl/evp.h"
#include "openssl/aes.h"
#include "openssl/sha.h"
#include "openssl/rand.h"
#include "EasyEncrypt.h"
#include "Base64.h"

int EasyEncrypt::Random::getGoodInt(int start, int end, int seed) {

    std::mt19937 rng;

    auto now = std::chrono::system_clock::now();
    auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch());

    char* randChar = secureRandom(1);

    int randBite;
    memcpy(&randBite, randChar, 1);

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

std::string EasyEncrypt::Utils::toHex(char* source, size_t size) {

    std::stringstream ss;

    int s = size;

    for ( size_t i = 0 ; i < s ; ++i ) {
        ss << std::hex << std::setw(2) << std::setfill('0') << ((int)(unsigned char) source[i]);
    }

    std::string data = ss.str();

    return data;

}

std::vector<char> EasyEncrypt::Utils::toVector(char* source, size_t _size) {

    std::vector<char> returnVal;
    size_t size = (_size == NULL) ? strlen(source) : _size;

    for(int i=0; i<size; i++) {

        returnVal.push_back(source[i]);

    }

    returnVal.push_back('\0');

    return returnVal;

}

std::vector<unsigned char> EasyEncrypt::Utils::hexToVector(const char* source, size_t size) {

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

char* EasyEncrypt::Utils::fromBase64(const char *source) {

    std::string out;

    Base64::Decode(source, out);

    return (char*) out.c_str();

}

char* EasyEncrypt::Utils::fromHex(const char *source) {

    std::vector<unsigned char> dataVector = hexToVector(source, strlen(source));

    char* data = (char*) malloc(dataVector.size());
    memset(data, 0, dataVector.size());
    memcpy(data, dataVector.data(), dataVector.size());

    return data;

}

void calcSize(unsigned char* n, int* s) {
    int p = -1; int c = 1; int ss = -1; bool f = false;
    for(int i=0; i<*s; i++) {
        ss++;
        int cc = (int) n[i];
        if(cc == p && cc > 0 && cc <= 16) { f = true; c++; }
        if(f && cc != p) {if(p == c) { break; } c = 1; } p = cc; }
        if(p == c) { int sss = ss - c; if(sss % 16 == 0) { *s = sss; }}
}

char* EasyEncrypt::AES::cbc256(char* data_in, char* key_in, char* iv_in, bool encrypt, int* data_len) {

    std::vector<char> data = EasyEncrypt::Utils::toVector(data_in, (encrypt) ? NULL : *data_len);
    std::vector<char> key = EasyEncrypt::Utils::toVector(key_in, 32);
    std::vector<char> iv = EasyEncrypt::Utils::toVector(iv_in, 16);

    size_t data_in_len = (encrypt) ? data.size() - 1 : *data_len;

    unsigned char aes_input[data_in_len];
    unsigned char aes_key[32];

    memset(aes_input, 0x00, data_in_len);
    memset(aes_key, 0x00, 32);

    memcpy(aes_input,  (unsigned char*) data.data(), data_in_len);
    memcpy(aes_key,  (unsigned char*) key.data(), 32);

    unsigned char aes_iv[16];
    memset(aes_iv, 0x00, 16);
    memcpy(aes_iv, (unsigned char*) iv.data(), 16);

    if(encrypt) {

        unsigned char res[data_in_len];

        EVP_CIPHER_CTX *ctx;

        int len;
        int ciphertext_len;

        ctx = EVP_CIPHER_CTX_new();

        EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
        EVP_EncryptUpdate(ctx, res, &len, aes_input, data_in_len);
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, res + len, &len);
        ciphertext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        *data_len = ciphertext_len;

        char* final = (char*) malloc(ciphertext_len);
        memcpy(final, res, ciphertext_len);

        return final;

    } else {

        unsigned char res[data_in_len];
        memset(res, 0, data_in_len);

        EVP_CIPHER_CTX *ctx;

        int len;
        int plaintext_len;

        ctx = EVP_CIPHER_CTX_new();

        EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
        EVP_DecryptUpdate(ctx, res, &len, aes_input, data_in_len);
        plaintext_len = len;
        EVP_DecryptFinal_ex(ctx, res + len, &len);
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        int ptLen = plaintext_len;
        calcSize(res, &ptLen);

        char* final = (char*) malloc(ptLen);
        memset(final, 0, ptLen + 1);
        memcpy(final, res, ptLen);

        return final;

    }

}

char* EasyEncrypt::AES::cbc128(char* data_in, char* key_in, char* iv_in, bool encrypt, int* data_len) {

    std::vector<char> data = EasyEncrypt::Utils::toVector(data_in, (encrypt) ? NULL : *data_len);
    std::vector<char> key = EasyEncrypt::Utils::toVector(key_in, 16);
    std::vector<char> iv = EasyEncrypt::Utils::toVector(iv_in, 16);

    size_t data_in_len = (encrypt) ? data.size() - 1 : *data_len;

    unsigned char aes_input[data_in_len];
    unsigned char aes_key[16];

    memset(aes_input, 0x00, data_in_len);
    memset(aes_key, 0x00, 16);

    memcpy(aes_input,  (unsigned char*) data.data(), data_in_len);
    memcpy(aes_key,  (unsigned char*) key.data(), 16);

    unsigned char aes_iv[16];
    memset(aes_iv, 0x00, 16);
    memcpy(aes_iv, (unsigned char*) iv.data(), 16);

    if(encrypt) {

        unsigned char res[data_in_len];

        EVP_CIPHER_CTX *ctx;

        int len;
        int ciphertext_len;

        ctx = EVP_CIPHER_CTX_new();

        EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
        EVP_EncryptUpdate(ctx, res, &len, aes_input, data_in_len);
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, res + len, &len);
        ciphertext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        *data_len = ciphertext_len;

        char* final = (char*) malloc(ciphertext_len);
        memcpy(final, res, ciphertext_len);

        return final;

    } else {

        unsigned char res[data_in_len];
        memset(res, 0, data_in_len);

        EVP_CIPHER_CTX *ctx;

        int len;
        int plaintext_len;

        ctx = EVP_CIPHER_CTX_new();

        EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
        EVP_DecryptUpdate(ctx, res, &len, aes_input, data_in_len);
        plaintext_len = len;
        EVP_DecryptFinal_ex(ctx, res + len, &len);
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        int ptLen = plaintext_len;
        calcSize(res, &ptLen);

        char* final = (char*) malloc(ptLen);
        memset(final, 0, ptLen + 1);
        memcpy(final, res, ptLen);

        return final;

    }

}

char* EasyEncrypt::AES::ecb256(char* data_in, char* key_in, bool encrypt, int* data_len) {

    std::vector<char> data = EasyEncrypt::Utils::toVector(data_in, (encrypt) ? NULL : *data_len);
    std::vector<char> key = EasyEncrypt::Utils::toVector(key_in, 32);

    size_t data_in_len = (encrypt) ? data.size() - 1 : *data_len;

    unsigned char aes_input[data_in_len];
    unsigned char aes_key[32];

    memset(aes_input, 0x00, data_in_len);
    memset(aes_key, 0x00, 32);

    memcpy(aes_input,  (unsigned char*) data.data(), data_in_len);
    memcpy(aes_key,  (unsigned char*) key.data(), 32);

    if(encrypt) {

        unsigned char res[data_in_len];

        EVP_CIPHER_CTX *ctx;

        int len;
        int ciphertext_len;

        ctx = EVP_CIPHER_CTX_new();

        EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

        EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, aes_key, NULL);
        EVP_EncryptUpdate(ctx, res, &len, aes_input, data_in_len);
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, res + len, &len);
        ciphertext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        *data_len = ciphertext_len;

        char* final = (char*) malloc(ciphertext_len);
        memcpy(final, res, ciphertext_len);

        return final;

    } else {

        unsigned char res[data_in_len];
        memset(res, 0, data_in_len);

        EVP_CIPHER_CTX *ctx;

        int len;
        int plaintext_len;

        ctx = EVP_CIPHER_CTX_new();

        EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

        EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, aes_key, NULL);
        EVP_DecryptUpdate(ctx, res, &len, aes_input, data_in_len);
        plaintext_len = len;
        EVP_DecryptFinal_ex(ctx, res + len, &len);
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        int ptLen = plaintext_len;
        calcSize(res, &ptLen);

        char* final = (char*) malloc(ptLen);
        memset(final, 0, ptLen + 1);
        memcpy(final, res, ptLen);

        return final;

    }

}

char* EasyEncrypt::AES::ecb128(char* data_in, char* key_in, bool encrypt, int* data_len) {

    std::vector<char> data = EasyEncrypt::Utils::toVector(data_in, (encrypt) ? NULL : *data_len);
    std::vector<char> key = EasyEncrypt::Utils::toVector(key_in, 16);

    size_t data_in_len = (encrypt) ? data.size() - 1 : *data_len;

    unsigned char aes_input[data_in_len];
    unsigned char aes_key[16];

    memset(aes_input, 0x00, data_in_len);
    memset(aes_key, 0x00, 16);

    memcpy(aes_input,  (unsigned char*) data.data(), data_in_len);
    memcpy(aes_key,  (unsigned char*) key.data(), 16);

    if(encrypt) {

        unsigned char res[data_in_len];

        EVP_CIPHER_CTX *ctx;

        int len;
        int ciphertext_len;

        ctx = EVP_CIPHER_CTX_new();

        EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

        EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, aes_key, NULL);
        EVP_EncryptUpdate(ctx, res, &len, aes_input, data_in_len);
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, res + len, &len);
        ciphertext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        *data_len = ciphertext_len;

        char* final = (char*) malloc(ciphertext_len);
        memcpy(final, res, ciphertext_len);

        return final;

    } else {

        unsigned char res[data_in_len];
        memset(res, 0, data_in_len);

        EVP_CIPHER_CTX *ctx;

        int len;
        int plaintext_len;

        ctx = EVP_CIPHER_CTX_new();

        EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

        EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, aes_key, NULL);
        EVP_DecryptUpdate(ctx, res, &len, aes_input, data_in_len);
        plaintext_len = len;
        EVP_DecryptFinal_ex(ctx, res + len, &len);
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        int ptLen = plaintext_len;
        calcSize(res, &ptLen);

        char* final = (char*) malloc(ptLen);
        memset(final, 0, ptLen + 1);
        memcpy(final, res, ptLen);

        return final;

    }

}

std::string cbc256Encoded(char* data_in, char* key_in, char* iv_in, bool encrypt, int* data_len, EasyEncrypt::encode_t encoding) {

    int len = *data_len;

    char* res = EasyEncrypt::AES::cbc256(data_in, key_in, iv_in, encrypt, &len);
    std::string str;

    if(encrypt) {
        str = (encoding == EasyEncrypt::BASE64) ?
              EasyEncrypt::Utils::toBase64(res, len)
                                                : EasyEncrypt::Utils::toHex(res, len);
    } else {
        str = (const char*) res;
    }

    *data_len = len;

    free(res);

    return str;

}

std::string cbc128Encoded(char* data_in, char* key_in, char* iv_in, bool encrypt, int* data_len, EasyEncrypt::encode_t encoding) {

    int len = (encrypt) ? 0 : *data_len;

    char* res = EasyEncrypt::AES::cbc128(data_in, key_in, iv_in, encrypt, &len);
    std::string str;

    if(encrypt) {
        str = (encoding == EasyEncrypt::BASE64) ?
              EasyEncrypt::Utils::toBase64(res, len)
                                                : EasyEncrypt::Utils::toHex(res, len);
    } else {
        str = (const char*) res;
    }

    *data_len = len;

    free(res);

    return str;

}

std::string ecb256Encoded(char* data_in, char* key_in, bool encrypt, int* data_len, EasyEncrypt::encode_t encoding) {

    int len = (encrypt) ? 0 : *data_len;

    char* res = EasyEncrypt::AES::ecb256(data_in, key_in, encrypt, &len);
    std::string str;

    if(encrypt) {
        str = (encoding == EasyEncrypt::BASE64) ?
              EasyEncrypt::Utils::toBase64(res, len)
                                                : EasyEncrypt::Utils::toHex(res, len);
    } else {
        str = (const char*) res;
    }

    *data_len = len;

    free(res);

    return str;

}

std::string ecb128Encoded(char* data_in, char* key_in,  bool encrypt, int* data_len, EasyEncrypt::encode_t encoding) {

    int len = (encrypt) ? 0 : *data_len;

    char* res = EasyEncrypt::AES::ecb128(data_in, key_in, encrypt, &len);
    std::string str;

    if(encrypt) {
        str = (encoding == EasyEncrypt::BASE64) ?
              EasyEncrypt::Utils::toBase64(res, len)
                                                : EasyEncrypt::Utils::toHex(res, len);
    } else {
        str = (const char*) res;
    }

    *data_len = len;

    free(res);

    return str;

}

std::string EasyEncrypt::AES::Hex::cbc256(char* data_in, std::string key_in, std::string iv_in, bool encrypt) {

    char* data = (encrypt) ? data_in : EasyEncrypt::Utils::fromHex((const char*) data_in);

    int len = (encrypt) ? 0 : strlen(data);

    char* key = EasyEncrypt::Utils::fromHex(key_in.c_str());
    char* iv = EasyEncrypt::Utils::fromHex(iv_in.c_str());

    return cbc256Encoded(data, key, iv, encrypt, &len, EasyEncrypt::HEX);

}

std::string EasyEncrypt::AES::Base64::cbc256(char* data_in, std::string key_in, std::string iv_in, bool encrypt) {

    char* data = (encrypt) ? data_in : EasyEncrypt::Utils::fromBase64((const char*) data_in);

    int len = (encrypt) ? 0 : strlen(data);

    char* key = EasyEncrypt::Utils::fromBase64(key_in.c_str());
    char* iv = EasyEncrypt::Utils::fromBase64(iv_in.c_str());

    return cbc256Encoded(data, key, iv, encrypt, &len, EasyEncrypt::BASE64);

}

std::string EasyEncrypt::AES::Hex::cbc128(char* data_in, std::string key_in, std::string iv_in, bool encrypt) {

    char* data = (encrypt) ? data_in : EasyEncrypt::Utils::fromHex((const char*) data_in);

    int len = (encrypt) ? 0 : strlen(data);

    char* key = EasyEncrypt::Utils::fromHex(key_in.c_str());
    char* iv = EasyEncrypt::Utils::fromHex(iv_in.c_str());

    return cbc128Encoded(data, key, iv, encrypt, &len, EasyEncrypt::HEX);

}

std::string EasyEncrypt::AES::Base64::cbc128(char* data_in, std::string key_in, std::string iv_in, bool encrypt) {

    char* data = (encrypt) ? data_in : EasyEncrypt::Utils::fromBase64((const char*) data_in);

    int len = (encrypt) ? 0 : strlen(data);

    char* key = EasyEncrypt::Utils::fromBase64(key_in.c_str());
    char* iv = EasyEncrypt::Utils::fromBase64(iv_in.c_str());

    return cbc128Encoded(data, key, iv, encrypt, &len, EasyEncrypt::BASE64);

}

std::string EasyEncrypt::AES::Hex::ecb256(char* data_in, std::string key_in, bool encrypt) {

    char* data = (encrypt) ? data_in : EasyEncrypt::Utils::fromHex((const char*) data_in);

    int len = (encrypt) ? 0 : strlen(data);

    char* key = EasyEncrypt::Utils::fromHex(key_in.c_str());

    return ecb256Encoded(data, key, encrypt, &len, EasyEncrypt::HEX);

}

std::string EasyEncrypt::AES::Base64::ecb256(char* data_in, std::string key_in, bool encrypt) {

    char* data = (encrypt) ? data_in : EasyEncrypt::Utils::fromBase64((const char*) data_in);

    int len = (encrypt) ? 0 : strlen(data);

    char* key = EasyEncrypt::Utils::fromBase64(key_in.c_str());

    return ecb256Encoded(data, key, encrypt, &len, EasyEncrypt::BASE64);

}

std::string EasyEncrypt::AES::Hex::ecb128(char* data_in, std::string key_in, bool encrypt) {

    char* data = (encrypt) ? data_in : EasyEncrypt::Utils::fromHex((const char*) data_in);

    int len = (encrypt) ? 0 : strlen(data);

    char* key = EasyEncrypt::Utils::fromHex(key_in.c_str());

    return ecb128Encoded(data, key, encrypt, &len, EasyEncrypt::HEX);

}

std::string EasyEncrypt::AES::Base64::ecb128(char* data_in, std::string key_in, bool encrypt) {

    char* data = (encrypt) ? data_in : EasyEncrypt::Utils::fromBase64((const char*) data_in);

    int len = (encrypt) ? 0 : strlen(data);

    char* key = EasyEncrypt::Utils::fromBase64(key_in.c_str());

    return ecb128Encoded(data, key,  encrypt, &len, EasyEncrypt::BASE64);

}

char* EasyEncrypt::SHA::hash512(char *source) {

    unsigned char hash[EVP_MD_size(EVP_sha512())];

    std::vector<char> data = EasyEncrypt::Utils::toVector(source, strlen(source));

    unsigned char* dataArr = (unsigned char*) malloc(data.size() - 1);
    memcpy(dataArr, data.data(), data.size() - 1);

    const EVP_MD *md = EVP_get_digestbyname("sha512");
    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, dataArr, data.size() - 1);
    unsigned int digest_len;
    EVP_DigestFinal_ex(mdctx, hash, &digest_len);

    EVP_MD_CTX_free(mdctx);

    char* final = (char*) malloc(129);
    memcpy(final, hash, 128);
    final[128] = '\0';

    return final;

}

char* EasyEncrypt::SHA::hash256(char *source) {

    unsigned char hash[EVP_MD_size(EVP_sha256())];

    std::vector<char> data = EasyEncrypt::Utils::toVector(source, strlen(source));

    unsigned char* dataArr = (unsigned char*) malloc(data.size() - 1);
    memcpy(dataArr, data.data(), data.size() - 1);

    const EVP_MD *md = EVP_get_digestbyname("sha256");
    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, dataArr, data.size() - 1);
    unsigned int digest_len;
    EVP_DigestFinal_ex(mdctx, hash, &digest_len);

    EVP_MD_CTX_free(mdctx);

    char* final = (char*) malloc(65);
    memcpy(final, hash, 64);
    final[64] = '\0';

    return final;

}

char* EasyEncrypt::SHA::hmac256(char * _data, char* _key) {

    size_t len;
    unsigned char hash[SHA256_DIGEST_LENGTH];

    std::vector<char> key = EasyEncrypt::Utils::toVector(_key, strlen(_key));
    std::vector<char> data = EasyEncrypt::Utils::toVector(_data, strlen(_data));

    unsigned char key_input[key.size() - 1];
    unsigned char hmac_input[data.size() - 1];

    memset(key_input, 0, data.size() - 1);
    memcpy(key_input, key.data(), key.size() - 1);

    memset(hmac_input, 0, data.size() - 1);
    memcpy(hmac_input, data.data(), data.size() - 1);

    OSSL_PARAM params[2];
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *mac_ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);

    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char*) "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    EVP_MAC_init(mac_ctx, key_input, key.size() - 1, params);
    EVP_MAC_update(mac_ctx, hmac_input, data.size() - 1);
    EVP_MAC_final(mac_ctx, hash, &len, sizeof(hash));

    EVP_MAC_CTX_free(mac_ctx);

    char* final = (char*) malloc(65);
    memcpy(final, hash, 64);
    final[64] = '\0';

    return final;

}

char* EasyEncrypt::SHA::hmac512(char * _data, char* _key) {

    size_t len;
    unsigned char hash[SHA512_DIGEST_LENGTH];

    std::vector<char> key = EasyEncrypt::Utils::toVector(_key, strlen(_key));
    std::vector<char> data = EasyEncrypt::Utils::toVector(_data, strlen(_data));

    unsigned char key_input[key.size() - 1];
    unsigned char hmac_input[data.size() - 1];

    memset(key_input, 0, key.size() - 1);
    memcpy(key_input, key.data(), key.size() - 1);

    memset(hmac_input, 0, data.size() - 1);
    memcpy(hmac_input, data.data(), data.size() - 1);

    OSSL_PARAM params[2];
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *mac_ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);

    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char*) "SHA512", 0);
    params[1] = OSSL_PARAM_construct_end();

    EVP_MAC_init(mac_ctx, key_input, key.size() - 1, params);
    EVP_MAC_update(mac_ctx, hmac_input, data.size() - 1);
    EVP_MAC_final(mac_ctx, hash, &len, sizeof(hash));

    EVP_MAC_CTX_free(mac_ctx);

    char* final = (char*) malloc(129);
    memcpy(final, hash, 128);
    final[128] = '\0';

    return final;

}

char* EasyEncrypt::MD5::get(char *_data) {

    std::vector<char> data = EasyEncrypt::Utils::toVector(_data, NULL);

    unsigned char hash[EVP_MD_size(EVP_md5())];
    unsigned char* arr = (unsigned char*) malloc(data.size() - 1);

    memset(arr, 0, data.size() - 1);
    memcpy(arr, data.data(), data.size() - 1);

    const EVP_MD *md = EVP_md5();
    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_create();
    EVP_MD_CTX_init(mdctx);
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, arr, data.size() - 1);
    unsigned int digest_len;
    EVP_DigestFinal_ex(mdctx, hash, &digest_len);

    EVP_MD_CTX_free(mdctx);

    char* final = (char*) malloc(17);
    memcpy(final, hash, 16);
    final[16] = '\0';

    return final;

}

std::string hash512Encoded(char* data, EasyEncrypt::encode_t encoding) {

    char* res = EasyEncrypt::SHA::hash512(data);

    return (encoding == EasyEncrypt::BASE64) ? Base64::Encode(res) : EasyEncrypt::Utils::toHex(res, 64);

}

std::string EasyEncrypt::SHA::Hex::hash512(char *data) {

    return hash512Encoded(data, EasyEncrypt::HEX);

}

std::string EasyEncrypt::SHA::Base64::hash512(char *data) {

    return hash512Encoded(data, EasyEncrypt::BASE64);

}

std::string hash256Encoded(char* data, EasyEncrypt::encode_t encoding) {

    char* res = EasyEncrypt::SHA::hash256(data);

    return (encoding == EasyEncrypt::BASE64) ? Base64::Encode(res) : EasyEncrypt::Utils::toHex(res, 32);

}

std::string EasyEncrypt::SHA::Hex::hash256(char *data) {

    return hash256Encoded(data, EasyEncrypt::HEX);

}

std::string EasyEncrypt::SHA::Base64::hash256(char *data) {

    return hash256Encoded(data, EasyEncrypt::BASE64);

}

std::string hmac512Encoded(char* data, char* key, EasyEncrypt::encode_t encoding) {

    char* res = EasyEncrypt::SHA::hmac512(data, key);

    return (encoding == EasyEncrypt::BASE64) ? Base64::Encode(res) : EasyEncrypt::Utils::toHex(res, 64);

}

std::string EasyEncrypt::SHA::Hex::hmac512(char *data, char* key) {

    return hmac512Encoded(data, key, EasyEncrypt::HEX);

}

std::string EasyEncrypt::SHA::Base64::hmac512(char *data, char* key) {

    return hmac512Encoded(data, key, EasyEncrypt::BASE64);

}

std::string hmac256Encoded(char* data, char* key, EasyEncrypt::encode_t encoding) {

    char* res = EasyEncrypt::SHA::hmac256(data, key);

    return (encoding == EasyEncrypt::BASE64) ? Base64::Encode(res) : EasyEncrypt::Utils::toHex(res, 32);

}

std::string EasyEncrypt::SHA::Hex::hmac256(char *data, char* key) {

    return hmac256Encoded(data, key, EasyEncrypt::HEX);

}

std::string EasyEncrypt::SHA::Base64::hmac256(char *data, char* key) {

    return hmac256Encoded(data, key, EasyEncrypt::BASE64);

}

std::string getMd5Encoded(char* data, EasyEncrypt::encode_t encoding) {

    char* res = EasyEncrypt::MD5::get(data);

    return (encoding == EasyEncrypt::BASE64) ? Base64::Encode(res) : EasyEncrypt::Utils::toHex(res, 16);

}

std::string EasyEncrypt::MD5::Hex::get(char *data) {

    return getMd5Encoded(data, EasyEncrypt::HEX);

}

std::string EasyEncrypt::MD5::Base64::get(char *data) {

    return getMd5Encoded(data, EasyEncrypt::BASE64);

}

std::vector<char> EasyEncrypt::Utils::base64ToVector(const char* source) {

    std::string decoded;
    Base64::Decode(source, decoded);

    return EasyEncrypt::Utils::toVector((char*) decoded.c_str(), decoded.size());

}

std::string EasyEncrypt::Utils::toBase64(char *source, size_t size) {

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

    char* dataArr = (char*) malloc(data.size());
    memcpy(dataArr, data.data(), data.size());

    std::string output = EasyEncrypt::Utils::toBase64(dataArr, data.size());

    return output;

}

char* EasyEncrypt::Random::secureRandom(size_t count) {

    unsigned char bytes[count];
    RAND_bytes(bytes, count);
    char* res = (char*) malloc(count);
    memset(res, 0, count);
    memcpy(res, bytes, count);

    return res;

}

std::string EasyEncrypt::Random::secureEncoded(EasyEncrypt::encode_t encoding, size_t count) {

    char* res = EasyEncrypt::Random::secureRandom(count);

    return (encoding == EasyEncrypt::BASE64) ? Base64::Encode(res) : EasyEncrypt::Utils::toHex(res, count);

}

char* EasyEncrypt::Random::goodRandom(size_t count) {

    char* arr = (char*)malloc(count);

    for(int i=0; i<count; i++) {

        char* s = EasyEncrypt::Random::secureRandom(1);
        int randBite;
        memcpy(&randBite, s, 1);

        unsigned char c = (unsigned char) EasyEncrypt::Random::getGoodInt(0, 255, randBite * 2);
        arr[i] = (char) c;

    }

    return arr;

}

std::string EasyEncrypt::Random::goodEncoded(EasyEncrypt::encode_t encoding, size_t count) {

    char* res = EasyEncrypt::Random::goodRandom(count);

    return (encoding == EasyEncrypt::BASE64) ? Base64::Encode(res) : EasyEncrypt::Utils::toHex(res, count);

}
