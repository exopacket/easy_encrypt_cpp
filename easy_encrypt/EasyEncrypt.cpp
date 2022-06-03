//
// Created by ryan on 10/17/21.
//

#include <random>
#include <sstream>
#include <iomanip>
#include <openssl/provider.h>
#include "openssl/evp.h"
#include "openssl/aes.h"
#include "openssl/sha.h"
#include "openssl/rand.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <chrono>
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

    ss << std::hex << std::setfill('0');
    for ( size_t i = 0 ; i < size ; ++i ) {
        ss << std::setw(2) << ((int)(unsigned char) source[i]);
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


    return returnVal;

}

std::vector<char> EasyEncrypt::Utils::hexToVector(std::string input, size_t size) {

    int _size = (size) / 2;

    int x=0;
    int i;

    std::vector<char> returnVal;

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

        returnVal.push_back((signed char) ((unsigned char) j));

    }

    return returnVal;


}

std::vector<char> EasyEncrypt::Utils::stringToVector(std::string source) {

    std::vector<char> returnVal;

    for(int i=0; i<source.length(); i++) {

        returnVal.push_back(source.at(i));

    }

    return returnVal;

}

std::vector<char> EasyEncrypt::Utils::fromBase64(std::string source) {

    std::string res = Base64::Decode(source);

    return stringToVector(res);

}

std::vector<char> EasyEncrypt::Utils::fromHex(std::string source) {

    return hexToVector(source, source.length());

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

char* EasyEncrypt::AES::cbc256(char* data_in, int* data_len, char* key_in, char* iv_in, bool encrypt) {

    bool get_str_size = (*data_len == NULL || *data_len <= 0) && encrypt;

    std::vector<char> data = EasyEncrypt::Utils::toVector(data_in, (get_str_size) ? NULL : *data_len);
    std::vector<char> key = EasyEncrypt::Utils::toVector(key_in, 32);
    std::vector<char> iv = EasyEncrypt::Utils::toVector(iv_in, 16);

    size_t data_in_len = data.size();

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
        EVP_DecryptUpdate(ctx, res, &len, aes_input, sizeof(aes_input));
        plaintext_len = len;
        EVP_DecryptFinal_ex(ctx, res + len, &len);
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        int ptLen = plaintext_len;
        calcSize(res, &ptLen);

        *data_len = ptLen;

        char* final = (char*) malloc(ptLen);
        memset(final, 0, ptLen + 1);
        memcpy(final, res, ptLen);

        return final;

    }

}

char* EasyEncrypt::AES::gcm128(char* data_in, int* data_len, char* key_in, char* iv_in, bool encrypt) {

    bool get_str_size = (*data_len == NULL || *data_len <= 0) && encrypt;

    std::vector<char> data = EasyEncrypt::Utils::toVector(data_in, (get_str_size) ? NULL : *data_len);
    std::vector<char> key = EasyEncrypt::Utils::toVector(key_in, 16);
    std::vector<char> iv = EasyEncrypt::Utils::toVector(iv_in, 16);

    size_t data_in_len = data.size();

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

        EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, aes_key, aes_iv);
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

        EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, aes_key, aes_iv);
        EVP_DecryptUpdate(ctx, res, &len, aes_input, data_in_len);
        plaintext_len = len;
        EVP_DecryptFinal_ex(ctx, res + len, &len);
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        int ptLen = plaintext_len;
        calcSize(res, &ptLen);

        *data_len = ptLen;

        char* final = (char*) malloc(ptLen);
        memset(final, 0, ptLen + 1);
        memcpy(final, res, ptLen);

        return final;

    }

}

char* EasyEncrypt::AES::gcm256(char* data_in, int* data_len, char* key_in, char* iv_in, bool encrypt) {

    bool get_str_size = (*data_len == NULL || *data_len <= 0) && encrypt;

    std::vector<char> data = EasyEncrypt::Utils::toVector(data_in, (get_str_size) ? NULL : *data_len);
    std::vector<char> key = EasyEncrypt::Utils::toVector(key_in, 32);
    std::vector<char> iv = EasyEncrypt::Utils::toVector(iv_in, 16);

    size_t data_in_len = data.size();

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

        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aes_key, aes_iv);
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

        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aes_key, aes_iv);
        EVP_DecryptUpdate(ctx, res, &len, aes_input, sizeof(aes_input));
        plaintext_len = len;
        EVP_DecryptFinal_ex(ctx, res + len, &len);
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        int ptLen = plaintext_len;
        calcSize(res, &ptLen);

        *data_len = ptLen;

        char* final = (char*) malloc(ptLen);
        memset(final, 0, ptLen + 1);
        memcpy(final, res, ptLen);

        return final;

    }

}

char* EasyEncrypt::AES::cbc128(char* data_in, int* data_len, char* key_in, char* iv_in, bool encrypt) {

    bool get_str_size = (*data_len == NULL || *data_len <= 0) && encrypt;

    std::vector<char> data = EasyEncrypt::Utils::toVector(data_in, (get_str_size) ? NULL : *data_len);
    std::vector<char> key = EasyEncrypt::Utils::toVector(key_in, 16);
    std::vector<char> iv = EasyEncrypt::Utils::toVector(iv_in, 16);

    size_t data_in_len = data.size();

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

        EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aes_key, aes_iv);
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

        EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aes_key, aes_iv);
        EVP_DecryptUpdate(ctx, res, &len, aes_input, data_in_len);
        plaintext_len = len;
        EVP_DecryptFinal_ex(ctx, res + len, &len);
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        int ptLen = plaintext_len;
        calcSize(res, &ptLen);

        *data_len = ptLen;

        char* final = (char*) malloc(ptLen);
        memset(final, 0, ptLen + 1);
        memcpy(final, res, ptLen);

        return final;

    }

}

char* EasyEncrypt::AES::ecb256(char* data_in, int* data_len, char* key_in, bool encrypt) {

    bool get_str_size = (*data_len == NULL || *data_len <= 0) && encrypt;

    std::vector<char> data = EasyEncrypt::Utils::toVector(data_in, (get_str_size) ? NULL : *data_len);
    std::vector<char> key = EasyEncrypt::Utils::toVector(key_in, 32);

    size_t data_in_len = data.size();

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

        *data_len = ptLen;

        char* final = (char*) malloc(ptLen);
        memset(final, 0, ptLen + 1);
        memcpy(final, res, ptLen);

        return final;

    }

}

char* EasyEncrypt::AES::ecb128(char* data_in, int* data_len, char* key_in, bool encrypt) {

    bool get_str_size = (*data_len == NULL || *data_len <= 0) && encrypt;

    std::vector<char> data = EasyEncrypt::Utils::toVector(data_in, get_str_size ? NULL : *data_len);
    std::vector<char> key = EasyEncrypt::Utils::toVector(key_in, 16);

    size_t data_in_len = data.size();

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

        *data_len = ptLen;

        char* final = (char*) malloc(ptLen);
        memset(final, 0, ptLen + 1);
        memcpy(final, res, ptLen);

        return final;

    }

}

std::string cbc256Encoded(char* data_in, char* key_in, char* iv_in, bool encrypt, int* data_len, EasyEncrypt::encode_t encoding) {

    int len = *data_len;

    char* res = EasyEncrypt::AES::cbc256(data_in, &len, key_in, iv_in, encrypt);
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

    int len = *data_len;

    char* res = EasyEncrypt::AES::cbc128(data_in, &len, key_in, iv_in, encrypt);
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

std::string gcm256Encoded(char* data_in, char* key_in, char* iv_in, bool encrypt, int* data_len, EasyEncrypt::encode_t encoding) {

    int len = *data_len;

    char* res = EasyEncrypt::AES::gcm256(data_in, &len, key_in, iv_in, encrypt);
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

std::string gcm128Encoded(char* data_in, char* key_in, char* iv_in, bool encrypt, int* data_len, EasyEncrypt::encode_t encoding) {

    int len = *data_len;

    char* res = EasyEncrypt::AES::gcm128(data_in, &len, key_in, iv_in, encrypt);
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

    int len = *data_len;

    char* res = EasyEncrypt::AES::ecb256(data_in, &len, key_in, encrypt);
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

    int len = *data_len;

    char* res = EasyEncrypt::AES::ecb128(data_in, &len, key_in, encrypt);
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

std::string EasyEncrypt::AES::Hex::cbc256(std::string data_in, std::string key_in, std::string iv_in, bool encrypt) {

    std::vector<char> data = (encrypt) ?
                             EasyEncrypt::Utils::stringToVector(data_in) :
                             EasyEncrypt::Utils::fromHex(data_in);

    int len = data.size();

    char* key = (char*) malloc(32);
    memcpy(key, EasyEncrypt::Utils::fromHex(key_in).data(), 32);

    char* iv = (char*) malloc(16);
    memcpy(iv, EasyEncrypt::Utils::fromHex(iv_in).data(), 16);

    char* data_arr = (char*) malloc(data.size());
    memcpy(data_arr, data.data(), data.size());

    return cbc128Encoded(data_arr, key, iv,  encrypt, &len, EasyEncrypt::HEX);

}

std::string EasyEncrypt::AES::Base64::cbc256(std::string data_in, std::string key_in, std::string iv_in, bool encrypt) {

    std::vector<char> data = (encrypt) ?
                             EasyEncrypt::Utils::stringToVector(data_in) :
                             EasyEncrypt::Utils::fromBase64(data_in);

    int len = data.size();


    char* key = (char*) malloc(32);
    memcpy(key, EasyEncrypt::Utils::fromBase64(key_in).data(), 32);

    char* iv = (char*) malloc(16);
    memcpy(iv, EasyEncrypt::Utils::fromBase64(iv_in).data(), 16);

    char* data_arr = (char*) malloc(data.size());
    memcpy(data_arr, data.data(), data.size());

    return cbc256Encoded(data_arr, key, iv,  encrypt, &len, EasyEncrypt::BASE64);

}

std::string EasyEncrypt::AES::Hex::cbc128(std::string data_in, std::string key_in, std::string iv_in, bool encrypt) {

    std::vector<char> data = (encrypt) ?
                             EasyEncrypt::Utils::stringToVector(data_in) :
                             EasyEncrypt::Utils::fromHex(data_in);

    int len = data.size();

    char* key = (char*) malloc(16);
    memcpy(key, EasyEncrypt::Utils::fromHex(key_in).data(), 16);

    char* iv = (char*) malloc(16);
    memcpy(iv, EasyEncrypt::Utils::fromHex(iv_in).data(), 16);

    char* data_arr = (char*) malloc(data.size());
    memcpy(data_arr, data.data(), data.size());

    return cbc128Encoded(data_arr, key, iv,  encrypt, &len, EasyEncrypt::HEX);

}

std::string EasyEncrypt::AES::Base64::cbc128(std::string data_in, std::string key_in, std::string iv_in, bool encrypt) {

    std::vector<char> data = (encrypt) ?
                             EasyEncrypt::Utils::stringToVector(data_in) :
                             EasyEncrypt::Utils::fromBase64(data_in);

    int len = data.size();

    char* key = (char*) malloc(16);
    memcpy(key, EasyEncrypt::Utils::fromBase64(key_in).data(), 16);

    char* iv = (char*) malloc(16);
    memcpy(iv, EasyEncrypt::Utils::fromBase64(iv_in).data(), 16);

    char* data_arr = (char*) malloc(data.size());
    memcpy(data_arr, data.data(), data.size());

    return cbc128Encoded(data_arr, key, iv,  encrypt, &len, EasyEncrypt::BASE64);

}

std::string EasyEncrypt::AES::Hex::gcm256(std::string data_in, std::string key_in, std::string iv_in, bool encrypt) {

    std::vector<char> data = (encrypt) ?
                             EasyEncrypt::Utils::stringToVector(data_in) :
                             EasyEncrypt::Utils::fromHex(data_in);

    int len = data.size();

    char* key = (char*) malloc(32);
    memcpy(key, EasyEncrypt::Utils::fromHex(key_in).data(), 32);

    char* iv = (char*) malloc(16);
    memcpy(iv, EasyEncrypt::Utils::fromHex(iv_in).data(), 16);

    char* data_arr = (char*) malloc(data.size());
    memcpy(data_arr, data.data(), data.size());

    return gcm128Encoded(data_arr, key, iv,  encrypt, &len, EasyEncrypt::HEX);

}

std::string EasyEncrypt::AES::Base64::gcm256(std::string data_in, std::string key_in, std::string iv_in, bool encrypt) {

    std::vector<char> data = (encrypt) ?
                             EasyEncrypt::Utils::stringToVector(data_in) :
                             EasyEncrypt::Utils::fromBase64(data_in);

    int len = data.size();


    char* key = (char*) malloc(32);
    memcpy(key, EasyEncrypt::Utils::fromBase64(key_in).data(), 32);

    char* iv = (char*) malloc(16);
    memcpy(iv, EasyEncrypt::Utils::fromBase64(iv_in).data(), 16);

    char* data_arr = (char*) malloc(data.size());
    memcpy(data_arr, data.data(), data.size());

    return gcm256Encoded(data_arr, key, iv,  encrypt, &len, EasyEncrypt::BASE64);

}

std::string EasyEncrypt::AES::Hex::gcm128(std::string data_in, std::string key_in, std::string iv_in, bool encrypt) {

    std::vector<char> data = (encrypt) ?
                             EasyEncrypt::Utils::stringToVector(data_in) :
                             EasyEncrypt::Utils::fromHex(data_in);

    int len = data.size();

    char* key = (char*) malloc(16);
    memcpy(key, EasyEncrypt::Utils::fromHex(key_in).data(), 16);

    char* iv = (char*) malloc(16);
    memcpy(iv, EasyEncrypt::Utils::fromHex(iv_in).data(), 16);

    char* data_arr = (char*) malloc(data.size());
    memcpy(data_arr, data.data(), data.size());

    return gcm128Encoded(data_arr, key, iv,  encrypt, &len, EasyEncrypt::HEX);

}

std::string EasyEncrypt::AES::Base64::gcm128(std::string data_in, std::string key_in, std::string iv_in, bool encrypt) {

    std::vector<char> data = (encrypt) ?
                             EasyEncrypt::Utils::stringToVector(data_in) :
                             EasyEncrypt::Utils::fromBase64(data_in);

    int len = data.size();

    char* key = (char*) malloc(16);
    memcpy(key, EasyEncrypt::Utils::fromBase64(key_in).data(), 16);

    char* iv = (char*) malloc(16);
    memcpy(iv, EasyEncrypt::Utils::fromBase64(iv_in).data(), 16);

    char* data_arr = (char*) malloc(data.size());
    memcpy(data_arr, data.data(), data.size());

    return gcm128Encoded(data_arr, key, iv,  encrypt, &len, EasyEncrypt::BASE64);

}

std::string EasyEncrypt::AES::Hex::ecb256(std::string data_in, std::string key_in, bool encrypt) {

    std::vector<char> data = (encrypt) ?
                             EasyEncrypt::Utils::stringToVector(data_in) :
                             EasyEncrypt::Utils::fromHex(data_in);

    int len = data.size();

    char* key = (char*) malloc(32);
    memcpy(key, EasyEncrypt::Utils::fromHex(key_in).data(), 32);

    char* data_arr = (char*) malloc(data.size());
    memcpy(data_arr, data.data(), data.size());

    return ecb256Encoded(data_arr, key,  encrypt, &len, EasyEncrypt::HEX);

}

std::string EasyEncrypt::AES::Base64::ecb256(std::string data_in, std::string key_in, bool encrypt) {

    std::vector<char> data = (encrypt) ?
                             EasyEncrypt::Utils::stringToVector(data_in) :
                             EasyEncrypt::Utils::fromBase64(data_in);

    int len = data.size();

    char* key = (char*) malloc(32);
    memcpy(key, EasyEncrypt::Utils::fromBase64(key_in).data(), 32);

    char* data_arr = (char*) malloc(data.size());
    memcpy(data_arr, data.data(), data.size());

    return ecb256Encoded(data_arr, key,  encrypt, &len, EasyEncrypt::BASE64);
}

std::string EasyEncrypt::AES::Hex::ecb128(std::string data_in, std::string key_in, bool encrypt) {

    std::vector<char> data = (encrypt) ?
                             EasyEncrypt::Utils::stringToVector(data_in) :
                             EasyEncrypt::Utils::fromHex(data_in);

    int len = data.size();

    char* key = (char*) malloc(16);
    memcpy(key, EasyEncrypt::Utils::fromHex(key_in).data(), 16);

    char* data_arr = (char*) malloc(data.size());
    memcpy(data_arr, data.data(), data.size());

    return ecb128Encoded(data_arr, key,  encrypt, &len, EasyEncrypt::HEX);

}

std::string EasyEncrypt::AES::Base64::ecb128(std::string data_in, std::string key_in, bool encrypt) {

    std::vector<char> data = (encrypt) ?
                             EasyEncrypt::Utils::stringToVector(data_in) :
                             EasyEncrypt::Utils::fromBase64(data_in);

    int len = data.size();

    char* key = (char*) malloc(16);
    memcpy(key, EasyEncrypt::Utils::fromBase64(key_in).data(), 16);

    char* data_arr = (char*) malloc(data.size());
    memcpy(data_arr, data.data(), data.size());

    return ecb128Encoded(data_arr, key,  encrypt, &len, EasyEncrypt::BASE64);

}

char* EasyEncrypt::SHA::hash512(char* source, int* len) {

    unsigned char hash[EVP_MD_size(EVP_sha512())];

    std::vector<char> data = EasyEncrypt::Utils::toVector(source, *len);

    unsigned char* dataArr = (unsigned char*) malloc(data.size());
    memcpy(dataArr, data.data(), data.size());

    const EVP_MD *md = EVP_get_digestbyname("sha512");
    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, dataArr, data.size());
    unsigned int digest_len;
    EVP_DigestFinal_ex(mdctx, hash, &digest_len);

    EVP_MD_CTX_free(mdctx);

    char* final = (char*) malloc(129);
    memcpy(final, hash, 128);
    final[128] = '\0';

    *len = 128;

    return final;

}

char* EasyEncrypt::SHA::hash256(char* source, int* len) {

    unsigned char hash[EVP_MD_size(EVP_sha256())];

    std::vector<char> data = EasyEncrypt::Utils::toVector(source, *len);

    unsigned char* dataArr = (unsigned char*) malloc(data.size());
    memcpy(dataArr, data.data(), data.size());

    const EVP_MD *md = EVP_get_digestbyname("sha256");
    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, dataArr, data.size());
    unsigned int digest_len;
    EVP_DigestFinal_ex(mdctx, hash, &digest_len);

    EVP_MD_CTX_free(mdctx);

    char* final = (char*) malloc(65);
    memcpy(final, hash, 64);
    final[64] = '\0';

    *len = 64;

    return final;

}

char* EasyEncrypt::SHA::hmac256(char * _data, int* data_len, char* _key, int key_len) {

    size_t len;
    unsigned char hash[SHA256_DIGEST_LENGTH];

    std::vector<char> key = EasyEncrypt::Utils::toVector(_key, key_len);
    std::vector<char> data = EasyEncrypt::Utils::toVector(_data, *data_len);

    unsigned char key_input[key.size()];
    unsigned char hmac_input[data.size()];

    memset(key_input, 0, data.size());
    memcpy(key_input, key.data(), key.size());

    memset(hmac_input, 0, data.size());
    memcpy(hmac_input, data.data(), data.size());

    OSSL_PARAM params[2];
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *mac_ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);

    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char*) "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    EVP_MAC_init(mac_ctx, key_input, key.size(), params);
    EVP_MAC_update(mac_ctx, hmac_input, data.size());
    EVP_MAC_final(mac_ctx, hash, &len, sizeof(hash));

    EVP_MAC_CTX_free(mac_ctx);

    char* final = (char*) malloc(65);
    memcpy(final, hash, 64);
    final[64] = '\0';



    *data_len = 64;

    return final;

}

char* EasyEncrypt::SHA::hmac512(char* _data, int* data_len, char* _key, int key_len) {

    size_t len;
    unsigned char hash[SHA512_DIGEST_LENGTH];

    std::vector<char> key = EasyEncrypt::Utils::toVector(_key, key_len);
    std::vector<char> data = EasyEncrypt::Utils::toVector(_data, *data_len);

    unsigned char key_input[key.size()];
    unsigned char hmac_input[data.size()];

    memset(key_input, 0, key.size());
    memcpy(key_input, key.data(), key.size());

    memset(hmac_input, 0, data.size());
    memcpy(hmac_input, data.data(), data.size());

    OSSL_PARAM params[2];
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *mac_ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);

    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char*) "SHA512", 0);
    params[1] = OSSL_PARAM_construct_end();

    EVP_MAC_init(mac_ctx, key_input, key.size(), params);
    EVP_MAC_update(mac_ctx, hmac_input, data.size());
    EVP_MAC_final(mac_ctx, hash, &len, sizeof(hash));

    EVP_MAC_CTX_free(mac_ctx);

    char* final = (char*) malloc(129);
    memcpy(final, hash, 128);
    final[128] = '\0';

    *data_len = 128;

    return final;

}

char* EasyEncrypt::MD5::get(char *_data, int* len) {

    std::vector<char> data = EasyEncrypt::Utils::toVector(_data, *len);

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

    *len = 16;

    return final;

}

std::string hash512Encoded(char* data, int* len, EasyEncrypt::encode_t encoding) {

    char* res = EasyEncrypt::SHA::hash512(data, len);

    return (encoding == EasyEncrypt::BASE64) ? Base64::Encode(res) : EasyEncrypt::Utils::toHex(res, 64);

}

std::string EasyEncrypt::SHA::Hex::hash512(std::string data) {

    std::vector<char> data_in = EasyEncrypt::Utils::stringToVector(data);
    int len = data.size();
    return hash512Encoded(data_in.data(), &len, EasyEncrypt::HEX);

}

std::string EasyEncrypt::SHA::Base64::hash512(std::string data) {

    std::vector<char> data_in = EasyEncrypt::Utils::stringToVector(data);
    int len = data.size();
    return hash512Encoded(data_in.data(), &len, EasyEncrypt::BASE64);

}

std::string hash256Encoded(char* data, int* len, EasyEncrypt::encode_t encoding) {

    char* res = EasyEncrypt::SHA::hash256(data, len);

    return (encoding == EasyEncrypt::BASE64) ? Base64::Encode(res) : EasyEncrypt::Utils::toHex(res, 32);

}

std::string EasyEncrypt::SHA::Hex::hash256(std::string data) {

    std::vector<char> data_in = EasyEncrypt::Utils::stringToVector(data);
    int len = data.size();
    return hash256Encoded(data_in.data(), &len, EasyEncrypt::HEX);

}

std::string EasyEncrypt::SHA::Base64::hash256(std::string data) {

    std::vector<char> data_in = EasyEncrypt::Utils::stringToVector(data);
    int len = data.size();
    return hash256Encoded(data_in.data(), &len, EasyEncrypt::BASE64);

}

std::string hmac512Encoded(char* data, int* data_len, char* key, int key_len, EasyEncrypt::encode_t encoding) {

    char* res = EasyEncrypt::SHA::hmac512(data, data_len, key, key_len);

    return (encoding == EasyEncrypt::BASE64) ? Base64::Encode(res) : EasyEncrypt::Utils::toHex(res, 64);

}

std::string EasyEncrypt::SHA::Hex::hmac512(std::string data, std::string key) {

    std::vector<char> data_in = EasyEncrypt::Utils::stringToVector(data);
    std::vector<char> key_in = EasyEncrypt::Utils::stringToVector(key);
    int len = data.size();
    return hmac512Encoded(data_in.data(), &len, key_in.data(), key_in.size(), EasyEncrypt::HEX);

}

std::string EasyEncrypt::SHA::Base64::hmac512(std::string data, std::string key) {

    std::vector<char> data_in = EasyEncrypt::Utils::stringToVector(data);
    std::vector<char> key_in = EasyEncrypt::Utils::stringToVector(key);
    int len = data.size();
    return hmac512Encoded(data_in.data(), &len, key_in.data(), key_in.size(), EasyEncrypt::BASE64);


}

std::string hmac256Encoded(char* data, int* data_len, char* key, int key_len, EasyEncrypt::encode_t encoding) {

    char* res = EasyEncrypt::SHA::hmac256(data, data_len, key, key_len);

    return (encoding == EasyEncrypt::BASE64) ? Base64::Encode(res) : EasyEncrypt::Utils::toHex(res, 32);

}

std::string EasyEncrypt::SHA::Hex::hmac256(std::string data, std::string key) {

    std::vector<char> data_in = EasyEncrypt::Utils::stringToVector(data);
    std::vector<char> key_in = EasyEncrypt::Utils::stringToVector(key);
    int len = data.size();
    return hmac256Encoded(data_in.data(), &len, key_in.data(), key_in.size(), EasyEncrypt::HEX);


}

std::string EasyEncrypt::SHA::Base64::hmac256(std::string data, std::string key) {

    std::vector<char> data_in = EasyEncrypt::Utils::stringToVector(data);
    std::vector<char> key_in = EasyEncrypt::Utils::stringToVector(key);
    int len = data.size();
    return hmac512Encoded(data_in.data(), &len, key_in.data(), key_in.size(), EasyEncrypt::BASE64);


}

std::string getMd5Encoded(std::string data, EasyEncrypt::encode_t encoding) {

    std::vector<char> data_in = EasyEncrypt::Utils::stringToVector(data);
    int len = data_in.size();
    char* res = EasyEncrypt::MD5::get(data_in.data(), &len);

    return (encoding == EasyEncrypt::BASE64) ? Base64::Encode(res) : EasyEncrypt::Utils::toHex(res, 16);

}

std::string EasyEncrypt::MD5::Hex::get(std::string data) {

    return getMd5Encoded(data, EasyEncrypt::HEX);

}

std::string EasyEncrypt::MD5::Base64::get(std::string data) {

    return getMd5Encoded(data, EasyEncrypt::BASE64);

}

std::vector<char> EasyEncrypt::Utils::base64ToVector(std::string source) {

    std::string decoded= Base64::Decode(source);

    return EasyEncrypt::Utils::toVector((char*) decoded.c_str(), decoded.size());

}

std::string EasyEncrypt::Utils::toBase64(char *source, size_t size) {

    std::string input = "";

    for(int i=0; i<size; i++) {
        input += source[i];
    }

    return Base64::Encode(input);

}

std::string EasyEncrypt::Utils::base64ToHex(std::string input) {

    return toHex(
            EasyEncrypt::Utils::base64ToVector(input).data(),
            EasyEncrypt::Utils::base64ToVector(input).size()
    );

}

std::string EasyEncrypt::Utils::hexToBase64(std::string input) {

    std::vector<char> data = hexToVector(input, input.length());

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

EasyEncrypt::PublicKey::KeyPair::KeyPair(int _bits) {

    int ret = 0;

    unsigned int primes = 3;
    unsigned int bits = (unsigned int) _bits;
    OSSL_PARAM params[3];
    EVP_PKEY *r = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);

    EVP_PKEY_keygen_init(pctx);

    params[0] = OSSL_PARAM_construct_uint("bits", &bits);
    params[1] = OSSL_PARAM_construct_uint("primes", &primes);
    params[2] = OSSL_PARAM_construct_end();
    EVP_PKEY_CTX_set_params(pctx, params);

    EVP_PKEY_generate(pctx, &r);
    EVP_PKEY_CTX_free(pctx);

    BIO *bp_pub = NULL;
    BIO *bp_priv = NULL;

    bp_pub = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_PUBKEY(bp_pub, r);
    if (ret != 1) {
        goto free_all;
    }

    bp_priv = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_PKCS8PrivateKey(bp_priv, r, NULL, NULL, 0, NULL, NULL);
    if (ret != 1) {
        goto free_all;
    }

    priv_len = BIO_pending(bp_priv);
    pub_len = BIO_pending(bp_pub);

    priv_key = (char*) malloc(priv_len + 1);
    pub_key = (char*) malloc(pub_len + 1);

    BIO_read(bp_priv, priv_key, priv_len);
    BIO_read(bp_pub, pub_key, pub_len);

    priv_key[priv_len] = '\0';
    pub_key[pub_len] = '\0';

    free_all:

    BIO_free_all(bp_pub);
    BIO_free_all(bp_priv);
    EVP_PKEY_free(r);

}

EasyEncrypt::PublicKey::KeyPair::KeyPair(const char* password, int _bits) {

    int ret = 0;

    unsigned int primes = 3;
    unsigned int bits = (unsigned int) _bits;
    OSSL_PARAM params[3];
    EVP_PKEY *r = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);

    EVP_PKEY_keygen_init(pctx);

    params[0] = OSSL_PARAM_construct_uint("bits", &bits);
    params[1] = OSSL_PARAM_construct_uint("primes", &primes);
    params[2] = OSSL_PARAM_construct_end();
    EVP_PKEY_CTX_set_params(pctx, params);

    EVP_PKEY_generate(pctx, &r);
    EVP_PKEY_CTX_free(pctx);

    BIO *bp_pub = NULL;
    BIO *bp_priv = NULL;

    bp_pub = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_PUBKEY(bp_pub, r);
    if (ret != 1) {
        goto free_all;
    }

    bp_priv = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_PrivateKey(bp_priv, r, EVP_des_ede3_cbc(), NULL, 0, 0, (void *) password);
    if (ret != 1) {
        goto free_all;
    }

    priv_len = BIO_pending(bp_priv);
    pub_len = BIO_pending(bp_pub);

    priv_key = (char*) malloc(priv_len + 1);
    pub_key = (char*) malloc(pub_len + 1);

    BIO_read(bp_priv, priv_key, priv_len);
    BIO_read(bp_pub, pub_key, pub_len);

    priv_key[priv_len] = '\0';
    pub_key[pub_len] = '\0';

    free_all:

    BIO_free_all(bp_pub);
    BIO_free_all(bp_priv);
    EVP_PKEY_free(r);

}

std::string EasyEncrypt::PublicKey::KeyPair::getPublicKey() {

    return pub_key;

}

std::string EasyEncrypt::PublicKey::KeyPair::getPrivateKey() {

    return priv_key;

}

char* EasyEncrypt::PublicKey::encrypt(char* data, int* len, char* pub_key) {

    int ret;
    unsigned char *out;
    char* final;
    size_t outlen;
    size_t inlen = *len;

    EVP_PKEY *key = NULL;
    BIO *bio = NULL;

    bio = BIO_new_mem_buf((unsigned char*) pub_key, strlen(pub_key));
    key = PEM_read_bio_PUBKEY(bio, &key, NULL, NULL);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!ctx) { goto free_all; }
    if (EVP_PKEY_encrypt_init(ctx)<=0) goto free_all;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING)<=0) goto free_all;

    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, (unsigned char*) data, inlen)<=0) goto free_all;

    out = (unsigned char*) OPENSSL_malloc(outlen);
    if(!out) goto free_all;

    if (EVP_PKEY_encrypt(ctx, out, &outlen, (unsigned char*) data, inlen)<=0) goto free_all;

    final = (char*) malloc(outlen);
    memset(final, 0, outlen + 1);
    memcpy(final, out, outlen);
    *len = outlen;

    free_all:

    EVP_PKEY_free(key);
    BIO_free_all(bio);
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(out);

    return final;

}

char* EasyEncrypt::PublicKey::decrypt(char* data, int* len, char* priv_key, const char* password) {

    int ret;
    unsigned char *out;
    char* final;
    size_t outlen;
    size_t inlen = *len;

    EVP_PKEY *key = NULL;
    BIO *bio = NULL;

    bio = BIO_new_mem_buf((unsigned char*) priv_key, strlen(priv_key));
    key = PEM_read_bio_PrivateKey(bio, &key, NULL, (void*) password);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!ctx) { goto free_all; }
    if (EVP_PKEY_decrypt_init(ctx)<=0) goto free_all;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING)<=0) goto free_all;

    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, (unsigned char*) data, inlen)<=0) goto free_all;

    out = (unsigned char*) OPENSSL_malloc(outlen);
    if(!out) goto free_all;

    if (EVP_PKEY_decrypt(ctx, out, &outlen, (unsigned char*) data, inlen)<=0) goto free_all;

    final = (char*) malloc(outlen);
    memset(final, 0, outlen + 1);
    memcpy(final, out, outlen);
    *len = outlen;

    free_all:

    EVP_PKEY_free(key);
    BIO_free_all(bio);
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(out);

    return final;

}

std::string EasyEncrypt::Utils::arrToStr(char* array, size_t len) {

    std::string res = "";

    for(int i=0; i<len; i++) {
        res += array[i];
    }

    return res;

}

std::string EasyEncrypt::PublicKey::Hex::encrypt(std::string data, char *pub_key) {

    std::vector<char> data_in = EasyEncrypt::Utils::stringToVector(data);
    int len = data_in.size();
    char* out = EasyEncrypt::PublicKey::encrypt(data_in.data(), &len, pub_key);
    return std::string(EasyEncrypt::Utils::toHex(out, len));

}

std::string EasyEncrypt::PublicKey::Hex::decrypt(std::string data, char *priv_key, const char* password) {

    std::vector<char> data_in = EasyEncrypt::Utils::fromHex(data);
    int len = data_in.size();
    char* out = EasyEncrypt::PublicKey::decrypt(data_in.data(), &len, priv_key, password);
    return EasyEncrypt::Utils::arrToStr(out, len);

}

std::string EasyEncrypt::PublicKey::Base64::encrypt(std::string data, char *pub_key) {

    std::vector<char> data_in = EasyEncrypt::Utils::stringToVector(data);
    int len = data_in.size();
    char* out = EasyEncrypt::PublicKey::encrypt(data_in.data(), &len, pub_key);
    return std::string(EasyEncrypt::Utils::toBase64(out, len));

}

std::string EasyEncrypt::PublicKey::Base64::decrypt(std::string data, char *priv_key, const char* password) {

    std::vector<char> data_in = EasyEncrypt::Utils::fromBase64(data);
    int len = data_in.size();
    char* out = EasyEncrypt::PublicKey::decrypt(data_in.data(), &len, priv_key, password);
    return EasyEncrypt::Utils::arrToStr(out, len);

}

EasyEncrypt::PublicKey::KeyPair::~KeyPair() {
    free(priv_key);
    free(pub_key);
}
