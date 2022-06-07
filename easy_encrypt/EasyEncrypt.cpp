//
// Created by ryan on 10/17/21.
//

#include <random>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <openssl/provider.h>
#include "openssl/evp.h"
#include "openssl/aes.h"
#include "openssl/sha.h"
#include "openssl/rand.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "EasyEncrypt.h"
#include "Base64.h"
#include "stdlib.h"

int EasyEncrypt::Random::getGoodInt(int start, int end, int seed) {

    std::mt19937 rng;

    auto now = std::chrono::system_clock::now();
    auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch());

    char* randChar = secureRandom(2);

    int randBite;
    memcpy(&randBite, randChar, 1);
    free(randChar);

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

char* EasyEncrypt::Utils::hexToArr(const char* input, int* len) {

    std::vector<char> res = hexToVector(std::string(input), *len);
    char* out = (char*) malloc(res.size());
    memcpy(out, res.data(), res.size());
    *len = res.size();
    return out;

}

char* EasyEncrypt::Utils::base64ToArr(const char *input, int *len) {

    std::vector<char> res = base64ToVector(std::string(input));
    char* out = (char*) malloc(res.size());
    memcpy(out, res.data(), res.size());
    *len = res.size();
    return out;

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

        returnVal.push_back((char) j);

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

    int i = source.length();

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

EasyEncrypt::AESData EasyEncrypt::AES::Hex::gcm(AESData data) {

    int tag_verifies;
    char* tag_val;

    std::vector<char> data_in = (data.do_encrypt) ?
                                EasyEncrypt::Utils::stringToVector(data.plaintext) :
                                EasyEncrypt::Utils::hexToVector(data.encrypted, data.encrypted.length());

    int data_len = data_in.size();

    char* key = (char*) malloc(data.key_size_bits / 8);
    memcpy(key, EasyEncrypt::Utils::fromHex(data.key).data(), data.key_size_bits / 8);

    char* iv = (char*) malloc(data.iv_size);
    memcpy(iv, EasyEncrypt::Utils::fromHex(data.iv).data(), data.iv_size);

    char* data_arr = (char*) malloc(data_len);
    memcpy(data_arr, data_in.data(), data_in.size());

    if(!data.do_encrypt) {
        std::vector<char> tag_in = EasyEncrypt::Utils::hexToVector(data.tag, data.tag.length());
        tag_val = (char*) malloc(16);
        memcpy(tag_val, tag_in.data(), tag_in.size());
    }

    char* aad = NULL;
    int aad_size = -1;

    if(data.aad_size > 0) {
        aad_size = data.aad_size;
        std::vector<char> aad_in = EasyEncrypt::Utils::hexToVector(data.additional_auth_data, data.additional_auth_data.length());
        aad = (char*) malloc(aad_size);
        memcpy(aad, aad_in.data(), aad_size);
    }

    char* res;
    switch(data.key_size_bits) {
        case 256:
            if(data.do_encrypt)
                res = gcm256(data_arr, &data_len, aad, aad_size, key, iv, data.iv_size, &tag_val, &tag_verifies, true);
            else
                res = gcm256(data_arr, &data_len, aad, aad_size, key, iv, data.iv_size, &tag_val, &tag_verifies, false);
            break;
        case 192:
            if(data.do_encrypt)
                res = gcm192(data_arr, &data_len, aad, aad_size, key, iv, data.iv_size, &tag_val, &tag_verifies, true);
            else
                res = gcm192(data_arr, &data_len, aad, aad_size, key, iv, data.iv_size, &tag_val, &tag_verifies, false);
            break;
        case 128:
            if(data.do_encrypt)
                res = gcm128(data_arr, &data_len, aad, aad_size, key, iv, data.iv_size, &tag_val, &tag_verifies, true);
            else
                res = gcm128(data_arr, &data_len, aad, aad_size, key, iv, data.iv_size, &tag_val, &tag_verifies, false);
            break;
    }

    free(key);
    free(iv);
    free(data_arr);

    if(data.aad_size > 0) {
        free(aad);
    }

    std::string str = (data.do_encrypt) ? EasyEncrypt::Utils::toHex(res, data_len) : std::string(res);

    free(res);

    if(data.do_encrypt)
        data.encrypted = str;
    else
        data.plaintext = str;

    if(!data.do_encrypt) {
        data.tag_verifies = tag_verifies;
    }

    data.encoding_type = EasyEncrypt::HEX;
    data.algorithm = EasyEncrypt::GCM;
    data.do_encrypt = !data.do_encrypt;
    data.is_encrypted = (data.encrypted.empty()) ? false : true;
    data.tag = EasyEncrypt::Utils::toHex(tag_val, 16);

    free(tag_val);

    return data;
}

EasyEncrypt::AESData EasyEncrypt::AES::Base64::gcm(AESData data) {

    int tag_verifies;
    char* tag_val;

    std::vector<char> data_in = (data.do_encrypt) ?
                                EasyEncrypt::Utils::stringToVector(data.plaintext) :
                                EasyEncrypt::Utils::base64ToVector(data.encrypted);

    int data_len = data_in.size();

    char* key = (char*) malloc(data.key_size_bits / 8);
    memcpy(key, EasyEncrypt::Utils::fromBase64(data.key).data(), data.key_size_bits / 8);

    char* iv = (char*) malloc(data.iv_size);
    memcpy(iv, EasyEncrypt::Utils::fromBase64(data.iv).data(), data.iv_size);

    char* data_arr = (char*) malloc(data_len);
    memcpy(data_arr, data_in.data(), data_in.size());

    if(!data.do_encrypt) {
        std::vector<char> tag_in = EasyEncrypt::Utils::base64ToVector(data.tag);
        tag_val = (char*) malloc(16);
        memcpy(tag_val, tag_in.data(), tag_in.size());
    }

    char* aad = NULL;
    int aad_size = -1;

    if(data.aad_size > 0) {
        aad_size = data.aad_size;
        std::vector<char> aad_in = EasyEncrypt::Utils::base64ToVector(data.additional_auth_data);
        aad = (char*) malloc(aad_in.size());
        memcpy(aad, aad_in.data(), aad_in.size());
    }

    char* res;
    switch(data.key_size_bits) {
        case 256:
            if(data.do_encrypt)
                res = gcm256(data_arr, &data_len, aad, aad_size, key, iv, data.iv_size, &tag_val, &tag_verifies, true);
            else
                res = gcm256(data_arr, &data_len, aad, aad_size, key, iv, data.iv_size, &tag_val, &tag_verifies, false);
            break;
        case 192:
            if(data.do_encrypt)
                res = gcm192(data_arr, &data_len, aad, aad_size, key, iv, data.iv_size, &tag_val, &tag_verifies, true);
            else
                res = gcm192(data_arr, &data_len, aad, aad_size, key, iv, data.iv_size, &tag_val, &tag_verifies, false);
            break;
        case 128:
            if(data.do_encrypt)
                res = gcm128(data_arr, &data_len, aad, aad_size, key, iv, data.iv_size, &tag_val, &tag_verifies, true);
            else
                res = gcm128(data_arr, &data_len, aad, aad_size, key, iv, data.iv_size, &tag_val, &tag_verifies, false);
            break;
    }

    free(key);
    free(iv);
    free(data_arr);

    if(data.aad_size > 0) {
        free(aad);
    }

    std::string str = (data.do_encrypt) ? EasyEncrypt::Utils::toBase64(res, data_len) : std::string(res);

    free(res);

    if(data.do_encrypt)
        data.encrypted = str;
    else
        data.plaintext = str;

    data.encoding_type = EasyEncrypt::BASE64;
    data.algorithm = EasyEncrypt::GCM;
    data.do_encrypt = !data.do_encrypt;
    data.is_encrypted = (data.encrypted.empty()) ? false : true;
    data.tag = EasyEncrypt::Utils::toBase64(tag_val, 16);

    free(tag_val);

    if(!data.do_encrypt) {
        data.tag_verifies = tag_verifies;
    }

    return data;

}

EasyEncrypt::AESData EasyEncrypt::AES::Base64::cbc(AESData data) {

    std::vector<char> data_in = (data.do_encrypt) ?
                                EasyEncrypt::Utils::stringToVector(data.plaintext) :
                                EasyEncrypt::Utils::base64ToVector(data.encrypted);

    int data_len = data_in.size();

    char* key = (char*) malloc(data.key_size_bits / 8);
    memcpy(key, EasyEncrypt::Utils::fromBase64(data.key).data(), data.key_size_bits / 8);

    char* iv = (char*) malloc(data.iv_size);
    memcpy(iv, EasyEncrypt::Utils::fromBase64(data.iv).data(), data.iv_size);

    char* data_arr = (char*) malloc(data_len);
    memcpy(data_arr, data_in.data(), data_in.size());

    char* res;
    switch(data.key_size_bits) {
        case 256:
            if(data.do_encrypt)
                res = EasyEncrypt::AES::cbc256(data_arr, &data_len, key, iv, true);
            else
                res = EasyEncrypt::AES::cbc256(data_arr, &data_len, key, iv, false);
            break;
        case 192:
            if(data.do_encrypt)
                res = EasyEncrypt::AES::cbc192(data_arr, &data_len, key, iv, true);
            else
                res = EasyEncrypt::AES::cbc192(data_arr, &data_len, key, iv, false);
            break;
        case 128:
            if(data.do_encrypt)
                res = EasyEncrypt::AES::cbc128(data_arr, &data_len, key, iv, true);
            else
                res = EasyEncrypt::AES::cbc128(data_arr, &data_len, key, iv, false);
            break;
    }

    free(key);
    free(iv);
    free(data_arr);

    std::string str = (data.do_encrypt) ? EasyEncrypt::Utils::toBase64(res, data_len) : std::string(res);

    free(res);

    if(data.do_encrypt)
        data.encrypted = str;
    else
        data.plaintext = str;

    data.encoding_type = EasyEncrypt::BASE64;
    data.algorithm = EasyEncrypt::CBC;
    data.do_encrypt = !data.do_encrypt;
    data.is_encrypted = (data.encrypted.empty()) ? false : true;

    return data;

}

EasyEncrypt::AESData EasyEncrypt::AES::Hex::cbc(AESData data) {

    std::vector<char> data_in = (data.do_encrypt) ?
                                EasyEncrypt::Utils::stringToVector(data.plaintext) :
                                EasyEncrypt::Utils::hexToVector(data.encrypted, data.encrypted.length());

    int data_len = data_in.size();

    char* key = (char*) malloc(32);
    memcpy(key, EasyEncrypt::Utils::fromHex(data.key).data(), 32);

    char* iv = (char*) malloc(data.iv_size);
    memcpy(iv, EasyEncrypt::Utils::fromHex(data.iv).data(), data.iv_size);

    char* data_arr = (char*) malloc(data_len);
    memcpy(data_arr, data_in.data(), data_in.size());

    char* res;
    switch(data.key_size_bits) {
        case 256:
            if(data.do_encrypt)
                res = EasyEncrypt::AES::cbc256(data_arr, &data_len, key, iv, true);
            else
                res = EasyEncrypt::AES::cbc256(data_arr, &data_len, key, iv, false);
            break;
        case 192:
            if(data.do_encrypt)
                res = EasyEncrypt::AES::cbc192(data_arr, &data_len, key, iv, true);
            else
                res = EasyEncrypt::AES::cbc192(data_arr, &data_len, key, iv, false);
            break;
        case 128:
            if(data.do_encrypt)
                res = EasyEncrypt::AES::cbc128(data_arr, &data_len, key, iv, true);
            else
                res = EasyEncrypt::AES::cbc128(data_arr, &data_len, key, iv, false);
            break;
    }

    free(key);
    free(iv);
    free(data_arr);

    std::string str = (data.do_encrypt) ? EasyEncrypt::Utils::toHex(res, data_len) : std::string(res);

    free(res);

    if(data.do_encrypt)
        data.encrypted = str;
    else
        data.plaintext = str;

    data.encoding_type = EasyEncrypt::HEX;
    data.algorithm = EasyEncrypt::CBC;
    data.do_encrypt = !data.do_encrypt;
    data.is_encrypted = (data.encrypted.empty()) ? false : true;

    return data;

}

EasyEncrypt::AESData EasyEncrypt::AES::Base64::ecb(AESData data) {

    std::vector<char> data_in = (data.do_encrypt) ?
                                EasyEncrypt::Utils::stringToVector(data.plaintext) :
                                EasyEncrypt::Utils::base64ToVector(data.encrypted);

    int data_len = data_in.size();

    char* key = (char*) malloc(data.key_size_bits / 8);
    memcpy(key, EasyEncrypt::Utils::fromBase64(data.key).data(), data.key_size_bits / 8);

    char* data_arr = (char*) malloc(data_len);
    memcpy(data_arr, data_in.data(), data_in.size());

    char* res;
    switch(data.key_size_bits) {
        case 256:
            if(data.do_encrypt)
                res = EasyEncrypt::AES::ecb256(data_arr, &data_len, key, true);
            else
                res = EasyEncrypt::AES::ecb256(data_arr, &data_len, key, false);
            break;
        case 192:
            if(data.do_encrypt)
                res = EasyEncrypt::AES::ecb192(data_arr, &data_len, key, true);
            else
                res = EasyEncrypt::AES::ecb192(data_arr, &data_len, key, false);
            break;
        case 128:
            if(data.do_encrypt)
                res = EasyEncrypt::AES::ecb128(data_arr, &data_len, key, true);
            else
                res = EasyEncrypt::AES::ecb128(data_arr, &data_len, key, false);
            break;
    }

    free(key);
    free(data_arr);

    std::string str = (data.do_encrypt) ? EasyEncrypt::Utils::toBase64(res, data_len) : std::string(res);

    free(res);

    if(data.do_encrypt)
        data.encrypted = str;
    else
        data.plaintext = str;

    data.encoding_type = EasyEncrypt::BASE64;
    data.algorithm = EasyEncrypt::ECB;
    data.do_encrypt = !data.do_encrypt;
    data.is_encrypted = (data.encrypted.empty()) ? false : true;

    return data;

}

EasyEncrypt::AESData EasyEncrypt::AES::Hex::ecb(AESData data) {

    std::vector<char> data_in = (data.do_encrypt) ?
                                EasyEncrypt::Utils::stringToVector(data.plaintext) :
                                EasyEncrypt::Utils::hexToVector(data.encrypted, data.encrypted.length());

    int data_len = data_in.size();

    char* key = (char*) malloc(data.key_size_bits / 8);
    memcpy(key, EasyEncrypt::Utils::fromHex(data.key).data(), data.key_size_bits / 8);

    char* data_arr = (char*) malloc(data_len);
    memcpy(data_arr, data_in.data(), data_in.size());

    char* res;
    switch(data.key_size_bits) {
        case 256:
            if(data.do_encrypt)
                res = EasyEncrypt::AES::ecb256(data_arr, &data_len, key, true);
            else
                res = EasyEncrypt::AES::ecb256(data_arr, &data_len, key, false);
            break;
        case 192:
            if(data.do_encrypt)
                res = EasyEncrypt::AES::ecb192(data_arr, &data_len, key, true);
            else
                res = EasyEncrypt::AES::ecb192(data_arr, &data_len, key, false);
            break;
        case 128:
            if(data.do_encrypt)
                res = EasyEncrypt::AES::ecb128(data_arr, &data_len, key, true);
            else
                res = EasyEncrypt::AES::ecb128(data_arr, &data_len, key, false);
            break;
    }

    free(key);
    free(data_arr);

    std::string str = (data.do_encrypt) ? EasyEncrypt::Utils::toHex(res, data_len) : std::string(res);

    free(res);

    if(data.do_encrypt)
        data.encrypted = str;
    else
        data.plaintext = str;

    data.encoding_type = EasyEncrypt::HEX;
    data.algorithm = EasyEncrypt::ECB;
    data.do_encrypt = !data.do_encrypt;
    data.is_encrypted = (data.encrypted.empty()) ? false : true;

    return data;

}

char* EasyEncrypt::AES::gcm256(char* data_in, int* data_len, char* aad_in, int aad_size, char* key_in, char* iv_in, int iv_size, char** tag_val, int* verifies, bool encrypt) {

    bool get_str_size = (*data_len == NULL || *data_len <= 0) && encrypt;

    std::vector<char> data = EasyEncrypt::Utils::toVector(data_in, (get_str_size) ? NULL : *data_len);
    std::vector<char> key = EasyEncrypt::Utils::toVector(key_in, 32);
    std::vector<char> iv = EasyEncrypt::Utils::toVector(iv_in, iv_size);
    std::vector<char> tag;

    if(!encrypt) {
        tag = EasyEncrypt::Utils::toVector(*tag_val, 16);
    }

    size_t data_in_len = data.size();

    unsigned char aes_input[data_in_len];
    unsigned char aes_key[32];

    memset(aes_input, 0x00, data_in_len);
    memset(aes_key, 0x00, 32);

    memcpy(aes_input,  (unsigned char*) data.data(), data_in_len);
    memcpy(aes_key,  (unsigned char*) key.data(), 32);

    unsigned char aes_iv[iv_size];
    memset(aes_iv, 0x00, iv_size);
    memcpy(aes_iv, (unsigned char*) iv.data(), iv_size);

    unsigned char* tag_buff = (unsigned char*) malloc(16);
    memset(tag_buff, 0, 16);

    if(!encrypt) {
        memcpy(tag_buff, (unsigned char*) tag.data(), 16);
    }

    bool has_aad = true;
    unsigned char* aad;

    if(aad_in == NULL || aad_size == NULL) {
        has_aad = false;
    } else if(aad_size > 0) {
        std::vector<char> aad_vector = EasyEncrypt::Utils::toVector(aad_in, aad_size);
        aad = (unsigned char*) malloc(aad_vector.size());
        memset(aad, 0x00, aad_vector.size());
        memcpy(aad, (unsigned char *) aad_vector.data(), aad_vector.size());
    } else {
        has_aad = false;
    }

    if(encrypt) {

        unsigned char res[data_in_len];

        EVP_CIPHER_CTX *ctx;

        int len;
        int ciphertext_len;

        ctx = EVP_CIPHER_CTX_new();

        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_size, NULL);

        EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aes_key, aes_iv);
        if(has_aad)
            EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_size);
        EVP_EncryptUpdate(ctx, res, &len, aes_input, data_in_len);
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, res + len, &len);
        ciphertext_len += len;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, (void*) tag_buff);

        *data_len = ciphertext_len;

        char* final = (char*) malloc(ciphertext_len);
        memcpy(final, res, ciphertext_len);

        *tag_val = (char*) malloc(16);
        memcpy(*tag_val, tag_buff, 16);

        free(tag_buff);
        if(has_aad)
            free(aad);

        EVP_CIPHER_CTX_free(ctx);

        return final;

    } else {

        unsigned char res[data_in_len];
        memset(res, 0, data_in_len);

        EVP_CIPHER_CTX *ctx;

        int len;
        int plaintext_len;

        ctx = EVP_CIPHER_CTX_new();

        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_size, NULL);

        EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aes_key, aes_iv);
        if(has_aad)
            EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_size);
        EVP_DecryptUpdate(ctx, res, &len, aes_input, data_in_len);
        plaintext_len = len;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*) tag_buff);

        int tag_matched = EVP_DecryptFinal_ex(ctx, len + res, &len);
        plaintext_len += len;

        int ptLen = plaintext_len;
        calcSize(res, &ptLen);

        *data_len = ptLen;

        char* final = (char*) malloc(ptLen);
        memset(final, 0, ptLen + 1);
        memcpy(final, res, ptLen);

        free(tag_buff);
        if(has_aad)
            free(aad);

        EVP_CIPHER_CTX_free(ctx);

        *verifies = (tag_matched > 0) ? 1 : 0;

        return final;

    }

}

char* EasyEncrypt::AES::gcm192(char* data_in, int* data_len, char* aad_in, int aad_size, char* key_in, char* iv_in, int iv_size, char** tag_val, int* verifies, bool encrypt) {

    bool get_str_size = (*data_len == NULL || *data_len <= 0) && encrypt;

    std::vector<char> data = EasyEncrypt::Utils::toVector(data_in, (get_str_size) ? NULL : *data_len);
    std::vector<char> key = EasyEncrypt::Utils::toVector(key_in, 24);
    std::vector<char> iv = EasyEncrypt::Utils::toVector(iv_in, iv_size);
    std::vector<char> tag;

    if(!encrypt) {
        tag = EasyEncrypt::Utils::toVector(*tag_val, 16);
    }

    size_t data_in_len = data.size();

    unsigned char aes_input[data_in_len];
    unsigned char aes_key[24];

    memset(aes_input, 0x00, data_in_len);
    memset(aes_key, 0x00, 24);

    memcpy(aes_input,  (unsigned char*) data.data(), data_in_len);
    memcpy(aes_key,  (unsigned char*) key.data(), 24);

    unsigned char aes_iv[iv_size];
    memset(aes_iv, 0x00, iv_size);
    memcpy(aes_iv, (unsigned char*) iv.data(), iv_size);

    unsigned char* tag_buff = (unsigned char*) malloc(16);
    memset(tag_buff, 0, 16);

    if(!encrypt) {
        memcpy(tag_buff, (unsigned char*) tag.data(), 16);
    }

    bool has_aad = true;
    unsigned char* aad;

    if(aad_in == NULL || aad_size == NULL) {
        has_aad = false;
    } else if(aad_size > 0) {
        std::vector<char> aad_vector = EasyEncrypt::Utils::toVector(aad_in, aad_size);
        aad = (unsigned char*) malloc(aad_vector.size());
        memset(aad, 0x00, aad_vector.size());
        memcpy(aad, (unsigned char *) aad_vector.data(), aad_vector.size());
    } else {
        has_aad = false;
    }

    if(encrypt) {

        unsigned char res[data_in_len];

        EVP_CIPHER_CTX *ctx;

        int len;
        int ciphertext_len;

        ctx = EVP_CIPHER_CTX_new();

        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_size, NULL);

        EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

        EVP_EncryptInit_ex(ctx, EVP_aes_192_gcm(), NULL, aes_key, aes_iv);
        if(has_aad)
            EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_size);
        EVP_EncryptUpdate(ctx, res, &len, aes_input, data_in_len);
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, res + len, &len);
        ciphertext_len += len;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, (void*) tag_buff);

        *data_len = ciphertext_len;

        char* final = (char*) malloc(ciphertext_len);
        memcpy(final, res, ciphertext_len);

        *tag_val = (char*) malloc(16);
        memcpy(*tag_val, tag_buff, 16);

        free(tag_buff);
        if(has_aad)
            free(aad);

        EVP_CIPHER_CTX_free(ctx);

        return final;

    } else {

        unsigned char res[data_in_len];
        memset(res, 0, data_in_len);

        EVP_CIPHER_CTX *ctx;

        int len;
        int plaintext_len;

        ctx = EVP_CIPHER_CTX_new();

        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_size, NULL);

        EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

        EVP_DecryptInit_ex(ctx, EVP_aes_192_gcm(), NULL, aes_key, aes_iv);
        if(has_aad)
            EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_size);
        EVP_DecryptUpdate(ctx, res, &len, aes_input, data_in_len);
        plaintext_len = len;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*) tag_buff);

        int tag_matched = EVP_DecryptFinal_ex(ctx, len + res, &len);
        plaintext_len += len;

        int ptLen = plaintext_len;
        calcSize(res, &ptLen);

        *data_len = ptLen;

        char* final = (char*) malloc(ptLen);
        memset(final, 0, ptLen + 1);
        memcpy(final, res, ptLen);

        free(tag_buff);
        if(has_aad)
            free(aad);

        EVP_CIPHER_CTX_free(ctx);

        *verifies = (tag_matched > 0) ? 1 : 0;

        return final;

    }

}

char* EasyEncrypt::AES::gcm128(char* data_in, int* data_len, char* aad_in, int aad_size, char* key_in, char* iv_in, int iv_size, char** tag_val, int* verifies, bool encrypt) {

    bool get_str_size = (*data_len == NULL || *data_len <= 0) && encrypt;

    std::vector<char> data = EasyEncrypt::Utils::toVector(data_in, (get_str_size) ? NULL : *data_len);
    std::vector<char> key = EasyEncrypt::Utils::toVector(key_in, 16);
    std::vector<char> iv = EasyEncrypt::Utils::toVector(iv_in, iv_size);
    std::vector<char> tag;

    if(!encrypt) {
        tag = EasyEncrypt::Utils::toVector(*tag_val, 16);
    }

    size_t data_in_len = data.size();

    unsigned char aes_input[data_in_len];
    unsigned char aes_key[24];

    memset(aes_input, 0x00, data_in_len);
    memset(aes_key, 0x00, 16);

    memcpy(aes_input,  (unsigned char*) data.data(), data_in_len);
    memcpy(aes_key,  (unsigned char*) key.data(), 16);

    unsigned char aes_iv[iv_size];
    memset(aes_iv, 0x00, iv_size);
    memcpy(aes_iv, (unsigned char*) iv.data(), iv_size);

    unsigned char* tag_buff = (unsigned char*) malloc(16);
    memset(tag_buff, 0, 16);

    if(!encrypt) {
        memcpy(tag_buff, (unsigned char*) tag.data(), 16);
    }

    bool has_aad = true;
    unsigned char* aad;

    if(aad_in == NULL || aad_size == NULL) {
        has_aad = false;
    } else if(aad_size > 0) {
        std::vector<char> aad_vector = EasyEncrypt::Utils::toVector(aad_in, aad_size);
        aad = (unsigned char*) malloc(aad_vector.size());
        memset(aad, 0x00, aad_vector.size());
        memcpy(aad, (unsigned char *) aad_vector.data(), aad_vector.size());
    } else {
        has_aad = false;
    }

    if(encrypt) {

        unsigned char res[data_in_len];

        EVP_CIPHER_CTX *ctx;

        int len;
        int ciphertext_len;

        ctx = EVP_CIPHER_CTX_new();

        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_size, NULL);

        EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

        EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, aes_key, aes_iv);
        if(has_aad)
            EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_size);
        EVP_EncryptUpdate(ctx, res, &len, aes_input, data_in_len);
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, res + len, &len);
        ciphertext_len += len;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, (void*) tag_buff);

        *data_len = ciphertext_len;

        char* final = (char*) malloc(ciphertext_len);
        memcpy(final, res, ciphertext_len);

        *tag_val = (char*) malloc(16);
        memcpy(*tag_val, tag_buff, 16);

        free(tag_buff);
        if(has_aad)
            free(aad);

        EVP_CIPHER_CTX_free(ctx);

        return final;

    } else {

        unsigned char res[data_in_len];
        memset(res, 0, data_in_len);

        EVP_CIPHER_CTX *ctx;

        int len;
        int plaintext_len;

        ctx = EVP_CIPHER_CTX_new();

        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_size, NULL);

        EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

        EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, aes_key, aes_iv);
        if(has_aad)
            EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_size);
        EVP_DecryptUpdate(ctx, res, &len, aes_input, data_in_len);
        plaintext_len = len;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*) tag_buff);

        int tag_matched = EVP_DecryptFinal_ex(ctx, len + res, &len);
        plaintext_len += len;

        int ptLen = plaintext_len;
        calcSize(res, &ptLen);

        *data_len = ptLen;

        char* final = (char*) malloc(ptLen);
        memset(final, 0, ptLen + 1);
        memcpy(final, res, ptLen);

        free(tag_buff);
        if(has_aad)
            free(aad);

        EVP_CIPHER_CTX_free(ctx);

        *verifies = (tag_matched > 0) ? 1 : 0;

        return final;

    }

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

char* EasyEncrypt::AES::cbc192(char* data_in, int* data_len, char* key_in, char* iv_in, bool encrypt) {

    bool get_str_size = (*data_len == NULL || *data_len <= 0) && encrypt;

    std::vector<char> data = EasyEncrypt::Utils::toVector(data_in, (get_str_size) ? NULL : *data_len);
    std::vector<char> key = EasyEncrypt::Utils::toVector(key_in, 24);
    std::vector<char> iv = EasyEncrypt::Utils::toVector(iv_in, 16);

    size_t data_in_len = data.size();

    unsigned char aes_input[data_in_len];
    unsigned char aes_key[24];

    memset(aes_input, 0x00, data_in_len);
    memset(aes_key, 0x00, 24);

    memcpy(aes_input,  (unsigned char*) data.data(), data_in_len);
    memcpy(aes_key,  (unsigned char*) key.data(), 24);

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

        EVP_EncryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, aes_key, aes_iv);
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

        EVP_DecryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, aes_key, aes_iv);
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

char* EasyEncrypt::AES::ecb192(char* data_in, int* data_len, char* key_in, bool encrypt) {

    bool get_str_size = (*data_len == NULL || *data_len <= 0) && encrypt;

    std::vector<char> data = EasyEncrypt::Utils::toVector(data_in, get_str_size ? NULL : *data_len);
    std::vector<char> key = EasyEncrypt::Utils::toVector(key_in, 24);

    size_t data_in_len = data.size();

    unsigned char aes_input[data_in_len];
    unsigned char aes_key[24];

    memset(aes_input, 0x00, data_in_len);
    memset(aes_key, 0x00, 24);

    memcpy(aes_input,  (unsigned char*) data.data(), data_in_len);
    memcpy(aes_key,  (unsigned char*) key.data(), 24);

    if(encrypt) {

        unsigned char res[data_in_len];

        EVP_CIPHER_CTX *ctx;

        int len;
        int ciphertext_len;

        ctx = EVP_CIPHER_CTX_new();

        EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

        EVP_EncryptInit_ex(ctx, EVP_aes_192_ecb(), NULL, aes_key, NULL);
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

        EVP_DecryptInit_ex(ctx, EVP_aes_192_ecb(), NULL, aes_key, NULL);
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

std::string cbc192Encoded(char* data_in, char* key_in, char* iv_in, bool encrypt, int* data_len, EasyEncrypt::encode_t encoding) {

    int len = *data_len;

    char* res = EasyEncrypt::AES::cbc192(data_in, &len, key_in, iv_in, encrypt);
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

std::string ecb192Encoded(char* data_in, char* key_in, bool encrypt, int* data_len, EasyEncrypt::encode_t encoding) {

    int len = *data_len;

    char* res = EasyEncrypt::AES::ecb192(data_in, &len, key_in, encrypt);
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

    std::string res = cbc256Encoded(data_arr, key, iv,  encrypt, &len, EasyEncrypt::HEX);

    free(key);
    free(iv);
    free(data_arr);

    return res;

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

    std::string res = cbc256Encoded(data_arr, key, iv,  encrypt, &len, EasyEncrypt::BASE64);

    free(key);
    free(iv);
    free(data_arr);

    return res;

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

    std::string res = cbc128Encoded(data_arr, key, iv,  encrypt, &len, EasyEncrypt::HEX);

    free(key);
    free(iv);
    free(data_arr);

    return res;

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

    std::string res = cbc128Encoded(data_arr, key, iv,  encrypt, &len, EasyEncrypt::BASE64);

    free(key);
    free(iv);
    free(data_arr);

    return res;

}

std::string EasyEncrypt::AES::Hex::cbc192(std::string data_in, std::string key_in, std::string iv_in, bool encrypt) {

    std::vector<char> data = (encrypt) ?
                             EasyEncrypt::Utils::stringToVector(data_in) :
                             EasyEncrypt::Utils::fromHex(data_in);

    int len = data.size();

    char* key = (char*) malloc(24);
    memcpy(key, EasyEncrypt::Utils::fromHex(key_in).data(), 24);

    char* iv = (char*) malloc(16);
    memcpy(iv, EasyEncrypt::Utils::fromHex(iv_in).data(), 16);

    char* data_arr = (char*) malloc(data.size());
    memcpy(data_arr, data.data(), data.size());

    std::string res = cbc192Encoded(data_arr, key, iv,  encrypt, &len, EasyEncrypt::HEX);

    free(key);
    free(iv);
    free(data_arr);

    return res;

}

std::string EasyEncrypt::AES::Base64::cbc192(std::string data_in, std::string key_in, std::string iv_in, bool encrypt) {

    std::vector<char> data = (encrypt) ?
                             EasyEncrypt::Utils::stringToVector(data_in) :
                             EasyEncrypt::Utils::fromBase64(data_in);

    int len = data.size();

    char* key = (char*) malloc(24);
    memcpy(key, EasyEncrypt::Utils::fromBase64(key_in).data(), 24);

    char* iv = (char*) malloc(16);
    memcpy(iv, EasyEncrypt::Utils::fromBase64(iv_in).data(), 16);

    char* data_arr = (char*) malloc(data.size());
    memcpy(data_arr, data.data(), data.size());

    std::string res = cbc192Encoded(data_arr, key, iv,  encrypt, &len, EasyEncrypt::BASE64);

    free(key);
    free(iv);
    free(data_arr);

    return res;

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

    std::string res = ecb256Encoded(data_arr, key,  encrypt, &len, EasyEncrypt::HEX);

    free(key);
    free(data_arr);

    return res;

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

    std::string res = ecb256Encoded(data_arr, key,  encrypt, &len, EasyEncrypt::BASE64);

    free(key);
    free(data_arr);

    return res;
}

std::string EasyEncrypt::AES::Hex::ecb192(std::string data_in, std::string key_in, bool encrypt) {

    std::vector<char> data = (encrypt) ?
                             EasyEncrypt::Utils::stringToVector(data_in) :
                             EasyEncrypt::Utils::fromHex(data_in);

    int len = data.size();

    char* key = (char*) malloc(24);
    memcpy(key, EasyEncrypt::Utils::fromHex(key_in).data(), 24);

    char* data_arr = (char*) malloc(data.size());
    memcpy(data_arr, data.data(), data.size());

    std::string res = ecb192Encoded(data_arr, key,  encrypt, &len, EasyEncrypt::HEX);

    free(key);
    free(data_arr);

    return res;

}

std::string EasyEncrypt::AES::Base64::ecb192(std::string data_in, std::string key_in, bool encrypt) {

    std::vector<char> data = (encrypt) ?
                             EasyEncrypt::Utils::stringToVector(data_in) :
                             EasyEncrypt::Utils::fromBase64(data_in);

    int len = data.size();

    char* key = (char*) malloc(24);
    memcpy(key, EasyEncrypt::Utils::fromBase64(key_in).data(), 24);

    char* data_arr = (char*) malloc(data.size());
    memcpy(data_arr, data.data(), data.size());

    std::string res = ecb192Encoded(data_arr, key,  encrypt, &len, EasyEncrypt::BASE64);

    free(key);
    free(data_arr);

    return res;
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

    std::string res = ecb128Encoded(data_arr, key,  encrypt, &len, EasyEncrypt::HEX);

    free(key);
    free(data_arr);

    return res;

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

    std::string res = ecb128Encoded(data_arr, key,  encrypt, &len, EasyEncrypt::BASE64);

    free(key);
    free(data_arr);

    return res;

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

    free(dataArr);

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

    free(dataArr);

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
    unsigned char arr[data.size()];

    memset(arr, 0, data.size());
    memcpy(arr, data.data(), data.size());

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

    std::string str = (encoding == EasyEncrypt::BASE64) ? Base64::Encode(res) : EasyEncrypt::Utils::toHex(res, 64);

    free(res);

    return str;

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

    std::string str = (encoding == EasyEncrypt::BASE64) ? Base64::Encode(res) : EasyEncrypt::Utils::toHex(res, 32);

    free(res);

    return str;

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

    std::string str =  (encoding == EasyEncrypt::BASE64) ? Base64::Encode(res) : EasyEncrypt::Utils::toHex(res, 64);

    free(res);

    return str;

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

    std::string str = (encoding == EasyEncrypt::BASE64) ? Base64::Encode(res) : EasyEncrypt::Utils::toHex(res, 32);

    free(res);

    return str;

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

    std::string str =(encoding == EasyEncrypt::BASE64) ? Base64::Encode(res) : EasyEncrypt::Utils::toHex(res, 16);

    free(res);

    return str;

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

    free(dataArr);

    return output;

}

char* EasyEncrypt::Random::secureRandom(int count) {

    unsigned char* bytes = (unsigned char*) malloc(count);
    RAND_bytes(bytes, count);
    char* res = (char*) malloc(count);
    memset(res, 0, count);
    memcpy(res, bytes, count);
    free(bytes);

    return res;

}

std::string EasyEncrypt::Random::secureEncoded(EasyEncrypt::encode_t encoding, size_t count) {

    char* res = EasyEncrypt::Random::secureRandom(count);
    std::string str = (encoding == EasyEncrypt::BASE64) ? Base64::Encode(res) : EasyEncrypt::Utils::toHex(res, count);
    free(res);

    return str;

}

char* EasyEncrypt::Random::goodRandom(int count) {

    char* arr = (char*) malloc(count);
    memset(arr, 0, count);

    for(int i=0; i<count; i++) {

        char* s = EasyEncrypt::Random::secureRandom(count);
        int randBite;
        memcpy(&randBite, s + i, 1);
        free(s);

        unsigned char c = (unsigned char) EasyEncrypt::Random::getGoodInt(0, 255, randBite * 2);
        arr[i] = (char) c;

    }

    return arr;

}

std::string EasyEncrypt::Random::goodEncoded(EasyEncrypt::encode_t encoding, size_t count) {

    char* res = EasyEncrypt::Random::goodRandom(count);

    std::string str = (encoding == EasyEncrypt::BASE64) ? Base64::Encode(res) : EasyEncrypt::Utils::toHex(res, count);

    free(res);

    return str;

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
    std::string res = std::string(EasyEncrypt::Utils::toHex(out, len));
    free(out);
    return res;

}

std::string EasyEncrypt::PublicKey::Hex::decrypt(std::string data, char *priv_key, const char* password) {

    std::vector<char> data_in = EasyEncrypt::Utils::fromHex(data);
    int len = data_in.size();
    char* out = EasyEncrypt::PublicKey::decrypt(data_in.data(), &len, priv_key, password);
    std::string res = EasyEncrypt::Utils::arrToStr(out, len);
    free(out);
    return res;

}

std::string EasyEncrypt::PublicKey::Base64::encrypt(std::string data, char *pub_key) {

    std::vector<char> data_in = EasyEncrypt::Utils::stringToVector(data);
    int len = data_in.size();
    char* out = EasyEncrypt::PublicKey::encrypt(data_in.data(), &len, pub_key);
    std::string res = std::string(EasyEncrypt::Utils::toBase64(out, len));
    free(out);
    return res;

}

std::string EasyEncrypt::PublicKey::Base64::decrypt(std::string data, char *priv_key, const char* password) {

    std::vector<char> data_in = EasyEncrypt::Utils::fromBase64(data);
    int len = data_in.size();
    char* out = EasyEncrypt::PublicKey::decrypt(data_in.data(), &len, priv_key, password);
    std::string res = EasyEncrypt::Utils::arrToStr(out, len);;
    free(out);
    return res;

}

EasyEncrypt::PublicKey::KeyPair::~KeyPair() {
    free(priv_key);
    free(pub_key);
}

EasyEncrypt::AESData::AESData(algorithm_t algorithm, encode_t encoding, std::string key, bool encrypt) {

    this->algorithm = algorithm;
    this->encoding_type = encoding;
    this->key = key;

    std::vector<char> key_data = (encoding == HEX) ?
                                 EasyEncrypt::Utils::hexToVector(key, key.length()) :
                                 EasyEncrypt::Utils::base64ToVector(key);

    this->key_size_bits = key_data.size() * 8;
    this->iv_size = 0;
    this->do_encrypt = encrypt;

}

EasyEncrypt::AESData::AESData(algorithm_t algorithm, encode_t encoding, std::string key, std::string iv, bool encrypt) {

    this->algorithm = algorithm;
    this->encoding_type = encoding;
    this->key = key;
    this->iv = iv;

    std::vector<char> key_data = (encoding == HEX) ?
                                 EasyEncrypt::Utils::hexToVector(key, key.length()) :
                                 EasyEncrypt::Utils::base64ToVector(key);

    std::vector<char> iv_data = (encoding == HEX) ?
                                EasyEncrypt::Utils::hexToVector(iv, iv.length()) :
                                EasyEncrypt::Utils::base64ToVector(iv);

    this->key_size_bits = key_data.size() * 8;
    this->iv_size = iv_data.size();
    this->do_encrypt = encrypt;

}

EasyEncrypt::AESData::AESData(algorithm_t algorithm, encode_t encoding, std::string key, std::string iv,
                              std::string aad, bool encrypt) {

    this->algorithm = algorithm;
    this->encoding_type = encoding;
    this->key = key;
    this->iv = iv;
    this->additional_auth_data = aad;

    std::vector<char> key_data = (encoding == HEX) ?
                                 EasyEncrypt::Utils::hexToVector(key, key.length()) :
                                 EasyEncrypt::Utils::base64ToVector(key);

    std::vector<char> iv_data = (encoding == HEX) ?
                                EasyEncrypt::Utils::hexToVector(iv, iv.length()) :
                                EasyEncrypt::Utils::base64ToVector(iv);
    
    std::vector<char> aad_data;
    
    if(!aad.empty()) {

            aad_data = (encoding == HEX) ?
                                     EasyEncrypt::Utils::hexToVector(aad, aad.length()) :
                                     EasyEncrypt::Utils::base64ToVector(aad);

    }

    this->key_size_bits = key_data.size() * 8;
    this->iv_size = iv_data.size();
    this->aad_size = (aad.empty()) ? -1 : aad_data.size();
    this->do_encrypt = encrypt;

}

EasyEncrypt::AESData* EasyEncrypt::AESData::gcm_hex_create(std::string input, std::string key, std::string iv, std::string aad,
                                                           bool encrypt) {

    AESData* obj = new AESData(GCM, HEX, key, iv, aad, encrypt);
    if(encrypt) {
        obj->plaintext = input;
        obj->is_encrypted = false;
    } else {
        obj->encrypted = input;
        obj->is_encrypted = true;
    }

    return obj;

}

EasyEncrypt::AESData* EasyEncrypt::AESData::cbc_hex_create(std::string input, std::string key, std::string iv,
                                                           bool encrypt) {

    AESData* out = new AESData(CBC, HEX, key, iv, encrypt);
    if(encrypt) {
        out->plaintext = input;
        out->is_encrypted = false;
    } else {
        out->encrypted = input;
        out->is_encrypted = true;
    }

    return out;

}

EasyEncrypt::AESData* EasyEncrypt::AESData::ecb_hex_create(std::string input, std::string key,
                                                           bool encrypt) {

    AESData* out = new AESData(CBC, HEX, key, encrypt);
    if(encrypt) {
        out->plaintext = input;
        out->is_encrypted = false;
    } else {
        out->encrypted = input;
        out->is_encrypted = true;
    }

    return out;

}

EasyEncrypt::AESData* EasyEncrypt::AESData::gcm_base64_create(std::string input, std::string key, std::string iv, std::string aad,
                                                              bool encrypt) {

    AESData* out = new AESData(GCM, BASE64, key, iv, aad, encrypt);
    if(encrypt) {
        out->plaintext = input;
        out->is_encrypted = false;
    } else {
        out->encrypted = input;
        out->is_encrypted = true;
    }
    
    return out;

}

EasyEncrypt::AESData* EasyEncrypt::AESData::cbc_base64_create(std::string input, std::string key, std::string iv,
                                                              bool encrypt) {

    AESData* out = new AESData(CBC, BASE64, key, iv, encrypt);
    if(encrypt) {
        out->plaintext = input;
        out->is_encrypted = false;
    } else {
        out->encrypted = input;
        out->is_encrypted = true;
    }

    return out;
    
}

EasyEncrypt::AESData* EasyEncrypt::AESData::ecb_base64_create(std::string input, std::string key,
                                                              bool encrypt) {

    AESData* out = new AESData(ECB, BASE64, key, encrypt);
    if(encrypt) {
        out->plaintext = input;
        out->is_encrypted = false;
    } else {
        out->encrypted = input;
        out->is_encrypted = true;
    }
    
    return out;

}

void EasyEncrypt::AESData::set_plaintext(std::string str) {
    this->plaintext = str;
}

void EasyEncrypt::AESData::set_encrypted_hex_encoded(std::string encrypted) {

    this->encrypted = encrypted;
    this->encoding_type = HEX;

}

void EasyEncrypt::AESData::set_encrypted_base64_encoded(std::string encrypted) {

    this->encrypted = encrypted;
    this->encoding_type = BASE64;

}

void EasyEncrypt::AESData::set_encrypted_hex(char *encrypted, size_t len) {

    set_encrypted_hex_encoded(EasyEncrypt::Utils::toHex(encrypted, len));

}

void EasyEncrypt::AESData::set_encrypted_base64(char *encrypted, size_t len) {

    set_encrypted_base64_encoded(EasyEncrypt::Utils::toBase64(encrypted, len));

}

void EasyEncrypt::AESData::set_key_hex_encoded(std::string key) {

    this->key = key;
    this->encoding_type = HEX;

}

void EasyEncrypt::AESData::set_key_base64_encoded(std::string key) {

    this->key = encrypted;
    this->encoding_type = BASE64;

}

void EasyEncrypt::AESData::set_key_hex(char *key, size_t len) {

    set_key_hex_encoded(EasyEncrypt::Utils::toHex(key, len));

}

void EasyEncrypt::AESData::set_key_base64(char *key, size_t len) {

    set_key_base64_encoded(EasyEncrypt::Utils::toBase64(key, len));

}

void EasyEncrypt::AESData::set_iv_hex_encoded(std::string iv) {

    this->iv = key;
    this->encoding_type = HEX;

}

void EasyEncrypt::AESData::set_iv_base64_encoded(std::string iv) {

    this->iv = encrypted;
    this->encoding_type = BASE64;

}

void EasyEncrypt::AESData::set_iv_hex(char *iv, size_t len) {

    set_iv_hex_encoded(EasyEncrypt::Utils::toHex(iv, len));

}

void EasyEncrypt::AESData::set_iv_base64(char *iv, size_t len) {

    set_iv_base64_encoded(EasyEncrypt::Utils::toBase64(iv, len));

}

void EasyEncrypt::AESData::set_aad_hex_encoded(std::string aad) {

    this->additional_auth_data = aad;
    this->encoding_type = HEX;

}

void EasyEncrypt::AESData::set_aad_base64_encoded(std::string aad) {

    this->additional_auth_data = aad;
    this->encoding_type = BASE64;

}

void EasyEncrypt::AESData::set_aad_hex(char *aad, size_t len) {

    set_aad_hex_encoded(EasyEncrypt::Utils::toHex(aad, len));

}

void EasyEncrypt::AESData::set_aad_base64(char *aad, size_t len) {

    set_aad_base64_encoded(EasyEncrypt::Utils::toBase64(aad, len));

}

void EasyEncrypt::AESData::set_tag_hex_encoded(std::string tag) {

    this->tag = tag;
    this->encoding_type = HEX;

}

void EasyEncrypt::AESData::set_tag_base64_encoded(std::string tag) {

    this->tag = tag;
    this->encoding_type = BASE64;

}

void EasyEncrypt::AESData::set_tag_hex(char *tag, size_t len) {

    set_tag_hex_encoded(EasyEncrypt::Utils::toHex(tag, len));

}

void EasyEncrypt::AESData::set_tag_base64(char *tag, size_t len) {

    set_tag_base64_encoded(EasyEncrypt::Utils::toBase64(tag, len));

}
