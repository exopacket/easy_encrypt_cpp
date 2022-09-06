//
// Created by ryan on 10/17/21.
//

#ifndef EASYENCRYPT_H
#define EASYENCRYPT_H

#include <vector>
#include <string>

class AESData;
class AES;
class SHA;
class MD5;
class Utils;

class EasyEncrypt {

public:

    enum encode_t {
        BASE64,
        HEX,
    };
    enum algorithm_t {
        GCM,
        CBC,
        ECB
    };
    class AESData {
    public:
        encode_t encoding_type;
        algorithm_t algorithm;
        bool do_encrypt;
        bool is_encrypted;
        bool tag_verifies;
        int key_size_bits;
        int iv_size;
        int aad_size = -1;
        std::string key;
        std::string iv;
        std::string encrypted;
        std::string plaintext;
        std::string additional_auth_data;
        std::string tag;

        AESData(algorithm_t algorithm, encode_t encoding, std::string key, std::string iv, bool encrypt);
        AESData(algorithm_t algorithm, encode_t encoding, std::string key, std::string iv, std::string aad, bool encrypt);
        AESData(algorithm_t algorithm, encode_t encoding, std::string key, bool encrypt);

        static AESData* cbc_hex_create(std::string input, std::string key, std::string iv, bool encrypt);
        static AESData* gcm_hex_create(std::string input, std::string key, std::string iv, std::string aad, bool encrypt);
        static AESData* ecb_hex_create(std::string input, std::string key, bool encrypt);

        static AESData* cbc_base64_create(std::string input, std::string key, std::string iv, bool encrypt);
        static AESData* gcm_base64_create(std::string input, std::string key, std::string iv, std::string aad, bool encrypt);
        static AESData* ecb_base64_create(std::string input, std::string key, bool encrypt);

        void set_plaintext(std::string str);

        void set_encrypted_hex_encoded(std::string encrypted);
        void set_encrypted_hex(char* encrypted, size_t len);
        void set_encrypted_base64_encoded(std::string encrypted);
        void set_encrypted_base64(char* encrypted, size_t len);

        void set_key_hex_encoded(std::string key);
        void set_key_hex(char* key, size_t len);
        void set_key_base64_encoded(std::string key);
        void set_key_base64(char* key, size_t len);

        void set_iv_hex_encoded(std::string iv);
        void set_iv_hex(char* iv, size_t len);
        void set_iv_base64_encoded(std::string iv);
        void set_iv_base64(char* iv, size_t len);

        void set_aad_hex_encoded(std::string aad);
        void set_aad_hex(char* aad, size_t len);
        void set_aad_base64_encoded(std::string aad);
        void set_aad_base64(char* aad, size_t len);

        void set_tag_hex_encoded(std::string tag);
        void set_tag_hex(char* tag, size_t len);
        void set_tag_base64_encoded(std::string tag);
        void set_tag_base64(char* tag, size_t len);

    };
    class AES {

    public:

        static char* gcm256(char* data_in, int* data_len, char* aad_in, int aad_size, char* key_in, char* iv_in, int iv_size, char** tag_val, int* verifies, bool encrypt);
        static char* gcm192(char* data_in, int* data_len, char* aad_in, int aad_size, char* key_in, char* iv_in, int iv_size, char** tag_val, int* verifies, bool encrypt);
        static char* gcm128(char* data_in, int* data_len, char* aad_in, int aad_size, char* key_in, char* iv_in, int iv_size, char** tag_val, int* verifies, bool encrypt);
        
        static char* cbc256(char* data, int* len, char* key, char* iv, bool encrypt);
        static char* cbc192(char* data, int* len, char* key, char* iv, bool encrypt);
        static char* cbc128(char* data, int* len, char* key, char* iv, bool encrypt);
        
        static char* ecb256(char* data, int* len, char* key, bool encrypt);
        static char* ecb192(char* data, int* len, char* key, bool encrypt);
        static char* ecb128(char* data, int* len, char* key, bool encrypt);

        class Hex {
        public:
            static AESData gcm(AESData data);

            static AESData cbc(AESData data);
            static std::string cbc256(std::string data, std::string hex_key, std::string hex_iv, bool encrypt);
            static std::string cbc192(std::string data, std::string hex_key, std::string hex_iv, bool encrypt);
            static std::string cbc128(std::string data, std::string hex_key, std::string hex_iv, bool encrypt);
            
            static AESData ecb(AESData data);
            static std::string ecb256(std::string data, std::string hex_key, bool encrypt);
            static std::string ecb192(std::string data, std::string hex_key, bool encrypt);
            static std::string ecb128(std::string data, std::string hex_key, bool encrypt);
        };

        class Base64 {
        public:
            static AESData gcm(AESData data);
            
            static AESData cbc(AESData data);
            static std::string cbc256(std::string data, std::string base64_key, std::string base64_iv, bool encrypt);
            static std::string cbc192(std::string data, std::string base64_key, std::string base64_iv, bool encrypt);
            static std::string cbc128(std::string data, std::string base64_key, std::string base64_iv, bool encrypt);
            
            static AESData ecb(AESData data);
            static std::string ecb256(std::string data, std::string base64_key, bool encrypt);
            static std::string ecb192(std::string data, std::string base64_key, bool encrypt);
            static std::string ecb128(std::string data, std::string base64_key, bool encrypt);
        };

    };
    class SHA {
    public:
        static char* hmac512(char *data, int* len, char* key, int key_len);
        static char* hmac384(char *data, int* len, char* key, int key_len);
        static char* hmac256(char *data, int* len, char* key, int key_len);
        static char* hash512(char* data, int* len);
        static char* hash384(char* data, int* len);
        static char* hash256(char* data, int* len);
        static char* sha1(char* data, int* len);

        class Hex {
        public:
            static std::string hmac512(std::string data, std::string key);
            static std::string hmac384(std::string data, std::string key);
            static std::string hmac256(std::string data, std::string key);
            static std::string hash512(std::string data);
            static std::string hash384(std::string data);
            static std::string hash256(std::string data);
            static std::string sha1(std::string data);
        };

        class Base64 {
        public:
            static std::string hmac512(std::string data, std::string key);
            static std::string hmac384(std::string data, std::string key);
            static std::string hmac256(std::string data, std::string key);
            static std::string hash512(std::string data);
            static std::string hash384(std::string data);
            static std::string hash256(std::string data);
            static std::string sha1(std::string data);
        };

    };
    class MD5 {
    public:
        static char* get(char* data, int* len);

        class Hex {
        public:
            static std::string get(std::string data);
        };

        class Base64 {
        public:
            static std::string get(std::string data);
        };

    };
    class Random {
    public:

        static int getGoodInt(int start, int end, int seed);

        static std::string secureEncoded(EasyEncrypt::encode_t encoding, size_t size);
        static std::string goodEncoded(EasyEncrypt::encode_t, size_t size);

        static char* secureRandom(int count);
        static char* goodRandom(int count);

    };
    class PublicKey {

    public:

        static char* encrypt(char* data, int* len, char* pub_key);
        static char* decrypt(char* data, int* len, char* priv_key, const char* priv_key_pass);

        class Hex {
        public:
            static std::string encrypt(std::string data, char* pub_key);
            static std::string decrypt(std::string data, char* priv_key, const char* priv_key_pass);
        };

        class Base64 {
        public:
            static std::string encrypt(std::string data, char* pub_key);
            static std::string decrypt(std::string data, char* priv_key, const char* priv_key_pass);
        };

        class KeyPair {

        public:
            KeyPair(int bits);
            KeyPair(const char* priv_key_pass, int bits);
            ~KeyPair();
            std::string getPublicKey();
            std::string getPrivateKey();

        private:
            char* priv_key;
            char* pub_key;
            size_t priv_len;
            size_t pub_len;

        };

    };
    class Utils {
    public:

        static std::string arrToStr(char* array, size_t len);

        static std::vector<char> fromHex(std::string source);
        static std::vector<char> fromBase64(std::string source);
        static char* hexToArr(const char* input, int* len);
        static char* base64ToArr(const char* input, int* len);

        //passing NULL to size attempts to calculate size with strlen
        static std::vector<char> toVector(char* source, size_t size);
        static std::vector<char> stringToVector(std::string source);
        static std::vector<char> base64ToVector(std::string source);
        static std::vector<char> hexToVector(std::string source, size_t size);

        static std::string toHex(char* source, size_t size);
        static std::string toBase64(char* source, size_t size);
        static std::string base64ToHex(std::string input);
        static std::string hexToBase64(std::string input);

        static std::string toUpperCase(std::string input);
        static std::string toLowerCase(std::string input);

    };

};

#endif
