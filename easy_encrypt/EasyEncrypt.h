//
// Created by ryan on 10/17/21.
//

#ifndef EASYENCRYPT_H
#define EASYENCRYPT_H

class AES;
class SHA;
class MD5;
class Utils;

class EasyEncrypt {

public:

    enum encode_t {
        BASE64,
        HEX,
        ARRAY
    };

    class AES {

    public:

        static char* cbc256(char* data, int* len, char* key, char* iv, bool encrypt);
        static char* ecb256(char* data, int* len, char* key, bool encrypt);
        static char* cbc128(char* data, int* len, char* key, char* iv, bool encrypt);
        static char* ecb128(char* data, int* len, char* key, bool encrypt);

        class Hex {
        public:
            static std::string cbc256(std::string data, std::string hex_key, std::string hex_iv, bool encrypt);
            static std::string ecb256(std::string data, std::string hex_key, bool encrypt);
            static std::string cbc128(std::string data, std::string hex_key, std::string hex_iv, bool encrypt);
            static std::string ecb128(std::string data, std::string hex_key, bool encrypt);
        };

        class Base64 {
        public:
            static std::string cbc256(std::string data, std::string base64_key, std::string base64_iv, bool encrypt);
            static std::string ecb256(std::string data, std::string base64_key, bool encrypt);
            static std::string cbc128(std::string data, std::string base64_key, std::string base64_iv, bool encrypt);
            static std::string ecb128(std::string data, std::string base64_key, bool encrypt);
        };

    };

    class SHA {
    public:
        static char* hmac512(char *data, int* len, char* key, int key_len);
        static char* hmac256(char *data, int* len, char* key, int key_len);
        static char* hash512(char* data, int* len);
        static char* hash256(char* data, int* len);

        class Hex {
        public:
            static std::string hmac512(std::string data, std::string key);
            static std::string hmac256(std::string data, std::string key);
            static std::string hash512(std::string data);
            static std::string hash256(std::string data);
        };

        class Base64 {
        public:
            static std::string hmac512(std::string data, std::string key);
            static std::string hmac256(std::string data, std::string key);
            static std::string hash512(std::string data);
            static std::string hash256(std::string data);
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

        static char* secureRandom(size_t count);
        static char* goodRandom(size_t count);

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
