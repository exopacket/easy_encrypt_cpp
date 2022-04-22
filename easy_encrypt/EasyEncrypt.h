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
    };

    class AES {

    public:

        static char* cbc256(char* data, char* key, char* iv, bool encrypt, int* len);
        static char* ecb256(char* data, char* key, bool encrypt, int* len);
        static char* cbc128(char* data, char* key, char* iv, bool encrypt, int* len);
        static char* ecb128(char* data, char* key, bool encrypt, int* len);

        class Hex {
        public:
            static std::string cbc256(char* data, std::string hex_key, std::string hex_iv, bool encrypt);
            static std::string ecb256(char* data, std::string hex_key, bool encrypt);
            static std::string cbc128(char* data, std::string hex_key, std::string hex_iv, bool encrypt);
            static std::string ecb128(char* data, std::string hex_key, bool encrypt);
        };

        class Base64 {
        public:
            static std::string cbc256(char* data, std::string hex_key, std::string hex_iv, bool encrypt);
            static std::string ecb256(char* data, std::string hex_key, bool encrypt);
            static std::string cbc128(char* data, std::string hex_key, std::string hex_iv, bool encrypt);
            static std::string ecb128(char* data, std::string hex_key, bool encrypt);
        };

    };

    class SHA {
    public:
        static char* hmac512(char *data, char* key);
        static char* hmac256(char *data, char* key);
        static char* hash512(char* data);
        static char* hash256(char* data);

        class Hex {
        public:
            static std::string hmac512(char *data, char* key);
            static std::string hmac256(char *data, char* key);
            static std::string hash512(char* data);
            static std::string hash256(char* data);
        };

        class Base64 {
        public:
            static std::string hmac512(char *data, char* key);
            static std::string hmac256(char *data, char* key);
            static std::string hash512(char* data);
            static std::string hash256(char* data);
        };

    };
    class MD5 {
    public:
        static char* get(char* data);

        class Hex {
        public:
            static std::string get(char* data);
        };

        class Base64 {
        public:
            static std::string get(char* data);
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
    class Utils {
    public:

        static char* fromHex(const char *source);
        static char* fromBase64(const char *source);

        //passing NULL to size attempts to calculate size with strlen
        static std::vector<char> toVector(char* source, size_t size);
        static std::vector<char> base64ToVector(const char* source);
        static std::vector<unsigned char> hexToVector(const char* source, size_t size);

        static std::string toHex(char* source, size_t size);
        static std::string toBase64(char* source, size_t size);
        static std::string base64ToHex(const char* input);
        static std::string hexToBase64(const char* input);

        static std::string toUpperCase(std::string input);
        static std::string toLowerCase(std::string input);

    };

};

#endif
