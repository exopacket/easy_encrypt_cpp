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

    class AES {
    public:
        static std::string cbc256(char* data, ssize_t data_len, char* key, char* iv, bool encrypt);
        static std::string ecb256(char* data, ssize_t data_len, char* key, bool encrypt);
        static std::string cbc128(char* data, ssize_t data_len, char* key, char* iv, bool encrypt);
        static std::string ecb128(char* data, ssize_t data_len, char* key, bool encrypt);
        
    };
    class SHA {
    public:
        static std::string hmac512(char *data, ssize_t data_len, char* key, ssize_t key_len);
        static std::string hmac256(char *data, ssize_t data_len, char* key, ssize_t key_len);
        static std::string hash512(char* data, ssize_t data_len);
        static std::string hash256(char* data, ssize_t data_len);
    };
    class MD5 {
    public:
        static std::string get(char* data);
    };
    class Utils {
    public:

        static void fromHex(const char *source, ssize_t size, char** destination);
        static void fromBase64(const char *source, ssize_t size, char* destination);

        static std::vector<unsigned char> base64ToVector(const char* source);
        static std::vector<unsigned char> hexToVector(const char* source, ssize_t size);
        static std::vector<unsigned char> toVector(char* source, size_t size);

        static void secureRandom(unsigned char* dest, ssize_t count);
        static int goodRandom(int start, int end, int seed);

        static std::string toHex(unsigned char* source, ssize_t size);
        static std::string toBase64(unsigned char* source, ssize_t size);
        static std::string base64ToHex(const char* input);
        static std::string hexToBase64(const char* input);

        static std::vector<std::string> explode(const std::string& str, const char& c);
        static int strToInt(std::string val);
        static std::string toUpperCase(std::string input);
        static std::string toLowerCase(std::string input);

    };

};

#endif
