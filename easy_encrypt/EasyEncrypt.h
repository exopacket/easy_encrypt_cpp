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
        
        static char* cbc256(char* data, char* key, char* iv, bool encrypt);
        static char* ecb256(char* data, char* key, bool encrypt);
        static char* cbc128(char* data, char* key, char* iv, bool encrypt);
        static char* ecb128(char* data, char* key, bool encrypt);
        
        class Hex {
            static std::string cbc256(char* data, char* key, char* iv, bool encrypt);
            static std::string ecb256(char* data, char* key, bool encrypt);
            static std::string cbc128(char* data, char* key, char* iv, bool encrypt);
            static std::string ecb128(char* data, char* key, bool encrypt);
        };
        
        class Base64 {
            static std::string cbc256(char* data, char* key, char* iv, bool encrypt);
            static std::string ecb256(char* data, char* key, bool encrypt);
            static std::string cbc128(char* data, char* key, char* iv, bool encrypt);
            static std::string ecb128(char* data, char* key, bool encrypt);
        };
    };
    
    class SHA {
    public:
        static char* hmac512(char *data, char* key);
        static char* hmac256(char *data, char* key);
        static char* hash512(char* data);
        static char* hash256(char* data);
        
        class Hex {
            static std::string hmac512(char *data, char* key);
            static std::string hmac256(char *data, char* key);
            static std::string hash512(char* data);
            static std::string hash256(char* data);
        };
        
        class Base64 {
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
            static std::string get(char* data);
        };
        
        class Base64 {
            static std::string get(char* data);
        };
        
    };
    
    class Random {

        static int getGoodInt(int start, int end, int seed);
        
        static void secureRandom(unsigned char* dest, ssize_t count);
        static void goodRandom(unsigned char* dest, ssize_t count);
        
        static std::string secureEncoded(EasyEncrypt::encode_t encoding, ssize_t size);
        static std::string goodEncoded(EasyEncrypt::encode_t, ssize_t size);
        
    };
    
    class Utils {
    public:

        //likely to change..
        
        static void fromHex(const char *source, ssize_t size, char** destination);
        static std::vector<char> hexIn(const char* source, ssize_t size);

        static std::vector<unsigned char> base64ToVector(const char* source);
        static std::vector<unsigned char> hexToVector(const char* source, ssize_t size);
        static std::vector<unsigned char> toVector(char* source, size_t size);

        static std::string toHex(unsigned char* source, ssize_t size);
        static std::string toBase64(unsigned char* source, ssize_t size);
        static std::string base64ToHex(const char* input);
        static std::string hexToBase64(const char* input);

        static std::vector<std::string> explode(const std::string& str, const char& c);
        static int strToInt(std::string val);
        static int sizeOfArr(char* arr);
        static std::string toUpperCase(std::string input);
        static std::string toLowerCase(std::string input);

    };

};

#endif
