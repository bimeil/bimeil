//Will terminate if there is an error
void secure_rng(void*bytes, int length);
WARN u32 secure_rng_u32();

//Returns 0 on success, negative value on error.
WARN int pbkdf2(u8*pass_, int passlen, u8*salt_, size_t salt_len, int rounds, u8*buf, size_t buf_len);
WARN int pbkdf2(const char*pass_, const u8*salt_, size_t salt_len, int rounds, void*buf, size_t buf_len);

enum Cipher{ AES, Camellia, TripleDES, Cipher_End };

//libnss3 forces me to use key and iv without const
//return length or if negative an error code
WARN int encrypt(const void*i, void*o, u8*key128, u8*iv128, int length, Cipher cipher);
WARN int decrypt(const void*i, void*o, u8*key128, u8*iv128, int length, Cipher cipher);
WARN int   crypt(const void*i, void*o, u8*key128, u8*iv128, int length, Cipher cipher, bool encrypt);
//return 0 on success
WARN int sha224(const void*data, int length, u8*sha224_result);
WARN int sha256(const void*data, int length, u8*sha256_result);
