##GENERAL INFO --------------------------------------------------------------------------------------------------------------

AUTHOR: Michail Theologitis (AM: 2017030043)

INFO: gcc (Ubuntu 9.3.0-17ubuntu1~20.04)

##General ---------------------------------------------------------------------------------------------------------------------

Everything runs perfectly. My functions, and my solutions are very readable, understandable and not overcomplicated.
Almost all the lines that i've written are accompanied with comments explaining exactly what is happening.

Everything that was asked was followed to the last detail.

##TASK F output------------------------------------------------------------------------------------------------------------------

Everything from 1-4 is done, and the .txt files that were asked are inside the zip.

About 4.

the file “hpy414_verifyme_128.txt” with password "hpy414", and bit_mode 128 is NOT verified. <-!!!!!!!!!
It's cmac is: "A6 18 94 13 55 F2 6B D4 77 C0 CF AF C3 B7 CD A1" and the
expected cmac is: "66 4C 57 6F 54 4B DC 7B 8E 10 FC F2 E2 4C BD B5"

the file “hpy414_verifyme_256.txt” with password "hpy414", and bit_mode 256 is NOT verified. <-!!!!!!!!!
It's cmac is: "D9 69 1C A9 38 DE F4 66 D2 91 EC B5 B8 D7 79 A8" and the
expected cmac is: "DC 35 11 2E 76 B5 64 29 25 99 E4 ED 20 B4 9E 2B"

##DOCUMENTATION------------------------------------------------------------------------------------------------------

I know this might be unprofessional but I haven't kept specific links of the documentation used.
To be honest, there wasn't much I needed beyond the https://www.openssl.org/docs (openssl docs), (the github evp.h header file)
https://github.com/openssl/openssl/blob/master/include/openssl/evp.h
, wikipedia and some usual random stackoverflow questions.

Before I started writing code, I studied for some time, the logic behind cryptographic Hash Functions/Message Digest algorithms
and how the work along ciphers for key generation and encryption. After that my basic help doc was openssl along with wiki!
Wiki was of much help. For example:
https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)
https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption?fbclid=IwAR2Ku5m9ogLlCo87VwxMMeH5ZrZLhPrcRDj3xI_gy8AVsCiIWzewBX2pIz0


##FUNCTIONS EXPLANATION------------------------------------------------------------------------------------------------------

TASK A.

/*
 * Generates a key using a password
 * Note: Initialization Vector will not be used. Usually initialization vectors
 *       are used as pseudorandom initial states, which we DONT want because
 *       we want the same password to derive the same key!
 *
 *
 * PARAMETERS
 * password : the user defined password 
 * key : Malloc'd Key to return modified
 * iv : Initialization vector - Will be NULL 
 * bit_mode : defines the key-size 128 or 256
*/
void keygen(unsigned char *password, unsigned char *key, unsigned char *iv, int bit_mode)


TASK B.

/* 
 * Reads plaintext from readfile
 * Creats the key from keygen using the password and the bit_mode
 * Encrypts plaintext using key and the bit_mode 
 * Writes to writefile the encrypted ciphertext
 * 
*/
void read_encrypt_store(char* readfile, char* writefile, unsigned char* password, int bit_mode)



TASK C.

/* 
 * Reads ciphertext from readfile
 * Creats the key from keygen using the password and the bit_mode
 * Decrypts ciphertext using key and the bit_mode 
 * Writes to writefile the decrypted plaintext
 * Returns the number of bytes of the decrypted plaintext
 * 
*/
void read_decrypt_store(char* readfile, char* writefile, unsigned char* password, int bit_mode)



TASK D.

/* 
 * Reads plaintext from readfile
 * Creats the key from keygen using the password and the bit_mode
 * Encrypts plaintext using key and the bit_mode 
 * Creates the cmac from the plaintext
 * Concatenates ciphertext with cmac
 * Stores in writefile the concatenated ciphertext-cmac
 * 
*/
void read_encryptwithcmac_store(char* readfile, char* writefile, unsigned char* password, int bit_mode)



TASK E.
/* 
 * Reads the concatenated ciphertext-cmac from readfile
 * Creats the key from keygen using the password and the bit_mode
 * Gets the ciphertext and the cmac from the concatenated bytes
 * Decrypts the ciphertext and gets the plaintext
 * Creates the cmac from the plaintext
 * Compares the concatenated_cmac, with the created new_cmac
 * Returns 1 (TRUE) if every byte matches, 0 (FALSE) otherwise
*/
int read_validatecmac_store(char* readfile, char* writefile, unsigned char* password, int bit_mode)



/* TASK A keygen() , HELPER FUNCTIONS EXPLANATION */

   int EVP_BytesToKey(const EVP_CIPHER *type, const EVP_MD *md,
                      const unsigned char *salt,
                      const unsigned char *data, int datal, int count,
                      unsigned char *key, unsigned char *iv);
 * type : is the cipher to derive the key and IV for (EVP_aes_128_cbc or EVP_aes_256_cbc)
 * md : is the message digest to use (SHA1)
 * salt : random data for safety (NULL)
 * data : the password to derive the key/iv from
 * count : the iteration count to use for strengthening the keygen (1)



##HELPER FUNCTIONS EXPLANATION (mostly for my own personal use)------------------------------------------------------------------------------------------------------

   EVP_CIPHER_CTX_new() 
 * creates a cipher context
 * 
 * 
   EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *c):
 * clears all information from a cipher context and free up any allocated memory associate with it, 
 * including ctx itself. This function should be called after all operations 
 * using a cipher are complete so sensitive information does not remain in memory.
 * 
 * 
   int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, 
                         ENGINE *impl, const unsigned char *key, const unsigned char *iv);
 * sets up cipher context ctx for encryption with cipher type from ENGINE impl. 
 * ctx must be created before calling this function. type is normally supplied by a function 
 * such as EVP_aes_256_cbc(). If impl is NULL then the default implementation is used. 
 * key is the symmetric key to use and iv is the IV to use (if necessary), 
 * the actual number of bytes used for the key and IV depends on the cipher. 
 * 
 * 
   int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                         int *outl, const unsigned char *in, int inl);
 * encrypts inl bytes from the buffer in and writes the encrypted version to out. 
 * This function can be called multiple times to encrypt successive blocks of data. 
 * The amount of data written depends on the block alignment of the encrypted data. 
 * For most ciphers and modes, the amount of data written can be anything 
 * from zero bytes to (inl + cipher_block_size - 1) bytes. For wrap cipher modes, 
 * the amount of data written can be anything from zero bytes to (inl + cipher_block_size) bytes. 
 * For stream ciphers, the amount of data written can be anything from zero bytes to inl bytes. 
 * Thus, out should contain sufficient room for the operation being performed. 
 * The actual number of bytes written is placed in outl. It also checks if in and out are partially overlapping, 
 * and if they are ! 0 is returned to indicate failure !.
 * 
 * 
   int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
 * If padding is enabled (the default) then EVP_EncryptFinal_ex() encrypts the "final" data, 
 * that is any data that remains in a partial block. It uses standard block padding (aka PKCS padding) 
 * as described in the NOTES section, below. The encrypted final data is written to out 
 * which should have sufficient space for one cipher block. The number of bytes written is placed in outl. 
 * After this function is called the encryption operation is finished and no further calls to EVP_EncryptUpdate() 
 * should be made.
 
 


/* TASK D gen_cmac() , HELPER FUNCTIONS EXPLANATION */

    CMAC_CTX * CMAC_CTX_new() 
 * allocates a new CMAC_CTX object, 
 * initializes the embedded EVP_CIPHER_CTX object, 
 * and marks the object itself as uninitialized.
 * returns the new context object or NULL in case of failure. It succeeds unless memory is exhausted
 * 
 * 
   int CMAC_Init(CMAC_CTX *ctx, const void *key, size_t key_len, const EVP_CIPHER *cipher, ENGINE *impl) 
 * selects the given block cipher for use by ctx. 
 * Unless key is NULL, CMAC_Init() also initializes ctx for use with 
 * the given symmetric key that is key_len bytes long. In particular, 
 * it calculates and internally stores the two subkeys and initializes ctx 
 * for subsequently feeding in data with CMAC_Update(). To use the 
 * default cipher implementations provided by the library, pass NULL as the impl argument.
 * return 1 on success or 0 on failure
 * 
 * 
   int CMAC_Update(CMAC_CTX *ctx, const void *in_data, size_t in_len) 
 * processes in_len bytes of input data pointed to by in_data. 
 * Depending on the number of input bytes already cached in ctx, on in_len, 
 * and on the block size, this may encrypt zero or more blocks. Unless in_len is zero, 
 * this function leaves at least one byte and at most one block of input cached 
 * but unprocessed inside the ctx object. 
 * return 1 on success or 0 on failure
 * 
 * 
   int CMAC_Final(CMAC_CTX *ctx, unsigned char *out_mac, size_t *out_len) 
 * stores the length of the message authentication code in bytes, 
 * which equals the cipher block size, into *out_len. 
 * Unless out_mac is NULL, it encrypts the last block, padding it if required,
 * and copies the resulting message authentication code to out_mac.
 * The caller is responsible for providing a buffer of sufficient size.
 * return 1 on success or 0 on failure
 * 
 * 
   void CMAC_CTX_free(CMAC_CTX *ctx) 
 * calls CMAC_CTX_cleanup(), then frees ctx itself. If ctx is NULL, no action occurs.
 */