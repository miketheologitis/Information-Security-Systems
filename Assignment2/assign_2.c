#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#define BLOCK_SIZE 16

//the underlying algorithm is AES, so maximum CMAC length is 16 bytes
//ref: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/CMACVS.pdf
#define CMAC_FIXED_LEN 16

/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t); 
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
void keygen(unsigned char *, unsigned char *, unsigned char *, int);
int encrypt(unsigned char *, int , unsigned char *,
            unsigned char *, unsigned char *, int);
int decrypt(unsigned char *, int , unsigned char *,
            unsigned char *, unsigned char *, int );
void gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char *, int);
int verify_cmac(unsigned char *, unsigned char *);



/* TODO Declare your function prototypes here... */
unsigned char* read_from_file(char* );
int read_bytes_from_file(char* , unsigned char **);
void write_to_file(char* , unsigned char *, size_t , char *);
void read_encrypt_store(char *, char *, unsigned char *, int );
void read_decrypt_store(char* , char* , unsigned char *, int );
void read_encryptwithcmac_store(char *, char *, unsigned char *, int);
int read_validatecmac_store(char* , char* , unsigned char* , int );



/*
 * Prints the hex value of the input
 * 16 values per line
 */
void print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 */
void print_string(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}


/*
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
void usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_2 -i in_file -o out_file -p passwd -b bits" 
	        " [-d | -e | -s | -v]\n"
	    "    assign_1 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -b    bits    Bit mode (128 or 256 only)\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -s            Encrypt+sign input and store results to output\n"
	    " -v            Decrypt+verify input and store results to output\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void check_args(char *input_file, char *output_file, unsigned char *password, 
    int bit_mode, int op_mode)
{
	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256)) {
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}


/*
 * Generates a key using a password
 *
 * PARAMETERS
 * password : the user defined password 
 * key : Malloc'd Key to return modified
 * iv : Initialization vector - Will be NULL 
 * bit_mode : defines the key-size 128 or 256
*/
void keygen(unsigned char *password, unsigned char *key, unsigned char *iv,
    int bit_mode)
{
    /* TODO Task A */

    //Use SHA1 hash function
    const EVP_MD* hash = EVP_sha1();

    const EVP_CIPHER* cipher;

    //the Cipher to derive the key FOR (AES-ECB)
    if(bit_mode == 128){
        cipher = EVP_aes_128_ecb();
    }
    else if(bit_mode == 256){
        cipher = EVP_aes_256_ecb();
    }
    else{
        printf("Please use 128 or 256 bit_mode");
        return;
    }

    //salt should be NULL (and not random) because we want the same password to derive the same key
    EVP_BytesToKey(cipher, hash, NULL, password, strlen((char*)password), 1, key, iv);
}

/*
 * Encrypts the data and returns the number of bytes of the encrypted ciphertext
 *
 * plaintext -> message to encrypt
 * plaintext_len -> how many bytes this message is
 * key -> the (128 or 256 bit) key to be used in encryption
 * iv -> NULL (initialization vector)
 * ciphertext -> our encrypted output
 * bit_mode -> 128 or 256 bit mode 
 * 
 */
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext, int bit_mode)
{

	/* TODO Task B */

    const EVP_CIPHER* cipher;

    //the Cipher to derive the key FOR (AES-ECB)
    if(bit_mode == 128){
        cipher = EVP_aes_128_ecb();
    }
    else if(bit_mode == 256){
        cipher = EVP_aes_256_ecb();
    }
    else{
        printf("Please use 128 or 256 bit_mode");
        return 0;
    }

    //set up the context
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();

    //actual number of bytes written in ciphertext from EVP_EncryptUpdate(), EVP_EncryptFinal_ex
    int bytes_written; 

    //final bytes written in ciphertext, to be returned by this function
    int ciphertext_len;

    //sets up cipher context for encryption with cipher type
    EVP_EncryptInit_ex(context, cipher, NULL, key, iv);

    //encrypts plaintext_len bytes from the plaintext and writes the encrypted version to ciphertext
    //also writes to bytes_written how many bytes were encrypted.
    EVP_EncryptUpdate(context, ciphertext, &bytes_written, plaintext, plaintext_len);
    ciphertext_len = bytes_written; //update ciphertext_len

    //encrypts the "final" data, that is any data that remains in a partial block.
    //The encrypted final data are written to &ciphertext[bytes_written] and onward, 
    //which has sufficient space for one cipher block (see my ciphertext initialization before function call
    EVP_EncryptFinal_ex(context, &ciphertext[bytes_written], &bytes_written);
    ciphertext_len += bytes_written;

    //clears all information from a cipher context and frees up any allocated memory associated with it, 
    //including context itself
    EVP_CIPHER_CTX_free(context);

    return ciphertext_len; //return bytes encrypted
}



/*
 * Decrypts the data and returns the plaintext size
 */
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext, int bit_mode)
{

    /*TODO Task C */

    const EVP_CIPHER* cipher;

    //the Cipher to derive the key FOR (AES-ECB)
    if(bit_mode == 128){
        cipher = EVP_aes_128_ecb();
    }
    else if(bit_mode == 256){
        cipher = EVP_aes_256_ecb();
    }
    else{
        printf("Please use 128 or 256 bit_mode");
        return 0;
    }

    //set up the context
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();

    //actual number of bytes written in plaintext from EVP_DecryptUpdate(), EVP_DecryptFinal_ex
    int bytes_written; 

    //final bytes written in ciphertext, to be returned by this function
    int plaintext_len;

    //sets up cipher context for decryption with cipher type
    EVP_DecryptInit_ex(context, cipher, NULL, key, iv);

    //decrypts ciphertext_len bytes from the ciphertext and writes the decrypted version to plaintext
    //also writes to bytes_written how many bytes were encrypted.
    EVP_DecryptUpdate(context, plaintext, &bytes_written, ciphertext, ciphertext_len);
    plaintext_len = bytes_written;

    //decrypts the "final" data, that is any data that remains in a partial block.
    //The decrypted final data are written to &plaintext[bytes_written] and onward, 
    //which has sufficient space for one cipher block (see my plaintext initialization before function call)
    EVP_DecryptFinal_ex(context, &plaintext[bytes_written], &bytes_written);
    plaintext_len += bytes_written;

    //clears all information from a cipher context and frees up any allocated memory associated with it, 
    //including context itself
    EVP_CIPHER_CTX_free(context);

	return plaintext_len;
}


/*
 * Generates a CMAC
 *
 * returns cmac num of bytes
 */
void gen_cmac(unsigned char *data, size_t data_len, unsigned char *key, 
              unsigned char *cmac, int bit_mode)
{
    /* TODO Task D */

    //key_bytes is number of bytes of the key, to be used in CMAC_Init()
    int key_bytes = bit_mode/8;

    const EVP_CIPHER* cipher;

    //the Cipher (AES-ECB)
    if(bit_mode == 128){
        cipher = EVP_aes_128_ecb();
    }
    else if(bit_mode == 256){
        cipher = EVP_aes_256_ecb();
    }
    else{
        printf("Please use 128 or 256 bit_mode");
        return ;
    }

    //number of bytes of message authentication
    size_t cmac_size;

    //set up the context
    CMAC_CTX *context = CMAC_CTX_new();

    //Calculate and internally store the two subkeys and select the given block cipher 
    //for use by context for subsequently feeding in data with CMAC_Update()
    CMAC_Init(context, key, key_bytes, cipher, NULL);

    //processes data_len bytes of input pointed to by data
    CMAC_Update(context, data, data_len);

    //Store the length of the message authentication code in bytes, 
    //which equals the cipher block size, into cmac_size
    //Eencrypt the last block, padding it if required,
    //and copy the resulting message authentication code to cmac
    CMAC_Final(context, cmac, &cmac_size);

    //calls CMAC_CTX_cleanup(), then frees context itself.
    CMAC_CTX_free(context);
}

/*
 * Verifies a CMAC
 */
int verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{
	/* TODO Task E */
    for(int i=0; i<CMAC_FIXED_LEN; i++){
        if(cmac1[i] != cmac2[i]) return 0;
    }
    return 1;
}


/* 
 * Reads the concatenated ciphertext-cmac from readfile
 * Creats the key from keygen using the password and the bit_mode
 * Gets the ciphertext and the cmac from the concatenated bytes
 * Decrypts the ciphertext and gets the plaintext
 * Creates the cmac from the plaintext
 * Compares the concatenated_cmac, with the created new_cmac
 * Returns 1 (TRUE) if every byte matches, 0 (FALSE) otherwise
 * 
*/
int read_validatecmac_store(char* readfile, char* writefile,
                            unsigned char* password, int bit_mode)
{
    //create the key from password using bit_mode
    unsigned char *key = malloc(bit_mode/8);
    keygen(password, key, NULL, bit_mode);

    //read the concatenated ciphertext and cmac from the file
    unsigned char* concatenated;
    int concatenated_len = read_bytes_from_file(readfile, &concatenated);

    //get the concatenated cmac. The first byte of the cmac starts at 
    //index = cncatenated_len-CMAC_FIXED_LEN of the concatenated byte array
    unsigned char* concatenated_cmac = malloc(CMAC_FIXED_LEN);
    memcpy(concatenated_cmac, &concatenated[concatenated_len-CMAC_FIXED_LEN], CMAC_FIXED_LEN);

    //get the ciphertext_len, and the ciphertext from the concatenated byte array
    int ciphertext_len = concatenated_len-CMAC_FIXED_LEN;
    unsigned char* ciphertext = malloc(ciphertext_len);
    memcpy(ciphertext, concatenated, ciphertext_len);

    //create plaintext to store decrypted ciphertext
    unsigned char* plaintext = malloc(ciphertext_len);

    //decrypt ciphertext and get the plaintext_len which is the number of bytes decrypted and stored in plaintext
    int plaintext_len = decrypt(ciphertext, ciphertext_len, key, NULL, plaintext, bit_mode);

    //create the new cmac derived from the decrypted plaintext from the ciphertext we read above.
    unsigned char* new_cmac = malloc(CMAC_FIXED_LEN);
    gen_cmac(plaintext, plaintext_len, key, new_cmac, bit_mode);

    //1 if verified, 0 if not
    int verified = verify_cmac(concatenated_cmac, new_cmac);
    
    //if verified write plaintext to appropriate file
    if(verified){
        write_to_file(writefile, plaintext, plaintext_len, "w");
    }
    

    free(concatenated);
    free(concatenated_cmac);
    free(ciphertext);
    free(plaintext);
    free(new_cmac);

    return verified;
}

/* TODO Develop your functions here... */


/*
 * Reads (plaintext) from file and returns str  (with '\0')
*/
unsigned char* read_from_file(char* filename)
{
    FILE *file = fopen(filename, "r");

    fseek(file, 0, SEEK_END); // Jump to the end of the file
    int number_of_bytes = ftell(file); // Get the current byte offset in the file
    rewind(file); // Jump back to the beginning of the file

    unsigned char* str = malloc(number_of_bytes+1);

    int i;
    for(i=0; i<number_of_bytes;i++){
        str[i] = fgetc(file);
    }
    str[i] = '\0'; //put EOF

    fclose(file);
    return str;
}

/*
 * Reads bytes from BINARY file and returns number_of_bytes 
 * I use a double pointer because its the only way to "return" the malloc'd output
 * and the number_of_bytes of this output
*/
int read_bytes_from_file(char* filename, unsigned char **buffer)
{
    FILE *file = fopen(filename, "rb");

    long number_of_bytes;

    fseek(file, 0, SEEK_END); // Jump to the end of the file
    number_of_bytes = ftell(file); // Get the current byte offset in the file
    rewind(file); // Jump back to the beginning of the file

    *buffer = malloc(number_of_bytes);

    for(int i=0; i<number_of_bytes; i++){
        (*buffer)[i] = fgetc(file);
    }

    fclose(file);
    return (int)number_of_bytes;
}

//mode either "wb" for binary, "w" for normal plaintext
void write_to_file(char* filename, unsigned char* bytes, size_t bytes_to_write, char *mode)
{
    FILE *file = fopen(filename, mode);

    if(bytes_to_write != fwrite(bytes, sizeof (unsigned char), bytes_to_write, file)){
        printf("Something went very wrong when writing the bytes to the file");
    }

    fclose(file);
    return;
}


/* 
 * Reads plaintext from readfile
 * Creats the key from keygen using the password and the bit_mode
 * Encrypts plaintext using key and the bit_mode 
 * Writes to writefile the encrypted ciphertext
 * 
 * Basically what Task B says
*/
void read_encrypt_store(char* readfile, char* writefile, 
                        unsigned char* password, int bit_mode)
{
    //create the key from password using bit_mode
    unsigned char *key = malloc(bit_mode/8);
    keygen(password, key, NULL, bit_mode);

    /* read from file */
    unsigned char* plaintext = read_from_file(readfile); //with '\0' which obviously we WONT encrypt
    int plaintext_len = strlen((char*)plaintext);

    //the bytes of the encrypted ciphertext is
    //from 0 bytes to (plaintext_len + cipher_block_size) bytes
    unsigned char* ciphertext = malloc(plaintext_len+BLOCK_SIZE);

    //Encrypt and get ciphertext_len which is the number of bytes of the ciphertext
    int ciphertext_len = encrypt(plaintext, plaintext_len, key, NULL, ciphertext, bit_mode);


    /* write to file */
    write_to_file(writefile, ciphertext, ciphertext_len, "wb");

    free(ciphertext);
    free(plaintext);
    free(key);
}


/* 
 * Reads ciphertext from readfile
 * Creats the key from keygen using the password and the bit_mode
 * Decrypts ciphertext using key and the bit_mode 
 * Writes to writefile the decrypted plaintext
 * Returns the number of bytes of the decrypted plaintext
 * 
 * Basically what Task C says
*/
void read_decrypt_store(char* readfile, char* writefile,
                        unsigned char* password, int bit_mode)
{
    //create the key from password using bit_mode
    unsigned char *key = malloc(bit_mode/8);
    keygen(password, key, NULL, bit_mode);

    //read the ciphertext from the file
    unsigned char* ciphertext;
    int ciphertext_len = read_bytes_from_file(readfile, &ciphertext);

    //create plaintext to store decrypted ciphertext
    unsigned char* plaintext = malloc(ciphertext_len);

    //decrypt and get the plaintext_len which is the number of bytes decrypted and stored in plaintext
    int plaintext_len = decrypt(ciphertext, ciphertext_len, key, NULL, plaintext, bit_mode);

    write_to_file(writefile, plaintext, plaintext_len, "w");
    
    free(plaintext);
    free(ciphertext);
    free(key);
}


/* Does what Task D says */
/* 
 * Reads plaintext from readfile
 * Creats the key from keygen using the password and the bit_mode
 * Encrypts plaintext using key and the bit_mode 
 * Creates the cmac from the plaintext
 * Concatenates ciphertext with cmac
 * Stores in writefile the concatenated ciphertext-cmac
 * 
*/
void read_encryptwithcmac_store(char* readfile, char* writefile,
                                unsigned char* password, int bit_mode)
{
    //create the key from password using bit_mode
    unsigned char *key = malloc(bit_mode/8);
    keygen(password, key, NULL, bit_mode);

    /* read from file */
    unsigned char* plaintext = read_from_file(readfile); //with '\0' which obviously we WONT encrypt
    int plaintext_len = strlen((char*)plaintext);

    //the bytes of the encrypted ciphertext is
    //from 0 bytes to (plaintext_len + cipher_block_size) bytes
    unsigned char* ciphertext = malloc(plaintext_len+BLOCK_SIZE);

    //Encrypt and get ciphertext_len which is the number of bytes of the ciphertext
    int ciphertext_len = encrypt(plaintext, plaintext_len, key, NULL, ciphertext, bit_mode);

    //Underlying algorithm is AES so the maximum CMAC length is 16 bytes (definition at the start)
    unsigned char* cmac = malloc(CMAC_FIXED_LEN);

    //generate the cmac
    gen_cmac(plaintext, plaintext_len, key, cmac, bit_mode);

    //printf("CMAC BYTES: %d", cmac_bytes);

    unsigned char* concatenated = malloc(ciphertext_len+CMAC_FIXED_LEN);

    //get ciphertext bytes
    for(int i=0; i<ciphertext_len; i++){
        concatenated[i] = ciphertext[i];
    }

    //get cmac bytes
    for(int i=0; i<CMAC_FIXED_LEN; i++){
        concatenated[ciphertext_len+i] = cmac[i];
    }

    //write to file concatenated bytes
    write_to_file(writefile, concatenated, ciphertext_len+CMAC_FIXED_LEN, "wb");

    free(plaintext);
    free(key);
    free(concatenated);
    free(cmac);
}


/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with 
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */
int main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */

	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;

	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
		switch (opt) {
		case 'b':
			bit_mode = atoi(optarg);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 1 the tool encrypts */
			op_mode = 0;
			break;
		case 's':
			/* if op_mode == 1 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 1 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	}

	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);

	/* TODO Develop the logic of your tool here... */

	/* Initialize the library */

	//I have  "OpenSSL 1.1.1f"  31 Mar 2020 so NO initialization needed,  
	//the library will initialize itself automatically.

	/* Operate on the data according to the mode */

	switch(op_mode)
	{
		/* encrypt */
		case 0:
			/* task B */
    		read_encrypt_store(input_file, output_file, password, bit_mode);
			break;
		/* decrypt */
		case 1: 
			/* task C */
    		read_decrypt_store(input_file, output_file, password, bit_mode);
			break;
		
		/* sign */
		case 2:
			/* Task D */
    		read_encryptwithcmac_store(input_file, output_file, password, bit_mode);
			break;

		/* verify */
		case 3:
			/* TODO Task E */
    		if(read_validatecmac_store(input_file, output_file, password, bit_mode))
			{
				printf("VERIFIED\n");
				break;
			}
    		printf("NOT VERIFIED\n");
			break;

		default:
			printf("op_code is not between 0 and 3");
	}
		
	/* Clean up */
	free(input_file);
	free(output_file);
	free(password);

	/* END */
	return 0;
}
