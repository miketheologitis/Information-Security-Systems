#define MAX_INPUT_SIZE 1024 //MAX INPUT SIZE FOR THE USER INPUT!!! CHANGE ACCORDINGLY

#define LEN_CAESAR_CYCLE 62 //how many characters ceasar_cycle has

#define LEN_ALPH 26 //alphabet size

#define A_ASCII 65 //decimal ascii value of 'A'

//the character set of the Ceasars Cipher, which consists of 
// characters 0-9 followed by uppercase characters A-Z and lowercase characters a-z,
//in this order, that is found in the ASCII table.
extern const char caesar_cycle[LEN_CAESAR_CYCLE]; 

extern char tabula_recta[LEN_ALPH][LEN_ALPH]; //the tabula recta array

/** 
 * Speaks of itself. 
*/
void print_tabula_recta();

/** 
 * Initializes the tabula_recta char [][] array
*/
void init_tabula_recta();

/** 
 *  Expands keyphrase to match the plaintext
	@param keyphrase the keyword to be repeated until it matches the length of the plaintext
    @param num_of_chars the number of characters of the plaintext
    @return the generated vigenere key
*/
char* vigenere_expanded_key(char* keyphrase, int num_of_chars);

/**
 *  Decrypt Vigenere encrypted key. Decryption is performed by going to the row in the table corresponding to
 *  the key, finding the position of the ciphertext letter in that row and then using the column's label
 *  as the plaintext
	@param encrypted the encrypted string we will decrypt
    @param key the key used in the encryption, used now to decrypt
    @param num_of_chars the number of characters to decrypt
    @return a (malloc'd) decrypted string
*/
char* vigenere_decrypt(char* encrypted, char* key, int num_of_chars);

/**
 *  Encrypt with Vigenere cipher using tabula_recta array
	@param plaintext the message we will encrypt
    @param key the key that will be used in the encryption
    @param num_of_char the number of characters to encrypt
    @return the encrypted string
*/
char* vigenere_encrypt(char* plaintext, char* key, int num_of_chars);

/** 
 *  Handles all the parameters of getting the user input safely back
 *  to the caller. Uses fgets(char *str, int count, FILE *stream) the correct way, safely, clearing
 *  stdin (in the case the user is malicious and gives us a HUGE input). The way
 *  I deal with input bigger than MAX_INPUT_SIZE-1 is that I only get those MAX_INPUT_SIZE-1 bytes
 *  and I ignore the rest. After, I clear the stdin until EOF(very unlikely) or newline like nothing happened 
 *  and the program continues.
 *  IMPORTAND: There are two cases:
 *             First case (flag=0) is OTP/CAESARS cipheres where 0-9, a-z, A-Z characters are allowed
 *             Second case (flag=1) is VIGENERE cipher where A-Z characters are allowed.
 *             Any not allowed characters will not be returned and the later encryption/decryption
 *             will continue without them completely! 
 * 
	@param flag -> 0 OTP/CAESARS ciphers with chars 0-9, a-z, A-Z
                -> 1 VIGENERE cipher with chars A-Z
    @param prompt for user to see before puting input
    @return the malloc'd user input after the above modifications
            with the minimum bytes necessary
*/
char* handle_user_string_input(int flag, char prompt[]);

/** 
 *  Handles all the parameters of getting integer user input safely back
 *  to the caller. I usse fgets(char *str, int count, FILE *stream) the correct way, safely, clearing
 *  stdin (in the case the user is malicious and gives us a HUGE input). The way
 *  I deal with input bigger than MAX_INPUT_SIZE-1 is that I only get those MAX_INPUT_SIZE-1 bytes
 *  and I ignore the rest. After, I clear the stdin until EOF(very unlikely) or newline like nothing happened 
 *  and the program continues.
 *  IMPORTAND: If the user input is malicious and wants to break the program, he can, in this fucntion.
 *             (I trust that leaving some obvious program breaking cases without very thorough
 *             checking of every possibility to be logical for this exercise!)
 *             For example if the user put a number out of the int range, it breaks!
 *             I convert the char array to the int value with strtol()
    @param prompt for user to see before puting input
    @return the user int
*/
int handle_user_integer_input(char* prompt);

/** 
 *  Modifies buffer char array, removing all non 0-9, a-z, A-Z characters. The modified array
 *  will have in the correct index the '\0' char.
    @param buffer char array to be modified
*/
void remove_non_alnum_chars(char *buffer);

/** 
 *  Modifies buffer char array, removing all non 0-9 characters. The modified array
 *  will have in the correct index the '\0' char.
    @param buffer char array to be modified
*/
void remove_non_numeric_chars(char* buffer);

/** 
 *  Modifies buffer char array, removing all non A-Z characters. The modified array
 *  will have in the correct index the '\0' char.
    @param buffer char array to be modified
*/
void remove_non_uppercase_al_chars(char* buffer);

/** 
 *  Produces EXACTLY n random alphanumeric characters from /dev/urandom
 *  From my understanding "the character set only consists of numbers 0-9 followed by
    uppercase characters A-Z and lowercase characters a-z" meant that the key has to 
    follow this aswell (not only the plaintext)
	@param n number of random alphanumeric characters to produce
    @return On success, the character array
            On error, NULL
*/
char* n_random_alnum_chars(int n);


/**
 *  modifies a string and strips it from all the "bad" characters
 *  we only let alphanumeric characters stay in the string
 * 
 *  DOC: //https://stackoverflow.com/questions/5457608/how-to-remove-the-character-at-a-given-index-from-a-string-in-c
 * 
	@param plaintext the string we will modify
*/
void remove_non_alnum_chars(char *plaintext);


/**
 *  Simple decryption character by character
	@param encrypted the encrypted string we will decrypt
    @param key the key used in the encryption, used now to decrypt
    @param num_of_chars the number of characters to decrypt
    @return a (malloced) decrypted string
*/
char* otp_decrypt(char* encrypted, char* key, int num_of_chars);


/**
 *  Encrypt with One-time pad algorithm characters XORing each character of plaintext and key,
 *  but also checking whether the XORed character is printable.
 *  Meaning characters like '\0', '\n', '\t' and many other
 *  ASCII chars are NOT printable and I modify the specific character
 *  of the key (get another one randomely from \dev\urandom, again and again if necessary) 
 *  to dodge this problem
	@param plaintext the message we will encrypt
    @param key the key that will be used in the encryption
    @param num_of_char the number of characters to encrypt
    @return the encrypted string
*/
char* otp_encrypt(char* plaintext, char* key, int num_of_chars);

/**
 *  Finds the character that will replace the char c.
 *  It basically finds the character at shift positions AHEAD (in a cycle), in the
 *  character array caesar_cycle
 *  It is used in encryption and decryption!
 *  Note: Notice that for encryption, shift = (key % LEN_CAESAR_CYCLE)
 *                    for decryption, shift = LEN_CAESAR_CYCLE - (key % LEN_CAESAR_CYCLE)
 * 
 *  For encryption we need to go (key % LEN_CAESAR_CYCLE) positions ahead (in a cycle)
 * 
 *  For decryption we need to go (key % LEN_CAESAR_CYCLE) positions back, which means
 *  LEN_CAESAR_CYCLE - (key % LEN_CAESAR_CYCLE) ahead (in a cycle) !
 * 
	@param c the character to be encrypted
    @param key the key that will be used in the encryption
    @return the encrypted char
*/
char caesar_shifted_char(char c, int shift);

/**
 *  Simple encryption (Caesar's cipher) character by character of the plaintext.
 *  First thing we do is key = key % LEN_CAESAR_CYCLE or obvious reasons!
 *  We encrypt shifting by (key) number of positions down the alphabet/ASCII set
 *  Uses the caesar_shifted_char that is explained above
 *  Note: character set : Only alphanumeric characters
	@param plaintext the message to be encrypted
    @param key the key that will be used in the encryption
    @param num_of_char the number of characters to encrypt
    @return the encrypted string
*/
char* caesar_encrypt(char* plaintext, int key, int num_of_char);

/**
 *  Simple dencryption (Caesar's cipher) character by character of the plaintext.
 *  First thing we do is key = key % LEN_CAESAR_CYCLE or obvious reasons!
 *  We decrypt shifting by (LEN_CAESAR_CYCLE - key) number of positions down the alphabet/ASCII set
 *  Uses the caesar_shifted_char that is explained above in the manner explained.
 *  Note: as explained in caesar_shifted_char, shifting (key) number of positions back, 
 *        is the same with shifting (LEN_CAESAR_CYCLE - key) number of positions ahead
	@param ncrypted the message to be dencrypted
    @param key the key that will be used in the dencryption
    @param num_of_char the number of characters to decrypt
    @return the dencrypted string
*/
char* caesar_decrypt(char* encrypted, int key, int num_of_char);