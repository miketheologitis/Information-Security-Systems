##GENERAL INFO --------------------------------------------------------------------------------------------------------------

AUTHOR: Michail Theologitis (AM: 2017030043)

INFO: gcc (Ubuntu 9.3.0-17ubuntu1~20.04)



##HOW TO RUN MY PROGRAM ------------------------------------------------------------------------------------------------------

1)
(make not necessary because --demoprogram-- is already created, but for good measure, you should do it too)
terminal: make 

2)
terminal: ./demoprogram




##IMPORTAND POINTS ------------------------------------------------------------------------------------------------------------

1)
In the Header File simple_crypto.h (line 1) there is the  #define MAX_INPUT_SIZE 1024  . Please, if you are 
going to give more than MAX_INPUT_SIZE-1 characters in plaintext, adjust the definition accordingly!
Although, if for example you give 1050 (with the current configuration), my program is made to work and not break. 
It will get the 1024-1=1023 characters, it will clear stdin, and will continue encryption with the 1023 characters plaintext.
But this is certainly not something that will match your outputs. So, please adjust MAX_INPUT_SIZE, accordingly.

2)
The .h header file has a description for every function/definition used in the library (and is also copy-pasted after this chapter).
My .c file is filled with useful comments explaining my train of thought in specific key spots and they should be read
while examining my code! 

3)
For all the cryptographic algorithms, the input I get from the user follows the constraints mentioned in the
Assignment 1 pdf. But it was never completely clear to me (I was 99% sure) if I was asked to remove the forbidden characters 
from the plaintext completely (thus not ever showing in the encryption/decryption) or completely removing 
them from the plaintext. Let me show an example for clarity:

------------CASE 1---------------------		        ------------CASE 2---------------------
[Vigenere] input:     AT$TA@CK$AT%DA*WN			[Vigenere] input:     AT$TA@CK$AT%DA*WN
[Vigenere] key:       LEMON			  OR 		[Vigenere] key:       LEMON
[Vigenere] encrypted: LX$FO@PV$EF%RN*HR			[Vigenere] encrypted: LXFOPVEFRNHR
[Vigenere] decrypted: AT$TA@CK$AT%DA*WN			[Vigenere] decrypted: ATTACKATDAWN

For me it was way more logical that "Special characters, such as “!”, “@”, “*”, etc. that are not part of the english
alphabet should be skipped as if the character set only consists of numbers 0-9 followed by
uppercase characters A-Z and lowercase characters a-z" meant CASE 2. And CASE 2 was my implementation. Maybe it
wasn't necessary to write this down in the README.txt but I wanted to mention it in the highly unlikely case that
I misunderstood. Online cryptographic websites that encrypt/decrypt offer BOTH cases with an option. So before I do anything
with encrypting the plaintext I modify it so it has no forbidden characters. For OTP/Caesars algorithm the allowed
characters are 0-9, a-z, A-Z. For Vigenere only A-Z.

4)

Everything works perfectly :)




##Makefile--------------------------------------------------------------------------------------------------------------------

It is the first time I am asked to use Makefile and organize code compilation. The link bellow was my help.
DOC: https://www.cs.colby.edu/maxwell/courses/tutorials/maketutor/

I have defined the constants CC, and CFLAGS that communicate to make how I want to compile the files simple_crypto.c ,
simple_crypto.h. CC is the gcc compiler and CFLAGS is -I (the compilation command). 

We then create the macro DEPS, which is the set of .h files on which the .c files depend (In our case simple_crypto.c depends on simple_crypto.h).
By putting the object file --simple_crypto.o-- in the dependency list and in the rule, make knows it must first compile the .c version
individually, and then build the executable --demoprogram--. We also need to tell make that .c files depend on certain .h files. In our case
simple_crypto.c depends on simple_crypto.h. So we add DEPS = simple_crypto.h.

Then we define a rule that applies to all files ending in the .o suffix.  The rule says that the .o file depends 
upon the .c version of the file and the .h files included in the DEPS macro. The rule then says that to generate the .o file, make needs to compile 
the .c file using the compiler defined in the CC macro. The -c flag says to generate the object file, the -o $@ says to put the output of the 
compilation in the file named on the left side of the :, the $< is the first item in the dependencies list.

(IMPORTAND NOTE: All of the above are written manually from the DOC website. I do not claim this knowledge, but I certainly understand the thinking, 
		  and from the next projects I will try creating my own Makefile)




##FUNCTIONS EXPLAINED ---------------------------------------------------------------------------------------------

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
 *  is the same with shifting (LEN_CAESAR_CYCLE - key) number of positions ahead
    @param ncrypted the message to be dencrypted
    @param key the key that will be used in the dencryption
    @param num_of_char the number of characters to decrypt
    @return the dencrypted string
*/
char* caesar_decrypt(char* encrypted, int key, int num_of_char);




