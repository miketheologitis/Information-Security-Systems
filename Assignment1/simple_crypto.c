#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include "simple_crypto.h"

const char caesar_cycle[LEN_CAESAR_CYCLE] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

const char alphabet[LEN_ALPH] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; //!

char tabula_recta[LEN_ALPH][LEN_ALPH]; 


//I will create the tabula recta based on rows, and its' alphabet shifts.
//i is the number for how many positions to the RIGHT of alphabet[j] is our ACTUAL character tabula_recta[i][j] 
void init_tabula_recta(){ 
    for(int i=0; i<LEN_ALPH; i++){ //i is row, 
        for(int j=0; j<LEN_ALPH; j++){ //j is column
            if(j+i < LEN_ALPH){ //this means we are in the bounds of alphabet array, so alphabet[j+i] is our char
                tabula_recta[i][j] = alphabet[j+i];
            }
            // (LEN-j) is how many more characters to the RIGHT we have to the end of the alphabet array from our j char. 
            // and i is how many chars to the RIGHT from alphabet[j] our shiftet char is
            // and since j+i is out of bounds, our char is at index alphabet[i - (LEN_ALPH-j)] !!!
            else{ 
                tabula_recta[i][j] = alphabet[i-(LEN_ALPH-j)];
            }
        }
    }
}

void print_tabula_recta(){
    for(int i=0; i<LEN_ALPH; i++){ //i is row
        for(int j=0; j<LEN_ALPH; j++){ //j is column
            printf("%c ", tabula_recta[i][j]);
        }
        printf("\n");
    }
}

//Expand keyphrase to match the plaintext
char* vigenere_expanded_key(char* keyphrase, int num_of_chars){
    //with strlen(keyphrase) i am very careful,
    //i know that keyphrase will have been already parsed by my handle_user_string_input()
    //function and it will CERTAINLY have '\0' char at the end of its' chars!
    int size = strlen(keyphrase);

    char* key = malloc(num_of_chars+1); //+1 for '\0' so i can print it and also feel safe
    int index = 0;

    for(int i=0; i<num_of_chars; i++){
        key[i] = keyphrase[index];
        if(index<size-1){ //reset index
            index++;
        }
        else{
            index = 0;
        }
    }
    key[num_of_chars] = '\0'; //'\0' so i can print it and also feel safe

    return key;
}

//Note: in C a character alone is also the decimal ASCII number
//      and can be used without an (int) cast!
char* vigenere_encrypt(char* plaintext, char* key, int num_of_chars){
    char* encrypted = malloc(num_of_chars+1); //+1 for '\0' so i can print it and also be safe 

    for(int i=0; i<num_of_chars; i++){
        encrypted[i] = tabula_recta[key[i]-A_ASCII][plaintext[i]-A_ASCII];
    }

    encrypted[num_of_chars] = '\0';

    return encrypted;
}

char* vigenere_decrypt(char* encrypted, char* key, int num_of_chars){
    char* decrypted = malloc(num_of_chars+1); //+1 for '\0' so i can print it and also be safe 

    for(int i=0; i<num_of_chars; i++){ //for each char of encrypted/key
        for(int j=0; j<LEN_ALPH; j++){ //for each column of tabula_recta
            //if in the row that is specified by our character at index i of the key
            //we find the encrypted character encrypted[i] at column j, then 
            //our decrypted character is alphabet[j], and we break!
            if(tabula_recta[key[i]-A_ASCII][j] == encrypted[i]){
                decrypted[i] = alphabet[j];
                break;
            }
        }
    }

    decrypted[num_of_chars] = '\0'; // '\0' so i can print it

    return decrypted;
}


char* n_random_alnum_chars(int n){
    int randomData = open("/dev/urandom", O_RDONLY);
    if (randomData < 0){
        return NULL;// something went wrong
    }
    else{
        char* myRandomData = malloc(n+1); //+1 for '\0' so i can print it and also be safe
        char myRandomChar;
        int count = 0;

        while(count < n){ //i want exactly n bytes
            if(read(randomData, &myRandomChar, 1) >= 0){ //means all good
                if(isalnum(myRandomChar)){ //myRandomChar is alphanumeric
                    myRandomData[count] = myRandomChar;
                    count++;
                }
            }
        }

        myRandomData[n] = '\0'; //I put this because I want to print it afterwards 
        
        return myRandomData;
    }
}

//find the character c, shift positions ahead in the alphanumeric ascii character set
char caesar_shifted_char(char c, int shift){
    int char_index;
    for(int i=0; i<LEN_CAESAR_CYCLE; i++){
        if(caesar_cycle[i] == c){
            char_index = i;
            break;
        }
    }
    
    if(shift < LEN_CAESAR_CYCLE-char_index){ //means our shifted char is ahead of us
        return caesar_cycle[char_index+shift];
    }
    else{ //means our shifted char behind us, so find its' index like this
        return caesar_cycle[shift-(LEN_CAESAR_CYCLE-char_index)];
    }
}

char* caesar_encrypt(char* plaintext, int key, int num_of_chars){
    key = key % LEN_CAESAR_CYCLE; //mod 

    char* encrypted = malloc(num_of_chars+1); //+1 for '\0' so i can print it and also be safe

    for(int i=0; i<num_of_chars; i++){
        encrypted[i] = caesar_shifted_char(plaintext[i], key);
    }

    encrypted[num_of_chars] = '\0'; //put '\0' at the end so we can print it like a string

    return encrypted;
}

//me to key, to plaintext pige brosta (key) theseis kuklika,
//ara gia na epanaxrisimopoihsoume tin caesar_shifted_char
//kai na kanoume decrypt, anti na pame (key) theseis pisw
//tha pame (LEN_CAESAR_CYCLE - key) theseis brosta ksana
char* caesar_decrypt(char* encrypted, int key, int num_of_chars){
    key = key % LEN_CAESAR_CYCLE; //mod 

    char* decrypted = malloc(num_of_chars+1); //+1 for '\0' so i can print it and also be safe

    for(int i=0; i<num_of_chars; i++){
        decrypted[i] = caesar_shifted_char(encrypted[i], LEN_CAESAR_CYCLE-key);
    }

    decrypted[num_of_chars] = '\0';//put '\0' at the end so we can print it like a string
    
    return decrypted;
}

char* otp_encrypt(char* plaintext, char* key, int num_of_chars){
    char* encrypted = malloc(num_of_chars+1); //+1 for '\0' so i can print it and also be safe
    
    //we will skip non alphanumeric chars in plaintext like they dont exist
    for(int i=0; i<num_of_chars; i++){
        if(isalnum(plaintext[i])){ //if alphanumeric, else skip it
            if(isprint(plaintext[i]^key[i])){  //if the encrypted char is printable
                encrypted[i] = plaintext[i]^key[i];
            }
            //else we will swap this key[i] char with another randomely,
            //until the encrypted char is printable
            else{ 
                char tmp_char = n_random_alnum_chars(1)[0];
                while(!isprint(plaintext[i]^tmp_char)){ //continue till you find one
                    tmp_char = n_random_alnum_chars(1)[0];
                }
                key[i] = tmp_char; //modify the key
                encrypted[i] = plaintext[i]^key[i];
            }
        }
    }
    encrypted[num_of_chars] = '\0'; //put \0 at the end so we can print it like a string
    return encrypted;
}

char* otp_decrypt(char* encrypted, char* key, int num_of_chars){
    char* decrypted = malloc(num_of_chars+1); //+1 for '\0' so i can print it and also be safe

    for(int i=0; i<num_of_chars; i++){
        decrypted[i] = encrypted[i]^key[i];
    }
    decrypted[num_of_chars] = '\0'; //pit '\0' so we can print it like a string

    return decrypted;
}

//remove all the non alphanumeric characters from the plaintext 
//as if they dont exist!
void remove_non_alnum_chars(char *buffer) {
    char *src, *dst;
    for (src = dst = buffer; *src != '\0'; src++) {
        *dst = *src;

        //if this char is 0-9, a-z, A-Z, alnum, then dst will move forward in memory, 
        //else dst will wait there to be replaced by the next acceptable char
        if (isalnum(*dst)) dst++;
    }
    *dst = '\0'; //either replace last non alnum char, or place '0' in the right position
}

void remove_non_uppercase_al_chars(char* buffer){
    char *src, *dst;
    for (src = dst = buffer; *src != '\0'; src++) {
        *dst = *src;

        //if this char A-Z then dst will move forward in memory, 
        //else dst will wait there to be replaced by the next acceptable char
        if (isalnum(*dst)!=0 && isalpha(*dst)!=0 && isupper(*dst)!=0) dst++; 
    }
    *dst = '\0'; //either replace last non alnum char, or place '0' in the right position
}

void remove_non_numeric_chars(char* buffer){
    char *src, *dst;
    for (src = dst = buffer; *src != '\0'; src++) {
        *dst = *src;

        //if this char 0-9 then dst will move forward in memory, 
        //else dst will wait there to be replaced by the next acceptable char
        if (isdigit(*dst)) dst++; 
    }
    *dst = '\0'; //either replace last non alnum char, or place '0' in the right position
}

//will give back a "string" meaning I will also put the \0 char at the end
//flag is for extra input modifications 
//flag -> 0 OTP/CAESARS ciphers with chars 0-9, a-z, A-Z
//flat -> 1 VIGENERE cipher with chars A-Z
char* handle_user_string_input(int flag, char prompt[]){
    char buffer[MAX_INPUT_SIZE];
    int num_of_chars_in_buffer;

    fflush(stdout);
    printf("%s", prompt);

    //About fgets(char *str, int count, FILE *stream);
    //Reads at most count - 1 characters from the given file stream and stores them in the character array pointed to by str.
    //Parsing stops if a newline character is found, in which case str will contain that newline character, or if end-of-file occurs.
    //If bytes are read and no errors occur, writes a null character at the position immediately after the last character written to str.
    fgets(buffer, MAX_INPUT_SIZE, stdin);

    
    //If there doesnt exist a newline in our buffer means that we read MAX_INPUT_SIZE-1 characters
    //which is the fgets limit (or we read some weird EOF which is highly unlikely...)
    //IN ANY CASE, a newline character or MANY more characters along with a newline are still in stdin 
    //and are waiting to cause trouble, so we have to deal with it :)
    if(strchr(buffer, '\n') == NULL) { 
        char c;
        while((c = getchar()) != '\n' && c != EOF){ };
    }

    if(flag){ //remove all non A-Z chars
        remove_non_uppercase_al_chars(buffer);
    }
    else{ //remove all non 0-9, a-z, A-Z chars
        remove_non_alnum_chars(buffer); 
    }

    //I am careful with strlen here, I know that fgets ALWAYS puts '\0' at the end (see doc)
    num_of_chars_in_buffer = strlen(buffer); 

    char* key = malloc(num_of_chars_in_buffer+1); //+1 for the \0 char

    //put our final characters of the key to the appropriate sized key and return it
    for(int i=0; i<num_of_chars_in_buffer+1; i++){ //+1 for \0
        key[i] = buffer[i];
    }
    key[num_of_chars_in_buffer] = '\0'; //I want '\0' so i print it after 
    return key;
}

int handle_user_integer_input(char* prompt){
    char buffer[MAX_INPUT_SIZE];
    char *eptr; //for strtol to convert "string" to int

    printf("%s", prompt);
    fgets(buffer, MAX_INPUT_SIZE, stdin);

    //If there doesnt exist a newline in our buffer means that we read MAX_INPUT_SIZE-1 characters
    //which is the fgets limit (or we read some weird EOF which is highly unlikely...)
    //IN ANY CASE, a newline character or MANY more characters along with a newline are still in stdin 
    //and are waiting to cause trouble, so we have to deal with it :)
    if(strchr(buffer, '\n') == NULL) { 
        char c;
        while((c = getchar()) != '\n' && c != EOF){ };
    }

    remove_non_numeric_chars(buffer);

    return strtol(buffer, &eptr, 10); 
}

int main(void){
    
    char* plaintext;
    char* key; //for OTP/VIGENERE
    char* encrypted;
    char* decrypted;
    int key_int; //for CAESARS

    //number of characters to be encrypted/decrypted
    //after modifying the input ofcourse (incase there were chars not allowed)
    int num_of_chars;

    
    //FOR OTP-------------------------------------------------------------------------------------------------
    plaintext = handle_user_string_input(0, "[OTP] input: "); //flag 0 because we are in OTP algo
    //printf("FEOF: %d", feof(stdin));
    num_of_chars = strlen(plaintext); 
    key = n_random_alnum_chars(num_of_chars);

    encrypted = otp_encrypt(plaintext, key, num_of_chars);
    decrypted = otp_decrypt(encrypted, key, num_of_chars);
    printf("[OTP] encrypted: %s\n", encrypted);
    printf("[OTP] decrypted: %s\n", decrypted);
    free(key);
    free(encrypted);
    free(decrypted);
    //FOR OTP-------------------------------------------------------------------------------------------------
    


    //FOR CAESARS---------------------------------------------------------------------------------------------
    plaintext = handle_user_string_input(0, "[Caesars] input: "); //flag 0 because we are in CEASARS algo
    key_int = handle_user_integer_input("[Caesars] key: ");
    num_of_chars = strlen(plaintext); 

    encrypted = caesar_encrypt(plaintext, key_int, num_of_chars);
    decrypted = caesar_decrypt(encrypted, key_int, num_of_chars);

    printf("[Caesars] encrypted: %s\n", encrypted);
    printf("[Caesars] decrypted: %s\n", decrypted);
    free(encrypted);
    free(decrypted);
    //FOR CAESARS----------------------------------------------------------------------------------------------
    

    
    //FOR VIGENERE---------------------------------------------------------------------------------------------
    init_tabula_recta();
    //print_tabula_recta();
    
    plaintext = handle_user_string_input(1, "[Vigenere] input: "); //flag 1 because we are in Vigenere algo
    num_of_chars = strlen(plaintext);
    key = vigenere_expanded_key(handle_user_string_input(1, "[Vigenere] key: "), num_of_chars);

    encrypted = vigenere_encrypt(plaintext, key, num_of_chars);
    decrypted = vigenere_decrypt(encrypted, key, num_of_chars);

    printf("[Vigenere] encrypted: %s\n", encrypted);
    printf("[Vigenere] decrypted: %s\n", decrypted);
    free(key);
    free(encrypted);
    free(decrypted);
    //FOR VIGENERE----------------------------------------------------------------------------------------------
    

    return 0;
    
}


