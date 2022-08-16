#ifndef _RSA_H
#define _RSA_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

/* MY OWN */
#include <sys/random.h>

# define RSA_SIEVE_LIMIT 1000

/* 
 * Memory effiecient way of calculating modular exponentation
 * Using: (a ⋅ b) mod m = [(a mod m) ⋅ (b mod m)] mod m
 * 
 * ret: base^exponent mod modulus
*/
size_t modular_exponentation(size_t, size_t, size_t);

/* 
 * cryptographically secure way to get random
 * number between 0 and the given parameter - 1
 * uses /dev/urandom
 *   
*/
unsigned int 
secure_random_positive_integer(unsigned int);


/* 
 * Checks if number is prime
 *
 * ret: 0 if its not prime, 1 if it is
*/
int is_prime(size_t n);

/*
 * Sieve of Eratosthenes Algorithm
 * https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
 *
 * arg0: The size of the generated primes list. Empty argument used as ret val
 *
 * ret:  The prime numbers that are less or equal to the limit
 */
size_t *
sieve_of_eratosthenes(size_t, size_t *);


/*
 * Greatest Common Denominator
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: the GCD
 */
int
gcd(int , int);


/*
 * Chooses 'e' where 
 *     1 < e < fi(n) AND gcd(e, fi(n)) == 1 AND e is prime
 *
 * arg0: fi(n)
 *
 * ret: 'e'
 */
size_t
choose_e(size_t);


/*
 * Calculates the modular inverse
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: modular inverse of arg0 mod arg1
 */
size_t
mod_inverse(size_t, size_t);


/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */
void
rsa_keygen(void);


/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_encrypt(char *, char *, char *);


/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_decrypt(char *, char *, char *);



#endif /* _RSA_H */
