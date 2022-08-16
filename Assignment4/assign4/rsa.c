#include "rsa.h"
#include "utils.h"
/*
 * Sieve of Eratosthenes Algorithm
 * https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
 *
 * arg0: A limit
 * arg1: The size of the generated primes list. Empty argument used as ret val
 *
 * ret:  The prime numbers that are less or equal to the limit
 */
size_t *
sieve_of_eratosthenes(size_t limit, size_t *primes_sz)
{
	size_t *primes;
	 
	//is_prime[i] is 0 (FALSE) or 1 (TRUE)
	//and means that the i+2 integer is prime
	unsigned short is_prime[limit-1];
	
	//make everything TRUE
	for(size_t i = 0; i<limit-1; i++){
		is_prime[i] = 1; 
	}

	// i < sqrt(limit)
	for(size_t i = 2; i*i < limit; i++){
		if(is_prime[i-2]){
			//starting from i^2 (optimization)
			//find all multiples of i (multiples of i are obviously NOT prime)
			for(size_t j = i*i; j<=limit; j += i){ 
				is_prime[j-2] = 0;
			}
		}
	} 

	*primes_sz = 0;
	//find how many primes we have, so we can allocate memory
	for(size_t i=0; i<limit-1; i++){
		if(is_prime[i]){
			*primes_sz += 1;
		}
	}

	primes = malloc(sizeof(size_t)*(*primes_sz));
	int index = 0;
	for(size_t i=0; i<limit-1; i++){
		if(is_prime[i]){
			//i+2 because every is_prime[i] means i+2 integer is_prime
			primes[index] = i+2; 
			index++;
		}
	}

	return primes;
}


/*
 * Greatest Common Denominator
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: the GCD
 */
int
gcd(int a, int b)
{
	//Euclidean algorithm
	int tmp;
    while (b != 0)
    {
        tmp = a % b;

        a = b;
        b = tmp;
    }

    return a;
}


/*
 * Chooses 'e' where 
 *     1 < e < fi(n) AND gcd(e, fi(n)) == 1 AND e is prime
 *
 * arg0: fi(n)
 *
 * ret: 'e'
 */
size_t
choose_e(size_t fi_n)
{
	size_t e;

	// i < fi_n , so we dont have to check (i % fi_n != 0)
	for(int i=2; i<fi_n; i++){
		if(is_prime(i) && (gcd(i, fi_n) == 1)){
			e = i;
			break;
		}
	}

	return e;
}


/*
 * Calculates the modular inverse 
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: modular inverse of arg0 mod arg1
 * 		0 if there is no mod inverse (arg0 and arg1 not coprime)
 * 
 * https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
 * -> function inverse(a, n)
 */
size_t
mod_inverse(size_t a, size_t b)
{
	int t = 0; //Modular multiplicative inverse of a (mod b)
	int newt = 1;
	int r = b;
	int newr = a;

	int tmp_t;
	int tmp_r;
	
	int quotient;

	while(newr != 0){
		quotient = r / newr;

		tmp_t = t;
		t = newt;
		newt = tmp_t - quotient*newt;

		tmp_r = r;
		r = newr;
		newr = tmp_r - quotient*newr;
	}
	if(r > 1){
		return 0;
	}
	if(t < 0){
		t += b;
	}

	return (size_t)t;

}


/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */
void
rsa_keygen(void)
{
	size_t p;
	size_t q;
	size_t n; //public/private key n 
	size_t fi_n;
	size_t e; //public key e 
	size_t d; //private key d

	/* TODO */

	size_t primes_sz;
	size_t *primes = sieve_of_eratosthenes(RSA_SIEVE_LIMIT, &primes_sz);

	p = primes[secure_random_positive_integer(primes_sz)];
	q = primes[secure_random_positive_integer(primes_sz)];

	n = p*q;

	fi_n = (p-1)*(q-1);

	//is is chosen in a way that e, fi_n are COPRIME.
	e = choose_e(fi_n);

	//so definitely exists a mod inverse d of e (mod fi_n)
	d = mod_inverse(e, fi_n);

	//printf("a->%ld, b->%ld\n", e, fi_n);
	//printf("private key: n->%ld, d->%ld\n", n, d);
	//printf("public key: n->%ld, e->%ld\n", n, e);

	size_t public_key[2] = {n, e};
	size_t private_key[2] = {n, d};

	write_sizet_elements_to_file("private.key", private_key, 2);
	write_sizet_elements_to_file("public.key", public_key, 2);

	free(primes);

}


/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_encrypt(char *input_file, char *output_file, char *key_file)
{
	//key[0] -> n , key[1] -> e or d
	size_t *key;
	read_sizet_elements_from_file(key_file, &key);

	unsigned char* plaintext;
	int plaintext_bytes = read_bytes_from_file(input_file, &plaintext);

	size_t ciphertext[plaintext_bytes];

	// encr = c^e mod n (c is the byte to encrypt, encr is the 8 byte encrypted ciphertext of c)
	for(int i=0; i<plaintext_bytes;i++){
		ciphertext[i] = modular_exponentation((size_t)plaintext[i], key[1], key[0]);
	}

	write_sizet_elements_to_file(output_file, ciphertext, plaintext_bytes);

	free(plaintext);
	free(key);
}


/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_decrypt(char *input_file, char *output_file, char *key_file)
{
	//key[0] -> n , key[1] -> e or d
	size_t *key;
	read_sizet_elements_from_file(key_file, &key);

	size_t *ciphertext;
	int n = read_sizet_elements_from_file(input_file, &ciphertext);

	unsigned char plaintext[n];

	// decr = c^d mod n (c is the 8 byte size_t to decrypt
	//                  ,decr is the decrypted unsigned char)
	for(int i = 0; i < n; i++){
		plaintext[i] = modular_exponentation(ciphertext[i], key[1], key[0]);
	}

	write_bytes_to_file(output_file, plaintext, n);

	free(ciphertext);
	free(key);
}

/*  
 * cryptographically secure way to get random
 * number between 0 and the given parameter - 1
 * uses /dev/urandom
 *   
 * n: n-1 is the max number we return
 *   
*/
unsigned int secure_random_positive_integer(unsigned int n){
	unsigned int r;
	do{
		getrandom(&r, sizeof(unsigned int), 0);
	}while(r < 0);

	return r%n;
}


/* 
 * Checks if number is prime
 *
 * ret: 0 if its not prime, 1 if it is
*/
int is_prime(size_t n){
	int i;
    for (i=2; i*i <= n; i++) {
        if (n % i == 0) return 0;
    }
    return 1;
}

/* 
 * Memory effiecient way of calculating modular exponentation
 * Using identity: (a ⋅ b) mod m = [(a mod m) ⋅ (b mod m)] mod m
 * O(e)
 * 
 * ret: base^exponent mod modulus
*/
size_t modular_exponentation(size_t base, size_t exponent,size_t modulus){
	if(modulus == 1) return 0;

	size_t c = 1;

	for(size_t i = 0; i<exponent; i++){
		c = (c*base) % modulus;
	}
	return c;
}