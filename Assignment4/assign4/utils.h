#ifndef _UTILS_H
#define _UTILS_H

#include <stdio.h>
#include <stdlib.h>

#include <unistd.h> // for file checking



/*
 * Checks if the file given is valid
 *
 * arg0: filename
 * 
 * ret: 0 if not valid, 1 if valid
 */
int is_file_valid(const char* filename);

/*
 * Prints the hex value of the input, 16 values per line
 *
 * arg0: data
 * arg1: data len
 */
void
print_hex(unsigned char *, size_t);


/*
 * Prints the input as string
 *
 * arg0: data
 * arg1: data len
 */
void
print_string(unsigned char *, size_t);


/*
 * Prints the usage message
 */
void
usage(void);


/*
 * Checks the validity of the arguments
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 * arg3: operation mode
 */
void
check_args(char *, char *, char *, int);

/*
 * Writes arr of n bytes to file
 * 
 * arg0: filename
 * arg1: array of bytes
 * arg3: number of bytes of array
*/
void write_bytes_to_file(const char*, unsigned char *, int);

/*
 * Reads bytes from file and stores them inside
 * malloc'd buffer.
 * 
 * arg0: path to input file
 * arg1: buffer in which the bytes will be put
 * 
 * ret: number of bytes read
*/
int read_bytes_from_file(const char*, unsigned char **);


/*
 * Writes array with size_t elements to file
 *
 * arg0: path to output file
 * arg1: array of the size_t elements
 * arg2: number of elements of array
*/
void write_sizet_elements_to_file(const char*, size_t*, size_t);


/*
 * Reads array with size_t elements from file
 *
 * arg0: path to input file
 * arg1: buffer for the size_t elements to be saved
 * 
 * ret: number of size_t elements written in buffer
*/
int read_sizet_elements_from_file(const char*, size_t **);



#endif /* _UTILS_H */
