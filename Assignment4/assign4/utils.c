#include "utils.h"

/*
 * Reads bytes from file and stores them inside
 * malloc'd buffer.
 * 
 * filename: path to input file
 * buffer: buffer in which the bytes will be put
 * 
 * ret: number of bytes read
*/
int read_bytes_from_file(const char* filename, unsigned char **buffer)
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

/*
 * Writes arr of n bytes to file
 * 
 * arg0: filename
 * arg1: array of bytes
 * arg3: number of bytes of array
*/
void write_bytes_to_file(const char* filename, unsigned char *arr, int n)
{
    FILE *file = fopen(filename, "wb");

	if(n != fwrite(arr, 1, n, file))
		printf("Problem writing bytes to file:%s", filename);

    fclose(file);
}

/*
 * Writes array with size_t elements to file
 *
 * filename: path to output file
 * arr: array of the size_t elements
 * n: number of elements of array
*/
void write_sizet_elements_to_file(const char* filename, size_t* arr, size_t n){
	FILE* file = fopen(filename, "w");

    if(n != fwrite(arr, sizeof(size_t), n, file)) 
		printf("Problem writing the size_t elements to %s", filename);

	fclose(file);
}

/*
 * Reads array with size_t elements from file
 *
 * filename: path to input file
 * buffer: buffer for the size_t elements to be saved
 * 
 * ret: number of size_t elements written in buffer
*/
int read_sizet_elements_from_file(const char* filename, size_t** buffer){
	FILE *file = fopen(filename, "r");

    long number_of_bytes;

    fseek(file, 0, SEEK_END); // Jump to the end of the file
    number_of_bytes = ftell(file); // Get the current byte offset in the file
    rewind(file); // Jump back to the beginning of the file

	if(number_of_bytes % sizeof(size_t) != 0) 
		printf("Ciphertext or keys not divisable by 8?? Problem on file:  %s", filename);

	size_t n = number_of_bytes/8;

    *buffer = malloc(sizeof(size_t)*n);

	if(n != fread(*buffer, sizeof(size_t), n, file))
		printf("Something went wrong while reading size_t elements from file: %s", filename);

	fclose(file);

	return n;
}

/*
 * Prints the hex value of the input
 *
 * arg0: data
 * arg1: data len
 */
void
print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("%02X ", data[i]);
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 *
 * arg0: data
 * arg1: data len
 */
void
print_string(unsigned char *data, size_t len)
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

int is_file_valid(const char* filename){
	if(access(filename, F_OK) != 0){
		return 0;
	}
	return 1;
}

/*
 * Prints the usage message
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_4 -g \n" 
	    "    assign_4 -i in_file -o out_file -k key_file [-d | -e]\n" 
	    "    assign_4 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -k    path    Path to key file\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -g            Generates a keypair and saves to 2 files\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 * arg3: operation mode
 */
void
check_args(char *input_file, char *output_file, char *key_file, int op_mode)
{
	if ((!input_file) && (op_mode != 2)) {
		printf("Error: No input file!\n");
		usage();
	}

	if ((!output_file) && (op_mode != 2)) {
		printf("Error: No output file!\n");
		usage();
	}

	if ((!key_file) && (op_mode != 2)) {
		printf("Error: No user key!\n");
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}

	if((!is_file_valid(input_file)) && (op_mode != 2)){
		printf("The input file %s is INVALID\n", input_file);
		usage();
	}

	if((!is_file_valid(key_file)) && (op_mode != 2)){
		printf("The key file %s is INVALID\n", key_file);
		usage();
	}
}


