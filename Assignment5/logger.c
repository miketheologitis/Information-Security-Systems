#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>

#include <errno.h> //for errno
#include <fcntl.h>  //for open


// Directory /file_logging , and file_logging.log file const variables 
const char logging_dir[] = "file_logging";
const char logging_file[] = "file_logging/file_logging.log";

//maximum absolute path length
//please change it if for some reason 300 chars is not enough!
//(if so, also change it in acmonitor.c)
#define MAX_PATH_LEN 600 

// logging_initialized ensures the create_logging_file_and_dir() function 
// only runs once in each "make run". please read the notes on the function
int logging_initialized = 0;


/* 
 * Creates the directory file_logging and puts inside the file_logging.log file
 * with all the access permissions given to owner/group/others as instructed
 * in the assignment.
 *
 * Note: It will run only once in every "make run" we make
 * 
 * Note2: If the /file_logging directory, /file_logging/file_logging.log file
 * 		  already exist (maybe from a previous "make run") then nothing happens
 * 		  or changes when the function is called.	  
 * 
*/
void create_logging_file_and_dir(){
	mode_t mode;

	mode_t old_mask = umask(0); // mode & ~umask so we need to be careful
	
	//mode is: all permissions to user, group, and others
	mode = S_IRWXU | S_IRWXG | S_IRWXO;

	//create the dir where the file_logging.log file will be at
	mkdir(logging_dir, mode);

	//create the file file_logging.log
	int fd = open(logging_file, O_RDONLY|O_CREAT, mode);

	close(fd); //close it 

	umask(old_mask); //give mask back :)

	logging_initialized = 1;
}


/* 
 * Read everything from the file, using the original fopen function 
 *
 * returns on success: number of bytes read
 * 		   on failure: -1
 * 
 * Possible reasons for failure is that the file
 * could not be opened, or that we dont have privilages
 * to read the file		  
 * 
*/
int read_file_using_original(const char* filename, unsigned char **buffer)
{
	FILE *file;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	file = (*original_fopen)(filename, "r");

	if(file == NULL) return -1; 

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
 *
 * Produces the digest[16] of the data
 * 
*/
void md5_hash(unsigned char* data, int data_bytes, unsigned char digest[16]){
	MD5_CTX context; //Allocate an MD5_CTX

	MD5_Init(&context); //initialize it

	MD5_Update(&context, data, data_bytes); //run over the data

	MD5_Final(digest, &context); //extract the result
}

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
 * Stores an entry to the logfile
 * 
 * 
 * PARAMETERS
 * 	  
 * user_id: the user id
 * abs_path: null-terminated string of the absolute path of the accessed file
 * tmp_date: null-terminated string (in the format "2021-11-23")
 * tmp_time: null-terminated string (in the format "18:34:57")
 * access_type: the access type (0 or 1 or 2)
 * action_denied_flag: the action denied flag (0 or 1)
 * hash: file fingerprint 16 bytes
 * 
*/

void store_entry_to_logfile(uid_t user_id, char *abs_path, char tmp_date[11], char tmp_time[9],
					        int access_type, int action_denied_flag, unsigned char hash[16],
							int could_not_find_hash)
{
	
	//create only once, the logging dir, logging_log.log file inside the dir
	//with the right permissions
	if(!logging_initialized) create_logging_file_and_dir();

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(logging_file, "a");

	/* convert hash bytes */
	char hash_hex_str[33];

	if(could_not_find_hash){ //if for some reason we didnt find the data to hash
		hash_hex_str[0] = '0';
		hash_hex_str[1] = '\0';
		//for(int i = 1; i < 32; i++) hash_hex_str[i] = ' ';
	}
	else{ //all good here
		for(int i = 0; i < 16; i++){
			sprintf(&hash_hex_str[2*i], "%02X", hash[i]);
		}
		hash_hex_str[32] = '\0';
	}
	//hash_hex_str[32] = '\0';

	//printf("BELLOW \n %s \n", hash_hex_str);
	
	//output to our log file the entry
	fprintf(original_fopen_ret, "%u %s %s %s %d %d %s\n",
		   user_id, abs_path, tmp_date, tmp_time, access_type, action_denied_flag, hash_hex_str);
	fclose(original_fopen_ret);
}

/* 
 * Importand notes:
 *
 * I calculate the hash after the call to the original fopen() function as requested.
 * That means that for mode = "w", "w+" etc the original fopen() function truncates
 * the file to zero length so the hash value will be the message digest of "nothing"
 * which is "d41d8cd98f00b204e9800998ecf8427e".
 * 
 * The same applies for a call to fopen() with mode = "w", "w+", "a", "a+" for a 
 * file that does not yet exist. The original fopen() will be called, and the
 * file will be created and, again, the hash value will be the message digest of "nothing".
 * 
 * To find the hash we are required to open the file from the parameter "path" 
 * and that means we should atleast have reading permission as the process.
 * If that is not the case then we CANNOT read the file from the parameter "path"
 * and (regardless of what the fopen() mode was) we will write as hash, the value "0".
 * 
 * 
 * 
 * Possible fopen() fail reasons that concern the implementation bellow:
 * 1. No permission for the requested mode.
 * 
 * Note: Even though we dont have permission for the requested mode
 * 		 maybe we can still read the data of the file and produce the
 * 		 (unchanged) hash value.
 *
 * 2. File doesn't exist and we want to open it with mode = "r", "r+"
 * 
 * Note: Since the file doesn't exist we don't have a hash value to produce
 * 		 so I will put "0" as the hash value, as requested from the assignement.
 *       Also the abs_path = realpath(path, NULL) will be NULL and the path
 *       that is requested in the assignment will have as value the "path" 
 *       parameter that, basically, does not exist.
 *
 * 
 * 
 * Importand note about parameter "mode":
 * The mode string can also include the letter 'b' either as a last
 * character or as a character between the characters in any of the
 * two-character strings of mode.
 * 
*/

FILE *
fopen(const char *path, const char *mode) 
{
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	// boolean helper variables to be used for permission checking
	// I do this so I don't have huge if statement in the code bellow

	// reading, writing, creating
	int w = (strcmp(mode, "w") == 0) || (strcmp(mode, "wb") == 0) || (strcmp(mode, "bw") == 0);

	int w_plus = (strcmp(mode, "w+") == 0) || (strcmp(mode, "bw+") == 0) || (strcmp(mode, "wb+") == 0) ||
		         (strcmp(mode, "w+b") == 0);

	int a = (strcmp(mode, "a") == 0) || (strcmp(mode, "ab") == 0) || (strcmp(mode, "ba") == 0);

	int a_plus = (strcmp(mode, "a+") == 0) || (strcmp(mode, "ba+") == 0) || (strcmp(mode, "ab+") == 0) ||
		    	 (strcmp(mode, "a+b") == 0);

	/* 5. Access Type (we need this before the fopen call because it will have already created the file) */ 
	
 	//For file creation, the access type is 0. For file open, the access type is 1. 
	int access_type;
	
	access_type = 1;
	//If there is a possibility for file creation we must check it.
	if(w || w_plus || a || a_plus){
		//F_OK tests for the existance of the file. access(path, F_OK) returns 0 if it exists
		if(access(path, F_OK) != 0) access_type = 0; //the file doesn't exist
	}

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);

	/* 1. get the real user ID of the calling process */

	uid_t user_id = getuid(); 

	/* 2. Absolute file name path */

	//abs_path is a null-terminated string
	char *abs_path = realpath(path, NULL);

	//if abs_path could not be resolved, the path that will be output in the
	//file_logging.log is the path that was requested (and probably doesnt exist)
	if(abs_path == NULL) abs_path = (char*)path; 

	/* 3. 4. Date - Time  */

	time_t t = time(NULL);
  	struct tm time_info = *localtime(&t);

	//both tmp_date , tmp_time are null-terminated strings
	char tmp_date[11]; // 2021-11-23 format
	char tmp_time[9]; // 18:34:57 format

	sprintf(tmp_date, "%d-%02d-%02d", time_info.tm_year + 1900, time_info.tm_mon + 1, time_info.tm_mday);
	sprintf(tmp_time, "%02d:%02d:%02d", time_info.tm_hour, time_info.tm_min, time_info.tm_sec);

	/* 6. Action Denied Flag */

	//It is 1 if the action was denied to the user with no access privileges, or 0 otherwise
	int action_denied_flag;

	//if we couldnt open the file for the reason that we didnt have access 
	//privilages (errno = EACCES) then action_denied_flag = 1
	if(original_fopen_ret == NULL && errno == EACCES) action_denied_flag = 1;
	else action_denied_flag = 0;


	/* 7. File Fingerprint */

	//Read everything from the file, using the original fopen function
	unsigned char *file_data;
	int file_data_bytes = read_file_using_original(path, &file_data);

	int could_not_find_hash; //1 if something went wrong reading data, 0 otherwise

	unsigned char hash[16];
	if(file_data_bytes != -1){ //if all good take the hash from the data
		md5_hash(file_data, file_data_bytes, hash);
		could_not_find_hash = 0;
	}
	else could_not_find_hash = 1;

	/*
	print_hex(hash, 16);

	printf("user_id: %d abs_path: %s date: %s time: %s access_type: %d action_denied_flag: %d\n",
		    user_id, abs_path, tmp_date, tmp_time, access_type, action_denied_flag);
	*/

	/* Store entry in the log file */
	store_entry_to_logfile(user_id, abs_path, tmp_date, tmp_time, access_type, action_denied_flag, hash, could_not_find_hash);

	if(!could_not_find_hash) free(file_data);

	return original_fopen_ret;
}


/* 
 * Importand notes:
 *
 * Firstly, what I want to point out is that we need fflush(stream) after the call to the
 * original fwrite() function, because the fwrite() implementation is buffered and 
 * we want to push the data we wrote (to the buffer), from the buffer to the file, RIGHT NOW.
 * This is because we are going to read the data of the file and create the hash 
 * some lines of code bellow the call to the original fwrite()!
 *
 * 1. user_id: we get it from the getuid()
 * 
 * 2. abs_path: Given the FILE* stream, I find the fd, and get
 * 				the abs_path from readlink("/proc/self/fd/NNN", abs_path, MAX_PATH_LEN)
 *  			where NNN is the fd and MAX_PATH_LEN is the max size of abs_path.
 * Possible problems: There is the possibility that the stream we were given is wrong
 * 					  (for example NULL) then the abs_path cannot be resolved obviously.
 * 					  then fileno(stream) will return -1. Also there is a chance that
 * 					  fileno(stream) succeeded but we dont have search permission 
 * 					  for a component of the path. In either case, my implementation
 * 					  will output as abs_path = "*****************************"
 * 				      which is my program's way of saying that the abs_path could not be 
 * 					  resolved.
 * 
 * 3. 4. date, time: all easy
 * 
 * 5. access_type: always =2 for write
 * 
 * 
 * 6. action_denied_flag: "This field reports if the action was denied to the user with no access
 *						   privileges. It is 1 if the action was denied to the user, or 0 otherwise."
 * 
 * Very Importand Note: Considering the above description from the assignment, action_denied_flag
 * 						should be set to 1 if and only if the write operation does not have access
 * 				        privilages to write. So, if the FILE *stream we are given is wrong (NULL for example)
 * 					    we cannot know whether or not we have access privilages for writing and 
 * 						action_denied_flag will be set to 0. So, considering a valid FILE* stream
 * 				 		the only way we don't have writing privilages to this stream is if the stream
 * 						was created with fopen(.., .., mode = "r" or "rb" or "br") and then this stream
 * 						was passed to our fwrite(). So, action_denied_flag, which is set based on
 * 						access privilages, will be set to 1 only in the last case.
 * 
 * Note: In the last case, where, considering a valid FILE* stream, created with fopen in reading mode
 * 		 only, and then passed on to fwrite(), we set the action_denied_flag = 1. But, it's very 
 *       importand to note, so you understand that I know this, that even though the stream
 * 		 was opened in reading mode and given to fwrite, maybe for this file that we wanted to write to,
 * 		 we would have had access privilages to write if we had created the FILE* stream with
 * 		 mode = "w" , "w+", "r+" etc instead of mode = "r". The latter, is something I don't
 * 		 check. The action_denied_flag will be set to 1 if and only if the FILE* stream was created
 * 		 with fopen for reading mode only (or anything else, that doesn't involve writing privilages).
 * 
 * 	     
 * 						   
*/

size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{
	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

	//fflush(stream) is very importand in our case, because the fwrite()
	//implementation is buffered and we want to push the data we wrote (to the buffer), 
	//from the buffer to the file, RIGHT NOW. This is because we are 
	//going to read the data of the file and create the hash some lines of code bellow!
	fflush(stream);

	/* 1. get the real user ID of the calling process */

	uid_t user_id = getuid(); 

	/* 2. Absolute file name path */

	char abs_path[MAX_PATH_LEN]; //MAX_PATH_LEN just to be safe

	char symbolic_link[20] = "/proc/self/fd/";

	char fd_str[8]; //fd string
	int fd = fileno(stream); //file discriptor
	if(fd != -1){  
		sprintf(fd_str, "%d", fd); //convert fd integer to string

		strcat(symbolic_link, fd_str);

		//get the contents of the symbolic link to abs_path without terminating null byte
		ssize_t number_of_bytes = readlink(symbolic_link, abs_path, MAX_PATH_LEN);

		if(number_of_bytes != -1) abs_path[number_of_bytes] = '\0'; //all good
		else { //error from readlink 
			memset(abs_path, 0, MAX_PATH_LEN); //clear possible readlink chars written in abs_path
			int i;
			for(i=0; i<50; i++) abs_path[i] = '*';
			abs_path[i] = '\0';
		}
	}
	else{ //error getting fd
		int i;
		for(i=0; i<50; i++) abs_path[i] = '*';
		abs_path[i] = '\0';
	}

	/* 3. 4. Date - Time  */

	time_t t = time(NULL);
  	struct tm time_info = *localtime(&t);

	//both tmp_date , tmp_time are null-terminated strings
	char tmp_date[11]; // 2021-11-23 format
	char tmp_time[9]; // 18:34:57 format

	sprintf(tmp_date, "%d-%02d-%02d", time_info.tm_year + 1900, time_info.tm_mon + 1, time_info.tm_mday);
	sprintf(tmp_time, "%02d:%02d:%02d", time_info.tm_hour, time_info.tm_min, time_info.tm_sec);

	/* 5. Access type */
	int access_type = 2; //2 for file write


	/* 6. Action Denied Flag */
	int action_denied_flag;

	//!!!Please read the 6. note on the comments above so you understand my logic.!!!!
	//EBADF  The file descriptor underlying stream is not a valid file
    //       descriptor open for writing.
	if(original_fwrite_ret < nmemb && errno == EBADF){
		action_denied_flag = 1;
	}
	else{
		action_denied_flag = 0;		
	}


	/* 7. File Fingerprint */

	//Read everything from the file, using the original fopen function
	unsigned char *file_data;
	int file_data_bytes = read_file_using_original(abs_path, &file_data);

	int could_not_find_hash; //1 if something went wrong reading data, 0 otherwise

	unsigned char hash[16];
	if(file_data_bytes != -1){ //if all good take the hash from the data
		md5_hash(file_data, file_data_bytes, hash);
		could_not_find_hash = 0;
	}
	else could_not_find_hash = 1;

	//print_hex(hash, 16);

	//printf("user_id: %d abs_path: %s date: %s time: %s access_type: %d action_denied_flag: %d\n",
	//	    user_id, abs_path, tmp_date, tmp_time, access_type, action_denied_flag);
	

	/* Store entry in the log file */
	store_entry_to_logfile(user_id, abs_path, tmp_date, tmp_time, access_type, action_denied_flag, hash, could_not_find_hash);

	if(!could_not_find_hash) free(file_data);

	return original_fwrite_ret;
}



/*
 *
 * Same routine with fopen() see comments above
 * Created for ssl binaries to use.
 * 
*/

FILE *
fopen64(const char *path, const char *mode) 
{
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	// boolean helper variables to be used for permission checking
	// I do this so I don't have huge if statement in the code bellow

	// reading, writing, creating
	int w = (strcmp(mode, "w") == 0) || (strcmp(mode, "wb") == 0) || (strcmp(mode, "bw") == 0);

	int w_plus = (strcmp(mode, "w+") == 0) || (strcmp(mode, "bw+") == 0) || (strcmp(mode, "wb+") == 0) ||
		         (strcmp(mode, "w+b") == 0);

	int a = (strcmp(mode, "a") == 0) || (strcmp(mode, "ab") == 0) || (strcmp(mode, "ba") == 0);

	int a_plus = (strcmp(mode, "a+") == 0) || (strcmp(mode, "ba+") == 0) || (strcmp(mode, "ab+") == 0) ||
		    	 (strcmp(mode, "a+b") == 0);

	/* 5. Access Type (we need this before the fopen call because it will have already created the file) */ 
	
 	//For file creation, the access type is 0. For file open, the access type is 1. 
	int access_type;
	
	access_type = 1;
	//If there is a possibility for file creation we must check it.
	if(w || w_plus || a || a_plus){
		//F_OK tests for the existance of the file. access(path, F_OK) returns 0 if it exists
		if(access(path, F_OK) != 0) access_type = 0; //the file doesn't exist
	}

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen64");
	original_fopen_ret = (*original_fopen)(path, mode);

	/* 1. get the real user ID of the calling process */

	uid_t user_id = getuid(); 

	/* 2. Absolute file name path */

	//abs_path is a null-terminated string
	char *abs_path = realpath(path, NULL);

	//if abs_path could not be resolved, the path that will be output in the
	//file_logging.log is the path that was requested (and probably doesnt exist)
	if(abs_path == NULL) abs_path = (char*)path; 

	/* 3. 4. Date - Time  */

	time_t t = time(NULL);
  	struct tm time_info = *localtime(&t);

	//both tmp_date , tmp_time are null-terminated strings
	char tmp_date[11]; // 2021-11-23 format
	char tmp_time[9]; // 18:34:57 format

	sprintf(tmp_date, "%d-%02d-%02d", time_info.tm_year + 1900, time_info.tm_mon + 1, time_info.tm_mday);
	sprintf(tmp_time, "%02d:%02d:%02d", time_info.tm_hour, time_info.tm_min, time_info.tm_sec);

	/* 6. Action Denied Flag */

	//It is 1 if the action was denied to the user with no access privileges, or 0 otherwise
	int action_denied_flag;

	//if we couldnt open the file for the reason that we didnt have access 
	//privilages (errno = EACCES) then action_denied_flag = 1
	if(original_fopen_ret == NULL && errno == EACCES) action_denied_flag = 1;
	else action_denied_flag = 0;


	/* 7. File Fingerprint */

	//Read everything from the file, using the original fopen function
	unsigned char *file_data;
	int file_data_bytes = read_file_using_original(path, &file_data);

	int could_not_find_hash; //1 if something went wrong reading data, 0 otherwise

	unsigned char hash[16];
	if(file_data_bytes != -1){ //if all good take the hash from the data
		md5_hash(file_data, file_data_bytes, hash);
		could_not_find_hash = 0;
	}
	else could_not_find_hash = 1;

	/*
	print_hex(hash, 16);

	printf("user_id: %d abs_path: %s date: %s time: %s access_type: %d action_denied_flag: %d\n",
		    user_id, abs_path, tmp_date, tmp_time, access_type, action_denied_flag);
	*/

	/* Store entry in the log file */
	store_entry_to_logfile(user_id, abs_path, tmp_date, tmp_time, access_type, action_denied_flag, hash, could_not_find_hash);

	if(!could_not_find_hash) free(file_data);

	return original_fopen_ret;
}