#include <stdio.h>
#include <stdlib.h> //strtol

#include <unistd.h> // mkdir/mask
#include <sys/stat.h> // mkdir/mask

#include <string.h> //strcat

#define MAX_PATH 300 //directory+filename

/*
 *
 * This function is created ONLY to be used by the bash script
 * for creating the new directory and the new files. This is because 
 * I want to use fopen() for file creation (and not "touch filename.txt")
 * so we have the file creation log entries.
 * 
 * Also in each file I write inside, using fwrite(), the
 * file_directory/filename , so we can confirm that the encryption,
 * decryption runs smoothly.
 * 
*/
int main(int argc, char *argv[]) 
{
	if(argc<3) return -1;

	const char* file_testing_dir = argv[1];

	char *x_str = argv[2];
    unsigned int x = (unsigned int)strtol(x_str, NULL, 10);


	/* make the directory */

	mode_t mode;

	mode_t old_mask = umask(0); // mode & ~umask so we need to be careful
	
	//mode is: all permissions to user, group, and others
	mode = S_IRWXU | S_IRWXG | S_IRWXO;

	//create the directory where the files will be put
	mkdir(file_testing_dir, mode);

	umask(old_mask);


	/*  
	 * create the x files and in each, 
	 * write inside the directory/filename 
	*/

	FILE* file;
	char dir_file[MAX_PATH]; // directory/filename ex. file_directory/file_10.txt
	char filename[50]; // filename ex. file_10.txt

	
	for(int i = 0; i < x; i++){
		memset(dir_file, 0, MAX_PATH); //empty string
		strcpy(dir_file, file_testing_dir); //copy directory name

		snprintf(filename, 50, "/file_%d.txt", i);

		strcat(dir_file, filename);

		file = fopen(dir_file, "w+");
		
		/* write in each file the directory/filename */
		fwrite(dir_file, 1, strlen(dir_file), file);
		fclose(file);
	}

	exit(EXIT_SUCCESS);

}
