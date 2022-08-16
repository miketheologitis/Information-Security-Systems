#include <stdio.h>
#include <string.h>


#include <fcntl.h>  //for open
#include <unistd.h> // for close
#include <sys/stat.h> //for umask

//this is because I want to put some FAKE data for testing malicious users.
//please read in "TESTING" the 7. comment bellow
const char logging_file[] = "file_logging/file_logging.log";



int main() 
{
	const char file_testing_dir[] = "file_testing";
	
	char read_write_files[5][40] = {"file_testing/file_read_write_1",
								    "file_testing/file_read_write_2",
									"file_testing/file_read_write_3",
									"file_testing/file_read_write_4",
								    "file_testing/file_read_write_5"};

	char read_only_files[5][40] = {"file_testing/file_read_only_1",
								   "file_testing/file_read_only_2",
								   "file_testing/file_read_only_3",
								   "file_testing/file_read_only_4",
								   "file_testing/file_read_only_5"};								

	char write_only_files[5][40] = {"file_testing/file_write_only_1",
								    "file_testing/file_write_only_2",
									"file_testing/file_write_only_3",
									"file_testing/file_write_only_4",
								    "file_testing/file_write_only_5"};
	
	/*---------------------CREATE FILE DIRECTORY / CREATE FILES------------------------- */
	
	//I do it this way (with open()), because I want my custom permissions everywhere.

	int i;
	mode_t mode; //permissions
	int tmp_fd; //file discriptor for close()
	mode_t old_mask; //for unmask
	
	old_mask = umask(0); // because open uses mode & ~umask

	//mode is: all permissions to user, group, and others
	mode = S_IRWXU | S_IRWXG | S_IRWXO;
	
	//create the dir where the file_logging.log file will be at
	mkdir(file_testing_dir, mode);
	
	//mode is: user has read-write permission, group has read-write permission,
	//		   others have read-write permission 
	mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH; 

	for (i = 0; i < 5; i++) {
		tmp_fd = open(read_write_files[i], O_RDONLY|O_CREAT, mode);
		close(tmp_fd);
	}
	
	//mode is: user has read permission, group has read permission,
	//		   others have read permission (only)
	mode = S_IRUSR | S_IRGRP | S_IROTH;

	for (i = 0; i < 5; i++) {
		tmp_fd = open(read_only_files[i], O_RDONLY|O_CREAT, mode);
		close(tmp_fd);
	}

	//mode is: user has write permission, group has write permission,
	//		   others have write permission (only)
	mode = S_IWUSR | S_IWGRP | S_IWOTH;

	for (i = 0; i < 5; i++) {
		tmp_fd = open(write_only_files[i], O_RDONLY|O_CREAT, mode);
		close(tmp_fd);
	}

	umask(old_mask);
	
	/*---------------------------------TESTING------------------------------ */

	FILE* file;

	/*
	 * The bellow comments are numbered from 1. to 8. , so I can refer to them from the following explanation
	 * so we know what to expect.
	 *
	 * In Total:
	 *
	 * 183 logs   <--------
	 * 
	 * Of which:
	 * 
	 * 175 real logs (1. 2. 3. 4. 5. 7.)
	 * 8  FAKE logs  (8.) (created for fake uid = 1777 to test another malicious user)
	 * 
	 * 
	 * 23 MALICIOUS  -> (2. , 5.) 10 read_only_files (5 distinct filenames),
	 * 					  (4.)     5 write_only_files 
	 *                    (8.)     8 (FAKE) logs for 8 distinct Pathnames
	 *   UID: 
	 * 		  Ours (uid = 1000) : 10 malicious logs (for distinct filenames)
	 * 		  FAKE (uid = 1777)  :  8 malicious logs (for distinct filenames) 
	 * 
	 * 160 NOT MALICIOUS  
	 * 
	 * File Modifications ->  1.   5 Modifications.  1 for each "i" file "read_write_files[i]"
	 * 						  8. 125 Modifications. 25 for each "i" file "read_write_files[i]" 
	 * 
	 * Note: There are file modifications for the write only files in (3.) but I did not list them
	 * 	     because there is no way to check the fingerprint in write-only files.
	 * 
	*/
	

	/*						  1.
	 *
	 * 					NOT MALICIOUS (Modifications)
	 * write the filename in each of the read-write files.
	 * 
	 * Expect: 
	 * 
	 * 5 open logs -> access_type = 1, is_action_denied = 0,
	 * 		          fingerprint = same for every one (mode = "w")
	 * 5 write logs -> access_type = 2, is_action_denied = 0,
	 * 				   fingerprint = different for every one (different filename)
	 * 
	 * TOTAL = 10 logs
	 * 
	*/
	for(i = 0; i < 5; i++){
		file = fopen(read_write_files[i], "w");
		if(file == NULL) continue;
		fwrite(read_write_files[i], 1, strlen(read_write_files[i]), file);
		fclose(file);
	}


	/*						 2.
	 *
	 * 					 MALICIOUS
	 * write the filename in each of the read-only files.
	 * 
	 * Expect: 
	 * 
	 * 5 open logs -> access_type = 1, is_action_denied = 1
	 * 		          fingerprint = same for every one (nothing inside the files)
	 * 
	 * 0 write logs -> (because of the continue in the loop)
	 * 
	 * 
	 * TOTAL = 5 logs
	 * 
	*/
	for(i = 0; i < 5; i++){
		file = fopen(read_only_files[i], "w");
		if(file == NULL) continue;
		fwrite(read_only_files[i], 1, strlen(read_only_files[i]), file);
		fclose(file);
	}


	/*	 	  				 3.
	 *
	 * 					NOT MALICIOUS (Modifications)
	 * write the filename in each of the write only files.
	 * 
	 * Expect: 
	 * 
	 * 5 open logs -> access_type = 1, is_action_denied = 0,
	 * 				  fingerprint = '0' because we cannot read the write-only files.
	 * 
	 * 5 write logs -> access_type = 2, is_action_denied = 0
	 * 				   fingerprint = '0' because we cannot read the write-only files.
	 * 
	 * 
	 * TOTAL = 10 logs
	 * 
	*/
	for(i = 0; i < 5; i++){
		file = fopen(write_only_files[i], "w");
		if(file == NULL) continue;
		fwrite(write_only_files[i], 1, strlen(write_only_files[i]), file);
		fclose(file);
	}


	/*						 4.
	 *
	 * 					  MALICIOUS
	 * try to open a write-only file for reading and writing
	 * 
	 * Expect: 
	 * 
	 * 5 open logs -> access_type = 1, is_action_denied = 1
	 * 				  fingerprint = '0' because we cannot read the write-only files.
	 * 
	 * TOTAL = 5 logs
	 * 
	*/
	for(i = 0; i < 5; i++){
		file = fopen(write_only_files[i], "r+");
		if(file == NULL) continue;
		fclose(file);
	}


	/*							5.
	 *
	 * 					  MALICIOUS (tricky)
	 * Open a read-only file, "supposedly" for reading, and then
	 * try to write in it! 
	 * 
	 * Expect: 
	 * 
	 * 5 open logs -> access_type = 1, is_action_denied = 0
	 * 				  fingerprint = same for everyone because it is a read-only file
	 * 								and it was initially empty 
	 * 
	 * 5 write logs -> access_type = 2, is_action_denied = 1
	 * 				  fingerprint = same with the read logs, because it is a read-only
	 * 								file and it was initially empty.
	 * 
	 * TOTAL = 10 logs
	 * 
	*/
	for(i = 0; i < 5; i++){
		file = fopen(read_only_files[i], "r");
		if(file == NULL) continue;
		fwrite(read_only_files[i], 1, strlen(read_only_files[i]), file);
		fclose(file);
	}


	/*							6.
	 * 					  NOT MALICIOUS
	 * Create files with fopen using many different modes
	 * 
	 * Expect: 
	 * 
	 * 5 open logs -> access_type = 0, is_action_denied = 0
	 * 				  fingerprint = same for everyone (md5 of 0 bytes)
	 * 
	 * TOTAL = 5 logs
	 * 
	*/

	file = fopen("file_testing/fopen1", "a+");
	fclose(file);
	file = fopen("file_testing/fopen2", "a");
	fclose(file);
	file = fopen("file_testing/fopen3", "ab+");
	fclose(file);
	file = fopen("file_testing/fopen4", "wb");
	fclose(file);
	file = fopen("file_testing/fopen5", "w+");
	fclose(file);

	/*						 7.
	 *
	 * 					NOT MALICIOUS  (Modifications)
	 * append the filename 5 times in each of the read-write files.
	 * 
	 * Expect: 
	 * 
	 * 5 open logs -> access_type = 1, is_action_denied = 0,
	 * 		          fingerprint = same for every one (mode = "w")
	 * 125 write logs -> access_type = 2, is_action_denied = 0,
	 * 				     fingerprint = different
	 * 
	 * TOTAL = 30 logs
	 * 
	*/
	for(i = 0; i < 5; i++){
		file = fopen(read_write_files[i], "a");
		if(file == NULL) continue;
		for(int j=0; j<25; j++) fwrite(read_write_files[i], 1, strlen(read_write_files[i]), file);
		fclose(file);
	}

	/*						   8.
	 *
	 *						FAKE DATA
     *
	 * 					    MALICIOUS
     *
	 * Put inside the file_logging.log fake data with the correct format
	 * so we have another user with UID = 1777, that has does some malicious stuff :)
	 * 8 different filenames, and 8 malicious distinct attemps
	 * 
	 * Note: I use open, fdopen, fprintf so we do not make logs for this fake data :)
	 * 
	 * Expect: 
	 * 
	 * 8 write logs -> access_type = 2, is_action_denied = 1
	 * 				   fingerprint = "0".
	 * 
	 * TOTAL = 8 (FAKE) logs
	 * 
	*/

	int fd = open(logging_file, O_RDWR|O_APPEND);
	file = fdopen(fd, "a");

	char fake_path[200] = "/home/FAKE/PATH/FAKE/PATH/FAKE/PATH/SUCH_A_FAKE/PATH/FAKE/PATH";
	char str_i[3];

	for(i=0; i < 8; i++){
		sprintf(str_i, "%d", i); //convert i string
		strcat(fake_path, str_i); //concatenate the strings so we have a different path

		fprintf(file, "%u %s %s %s %d %d %s\n",
		   	    1777, fake_path, "2025-11-26", "00:30:21", 2, 1, "0");
	}

	fclose(file);
	close(fd);




}
