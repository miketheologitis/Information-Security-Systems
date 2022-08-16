
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <time.h>

//maximum absolute path length
//please change it if for some reason 300 chars is not enough!
//(if so, also change it in logger.c)
#define MAX_PATH_LEN 600

//the maximum number of distinct UIDs in the log file. Change it 
//as you wish.
#define MAX_DISTINCT_USERS 50

const char logging_file[] = "file_logging/file_logging.log";

typedef struct entry_info {

	uid_t uid; /* user id */
	int access_type; /* access type values [0-2] */
	int action_denied_flag; /* is action denied values [0-1] */

	char date[11]; /* file access date (string) */
	char time[9]; /* file access time (string) */

	char abs_path[MAX_PATH_LEN]; /* filename (string) */
	char fingerprint[33]; /* file fingerprint (string)*/


}entry_info;


typedef struct user {
	uid_t uid;
	int malicious_attempts; //malicious attempt on DISTINCT files 
}user;


void
usage(void)
{
	printf(
	       "\n"
	       "Usage:\n"
	       "    ./acmonitor -m -i file_directory/filename -v number_of_files -e\n"
		   "Options:\n"
		   "    -i <file_directory/filename>   Prints all users that modified the <filename>\n"
		   "                                   and the number of modifications.\n"
		   "                                   It's really IMPORTAND to put the input in this\n"
		   "                                   exac manner. <file_directory> is the directory\n"
		   "                                   in which the <filename> file is/was stored.\n"
		   "                                   So, the input is expected as: <file_directory/filename>\n\n"
		   "    -v <number of files>           Prints the total number of files created in \n"
		   "                                   the last 20 minutes. if this number is smaller\n"
		   "                                   than the <number of files>, then this does not \n"
		   "                                   indicate a suspicious behavior. Othwerwise,\n"
		   "                                   it is suspicious\n\n"
		   "    -e                             Prints all the unencrypted files that were opened\n"
		   "                                   by the ransomware and then were encrypted.\n\n"
		   "    -h                             Help message\n"
		   "Examples:\n"
		   "    ./acmonitor -m -i file_directory/filename -v 100 -e\n"
		   "    ./acmonitor -v 20 -e\n"
		   "    ./acmonitor -m -v 100 -e\n"
		   "    ./acmonitor -i file_directory/filename -v 100\n"
		   "    ./acmonitor -e\n\n"
		   );
	exit(1);
}


int find_index_of_distinct_user(user* distinct_users, int number_of_distinct_users, uid_t uid){
	for(int i=0; i<number_of_distinct_users; i++){
		if(distinct_users[i].uid == uid) return i;
	}
	return -1; //impossible
}

void print_malicious_users(user* distinct_users, int number_of_distinct_users){
	printf("\nMALICIOUS ATTEMPTS (on different files) > 7\n");
	printf("*******************************************\n");
	for(int i=0; i<number_of_distinct_users; i++){
		if(distinct_users[i].malicious_attempts > 7)
		printf("User: %4u  Malicious Attempts: %d\n", distinct_users[i].uid, distinct_users[i].malicious_attempts);
	}
	printf("*******************************************\n\n");
}

void print_file_modifications(user* distinct_users, int number_of_distinct_users, int* user_file_modifications){
	printf("\n    ALL USER MODIFICATIONS FOR THE FILE\n");
	printf("*******************************************\n");
	for(int i=0; i<number_of_distinct_users; i++){
		printf("User: %4u  Modifications: %d\n", distinct_users[i].uid, user_file_modifications[i]);
	}
	printf("*******************************************\n\n");
}

void print_num_of_files_created_last_20minutes(int file_creations, int sus_bound){
	printf("\n               FILE CREATIONS               \n");
	printf("*************************************************\n");
	if(file_creations >= sus_bound) //then it is suspicious :(
		printf("Number Of File Creations Last 20 minutes: %d     SUSPICIOUS (>= %d)\n", file_creations, sus_bound);
	else
		printf("Number Of File Creations Last 20 minutes: %d     NOT SUSPICIOUS (< %d)\n", file_creations, sus_bound);
	printf("*************************************************\n\n");
}

void print_encr_files_menu(int flag){
	if(flag){
		printf("\n           ALL FILES THAT WERE ENCRYPTED BY THE RANSOMWERE              \n");
		printf("**************************************************************************\n");
	}
	else{
		printf("**************************************************************************\n\n");
	}
}
/*
 * Allocates for an entry_info struct, reads the entry, and returns the pointer to it.
 *
*/
entry_info* read_log_entry(FILE *log){

	entry_info* entry = malloc(sizeof(entry_info));

	int ret = fscanf(log, "%u %s %s %s %d %d %s\n", 
		   		     &entry->uid, entry->abs_path, entry->date,
					 entry->time, &entry->access_type, &entry->action_denied_flag,
					 entry->fingerprint);

	if(ret == EOF){
		free(entry);
		return NULL;
	}

	return entry;
}

/*
 * Finds all the distinct users inside the log file. And returns the array "distinct_users"
 * with all the distinct struct user data we find.
 *  
 * Distinct user: Every user with a specific UID is considered distinct and will be put
 * 				  only ONCE in the "distinct_users" 
 * struct user: This is how my implementation stores each user inside the "distinct_users"
 * 
 * The idea is we have two file pointers. The log_1, log_2. The log_1 starts reading the entries
 * entry_1 of the log file from the start to the end. For each entry_1 the log_2 parses
 * all the entries entry_2 starting from the NEXT entry after entry_1 to the end. So for each iteration 
 * log_2's stream starts from ftell(log_1) position and parses onward. If it finds the entry_1->uid
 * (meaning finds entry_2->uid == entry_1->uid) this means that the entry_1->uid exists somewhere
 * infront of the current log_1 position and we break. In case we do not find the entry_1->uid
 * somewhere infront (entry_2 becomes NULL since it reaches the end), 
 * this means that the entry_1->uid is ready to be stored as a distinct user.
 * 
 * The implementation is O(N^2) which is bad, but I could not think of something better in C.
 * 
 * returns: the "distinct_user" array with all the distinct users (with distinct UID i mean)
 * 			Also "returns" the number_of_distinct_users it found through a pointer.
 *
*/
user* find_distinct_users(int *number_of_distinct_users){
	FILE* log_1 = fopen(logging_file, "r");
	FILE* log_2 = fopen(logging_file, "r");

	entry_info* entry_1;
	entry_info* entry_2;

	user* distinct_users = malloc(MAX_DISTINCT_USERS*sizeof(user));
	*number_of_distinct_users = 0;

	while((entry_1 = read_log_entry(log_1)) != NULL){ //for this entry uid, find if it is distinct
		
		fseek(log_2, ftell(log_1), SEEK_SET); // start log_2 from where log_1 is and forward

		while((entry_2 = read_log_entry(log_2)) != NULL){
			//if the entry_1->uid is found somewhere infront, then dont add it to distinct yet.
			if(entry_1->uid == entry_2->uid) break;

		}
		//means we didnt break (we didn't find entry_1->uid infront anywhere, so it is distinct)
		if(entry_2 == NULL){ 
			distinct_users[*number_of_distinct_users].uid = entry_1->uid;
			distinct_users[*number_of_distinct_users].malicious_attempts = 0;
			(*number_of_distinct_users)++;
		}
		
	}
	fclose(log_1);
	fclose(log_2);
	return distinct_users;
}

/*
 * Same idea with find_distinct_users(). Please read the above comments
 * 
*/
void 
list_unauthorized_accesses(user* distinct_users, int number_of_distinct_users)
{

	FILE* log_1 = fopen(logging_file, "r");
	FILE* log_2 = fopen(logging_file, "r");

	entry_info* entry_1;
	entry_info* entry_2;

	int index_of_distinct_user;


	while((entry_1 = read_log_entry(log_1)) != NULL){ 

		//only investigate entries with action denied flag = 1
		if(!entry_1->action_denied_flag) continue;

		index_of_distinct_user = find_index_of_distinct_user(distinct_users, number_of_distinct_users, entry_1->uid);
		
		fseek(log_2, ftell(log_1), SEEK_SET); // start log_2 from where log_1 is and forward

		while((entry_2 = read_log_entry(log_2)) != NULL){
			//if its the same file, and the same user, and also entry_2->action_denied_flag = 1, then 
			//there exists a malicious attempt on the same file, so break because it is not distinct (we will count it later)
			if(!strcmp(entry_1->abs_path, entry_2->abs_path) && entry_2->action_denied_flag && entry_1->uid == entry_2->uid) break;

		}
		//means we didnt break (we didn't find the same file, for the same user,
		//with action denied flag = 1 so it is distinct and we have to count it)
		if(entry_2 == NULL){ 
			distinct_users[index_of_distinct_user].malicious_attempts++;
		}
	}
	fclose(log_1);
	fclose(log_2);

	print_malicious_users(distinct_users, number_of_distinct_users);

	return ;
}

/*
 * 
 * Definition of file modification in my implementation:
 * A file modification, for given file "file_to_scan", is when the fingerprint of the file
 * in an entry is different from the last seen fingerprint of this file in the logs, and
 * the entry has access_type = 2 (for write). So, no opens are considered as file change.
 * 
 * The idea is simple. For each distinct user, find the file modifications he did on
 * the specific file. We have a variable last_file_fingerprint and we parse through
 * the log file and we set last_file_fingerprint when we see the file. In case the distinct
 * user is responsible for its' change, then ++.
 * 
 * The one "problem":
 * 1. A user might call fopen() with mode = "w", "w+", "wb" etc and NEVER use an fwrite().
 *    The fopen() call will truncate the file to 0 length and possibly change the fingerprint
 *    (if there was something in there before). I do not count this as a modification
 *    because we do not have enough information. I won't get into details about this, 
 *    but if you really think about it there are a few reasons we cannot do something about it
 *    with the current information.
 * 
*/
void
list_file_modifications(user* distinct_users, int number_of_distinct_users, char *file_to_scan)
{

	FILE* log = fopen(logging_file, "r");

	entry_info* entry;

	//user_file_modifications[i] corresponds to the number of modifications the user
	//distinct_users[i] has done.
	int user_file_modifications[number_of_distinct_users];
	for(int i=0; i<number_of_distinct_users; i++) user_file_modifications[i] = 0; //start all 0

	//last_file_fingerprint is the file_to_scan fingerprint
	//before the user in each loop accessed it. Obviously the user can 
	//be the first to access it, but this will be dealt with bellow.
	char* last_file_fingerprint = NULL;

	char abs_path[MAX_PATH_LEN];
	getcwd(abs_path, MAX_PATH_LEN);
	abs_path[strlen(abs_path)] = '/';
	strcat(abs_path, file_to_scan);

	user tmp_user;

	int count = 0;

	for(int i = 0; i<number_of_distinct_users; i++){ //for each user

		tmp_user = distinct_users[i];

		while((entry = read_log_entry(log)) != NULL){  //for each entry

			if(!strcmp(entry->abs_path, abs_path)){ //if we found an occurance of the file
				//first occurance we can do nothing more than store it 
				//(because we have no previous info about it)
				if(last_file_fingerprint == NULL) { 
					last_file_fingerprint = entry->fingerprint;
					continue;
				}
				//if it is about the user we are invastigating, and also the file fingerprint
				//has changed since it was last seen, then it was the user who is responsible
				//and also we need to have a write log entry. 
				if(entry->uid == tmp_user.uid && strcmp(entry->fingerprint, last_file_fingerprint) != 0 &&
				   entry->access_type == 2){ 
					user_file_modifications[i]++;
				}
				last_file_fingerprint = entry->fingerprint;

			}
		}
		rewind(log); //return to the start for the next user;
		last_file_fingerprint = NULL; //reset this too
	}

	fclose(log);

	print_file_modifications(distinct_users, number_of_distinct_users, user_file_modifications);

	return ;

}
/*
 * Finds the number of files created in the last 20 minutes
 *
 * Note: Iff a file gets deleted and then recreated with the
 * same name again, I obviously count it again as another file creation.
*/
void num_of_files_created_last_20minutes(char* optarg)
{
	FILE* log = fopen(logging_file, "r");

	struct tm tmp_tm_info; //for each entry the time info

	time_t curr_epoch = time(NULL); //curr time relative to epoch

	time_t tmp_epoch; //tmp entry time relative to epoch

	double sec_diff; //will be the seconds diff of curr_epoch and tmp_epoch

	double sec_of_20mins = 20*60; 

	entry_info* entry;

	unsigned int file_creations = 0; //number of file creations

	while((entry = read_log_entry(log)) != NULL){  //for each entry

		if(entry->access_type == 0){ //means file creation
			sscanf(entry->date, "%d-%d-%d", &tmp_tm_info.tm_year, &tmp_tm_info.tm_mon, &tmp_tm_info.tm_mday);
			sscanf(entry->time, "%d:%d:%d", &tmp_tm_info.tm_hour, &tmp_tm_info.tm_min, &tmp_tm_info.tm_sec);

			tmp_tm_info.tm_year -= 1900; //fix year (relative to epoch)
			tmp_tm_info.tm_mon -= 1; //fix month (0-11)

			tmp_epoch = mktime(&tmp_tm_info);

			/*function returns the number of seconds elapsed
       		between time tmp_epoch and curr_epoch */
			sec_diff = difftime(tmp_epoch, curr_epoch);

			//if the file was created last 20 minutes then ++
			if(sec_diff <= sec_of_20mins) file_creations++;
			else printf("\nI AM HERE\n");
		}
	}

	fclose(log);

	print_num_of_files_created_last_20minutes(file_creations, (int)strtol(optarg, NULL, 10));
}

/*
 *
 * Remove substring <sub> from string <str> and return <str>
 * 
*/
char *strremove(char *str, const char *sub) {
    size_t len = strlen(sub);
    if (len > 0) {
        char *p = str;
        while ((p = strstr(p, sub)) != NULL) {
            memmove(p, p + len, strlen(p + len) + 1);
        }
    }
    return str;
}

/*
 *
 * Prints all the files that were opened and then encrypted 
 * by the ransomwere.
 * 
*/
void list_encrypted_files()
{
	FILE* log = fopen(logging_file, "r");

	entry_info* entry;

	//last opened file is the last NOT encrypted file that was opened
	char* last_opened_file = NULL; 

	char buffer[MAX_PATH_LEN];

	print_encr_files_menu(1);

	int count = 1;

	while((entry = read_log_entry(log)) != NULL){  //for each entry
		//last opened file
		if((entry->access_type == 1) && (strstr(entry->abs_path, ".encrypt") == NULL)){
			last_opened_file = entry->abs_path;
			continue;
		}
		//if this is a file creation, it is an .encrypt file, and also the path is equal
		//to the last opened (unecrypted) file, then print this file because it became encrypted
		if((entry->access_type == 0) && (strstr(entry->abs_path, ".encrypt") != NULL) &&
		   !strcmp(last_opened_file, strremove(entry->abs_path, ".encrypt")))
		{
			printf("%5d.  %s\n", count, last_opened_file);
			count++;
		}
	}

	fclose(log);

	print_encr_files_menu(0);

}



int 
main(int argc, char *argv[])
{

	int ch;
	
	if (argc < 2)
		usage();

	int number_of_distinct_users;
	user* distinct_users = find_distinct_users(&number_of_distinct_users);

	while ((ch = getopt(argc, argv, "v:hei:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(distinct_users, number_of_distinct_users, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(distinct_users, number_of_distinct_users);
			break;
		case 'v':
			num_of_files_created_last_20minutes(optarg);
			break;
		case 'e':
			list_encrypted_files();
			break;	
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;	
	
	return 0;
}
