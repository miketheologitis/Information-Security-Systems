GCC version : gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0
Author: Michail Theologitis
AM: 2017030043

**************************Usage*************************************

test_aclog.c , logger.c

>
>make clean
>make
>make run

My test_acloc.c will create one folder "file_testing" with 20
different files, with different permissions inside. 15 created with
open() with custom permissions for testing, and 5 created with fopen().

From the first fopen(), logger.c will create one folder "file_logging"
which will have the "file_logging.log" file inside, with the correct
accessibility permissions to user/group/others for both the folder 
and the file as it was asked in the assignment.



acmonitor.c 

>
>./acmonitor -m -i file_testing/file_read_write_1


Please remember that the testing files are inside a folder so when you
do your own tests remember to put "file_testing/XXX" where XXX is the file
you want to open in my "file_testing" folder.


Be wary, that I some read-only files, and some write-only files. In both 
types of files, acmonitor.c will find 0 file modifications for 
obvious reasons :)


***********************General*******************************************

Inside the test_aclog.c program, where the testing happens there are
extensive comments, and precalculations of what to expect to see as 
results in the file_logging.log file. These comments are really well
made and very tidy, so I think there is no reason to explain anything
more here.

Whatever happens in test_aclog.c for testing is numbered from 1. to 8.
and explained very thoroughly.

Note: You will read this in the general test_aclog.c comment for testing
      but I want to mention it here aswell. I put inside the file_logging.log
      data that are FAKE. This happens in the (8.) number of testing.
      This data puts a malicious user with UID = 1777 and this user "does"
      8 malicious attempts on different FAKE files. As I said, the data
      is fake and was put inside the file_logging.log with open() , fdopen()
      to avoid more fopen() logs. So you will see the UID = 1777 in results using the 
      acmonitor.c . If this is something you do not want, then just comment out
      the (8.) section of testing inside the test_aclog.c file.

My code is filled with comments and there is an explanation for almost every
function at the start, and almost each line of code! So there is nothing more
to say in this README.txt


Lastly, everything runs perfectly.

