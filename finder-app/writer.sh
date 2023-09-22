#!/bin/bash

# check on number of args
if [ $# -ne 2 ]; then
        echo "Error: wrong number of arguments"
        echo "Usage: $0 <path-to-directory> <search-string>"
        exit 1
fi

FILE_PATH=$1
FILE_NAME=$(basename ${FILE_PATH})
DIR_PATH=$(dirname ${FILE_PATH})
WRITE_STR=$2

# create direcotory path
mkdir -p ${DIR_PATH}
if [ $? -ne 0 ]; then
	echo "Error: unable to create directory ${DIR_PATH}"
fi

# create file
touch ${FILE_PATH}
if [ $? -ne 0 ]; then
	echo "Error: unable to create file ${FILE_NAME}"
fi

# write file
echo ${WRITE_STR} >> ${FILE_PATH}
