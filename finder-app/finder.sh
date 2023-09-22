#!/bin/bash

# check on number of args
if [ $# -ne 2 ]; then
        echo "Error: wrong number of arguments"
        echo "Usage: $0 <path-to-directory> <search-string>"
        exit 1
fi

FILES_DIR=$1
SEARCH_STR=$2

# check on directory path
if ! [ -d ${FILES_DIR} ]; then
        echo "Error: ${FILES_DIR} not a directory"
        exit 1
fi

# count number of files in directory
FILES_LIST=$(ls ${FILES_DIR})
FILES_NUM=$(ls ${FILES_DIR} | wc -l)
MATCH_NUM=$(grep --recursive "${SEARCH_STR}" ${FILES_DIR} | wc -l)

echo "The number of files are ${FILES_NUM} and the number of matching lines are ${MATCH_NUM}"


