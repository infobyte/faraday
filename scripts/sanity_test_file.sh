#!/bin/sh
# Check that a white branch doesn't contain commits of pink or black
# and a pink branch has no black commits
# Requires setting BRANCH_NAME environment variable
PINK_FILE=faraday/server/api/modules/reports.py
BLACK_FILE=faraday/server/api/modules/jira.py

if [ $CI_COMMIT_REF_NAME ]; then
   BRANCH_NAME=$CI_COMMIT_REF_NAME
else
   BRANCH_NAME=$(git rev-parse --abbrev-ref HEAD)
fi

function fail(){
    echo "Branch $BRANCH_NAME contains file of another version ($1). You
    shouldn't do that!!!!!!"
    exit 1
}


function check_no_files(){
    # Check that current branch doesn't contain the files passed as arguments
    # If it does contain at least one of then, quit the script with a non-zero exit code
    for file in $*
    do
        for new_file in $(git diff --cached --name-status | awk '$1 != "D" {
        print $2 }')
        do
          echo trying $file and $new_file
          test $file == $new_file && fail $file
        done
    done
}

echo current branch $(git rev-parse --abbrev-ref HEAD) should be equal to $BRANCH_NAME
echo $BRANCH_NAME | grep -i white && check_no_files $PINK_FILE $BLACK_FILE
echo $BRANCH_NAME | grep -i pink && check_no_files $BLACK_FILE
exit 0
