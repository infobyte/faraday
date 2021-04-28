#!/bin/sh
# Check that a white branch doesn't contain commits of pink or black
# and a pink branch has no black commits
# Requires setting BRANCH_NAME environment variable
PROF_COMMIT=da7a869e186f61f1b138392734be4eae62cb2e31  # Always redirect to login page when user is logged out
CORP_COMMIT=ec3dcfbe8955d41125944e82aa084b441c0b9e77  # Fix msg in webshell

if [ $CI_COMMIT_REF_NAME ]; then
   BRANCH_NAME=$CI_COMMIT_REF_NAME
else
   BRANCH_NAME=$(git rev-parse --abbrev-ref HEAD)
fi

fail(){
    echo "Branch $BRANCH_NAME contains commit of another version ($1). You shouldn't do that!!!!!!"
    exit 1
}

check_no_commits(){
    # Check that current branch doesn't contain the commits passed as arguments
    # If it does contain at least one of then, quit the script with a non-zero exit code
    for commit in $*
    do
        git branch --all --contains "$commit" | grep "$BRANCH_NAME" && fail $commit
    done
}

echo current branch $(git rev-parse --abbrev-ref HEAD) should be equal to $BRANCH_NAME
echo $BRANCH_NAME | grep -i white && check_no_commits $PROF_COMMIT $CORP_COMMIT
exit 0
