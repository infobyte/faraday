#!/usr/bin/env bash

CLIENT_ROOTS="(apis|bin[^a]|data|gui|helpers|managers|model[^s]|persistence|plugins)"
OTHER_ROOTS="(migrations|server|utils|config[^p]|reports)"

if [[ "$1" ]]
then
    FILES="$1"
else
    FILES="$(git ls-files | egrep '\.py$')"
fi

echo -n "This will mess most of the python files of the repo. Are you sure you have a clean git dir? (Type uppercase yes): "
read ANSWER
if [[ "$ANSWER" != "YES" ]]
then
    exit 1
fi

for PYFILE in $FILES
do
    echo $PYFILE
    sed -Ei "s/^(\s*)from $CLIENT_ROOTS/\1from faraday.client.\2/" $PYFILE
    sed -Ei "s/^(\s*)from $OTHER_ROOTS/\1from faraday.\2/" $PYFILE
    sed -Ei "/ as / { s/^(\s*)import $CLIENT_ROOTS/\1import faraday.client.\2/; }" $PYFILE
    sed -Ei "/ as / { s/^(\s*)import $OTHER_ROOTS/\1import faraday.\2/; }" $PYFILE
    sed -Ei "/__version__/! s/^(\s*)from faraday import/\1from faraday.client.start_client import/" $PYFILE
done

