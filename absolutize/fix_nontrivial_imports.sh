CLIENT_IMPORTED="managers.mapper_manager model.api model.common model.controller model.guiapi model.log persistence.server.server plugins.controller"  # I assume there are no "import ... as ..."
OTHER_IMPORTED="server.config server.utils.logger server.web"  # I assume there are no "import ... as ..."

echo -n "This will mess most of the python files of the repo. Are you sure you have a clean git dir? (Type uppercase yes): "
read ANSWER
if [[ "$ANSWER" != "YES" ]]
then
    exit 1
fi

replace_occurences(){
    CURRENT_MODULE_NAME=$1
    TARGET_MODULE_NAME=$2
    FILE=$3
    echo $FILE
    sed -Ei "/$TARGET_MODULE_NAME/! s/\<$CURRENT_MODULE_NAME\>/$TARGET_MODULE_NAME/g" $FILE
}

for MODULE in $OTHER_IMPORTED
do
    for FILE in $(git grep --name-only -E "^\s*import (faraday\.)?$MODULE")
    do
        replace_occurences $MODULE faraday.$MODULE $FILE
    done
done

for MODULE in $CLIENT_IMPORTED
do
    for FILE in $(git grep --name-only -E "^\s*import (faraday\.)?$MODULE")
    do
        replace_occurences $MODULE faraday.client.$MODULE $FILE
    done
done

