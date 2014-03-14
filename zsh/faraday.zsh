#'''
#Faraday Penetration Test IDE - Community Version
#Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
#See the file 'doc/LICENSE' for the license information
#
#'''

echo ">>> WELCOME TO FARADAY"

setopt multios

plugin_controller_client=$ZDOTDIR/plugin_controller_client.py

add-output() {
    output=`python2 $plugin_controller_client get_cmd $BUFFER`
    response=("${(f)output}")
    echo $response

    # if [ ! -z $output ]; then
    #     if [[ $output == "default" ]]; then
    #         output=">&1 > output.txt"
    #     fi
    #     # else
    #     #     BUFFER="$BUFFER $output"
    #     # fi

    #     BUFFER="$BUFFER $output && $plugin_controller_client send_output $output"
    # fi
    zle .$WIDGET "$@"
}

zle -N accept-line add-output
