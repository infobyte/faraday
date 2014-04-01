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
    new_cmd=`python2 $plugin_controller_client send_cmd $BUFFER`
    BUFFER="$new_cmd"
    zle .$WIDGET "$@"
}

zle -N accept-line add-output
