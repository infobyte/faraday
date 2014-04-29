#'''
#Faraday Penetration Test IDE - Community Version
#Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
#See the file 'doc/LICENSE' for the license information
#
#'''

echo ">>> WELCOME TO FARADAY"
PS1="%{${fg_bold[red]}%}[faraday]%{${reset_color}%} $PS1"

setopt multios
setopt histignorespace

plugin_controller_client=$ZDOTDIR/plugin_controller_client.py
old_cmd=

add-output() {
    old_cmd=$BUFFER
    new_cmd=`python2 $plugin_controller_client send_cmd $BUFFER`
    BUFFER=" $new_cmd"
    zle .accept-line "$@"
}

function zshaddhistory() {
    emulate -L zsh
    print -sr -- "$old_cmd"
    fc -p
    return 1
}

zle -N accept-line add-output
