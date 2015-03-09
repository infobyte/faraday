#'''
#Faraday Penetration Test IDE
#Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
#See the file 'doc/LICENSE' for the license information
#
#'''


WORKSPACE=`cat $HOME/.faraday/config/user.xml |  grep '<last_workspace' | cut -d '>' -f 2 | cut -d '<' -f 1`
STATUS=`curl -s 127.0.0.1:9977/status/check |  sed "s/[^0-9]//g" | grep -v '^[[:space:]]*$'`
PS1="%{${fg_bold[red]}%}[faraday]($WORKSPACE)%{${reset_color}%} $PS1"

echo ">>> WELCOME TO FARADAY"
echo "[+] Current Workspace: $WORKSPACE"
if [[ -z $STATUS ]]; then
		echo "[-] API: Warning API unreachable"
	
	elif [[ $STATUS == "200" ]]; then	 
		echo "[+] API: OK"
	else	
		echo "[!] API: $STATUS"	
	
fi

setopt multios
setopt histignorespace

plugin_controller_client=$HOME/.faraday/zsh/plugin_controller_client.py
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
