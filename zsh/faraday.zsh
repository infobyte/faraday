#'''
#Faraday Penetration Test IDE
#Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
#See the file 'doc/LICENSE' for the license information
#
#'''

WORKSPACE=`cat $HOME/.faraday/config/user.xml |  grep '<last_workspace' | cut -d '>' -f 2 | cut -d '<' -f 1`
STATUS=`curl -s $FARADAY_ZSH_HOST:$FARADAY_ZSH_RPORT/status/check |  sed "s/[^0-9]//g" | grep -v '^[[:space:]]*$'`
PS1="%{${fg_bold[red]}%}[faraday]($WORKSPACE)%{${reset_color}%} $PS1"
FARADAY_OUTPUT=
FARADAY_PLUGIN=

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
    json_response=`$plugin_controller_client send_cmd $$ $BUFFER`
	FARADAY_PLUGIN=
	FARADAY_OUTPUT=

	if [ "$json_response" != "" ]; then
		new_cmd=`python -c 'import json;print(json.loads($json_response))["cmd"]'`
		if [ "$new_cmd" != "null" ]; then
			BUFFER=" $new_cmd"
			FARADAY_OUTPUT = `$plugin_controller_client gen_output $$`
			BUFFER = $BUFFER + " >&1 > $OUTPUT"
		FARADAY_PLUGIN=`python -c 'import json;print(json.loads($json_response))["plugin"]'`

	zle .accept-line "$@"
}

send-output(){
	if [ ! -z "$FARADAY_PLUGIN" ]; then
		`$plugin_controller_client send_output $$ $? $FARADAY_OUTPUT`
	fi

	FARADAY_OUTPUT=
	FARADAY_PLUGIN=
}

function zshaddhistory() {
    emulate -L zsh
    print -sr -- "$old_cmd"
    fc -p
    return 1
}

function precmd(){
	WORKSPACE=`cat $HOME/.faraday/config/user.xml |  grep '<last_workspace' | cut -d '>' -f 2 | cut -d '<' -f 1`
	send-output()
}

function zshexit(){
	send-output()
}

zle -N accept-line add-output
