#'''
#Faraday Penetration Test IDE
#Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
#See the file 'doc/LICENSE' for the license information
#
#'''

WORKSPACE=`cat $HOME/.faraday/config/user.xml |  grep '<last_workspace' | cut -d '>' -f 2 | cut -d '<' -f 1`
STATUS=`curl -s $FARADAY_ZSH_HOST:$FARADAY_ZSH_RPORT/status/check |  sed "s/[^0-9]//g" | grep -v '^[[:space:]]*$'`
PS1="%{${fg_bold[red]}%}[faraday]($WORKSPACE)%{${reset_color}%} $PS1"
export FARADAY_OUTPUT=
export FARADAY_PLUGIN=

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

function add-output() {
    old_cmd=$BUFFER
	FARADAY_PLUGIN=
    FARADAY_OUTPUT=
	json_response=`curl -s -X POST -H "Content-Type: application/json" -d "{\"cmd\": \"$BUFFER\", \"pid\": $$}" http://$FARADAY_ZSH_HOST:$FARADAY_ZSH_RPORT/cmd/input`
    if [[ $? -eq 0 ]]; then
		code=`echo $json_response | env python2.7 -c "import sys, json; print(json.load(sys.stdin)[\"code\"])"`
		if [[ "$code" == "200" ]]; then
			FARADAY_PLUGIN=`echo $json_response | env python2.7 -c "import sys, json; print(json.load(sys.stdin)[\"plugin\"])"`
			new_cmd=`echo $json_response | env python2.7 -c "import sys, json; print(json.load(sys.stdin)[\"cmd\"])"`
	        if [[ "$new_cmd" != "null" ]]; then
	            BUFFER=" $new_cmd"
	            FARADAY_OUTPUT=`mktemp`
	            BUFFER="$BUFFER >&1 >> $FARADAY_OUTPUT"

		    fi
		fi
	fi
    zle .accept-line "$@"
}

function send-output() {
    if [ ! -z "$FARADAY_PLUGIN" ]; then
		output=`env python2.7 -c "import base64; print(base64.b64encode(open(\"$FARADAY_OUTPUT\",'r').read()))"`
        curl -s -X POST -H "Content-Type: application/json" -d "{\"exit_code\": \"$?\", \"pid\": \"$$\", \"output\": \"$output\" }" http://$FARADAY_ZSH_HOST:$FARADAY_ZSH_RPORT/cmd/output
    fi
	if [ -f $FARADAY_OUTPUT ];then
		rm -f $FARADAY_OUTPUT
	fi
    FARADAY_OUTPUT=
    FARADAY_PLUGIN=
}

zshaddhistory() {
    emulate -L zsh
    print -sr -- "$old_cmd"
    fc -p
    return 1
}

precmd() {
    send-output
    WORKSPACE=`cat $HOME/.faraday/config/user.xml |  grep '<last_workspace' | cut -d '>' -f 2 | cut -d '<' -f 1`
    return 0
}

zshexit() {
    send-output
}

zle -N accept-line add-output
