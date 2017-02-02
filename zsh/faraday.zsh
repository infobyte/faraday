#'''
#Faraday Penetration Test IDE
#Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
#See the file 'doc/LICENSE' for the license information
#
#'''

WORKSPACE=`cat $HOME/.faraday/config/user.xml |  grep '<last_workspace' | cut -d '>' -f 2 | cut -d '<' -f 1`
STATUS=`curl -s $FARADAY_ZSH_HOST:$FARADAY_ZSH_RPORT/status/check |  sed "s/[^0-9]//g" | grep -v '^[[:space:]]*$'`
USERPS1=$PS1
PS1="%{${fg_bold[red]}%}[faraday]($WORKSPACE)%{${reset_color}%} $USERPS1"
export FARADAY_OUTPUT=
export FARADAY_PLUGIN=
alias faraday_b64='base64 -w 0'

if [[ $(uname) == 'Darwin' ]]; then
     alias faraday_b64='base64'
fi

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

old_cmd=

function add-output() {
    old_cmd=$BUFFER
	FARADAY_PLUGIN=
    FARADAY_OUTPUT=
    pwd_actual=$(printf "%s" "$(pwd)"| faraday_b64)
    cmd_encoded=$(printf "%s" "$BUFFER"| faraday_b64)
	json_response=`curl -s -X POST -H "Content-Type: application/json" -d "{\"cmd\": \"$cmd_encoded\", \"pid\": $$, \"pwd\": \"$pwd_actual\"}" http://$FARADAY_ZSH_HOST:$FARADAY_ZSH_RPORT/cmd/input`
    if [[ $? -eq 0 ]]; then
		code=`echo $json_response|env python2.7 -c "import sys, json;print(json.load(sys.stdin)[\"code\"])"`
		if [[ "$code" == "200" ]]; then
			FARADAY_PLUGIN=`echo $json_response | env python2.7 -c "import sys, json; print(json.load(sys.stdin)[\"plugin\"])"`
			new_cmd=`echo $json_response | env python2.7 -c "import sys, json; print(json.load(sys.stdin)[\"cmd\"])"`
	        if [[ "$new_cmd" != "None" ]]; then
	            BUFFER=" $new_cmd"
		    fi
            FARADAY_OUTPUT=`mktemp tmp.XXXXXXXXXXXXXXXXXXXXXXXXXXXXX`
            BUFFER="$BUFFER 2>&1 | tee -a $FARADAY_OUTPUT"
		fi
	fi
    zle .accept-line "$@"
}

function send-output() {
    if [ ! -z "$FARADAY_PLUGIN" ]; then
		output=`env python2.7 -c "import base64; print(base64.b64encode(open(\"$FARADAY_OUTPUT\",'r').read()))"`
        temp_file=`mktemp tmp.XXXXXXXXXXXXXXXXXXXXXXXXXXXXX`
        echo "{\"exit_code\": $?, \"pid\": $$, \"output\": \"$output\" }" >> $temp_file
        curl=`curl -s -X POST -H "Content-Type: application/json" -d @$temp_file http://$FARADAY_ZSH_HOST:$FARADAY_ZSH_RPORT/cmd/output`
        rm -f $temp_file
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
    PS1="%{${fg_bold[red]}%}[faraday]($WORKSPACE)%{${reset_color}%} $USERPS1"
    return 0
}

zshexit() {
    send-output
}

if [ -n "${FARADAY_PATH+x}" ]; then
    echo "[+] Faraday path set. Aliasing fplugin"

    function fplugin() {
     "$FARADAY_PATH/bin/fplugin" $*;
     }
else
    echo "[-] Faraday path not set"
fi

zle -N accept-line add-output
