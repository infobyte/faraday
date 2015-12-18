#!/bin/zsh

###
## Faraday Penetration Test IDE
## Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
## See the file 'doc/LICENSE' for the license information
###

#ZDOTDIR="~/.faraday/zsh/" /bin/zsh
FARADAY_ZSH_RPORT="9977"
FARADAY_ZSH_HOST="127.0.0.1"
if [ $# -eq 2 ]; then
    FARADAY_ZSH_HOST=$1
    FARADAY_ZSH_RPORT=$2
else
    if [ $# -gt 2 ] || [ $# -eq 1 ]; then
        echo "[*] Usage $0 host port"
        echo "[*] Usage $0 127.0.0.1 9977"
        exit
    else
        echo "[!] Using default configuration" $FARADAY_ZSH_HOST:$FARADAY_ZSH_RPORT
    fi
fi

export FARADAY_ZSH_RPORT
export FARADAY_ZSH_HOST
FARADAYZDOTDIR="$HOME/.faraday/zsh/"
OLDZDOTDIR=$ZDOTDIR
ZDOTDIR=$FARADAYZDOTDIR /bin/zsh

#source ~/.faraday/zsh/.zshrc
