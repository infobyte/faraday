#'''
#Faraday Penetration Test IDE - Community Version
#Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
#See the file 'doc/LICENSE' for the license information
#
#'''

echo "WELCOME MY FRIEND"
alias nmap_test="nmap -A -T4"

autoload -U add-zsh-hook
setopt multios
#zle -N accept-line
#if 

hook_function()
{
    echo $3
}

add-zsh-hook preexec hook_function

add-output() {
    echo "BUFFER:" $BUFFER
    #[[ $BUFFER = grc* ]] || BUFFER="grc $BUFFER"; zle .$WIDGET "$@"; 
    BUFFER="$BUFFER >&1 > output.txt"
    zle .$WIDGET "$@"
}

zle -N accept-line add-output