#!/bin/zsh

###
## Faraday Penetration Test IDE - Community Version
## Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
## See the file 'doc/LICENSE' for the license information
###

#ZDOTDIR="~/.faraday/zsh/" /bin/zsh
FARADAYZDOTDIR="$HOME/.faraday/zsh/"
OLDZDOTDIR=$ZDOTDIR
ZDOTDIR=$FARADAYZDOTDIR /bin/zsh
#source ~/.faraday/zsh/.zshrc 
