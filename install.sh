#!/bin/bash
###
## Faraday Penetration Test IDE
## Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
## See the file 'doc/LICENSE' for the license information
###

#Check if is it root
if [ $EUID -ne 0 ]; then
 echo "You must be root."
 exit 1
fi

update=0

#os detection
arch=$(uname -m)
kernel=$(uname -r)
if [ -f /etc/lsb-release ]; then
	if [ ! -f /usr/bin/lsb_release ] ; then
           apt-get update
           update=1
	       apt-get -y install lsb-release
        fi
        os=$(lsb_release -s -d)
elif [ -f /etc/debian_version ]; then
        os="Debian $(cat /etc/debian_version)"
elif [ -f /etc/redhat-release ]; then
        os=`cat /etc/redhat-release`
else
        os="$(uname -s) $(uname -r)"
fi

echo "[+] Install $os $arch"

if [[ "$os" =~ "Debian 8".*|"stretch/sid".* ]]; then

    #Check if user agree with change to experimental
    read -r -p "We need change your debian to experimental - sid branch (If you are not). You agree?[Y/n] " input

    case $input in

        [nN][oO]|[nN])
                    echo "[!]Faraday install: Aborted"
                    echo "[!]You need agree the update to experimental - sid"
                    exit 1;;
    esac

    echo "deb http://ftp.debian.org/debian experimental main" >> /etc/apt/sources.list
    echo "deb http://ftp.debian.org/debian sid main" >> /etc/apt/sources.list
    apt-get update
    update=1
fi

if [ "$update" -eq 0 ]; then
    apt-get update
    update=1
fi

apt-get --ignore-missing -y install ipython python-setuptools python-pip python-dev libpq-dev libffi-dev couchdb gir1.2-gtk-3.0 gir1.2-vte-2.91 python-gobject zsh curl

pip2 install -r requirements.txt

echo "You can now run Faraday, enjoy!"
