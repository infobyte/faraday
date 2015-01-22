#!/bin/bash
###
## Faraday Penetration Test IDE - Community Version
## Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
## See the file 'doc/LICENSE' for the license information
###


#Check if is it root
if [ $EUID -ne 0 ]; then
 echo "You must be root."
 exit 1
fi

#protection
sha_kali_i686=f071539d8d64ad9b30c7214daf5b890a94b0e6d68f13bdcc34c2453c99afe9c4
sha_kali_x86_64=02a050372fb30ede1454e1dd99d97e0fe0963ce2bd36c45efe90eec78df11d04
sha_ubuntu13_10_i686=8199904fb5fca8bc244c31b596c3ae0d441483bfbb2dc47f66186ceffbf3586e
sha_ubuntu13_10_x86_64=2b1af6f8d7463324f6df103455748e53cdb1edf6ee796056cdf2f701ccaef031
sha_ubuntu13_04_i686=d3632a393aa0bf869653afe252248de62e528c4e42ab49a0d16850ab89fda13e
sha_ubuntu13_04_x86_64=ea3010b8c3f81229a6b79c8d679005c1d482548223ebc448963d2d29aabe5692

#os detection
arch=$(uname -m)
kernel=$(uname -r)
if [ -f /etc/lsb-release ]; then
	if [ ! -f /usr/bin/lsb_release ] ; then
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
down=0
if [ "$os" = "Ubuntu 10.04.2 LTS" ]; then
    version="ubuntu10-04.02$arch"
elif [[ "$os" =~ .*Kali.* ]]; then
    version="kali-$arch"
    down=1
elif [ "$os" = "Ubuntu 12.04.3 LTS" ]; then
    version="ubuntu12-$arch"
elif [ "$os" = "Ubuntu 13.10" ]; then
    version="ubuntu13-10-$arch"
    down=1
elif [ "$os" = "Ubuntu 13.04" ]; then
    version="ubuntu13-04-$arch"
    down=1
elif [[ "$os" =~ "Ubuntu 14.04".* ]]; then
    version="ubuntu13-10-$arch"
    down=1
    # Install pip from github.
    # Bug: https://bugs.launchpad.net/ubuntu/+source/python-pip/+bug/1306991
    wget https://raw.github.com/pypa/pip/master/contrib/get-pip.py
    python get-pip.py
else
    echo "[-] Could not find a install for $os ($arch $kernel)"
    exit
fi

if [ "$down" -eq 1 ]; then
    
    if [ -e lib-$version.tgz ]; then
        echo "[+] QT Libs already downloaded"
    else
        echo "[+] Download QT Libs"
        wget "https://www.faradaysec.com/down/faraday/lib-$version.tgz" -O lib-$version.tgz
    fi
    
    shav="sha_${version//-/_}"
    echo `sha256sum lib-$version.tgz`
    if [ -e lib-$version.tgz ]; then
        if [ "`echo ${!shav}`" = "`sha256sum lib-$version.tgz | awk -F\" \" \{'print $1'\}`" ]; then
            echo "[+] SHA256 ok"
            tar -xvzf lib-$version.tgz 
            mv lib-$version/ external_libs
        else
            echo "[-] SHA256 file corrupt"
            exit
        fi
    else
        echo "[-] Download error"
        exit
    fi
else
    apt-get -y install python-qt3
fi

apt-get -y install ipython python-pip python-dev couchdb libpq-dev
pip install -r requirements.txt

echo "You can now run Faraday, enjoy!"
