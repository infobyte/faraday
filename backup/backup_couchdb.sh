#!/bin/sh

###
## Faraday Penetration Test IDE - Community Version
## Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
## See the file 'doc/LICENSE' for the license information
###

####################################
# Backup CouchDB script.
####################################

# Configure daily cron 
#0 0 * * * bash $faradaypath/backup/backup_couchdb.sh


# What to backup. 
#backup_files="/etc/couchdb /var/lib/couchdb /var/log/couchdb"
backup_files=$1


# Where to backup to.
dest="/mnt/backup"
dest=$2

# Create archive filename.
day=$(date +%d_%b_%Y)
hostname=$(hostname -s)
archive_file="couchdb_$hostname-$day.tgz"

# Print start status message.
echo "Backing up $backup_files to $dest/$archive_file"
date
echo

# Backup the files using tar.
tar czf $dest/$archive_file $backup_files

# Print end status message.
echo
echo "Backup finished"
date

# Long listing of files in $dest to check file sizes.
ls -lh $dest
