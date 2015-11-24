#!/bin/bash

# Compress database (to be run from cron)

export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

[ -z "$1" ] && exit 0
[ ! -d "$1" ] && exit 0

find $1 -type f -mtime +3 -name \*.eas | while read file ; do
    if ! fuser -s $file ; then
        bzip2 -9 $file
    fi
done
