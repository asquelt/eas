#!/bin/bash

# Fixes permissions on sessions directory.

export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

#exec >/tmp/eas_tidy.log 2>&1
#set -x

dir=$(grep "^SessionDirectory" /etc/eas/easd_config|awk '{print $2}')

[ ! -d $dir ] && exit 0
id easd >/dev/null 2>/dev/null || exit 0

find $dir -not -uid $(id -u easd) -exec chown -v easd {} \;
find $dir -not -gid $(id -g easd) -exec chown -v :easd {} \;

