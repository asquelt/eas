#!/bin/bash

# puppet managed file, for more info 'puppet-find-resources $filename'
# BEFORE YOU MAKE ANY CHANGES, READ https://stonka.non.3dart.com/wiki/wiki/Puppet#Zarz.C4.85dzanie_konfiguracjami

export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

#exec >/tmp/eas_tidy.log 2>&1
#set -x

dir=$(grep "^SessionDirectory" /etc/eas/easd_config|awk '{print $2}')
uid=$(id -u easd 2>/dev/null)

tmpf=$(mktemp /tmp/$(basename $0).XXXXXX)
sqlf=$(mktemp /tmp/$(basename $0).XXXXXX)
errf=$(mktemp /tmp/$(basename $0).XXXXXX)
logf=/tmp/$(basename $0).log

sqlite_with_retry() {
    q="$*"
    retries=20
    for i in $(seq $retries) ; do
        sqlite3 -separator ' ' $dir/db "$q" 2>$errf
        ret=$?
        [ $ret -eq 0 ] && break
        err="$(cat $errf)"
        sleep $((2+i*2))
    done
    if [ $ret -ne 0 ] ; then
        echo "Error executing SQL (after $retries retries): $q -- $(cat $errf)"
        exit 1
    fi
}

[ ! -f $dir/db ] && exit 1
[ -z "$uid" ] && exit 2
which find >/dev/null 2>/dev/null || exit 5
[ -z "$(find $dir -maxdepth 0 -uid $uid)" ] && exit 3
which sqlite3 >/dev/null 2>/dev/null || exit 4

purges=0
purgesf=0
nulles=0
nullesf=0

sqlite_with_retry "pragma synchronous=0"
sqlite_with_retry "pragma cache_size=32000"

sqlite_with_retry "select id,file_session from USER where remote_command like '/bin/echo %nagios test%' and real_pw_name='nagios'" >$tmpf || exit 1

while read id f ; do
    echo "delete from USER where id=$id;" >>$sqlf
    purges=$((purges+1))
    [ ! -f $f ] && continue
    [ "$f" == "/dev/null" ] && continue
    rm -f $f
    purgesf=$((purgesf+1))
done <$tmpf

while read f ; do
    echo "update USER set file_session='/dev/null',hash_session='b620fc55c20e15b74cf48651dfed245cecd885f1' where file_session='$f';" >>$sqlf
    nulles=$((nulles+1))
    [ ! -f $f ] && continue
    [ "$f" == "/dev/null" ] && continue
    rm -f $f
    nullesf=$((nullesf+1))
done < <(find $dir -type f -size 0 -ctime +7 -uid $uid -print 2>/dev/null)

if [ $purgesf -ne 0 ] || [ $nullesf -ne 0 ] ; then
    date +"%Y-%m-%d %H:%M:%S $0 Files purge Completed. Purged: $purgesf Nulled: $nullesf" >>$logf
fi

cat $sqlf | sqlite3 $dir/db

if [ $purges -ne 0 ] || [ $nulles -ne 0 ] ; then
    date +"%Y-%m-%d %H:%M:%S $0 SQL purge Completed. Purged: $purges Nulled: $nulles" >>$logf
fi

sqlite_with_retry "vacuum"

if [ $purgesf -ne 0 ] || [ $nullesf -ne 0 ] || [ $purges -ne 0 ] || [ $nulles -ne 0 ] ; then
    date +"%Y-%m-%d %H:%M:%S $0 Database cleaned up. All done in $SECONDS seconds." >>$logf
fi

[ -f $tmpf ] && rm -f $tmpf
[ -f $sqlf ] && rm -f $sqlf
[ -f $errf ] && rm -f $errf

# we can be called as hook
exit 0
