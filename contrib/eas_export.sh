#!/bin/bash

# Move sessions logged locally to central repository

export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

config=/etc/eas/easd_config
params=~/.eas_export.vars
table=USER

if [ ! -f $config ] ; then
    echo "Can't read $config"
    exit 3
fi

p1=$1
p2=$2

if [ -f $params ] ; then
    pp1=$(grep ^ip $params|cut -f2 -d=)
    if [ -z "$p1" ] && [ ! -z "$pp1" ] ; then
        p1=$pp1
        echo "$params:ip=$p1"
    fi

    pp2=$(grep ^basedir $params|cut -f2 -d=)
    if [ -z "$p2" ] && [ ! -z "$pp2" ] ; then
        p2=$pp2
        echo "$params:basedir=$p2"
    fi
fi

if [ -z "$p1" ] || [ -z "$p2" ] ; then
    cat <<.
    Usage: $0 <IP> <BASEDIR>

    IP - ipaddress that should be included in dump instead of 127.0.0.1
    BASEDIR - SessionDirectory on remote server (where data will be imported)
.
    exit 1
fi

echo -en "ip=$p1\nbasedir=$p2\n" >$params

easdir=$(grep ^SessionDirectory $config |awk '{print $2}'|head -1)

tarfile=$easdir/export-$p1-$(date +%Y-%m-%d).tar
sqlfile=$easdir/export-$p1-$(date +%Y-%m-%d).sql

fail=0

if [ -f $tarfile.bz2 ] ; then
    echo "$tarfile.bz2 already exists"
    fail=1
fi

if [ -f $sqlfile ] ; then
    echo "$sqlfile already exists"
    fail=1
fi

if [ $fail -ne 0 ] ; then
    exit 4
fi

sqlite_with_retry() {
    q="$*"
    retries=20
    for i in $(seq $retries) ; do
        sqlite3 -separator ' ' $easdir/db "$q" 2>/dev/null
        [ $? -eq 0 ] && break
        sleep 2
    done
    if [ $? -ne 0 ] ; then
        echo "Error executing SQL (after $retries retries): $q"
        exit 1
    fi
}

db=$(sqlite_with_retry .dump)
fields=$(echo "$db"|grep -A999 "^CREATE TABLE $table"|grep -B999 "^);"|cut -f2 -d' '|egrep -v "^(\(|\)|TABLE$)"|xargs|sed -e 's/ /,/g' -e 's/,release,/,\`release\`,/')
logs=$(echo "$db"|grep "^INSERT INTO \"$table\""|grep "'127\.0\.0\.1'"|sed -e "s@\"$table\"@$table@" -e "s@127.0.0.1@${p1}i@g" -e "s@$easdir@$p2@g" -e "s@VALUES([0-9]*,@VALUES(NULL,@" -e "s@VALUES(@($fields) VALUES(@")
ids=$(echo "$db"|grep "^INSERT INTO \"$table\""|sed -e 's/.*VALUES(\([0-9]*\),.*/\1/')

if [ -z "$db" ] || [ -z "$fields" ] || [ -z "$logs" ] || [ -z "$ids" ] ; then
    echo "Database empty ($easdir/db:$table)"
    exit 5
fi

echo "Making $sqlfile"
echo "$logs" >$sqlfile

echo "Making $tarfile"
cd $easdir && ln -s 127.0.0.1 ${p1}i || exit 6

paths=""
tar="c"
for i in $ids ; do
    path=$(sqlite_with_retry "select file_session from $table where id=$i and file_session like '$easdir/%'")
    if [ ! -z "$path" ] && [ -s $path ] ; then
        paths="$paths $path"
        cd $easdir && tar --numeric-owner -${tar}f $tarfile $(echo "$path"|sed -e "s@^$easdir@./@" -e "s@127.0.0.1@${p1}i@") || exit 7
        tar=r
    fi
done

if [ -f $tarfile ] ; then
    echo "Compressing $tarfile.bz2"
    bzip2 -9 $tarfile || exit 8
else
    echo "Empty $tarfile -- no interactive sessions. Removing."
fi

echo "Removing records from local database"
cd $easdir && rm -f ${p1}i || exit 8
rm -f $paths || exit 9
sqlite_with_retry "delete from $table where id in ($(echo "$ids"|xargs|sed -e 's/ /,/g'))" || exit 10

echo "Done"

cat <<END

In order to complete export:

1) Transfer files to destination log server (ie. rsync)
2) Untar session file on destination server (ie. cd $p2 ; tar jxvf $(basename $tarfile).bz2)
3) Load sql file on destination server (ie. mysql eashd < $(basename $sqlfile))
4) Delete both files on this server.

END

exit 0
