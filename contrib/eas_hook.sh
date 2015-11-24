#!/bin/bash

# Example Hook
# Disconnects on suspicious commands - binaries executed from user's home directory
# Handles nagios checks

export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

#echo "###" >>/tmp/eas_hook
#date >>/tmp/eas_hook
#env >>/tmp/eas_hook

# EASH_ORIGINAL_UID=0
# EASH_COMMAND=/bin/bash
# EASH_ID=310538
# EASH_ORIGINAL_GR_NAME=root
# EASH_EFFECTIVE_GID=1001
# EASH_TERMINAL=not a terminal
# EASH_REAL_GID=1001
# EASH_REAL_GR_NAME=joe
# EASH_IP=10.0.100.69
# EASH_EFFECTIVE_UID=0
# EASH_ORIGINAL_PW_NAME=root
# EASH_ORIGINAL_GID=0
# EASH_REAL_PW_NAME=joe
# PWD=/
# EASH_EFFECTIVE_GR_NAME=joe
# EASH_EFFECTIVE_PW_NAME=root
# EASH_REAL_UID=20060900
# SHLVL=1
# _=/bin/env

suspicious=""
logf=/tmp/eas_hook.log

if [ ! -z "$EASH_COMMAND" ] ; then
    if [ -r /etc/shells ] ; then
        for s in $(cat /etc/shells) ; do
            if [ "$EASH_COMMAND" == "$s" ] ; then
                suspicious="$s"
                break
            fi
        done
    fi

    if echo "$EASH_COMMAND" | grep -q "^/home/$EASH_REAL_PW_NAME/" ; then
        suspicious="$s"
    fi
fi

if [ ! -z "$suspicious" ] ; then
    ptr=$(host -t ptr $EASH_IP| awk '{print $NF}'|grep -v NXDOMAIN|sed -e 's/\.$//')
    ptr="$ptr[$EASH_IP]"
    msg="[EAS ALERT] Suspicious command call $EASH_REAL_PW_NAME@$ptr:$EASH_COMMAND"
    env|mail -s "$msg" root
else
    if [ -z "$EASH_COMMAND" ] || [ "$EASH_COMMAND" == "null" ] ; then
        msg="[EAS OK SHELL] Passed $EASH_REAL_PW_NAME@$EASH_IP"
    elif [ "$EASH_COMMAND" == "/bin/echo nagios test" ] ; then
        msg="[EAS OK NAGIOS] Passed $EASH_REAL_PW_NAME@$EASH_IP:$EASH_COMMAND"
    else
        msg="[EAS OK COMMAND] Passed $EASH_REAL_PW_NAME@$EASH_IP:$EASH_COMMAND"
    fi
fi

date +"%Y-%m-%d %H:%M:%S $msg" >>$logf

exit 0
