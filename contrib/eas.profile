#!/bin/sh
#
# profile.d script for bash-like shells
# defaults sudo -s to spawn eash rather than default shell

# if you have shell_noargs enabled for sudo
# set SHELL_NOARGS to 1 below
SHELL_NOARGS=0
EASH_SUDO_S=1

[ -r /etc/sysconfig/eash ] && . /etc/sysconfig/eash

SUDO=$( which sudo )

if [ $EASH_SUDO_S == 1 ]
then
function sudo() {
    local ARGS
    [ "$#" -lt 1 -a "$SHELL_NOARGS" -eq 1 ] && ARGS="$ARGS eash"
    for arg in $*; do
        if [ "$arg" = "-s" ]; then
            ARGS="$ARGS eash" && shift
        else
            ARGS="$ARGS $1" && shift
        fi
    done
    $SUDO $ARGS
}
fi
