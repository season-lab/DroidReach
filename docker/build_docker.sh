#!/bin/bash

SCRIPT=`realpath $0`
SCRIPTPATH=`dirname $SCRIPT`

docker build -t droidreach              \
    --build-arg USER_ID=$(id -u $USER)  \
    --build-arg GROUP_ID=$(id -g $USER) \
    $SCRIPTPATH

echo "[+] compiling rizin plugin"
docker run --rm -it --shm-size=4gb \
    -v "$SCRIPTPATH/..:/home/ubuntu/droidreach" \
    droidreach dreach_install_plugins.sh
