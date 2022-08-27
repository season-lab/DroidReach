#!/bin/bash

SCRIPT=`realpath $0`
SCRIPTPATH=`dirname $SCRIPT`

docker run --rm -it --shm-size=4gb \
    -v "$SCRIPTPATH/..:/home/ubuntu/droidreach" \
    droidreach bash
