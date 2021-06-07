#!/bin/bash

SCRIPT=`realpath $0`
SCRIPTPATH=`dirname $SCRIPT`

docker run --rm -it -v "$SCRIPTPATH/..:/home/ubuntu/android-paths" android-paths bash
