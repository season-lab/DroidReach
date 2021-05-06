#!/bin/bash

SCRIPT=`realpath $0`
SCRIPTPATH=`dirname $SCRIPT`

docker run --rm -it -v $SCRIPTPATH:/home/nativedroid/data nativedroid bash
