#!/bin/bash

SCRIPT=`realpath $0`
SCRIPTPATH=`dirname $SCRIPT`

so_path=$1
so_name=`basename $so_path`

args="${@:2}"

[ -d /tmp/nativedroid_tmp ] || mkdir /tmp/nativedroid_tmp
cp $so_path /tmp/nativedroid_tmp

docker run --rm -it \
    -v $SCRIPTPATH:/home/nativedroid/data \
    -v /tmp/nativedroid_tmp:/tmp/nativedroid_tmp \
    nativedroid bash -c "python data/pointers_from_java.py /tmp/nativedroid_tmp/$so_name $args"
