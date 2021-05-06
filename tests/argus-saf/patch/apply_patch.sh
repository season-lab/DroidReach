#!/bin/bash

SCRIPT=`realpath $0`
SCRIPTPATH=`dirname $SCRIPT`

sudo cp "$SCRIPTPATH"/armel_resolver.py /usr/local/lib/python2.7/dist-packages/nativedroid/analyses/resolver/armel_resolver.py
