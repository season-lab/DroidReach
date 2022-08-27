#!/bin/bash

if [ `whoami` != "ubuntu" ]; then
    echo "!Err: this script must be executed in the docker container"
    exit 1
fi

pushd /home/ubuntu/droidreach/apk_analyzer/bin
make
cd rz_jni_finder
mkdir -p /home/ubuntu/.local/lib/x86_64-linux-gnu/rizin/plugins/
make clean
make
make install
popd
