
#!/bin/bash

SCRIPT=`realpath $0`
SCRIPTPATH=`dirname $SCRIPT`

docker run --rm -t --shm-size=8gb \
    -v "$SCRIPTPATH/..:/home/ubuntu/droidreach" \
    -v "/tmp/dreach:/home/ubuntu/shared" \
    droidreach dreach --full-analysis --reachable --ghidra-timeout 3600 --angr-max-memory 60000 shared/74ACAD6F3A8FB7DD80FE00A93847D9574C7B7AAFC55D20AA988177DF31BBF4B6.apk
