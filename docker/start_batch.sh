
#!/bin/bash

SCRIPT=`realpath $0`
SCRIPTPATH=`dirname $SCRIPT`

docker run --rm -t --shm-size=8gb \
    -v "$SCRIPTPATH/..:/home/ubuntu/droidreach" \
    -v "/tmp/dreach:/home/ubuntu/shared" \
    droidreach dreach --full-consumer --reachable shared/sample.apk
