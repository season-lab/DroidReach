#!/bin/bash
APK_POS=$1 
CUSTOM_TIME=$2
TIMEOUT=${CUSTOM_TIME:-"2h"}

for APK in $(cat subset.txt) ; 
do 
echo "$(date +%s): Working on $APK";
tar -xvf $APK_POS $APK; 
mv $APK /tmp/dreach/sample.apk; 
echo "$(date +%s): starting docker batch script"; 
sg docker -c "timeout $TIMEOUT DroidReach/docker/start_batch.sh" > ~/log_$APK 2>&1;
echo "$(date +%s): Completed analysis of $APK";
done
