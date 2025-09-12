#!/bin/bash
APK_POS=$1 
for APK in $(tar -tf $APK_POS | grep -e "[^/]$") ; 
do 
echo "Working on $APK";
tar -xvf $APK_POS $APK; 
mv $APK /tmp/dreach/sample.apk;  
sg docker -c "DroidReach/docker/start_batch.sh" > ~/log_$APK 2>&1;
done
