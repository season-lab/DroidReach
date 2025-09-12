for APK in $(tar -tf /home/android/benchmark_samples.tgz | grep -e "[^/]$") ; 
do 
date +%s;
echo "Working on $APK";
tar -xvf /home/android/benchmark_samples.tgz $APK; 
mv $APK /tmp/dreach/sample.apk;  
sg docker -c "DroidReach/docker/start_batch.sh" > ~/benchmark_log_$APK 2>&1;
done
