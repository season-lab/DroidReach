#!/bin/bash

mkdir /tmp/dr_logs;
cd log_apk_dataset;

# Consumer analysis:
# Count all methods where at least one positional argument is a consumer
grep -c "the args.*[0-9]" * | grep -v ":0"  > /tmp/dr_logs/consumers_found.txt;
# Count all methods with at least 1 jlong (triggers analysis, which stores positional arguments in a set), but doesn't find consumers (set is empty and prints as "set()")
grep -Ec  'the args set' * | grep -v ":0" > /tmp/dr_logs/jlong_but_not_consumers.txt;
# All methods where analysis ends (those without a jlong have a default empty list)
grep -Ec  'the args (set|\[\])' * | grep -v ":0" > /tmp/dr_logs/total_not_consumers.txt;

#Producer analysis
# Count all expanded potential producers at the end of execution. This does not necessarily imply there is at least a pair, but it's a good approximation.
# NB: only exists if successfully completed! There may be successful pairs in incomplete/crashed samples
grep -oP "\!CONS.*\: \K(\w+)" * | grep -v ":0"  > /tmp/dr_logs/full_runs_producers.txt;
# Count all producer pairs. Due to two (now fixed) bugs, most of the new implementation data on this is wrong. 
grep "Producer:" * -c | grep -v ":0" > /tmp/dr_logs/num_producer_pairs.txt;

# Other metrics 
# Determine whether the full analysis successfully completed
grep -c "\!CONS" * | grep -v ":0"  > /tmp/dr_logs/completed_execution.txt;
# Count all warnings emitted by the internal logging
grep "WARN" * -c | grep -v ":0" > /tmp/dr_logs/warnings.txt;
# Count all analyzed methods. 
# Match with sum of (consumer + not consumer) to find number of failed analysis/crashes
grep "Checking if" * -c | grep -v ":0" > /tmp/dr_logs/methods_explored.txt;
# These are more specific but also less interesting than the warnings. Mostly errors in CFG generation/angr stuff.
grep "error" * -c | grep -v ":0" > /tmp/dr_logs/errors.txt;
# We use last edit time between samples to calculate processing time.
stat -c "%n:%Z" * > /tmp/dr_logs/last_timestamp.txt;

tar -czf ../dr_logs.tgz -C /tmp/dr_logs/ .;
rm /tmp/dr_logs/*;
