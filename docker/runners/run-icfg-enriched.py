from threading import Thread

import subprocess
import time
import os

DATASET_DIR     = "/media/luca/HD2T/Home/Data/dataset_android"
LOGS_VTABLE_DIR = "/media/luca/HD2T/Home/Data/logs_android/log_vtables"
LOGS_RESULT_DIR = "/media/luca/HD2T/Home/Data/logs_android/log_results_enriched"

MAX_MEM   = 6
N_CONC    = 2
SCRIPTDIR = os.path.dirname(os.path.realpath(__file__))

DOCKER_CMD  = [
    "docker", "run", "--rm",
    "-v", SCRIPTDIR + "/../../../android-paths:/home/ubuntu/android-paths:ro",
    "-v", DATASET_DIR + ":/home/ubuntu/dataset:ro",
    "-v", LOGS_VTABLE_DIR + ":/home/ubuntu/vtables:ro",
    "--memory=" + str(MAX_MEM) + "g", "--memory-swap=" + str(MAX_MEM) + "g", "--shm-size=10240m",
    "android-paths", "bash", "-c"
]

def iterate_files(path, recursive=False):
    for subdir, dirs, files in os.walk(path):
        for file in files:
            yield os.path.join(subdir, file)
        if not recursive:
            break

def thread_runner(apk):
    cmd = "timeout %d python3 -u ./android-paths/tests/collect_icfg_enriched.py /home/ubuntu/dataset/%s /home/ubuntu/vtables/%s_0.log" % \
        (7200, apk, apk)
    cmd = DOCKER_CMD + [cmd]

    logname = LOGS_RESULT_DIR + "/" + apk + ".log"
    log     = open(logname, "w")

    start = time.time()
    print("Running APK", apk)
    proc = subprocess.Popen(cmd, stdout=log, stderr=log)
    _    = proc.communicate()
    print("APK", apk, "done", time.time() - start)

    log.close()

if __name__ == "__main__":
    to_run = set()
    for f in iterate_files(LOGS_VTABLE_DIR):
        if "_0.log" not in f:
            continue
        to_run.add(os.path.basename(f).replace("_0.log", ""))

    already_run = set()
    for f in iterate_files(LOGS_RESULT_DIR):
        already_run.add(os.path.basename(f).replace(".log", ""))

    to_run = to_run - already_run

    threads = list()
    queue   = list(sorted(to_run, reverse=True))
    while queue:
        if len(threads) < N_CONC:
            apk = queue.pop()
            t = Thread(target=thread_runner, args=(apk,))
            t.start()
            threads.append(t)
            continue

        to_erase = list()
        for i, t in enumerate(threads):
            if not t.is_alive():
                to_erase.append(i)

        for i in to_erase:
            del threads[i]
            break

        if len(to_erase) == 0:
            time.sleep(10)

    for t in threads:
        t.join()
