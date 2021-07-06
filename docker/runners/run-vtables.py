from threading import Thread

import subprocess
import time
import os

DATASET_DIR = "/media/luca/HD2T/Home/Data/dataset_android"
LOGS_DIR    = "/media/luca/HD2T/Home/Data/logs_android"

MAX_MEM   = 6
N_CONC    = 2
SCRIPTDIR = os.path.dirname(os.path.realpath(__file__))

LOG_DIRNAME = "log_vtables"
HOST_CMD    = "timeout 7200 python3 -u ./android-paths/tests/collect_vtables.py ./dataset/"
DOCKER_CMD  = [
    "docker", "run", "--rm",
    "-v", SCRIPTDIR + "/../../../android-paths:/home/ubuntu/android-paths",
    "-v", DATASET_DIR + ":/home/ubuntu/dataset:ro",
    "-v", LOGS_DIR + "/" + LOG_DIRNAME + ":/home/ubuntu/" + LOG_DIRNAME,
    "--memory=" + str(MAX_MEM) + "g", "--memory-swap=" + str(MAX_MEM) + "g", "--shm-size=10240m",
    "android-paths", "bash", "-c"
]

def iterate_files(path, recursive=False):
    for subdir, dirs, files in os.walk(path):
        for file in files:
            yield os.path.join(subdir, file)
        if not recursive:
            break

def thread_runner(apk, mode):
    cmd = "timeout %d python3 -u ./android-paths/tests/collect_vtables.py /home/ubuntu/dataset/%s %s" % \
        (7200, apk, mode)
    cmd = DOCKER_CMD + [cmd]

    logname = LOGS_DIR + "/" + LOG_DIRNAME + "/" + apk + "_" + mode + ".log"
    log     = open(logname, "w")

    start = time.time()
    print("Running APK", apk, mode)
    proc = subprocess.Popen(cmd, stdout=log, stderr=log)
    _    = proc.communicate()
    print("APK", apk, mode, "done", time.time() - start)

    log.close()

if __name__ == "__main__":
    interesting_hashes = set()
    f = open(os.path.join(SCRIPTDIR, "cpp_libs.txt"), "r")
    for line in f:
        line = line.strip()
        if line == "":
            continue
        interesting_hashes.add(line)

    to_run = set()
    for f in iterate_files(DATASET_DIR):
        if os.path.basename(f).replace(".apk", "") not in interesting_hashes:
            continue

        for i in range(2):
            to_run.add(os.path.basename(f) + "_" + str(i))

    already_run = set()
    for f in iterate_files(LOGS_DIR + "/" + LOG_DIRNAME):
        already_run.add(os.path.basename(f).replace(".log", ""))

    to_run = to_run - already_run

    threads = list()
    queue   = list(sorted(to_run, reverse=True))
    while queue:
        if len(threads) < N_CONC:
            apk, mode = queue.pop().split("_")
            t = Thread(target=thread_runner, args=(apk, mode))
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
