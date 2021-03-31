import json
import os

from shutil import copyfile
from .cg_extractor import find_paths


SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))
TMP_DIR   = "/dev/shm/android_tmp"
CALLS_DIR = os.path.join(TMP_DIR, "calls_data")
GRAPH_DIR = os.path.join(TMP_DIR, "graph_data")
JSONG_DIR = os.path.join(TMP_DIR, "json_graph_data")
INPUT_DIR = os.path.join(TMP_DIR, "apks")


def build_paths_android(apk_path):
    if not os.path.exists(TMP_DIR):
        os.mkdir(TMP_DIR)
        os.mkdir(INPUT_DIR)
        os.mkdir(CALLS_DIR)
        os.mkdir(GRAPH_DIR)
        os.mkdir(JSONG_DIR)

    copyfile(apk_path, os.path.join(INPUT_DIR, os.path.basename(apk_path)))
    find_paths(INPUT_DIR, TMP_DIR)

    apk_name = os.path.basename(apk_path).replace(".apk", "")
    json_path = os.path.join(CALLS_DIR, apk_name + ".json")

    with open(json_path) as fin:
        data = json.load(fin)
    return data
