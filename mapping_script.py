import networkx as nx
import sys

from apk_analyzer import APKAnalyzer
from cex_src.cex import CEXProject

def print_err(*msg):
    sys.stderr.write(" ".join(map(str, msg)) + "\n")

def usage():
    print_err(f"USAGE: {sys.argv[0]} <apk_path>")
    exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()

    apk_path = sys.argv[1]

    apka   = APKAnalyzer(apk_path)
    ghidra = CEXProject.pm.get_plugin_by_name("Ghidra")

    native_methods = apka.find_native_methods()
    if len(native_methods) == 0:
        print("[ERR] No native methods")
        exit(0)

    arm_libs = apka.get_armv7_libs()
    if len(arm_libs) == 0:
        print("[ERR] No arm libs")
        exit(0)

    arm_libs = list(map(lambda l: l.libhash, arm_libs))

    n_found = 0
    for native_name, class_name, args_string in native_methods:
        matches = apka.find_native_implementations(class_name, native_name, args_string, lib_whitelist=arm_libs)

        if len(matches) == 0:
            print("Not found implementation of native method: %s : %s %s" % (class_name, native_name, args_string))
        else:
            n_found += 1

    print("Found %d / %d" % (n_found, len(native_methods)))
