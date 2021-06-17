import networkx as nx
import sys

from apk_analyzer import APKAnalyzer
from cex_src.cex import CEXProject

def print_err(*msg):
    sys.stderr.write(" ".join(map(str, msg)) + "\n")

def usage():
    print_err(f"USAGE: {sys.argv[0]} <apk_path> <native_name>")
    exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()

    apk_path    = sys.argv[1]
    native_name = sys.argv[2]

    apka = APKAnalyzer(apk_path)

    paths = apka.get_paths_to_native()
    print(paths)
