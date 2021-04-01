import networkx as nx
import logging
import yaml
import sys
import os

from collections import namedtuple
from apk_analyzer import APKAnalyzer
from cex.cex import CEX

log = logging.getLogger("ap.run")


NativeMethod = namedtuple("NativeMethod", ["libname", "libpath", "libhash", "jni_desc", "method_name", "offset", "path"])


def print_err(msg):
    sys.stderr.write(msg + "\n")

def usage():
    print_err("USAGE: %s <apk-path> <vuln.yaml>" % sys.argv[0])
    exit(1)

def setup_logging():
    logging.basicConfig(filename="/tmp/android-paths.log", encoding="ascii", level=logging.WARNING,
        format="%(asctime)s : [%(name)s] %(message)s", datefmt="%m/%d/%Y %I:%M:%S %p")

    log_nan  = logging.getLogger("ap.NativeLibAnalyzer")
    log_apka = logging.getLogger("ap.APKAnalyzer")

    log.setLevel(logging.INFO)
    log_nan.setLevel(logging.INFO)
    log_apka.setLevel(logging.INFO)


# TODO: merge graphs of different libraries

if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()

    apk_path  = sys.argv[1]
    vuln_yaml = sys.argv[2]

    with open(vuln_yaml, "r") as fin:
        vulns = yaml.load(fin, Loader=yaml.FullLoader)
    vuln_libs = dict()
    for lib in vulns["libs"]:
        vuln_libs[lib["hash"]] = {
            "name":    lib["name"],
            "offsets": lib["offsets"]
        }

    setup_logging()
    log.info(f"running android-paths on {apk_path}")
    cex          = CEX()
    apk_analyzer = APKAnalyzer(cex, apk_path)
    paths_result = apk_analyzer.get_paths_to_native()

    log.info("android paths built")
    native_signatures = list(paths_result["paths"].keys())
    native_names      = list(map(
        lambda x: x.split(";->")[1].split("(")[0],
        native_signatures))

    log.info("building library dependency graph")
    lib_dep_g = apk_analyzer.build_lib_dependency_graph()
    reversed_lib_dep_g = lib_dep_g.reverse()

    log.info("building subgraph containing vulnerable libraries")
    interesting_libs = set()
    for l_hash in vuln_libs:
        vuln_libs[l_hash]["libs"] = set(nx.dfs_preorder_nodes(reversed_lib_dep_g, l_hash))
        interesting_libs |= vuln_libs[l_hash]["libs"]
    log.info(f"found {len(interesting_libs)} interesting libraries")

    log.info("finding mapping between native methods and implementation")
    native_methods = list()
    for i, name in enumerate(native_names):
        jni_descs = apk_analyzer.find_native_implementations(name, interesting_libs)
        for jni_desc in jni_descs:
            native_methods.append(
                NativeMethod(
                    libname=jni_desc.analyzer.libname,
                    libpath=jni_desc.analyzer.libpath,
                    libhash=jni_desc.analyzer.libhash,
                    jni_desc=jni_desc,
                    method_name=name,
                    offset=jni_desc.offset,
                    path=paths_result["paths"][native_signatures[i]]))
    log.info(f"found {len(native_methods)} methods")

    # Check path to vulns
    for native_method in native_methods:
        if native_method.libhash not in vuln_libs:
            continue

        vuln_offsets = vuln_libs[native_method.libhash]["offsets"]

        libpath = native_method.libpath
        for vuln_offset in vuln_offsets:
            vuln_offset = CEX.rebase_addr(vuln_offset)

            log.info(f"checking path from {native_method.offset:#x} @ {libpath} to {vuln_offset:#x} @ {libpath}")
            path = cex.find_path(libpath, native_method.offset, vuln_offset, plugins=["Ghidra"])
            if len(path) > 0:
                print("[!] Found potentially vulnerable path to %#x @ %s" % (vuln_offset, native_method.libname))
                log.info("path found")
                for m in native_method.path:
                    print(f"  - {m}")
                print(f"  -> {native_method.libname}")
                for cfg_node in path:
                    node_addr = hex(cfg_node.addr)
                    print(f"  - {node_addr}")  # FIXME: nomi funzione
            else:
                log.info("path not found")
