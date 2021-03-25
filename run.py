import tempfile
import yaml
import sys
import os

from collections import namedtuple
from native_finder import APKAnalyzer
from apk_cg import build_paths_android
from cex.cex import CEX


NativeMethod = namedtuple("NativeMethod", ["lib_obj", "method_name", "offset", "path"])


def print_err(msg):
    sys.stderr.write(msg + "\n")

def usage():
    print_err("USAGE: %s <apk-path> <vuln.yaml>" % sys.argv[0])
    exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()

    apk_path  = sys.argv[1]
    vuln_yaml = sys.argv[2]

    with open(vuln_yaml, "r") as fin:
        vulns = yaml.load(fin, Loader=yaml.FullLoader)
    vuln_libs = {lib["libname"]: lib["offsets"] for lib in vulns["libs"]}

    cex          = CEX()
    apk_analyzer = APKAnalyzer(apk_path)
    paths_result = build_paths_android(apk_path)

    native_signatures = list(paths_result["paths"].keys())
    native_names      = list(map(
        lambda x: x.split(";->")[1].split("(")[0],
        native_signatures))

    native_methods = list()
    for i, name in enumerate(native_names):
        lib, off = apk_analyzer.get_native_implementation(name)
        if lib is None:
            continue
        native_methods.append(
            NativeMethod(
                lib_obj=lib,
                method_name=name,
                offset=off,
                path=paths_result["paths"][native_signatures[i]]["a"][0][0]))

    # Check path to vulns
    for native_method in native_methods:
        lib = native_method.lib_obj
        if lib.name not in vuln_libs:
            continue

        vuln_offsets = vuln_libs[lib.name]

        with tempfile.TemporaryDirectory() as tmpdirname:
            libpath = os.path.join(tmpdirname, lib.name)
            with open(libpath, "wb") as native_f:
                native_f.write(lib.native_raw)

            for vuln_offset in vuln_offsets:
                path = cex.find_path(libpath, CEX.rebase_addr(native_method.offset), CEX.rebase_addr(vuln_offset), plugins=["Ghidra"])
                if len(path) > 0:
                    print("[!] Found potentially vulnerable path to %#x @ %s" % (vuln_offset, lib.name))
                    for m in native_method.path:
                        print(f"  - {m}")
                    print(f"  -> {lib.name}")
                    for cfg_node in path:
                        node_addr = hex(cfg_node.addr)
                        print(f"  - {node_addr}")  # FIXME: nomi funzione
