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
Callgraph = namedtuple("Callgraph", ["libhash", "graph"])


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

def get_supergraph_id(libhash, off):
    return f"{libhash}_{off:x}"

def get_supergraph(native_dep_g, *callgraphs):
    g = nx.DiGraph()

    libhashes = set()
    for cg in callgraphs:
        libhashes.add(cg.libhash)
        for n_id in cg.graph.nodes:
            data = cg.graph.nodes[n_id]["data"]
            g.add_node(
                get_supergraph_id(cg.libhash, data.addr),
                libhash=cg.libhash,
                fname=data.name,
                addr=data.addr)
        for src_id, dst_id in cg.graph.edges:
            data_src = cg.graph.nodes[src_id]["data"]
            data_dst = cg.graph.nodes[dst_id]["data"]
            g.add_edge(
                get_supergraph_id(cg.libhash, data_src.addr),
                get_supergraph_id(cg.libhash, data_dst.addr))

    native_dep_subgraph = g.subgraph(libhashes)
    for src_id, dst_id, n in native_dep_subgraph:
        edge_data = native_dep_subgraph.edges[(src_id, dst_id, n)]
        supergraph_src = get_supergraph_id(src_id, edge_data.src_off)
        supergraph_dst = get_supergraph_id(dst_id, edge_data.dst_off)
        g.add_edge(supergraph_src, supergraph_dst)

    return g

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
        for vuln_lib_hash in vuln_libs:

            if native_method.libhash == vuln_lib_hash:
                libs_to_be_analyzed = { vuln_lib_hash }
            else:
                paths = nx.all_simple_paths(lib_dep_g, source=native_method.libhash, target=vuln_lib_hash)
                libs_to_be_analyzed = { node for path in paths for node in path }

            if len(libs_to_be_analyzed) == 0:
                continue

            log.info(f"building callgraphs for {len(libs_to_be_analyzed)} libs")
            callgraphs = list()
            for lib_hash in libs_to_be_analyzed:
                cg = cex.get_callgraph(apk_analyzer.get_libpath_from_hash(lib_hash), plugins=["Ghidra"])
                callgraphs.append(Callgraph(libhash=lib_hash, graph=cg))

            log.info("building supergraph")
            libs_supergraph = get_supergraph(lib_dep_g, *callgraphs)
            vuln_offsets = vuln_libs[vuln_lib_hash]["offsets"]
            vuln_libname = vuln_libs[vuln_lib_hash]["name"]
            log.info(f"supergraph with {libs_supergraph.number_of_nodes()} nodes built")

            for vuln_offset in vuln_offsets:
                vuln_offset = CEX.rebase_addr(vuln_offset)
                src_id = get_supergraph_id(native_method.libhash, native_method.offset)
                dst_id = get_supergraph_id(vuln_lib_hash, vuln_offset)

                log.info(f"checking path from {native_method.offset:#x} @ {native_method.libname} to {vuln_offset:#x} @ {vuln_libname}")
                path = next(nx.all_simple_paths(libs_supergraph, src_id, dst_id), None)
                if path is not None:
                    print(f"[!] Found potentially vulnerable path to {vuln_offset:#x} @ {vuln_libname}")
                    log.info("path found")
                    for m in native_method.path:
                        print(f"  - {m}")
                    for n in path:
                        data = libs_supergraph.nodes[n]
                        libname = apk_analyzer.get_libname_from_hash(data["libhash"])
                        fname = data["fname"]
                        print(f"  - {fname} @ {libname}")
                else:
                    log.info("path not found")
