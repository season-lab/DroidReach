import networkx as nx
import subprocess
import sys
import os
import gc

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
from apk_analyzer import APKAnalyzer
from cex.cex import CEX

def usage():
    print("USAGE: %s <apk_path>" % sys.argv[0])
    exit(1)

def print_stderr(*msg):
    sys.stderr.write(" ".join(map(str, msg)) + "\n")

def define_functions_ghidra(ghidra, path, offsets):
    OUT_FILE   = "/dev/shm/offsets.txt"
    CMD_GHIDRA = [
        "$GHIDRA_HOME/support/analyzeHeadless",
        "$PROJ_FOLDER",
        "$PROJ_NAME",
        "-noanalysis",
        "-process",
        "$BINARY",
        "-postScript",
        "CreateFunctions.java",
        OUT_FILE,
        "-scriptPath",
        os.path.realpath(os.path.join(os.path.dirname(__file__), "../../apk_analyzer/bin"))]

    with open(OUT_FILE, "w") as fout:
        for off in offsets:
            fout.write("%#x\n" % off)

    proj_path = ghidra.get_project_path(path)
    proj_dir  = os.path.dirname(proj_path)
    proj_name = os.path.basename(proj_path)
    libname   = os.path.basename(path)

    ghidra_home = os.environ["GHIDRA_HOME"]
    cmd = CMD_GHIDRA[:]
    for i in range(len(cmd)):
        cmd[i] = cmd[i]                                     \
            .replace("$GHIDRA_HOME", ghidra_home)           \
            .replace("$BINARY", libname)                    \
            .replace("$PROJ_FOLDER", proj_dir)              \
            .replace("$PROJ_NAME", proj_name)
    subprocess.check_output(cmd, stderr=subprocess.DEVNULL)

def is_in_java(jni_desc, native_methods):
    for class_name, method_name, args_str in native_methods:
        if (jni_desc.method_name == method_name) and                               \
            (jni_desc.class_name == "???" or jni_desc.class_name == class_name) and \
            (jni_desc.args == "???" or args_str.startswith(jni_desc.args)):
            return True
    return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()

    apk_path = sys.argv[1]

    cex  = CEX()
    apka = APKAnalyzer(None, apk_path)

    native_methods = apka.find_native_methods()
    if len(native_methods) == 0:
        print("No native methods")
        exit(0)

    added_libs = set()
    arm_libs   = list()
    libs = apka.get_analyzed_libs()
    for lib in libs:
        if lib.arch in {"armeabi", "armeabi-v7a"}:
            # Relaxed a little bit... If the library is not in a standard location, analyze it
            if lib.libname in added_libs and ("lib/"+lib.arch) in lib.libpath:
                continue
            added_libs.add(lib.libname)
            arm_libs.append(lib)

    depgraph = apka.build_lib_dependency_graph()
    ghidra   = cex.pm.get_plugin_by_name("Ghidra")

    jni_functions = 0
    linked_calls  = 0
    for lib in arm_libs:
        linked_funcs = set()
        for e in depgraph.edges:
            if e[0] != lib.libhash:
                continue
            fun_name = depgraph.edges[e]["fun"]
            linked_funcs.add(fun_name)
        if len(linked_funcs) == 0:
            continue

        jni_offsets = list()
        for jni_method in lib.get_jni_functions():
            if not is_in_java(jni_method, native_methods):
                continue
            jni_offsets.append(jni_method.offset)

        define_functions_ghidra(ghidra, lib.libpath, jni_offsets)
        cg = cex.get_callgraph(lib.libpath, plugins=["Ghidra"])

        for off in jni_offsets:
            jni_functions += 1

            subgraph = nx.ego_graph(cg, off, sys.maxsize)
            for addr in subgraph.nodes:
                data = subgraph.nodes[addr]["data"]
                if data.name in linked_funcs:
                    linked_calls += 1
                    break

    print("JNI Functions:", jni_functions)
    print("Linked Calls: ", linked_calls)
