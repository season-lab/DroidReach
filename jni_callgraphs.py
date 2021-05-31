#!/usr/env python3

import networkx as nx
import angr
import time
import sys
import cle
import os

from tests.timeout_decorator import timeout, TimeoutError
from apk_analyzer import APKAnalyzer
from apk_analyzer.utils import prepare_initial_state
from cex_src.cex import to_dot
from cex_src.cex import CEXProject
from cex_src.cex.cfg_extractors import CGNodeData

def print_err(*msg):
    sys.stderr.write(" ".join(map(str, msg)) + "\n")

def usage():
    print_err(f"USAGE: {sys.argv[0]} <apk_path>")
    exit(1)

@timeout(60*10)  # Risky
def jni_angr_wrapper(lib):
    jni_dyn_functions_angr = lib._get_jni_functions_angr()
    return jni_dyn_functions_angr

@timeout(60*10)  # Risky
def jni_rizin_wrapper(lib):
    jni_functions_rizin    = lib._get_jni_functions_rizin()
    return jni_functions_rizin

def callgraph_gen_ghidra_wrapper(proj, addr):
    return proj.get_callgraph(addr)

def callgraph_gen_angr_wrapper(main_bin, entry, addresses, args, other_libs=None):
    other_libs = other_libs or []

    main_opts = { 'base_addr' : addresses[main_bin] }
    lib_opts  = {}
    for l in other_libs:
        lib_opts[os.path.basename(l)] = { "base_addr" : addresses[l] }

    proj = angr.Project(
            main_bin,
            main_opts = main_opts,
            use_system_libs     = False,
            auto_load_libs      = False,
            except_missing_libs = False,
            use_sim_procedures  = True,
            force_load_libs     = other_libs,
            lib_opts            = lib_opts
        )
    if entry % 2 == 0:
        blank_state = proj.factory.blank_state()
        blank_state.ip = entry
        if blank_state.block().size == 0:
            # thumb mode
            entry += 1

    state = prepare_initial_state(proj, args)

    cfg = proj.analyses.CFGEmulated(
        fail_fast=True, keep_state=True, starts=[entry],
        context_sensitivity_level=1, call_depth=5, initial_state=state)

    callgraph = proj.kb.callgraph
    subgraph  = nx.ego_graph(callgraph, entry, radius=sys.maxsize)

    g = nx.DiGraph()
    for addr in subgraph.nodes:
        fun = proj.kb.functions[addr]
        if fun.is_simprocedure:
            continue
        g.add_node(addr, data=CGNodeData(addr=addr, name=fun.name))

    for src, dst, c in subgraph.edges:
        if c != 0:
            continue
        if src not in g.nodes or dst not in g.nodes:
            continue
        g.add_edge(src, dst)

    return g

def find_java_jni(jni, java_natives):
    for class_name, method_name, args_str in java_natives:
        if (jni.method_name == method_name) and                                                  \
           (jni.class_name == "???" or jni.class_name == class_name[1:-1].replace("/", ".")) and \
           (jni.args == "???" or args_str.startswith(jni.args)):
           return class_name, method_name, args_str
    return None, None, None


if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()

    apk_path = sys.argv[1]

    apka     = APKAnalyzer(apk_path)
    ghidra   = CEXProject.pm.get_plugin_by_name("Ghidra")

    native_methods = apka.find_native_methods()
    if len(native_methods) == 0:
        print("[ERR] No native methods")
        exit(0)

    arm_libs = apka.get_armv7_libs()
    if len(arm_libs) == 0:
        print("[ERR] No arm libs")
        exit(0)

    # Check differences of JNI methods mapping between angr and rizin
    jni_functions = dict()
    for arm_lib in arm_libs:
        if not arm_lib.is_jni_lib():
            continue

        start = time.time()
        try:
            jni_functions_rizin = jni_rizin_wrapper(arm_lib)
        except TimeoutError:
            print("[ERR_TIMEOUT] rizin; lib %s" % arm_lib.libpath)
            jni_functions_rizin = list()
        time_rizin = time.time() - start

        start = time.time()
        try:
            jni_dyn_functions_angr = jni_angr_wrapper(arm_lib)
        except TimeoutError:
            print("[ERR_TIMEOUT] angr; lib %s" % arm_lib.libpath)
            jni_dyn_functions_angr = list()
        except NotImplementedError as e:
            print("[ERR_NOT_IMPLEMENTED] angr; lib %s; msg %s" % (arm_lib.libpath, e))
            jni_dyn_functions_angr = list()
        except cle.CLEError as e:
            print("[ERR_CLE] angr; lib %s; msg %s" % (arm_lib.libpath, e))
            jni_dyn_functions_angr = list()
        except Exception as e:
            print("[ERR_UNKNOWN] angr; lib %s; msg %s" % (arm_lib.libpath, e))
            cg = nx.DiGraph()

        time_angr = time.time() - start

        jni_dyn_functions_rizin = list(filter(lambda f: f.class_name == "???", jni_functions_rizin))
        jni_dyn_rizin = set(map(lambda f: (f.method_name, f.args), jni_dyn_functions_rizin))
        jni_dyn_angr  = set(map(lambda f: (f.method_name, f.args), jni_dyn_functions_angr))

        only_rizin = len(jni_dyn_rizin - jni_dyn_angr)
        only_angr  = len(jni_dyn_angr - jni_dyn_rizin)

        print("[JNI_MAPPING] lib %s; n_jni %d; angr unique %d; rizin unique %d; angr time %f; rizin time %f" % \
            (arm_lib.libpath, len(jni_functions_rizin), only_angr, only_rizin, time_angr, time_rizin))

        jni_functions[arm_lib.libpath] = jni_functions_rizin

    # Check callgraphs
    for libpath in jni_functions:
        jni_descriptions = jni_functions[libpath]

        main_bin   = libpath
        other_bins = list(map(lambda l: l.libpath, filter(lambda l: l.libpath != libpath, arm_libs)))

        proj_ghidra = CEXProject(main_bin, other_bins, plugins=["Ghidra"])

        offsets = list()
        for jni in jni_descriptions:
            offsets.append(jni.offset)

        start = time.time()
        ghidra.define_functions(libpath, offsets)
        print("[GHIDRA] def funcs time %f" % (time.time() - start))

        def angr_state_builder(proj):
            pass

        for jni in jni_descriptions:
            print_err(jni)
            class_name, method_name, args_str = find_java_jni(jni, native_methods)
            if class_name is None:
                continue

            demangled_name = apka.demangle(class_name, method_name, args_str)
            demangled_args = "Java.lang.Object," + demangled_name[demangled_name.find("(")+1:demangled_name.find(")")].replace(" ", "")

            start = time.time()
            cg = callgraph_gen_ghidra_wrapper(proj_ghidra, jni.offset & 0xfffffffe)
            ghidra_time    = time.time() - start
            ghidra_n_nodes = len(cg.nodes)
            ghidra_n_edges = len(cg.edges)
            print_err("ghidra OK")
            # with open("/dev/shm/graph.dot", "w") as fout:
            #     fout.write(to_dot(cg))
            # os.system("xdot /dev/shm/graph.dot")

            start = time.time()
            try:
                cg = callgraph_gen_angr_wrapper(main_bin, jni.offset, proj_ghidra._addresses, demangled_args)
            except NotImplementedError as e:
                print("[ERR_NOT_IMPLEMENTED] angr; jni %s; msg %s" % (jni, e))
                cg = nx.DiGraph()
            except cle.CLEError as e:
                print("[ERR_CLE] angr; jni %s; msg %s" % (jni, e))
                cg = nx.DiGraph()
            except Exception as e:
                print("[ERR_UNKNOWN] angr; jni %s; msg %s" % (jni, e))
                cg = nx.DiGraph()

            angr_time    = time.time() - start
            angr_n_nodes = len(cg.nodes)
            angr_n_edges = len(cg.edges)
            print_err("angr OK")
            # with open("/dev/shm/graph.dot", "w") as fout:
            #     fout.write(to_dot(cg))
            # os.system("xdot /dev/shm/graph.dot")

            start = time.time()
            try:
                cg = callgraph_gen_angr_wrapper(main_bin, jni.offset, proj_ghidra._addresses, demangled_args, other_libs=other_bins)
            except NotImplementedError as e:
                print("[ERR_NOT_IMPLEMENTED] angr; jni %s; msg %s" % (jni, e))
                cg = nx.DiGraph()
            except cle.CLEError as e:
                print("[ERR_CLE] angr; lib %s; msg %s" % (jni, e))
                cg = nx.DiGraph()
            except Exception as e:
                print("[ERR_UNKNOWN] angr; jni %s; msg %s" % (jni, e))
                cg = nx.DiGraph()

            angr_all_time    = time.time() - start
            angr_all_n_nodes = len(cg.nodes)
            angr_all_n_edges = len(cg.edges)
            print_err("angr_all OK")
            # with open("/dev/shm/graph.dot", "w") as fout:
            #     fout.write(to_dot(cg))
            # os.system("xdot /dev/shm/graph.dot")

            print("[CALLGRAPH] lib %s; fun %#x; ghidra nodes %d; ghidra edges %d; ghidra time %f; angr nodes %d; angr edges %d; angr time %f; angr_all nodes %d; angr_all edges %d; angr_all time %f" % \
                (libpath, jni.offset, ghidra_n_nodes, ghidra_n_edges, ghidra_time, angr_n_nodes, angr_n_edges, angr_time, angr_all_n_nodes, angr_all_n_edges, angr_all_time))
