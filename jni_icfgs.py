#!/usr/env python3

import networkx as nx
import traceback
import angr
import time
import sys
import cle
import os

from tests.timeout_decorator import timeout, TimeoutError
from apk_analyzer import APKAnalyzer
from apk_analyzer.APKAnalyzer import NativeMethod
from apk_analyzer.utils import prepare_initial_state
from cex_src.cex import to_dot
from cex_src.cex import CEXProject
from cex_src.cex.cfg_extractors import CFGInstruction, CFGNodeData
from cex_src.cex.cfg_extractors.angr_plugin.common import AngrCfgExtractor

def print_err(*msg):
    sys.stderr.write(" ".join(map(str, msg)) + "\n")

def usage():
    print_err(f"USAGE: {sys.argv[0]} <apk_path>")
    exit(1)

def icfg_gen_ghidra_wrapper(proj, addr):
    return proj.get_icfg(addr)

def hook_fp_functions(proj):
    class DummyEmptyModel(angr.SimProcedure):
        def run(self, *args):
            return None

    def hook_with_dummy(name):
        proj.hook_symbol(name, DummyEmptyModel(), replace=True)

    float_functions = set()
    for s in proj.loader.symbols:
        if proj.is_hooked(s.rebased_addr):
            h = proj.hooked_by(s.rebased_addr)
            fun_ty = h.cc.func_ty
            if fun_ty is None:
                continue
            if "double" in fun_ty.returnty.name or "float" in fun_ty.returnty.name:
                float_functions.add(h.display_name)

    to_hook = float_functions
    for n in to_hook:
        hook_with_dummy(n)

def icfg_gen_angr_wrapper(main_bin, entry, addresses, args, other_libs=None):
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
    hook_fp_functions(proj)

    if entry % 2 == 0 and AngrCfgExtractor.is_thumb(proj, entry):
        entry += 1

    state = prepare_initial_state(proj, args)

    cfg = proj.analyses.CFGEmulated(
        fail_fast=True, keep_state=True, starts=[entry],
        context_sensitivity_level=1, call_depth=5, initial_state=state)

    g = nx.DiGraph()
    for node in cfg.graph.nodes:
        g.add_node(node.addr, data=CFGNodeData(node.addr,
            [ CFGInstruction(a, [], "???") for a in node.instruction_addrs ], []))

    for node_src, node_dst in cfg.graph.edges:
        g.add_edge(node_src.addr, node_dst.addr)

    return nx.ego_graph(g, entry, radius=sys.maxsize)

def find_java_jni(jni, java_natives):
    for class_name, method_name, args_str in java_natives:
        if (jni.method_name == method_name) and                                                  \
           (jni.class_name == "???" or jni.class_name == class_name[1:-1].replace("/", ".")) and \
           (jni.args == "???" or args_str.startswith(jni.args)):
           return class_name, method_name, args_str
    return None, None, None

def n_distinct_instructions(graph):
    instructions = set()
    for addr in graph.nodes:
        node = graph.nodes[addr]["data"]
        for i in node.insns:
            instructions.add(i.addr)
    return len(instructions)

def find_native_from_pool(apka, print_label, libs, method_pool):
    found_mapping          = 0
    found_dynamic_rizin    = 0
    found_static           = 0
    found_dynamic_angr     = 0
    rizin_clash            = 0
    angr_clash             = 0
    clash_resolved_by_angr = 0

    arm_hashes = list(map(lambda l: l.libhash, libs))

    angr_found_methods = set()
    start              = time.time()
    for class_name, native_name, args_string in method_pool:
        # NOTE: angr has a timeout of 15 minutes per lib
        jnis = apka.find_native_implementations_angr(native_name, class_name, args_string, lib_whitelist=arm_hashes)
        if len(jnis) > 0:
            found_dynamic_angr += 1
            angr_found_methods.add((class_name, native_name, args_string))
        elif len(jnis) > 1:
            found_dynamic_angr += 1
            angr_clash         += 1
            angr_found_methods.add((class_name, native_name, args_string))
    time_angr = time.time() - start

    jni_functions = dict()
    def add_to_jni_functions(jni):
        if jni.analyzer.libpath not in jni_functions:
            jni_functions[jni.analyzer.libpath] = list()
        jni_functions[jni.analyzer.libpath].append(jni)

    rizin_found_methods = set()
    start               = time.time()
    for class_name, native_name, args_string in method_pool:
        jnis = apka.find_native_implementations(native_name, class_name, args_string, lib_whitelist=arm_hashes)
        if len(jnis) == 1:
            found_mapping += 1

            jni = jnis[0]
            if jni.class_name != "???":
                found_static += 1
            else:
                found_dynamic_rizin += 1
                rizin_found_methods.add((class_name, native_name, args_string))
            add_to_jni_functions(jni)

        elif len(jnis) > 1:
            rizin_clash         += 1
            found_dynamic_rizin += 1
            found_mapping       += 1

            rizin_found_methods.add((class_name, native_name, args_string))

            # This should be fast since the result is cached
            angr_jnis = apka.find_native_implementations_angr(native_name, class_name, args_string, lib_whitelist=arm_hashes)
            if len(angr_jnis) == 1:
                clash_resolved_by_angr += 1
                add_to_jni_functions(angr_jnis[0])
            else:
                # add all jni methods (even with clash)
                for jni in jnis:
                    add_to_jni_functions(jni)
    time_rizin = time.time() - start

    rizin_unique = len(rizin_found_methods - angr_found_methods)
    angr_unique  = len(angr_found_methods - rizin_found_methods)

    # Add angr unique (cached! This should be fast)
    for class_name, native_name, args_string in (angr_found_methods - rizin_found_methods):
        jnis = apka.find_native_implementations_angr(native_name, class_name, args_string, lib_whitelist=arm_hashes)
        add_to_jni_functions(jnis[0])

    print("[%s] apk_jni: %d; found_jni %d; static_jni %d; dyn angr %d; angr unique %d; angr clashes %d; time angr %f; dyn rizin %d; rizin unique %d; rizin clashes %d; rizin time %f; clash resolved by angr %d" % \
        (print_label, len(method_pool), found_mapping, found_static, found_dynamic_angr, angr_unique, angr_clash, time_angr, found_dynamic_rizin, rizin_unique, rizin_clash, time_rizin, clash_resolved_by_angr))
    return jni_functions

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

    # Check differences of JNI methods mapping between angr and rizin (ALL METHODS)
    # _ = find_native_from_pool(apka, "JNI_MAPPINGS", arm_libs, native_methods)

    # Check differences of JNI methods mapping between angr and rizin (REACHABLE METHODS)
    reachable_native_methods = apka.find_reachable_native_methods()
    jni_functions_reachable = find_native_from_pool(apka, "JNI_MAPPING_REACHABLE", arm_libs, reachable_native_methods)

    # Check icfgs
    for libpath in jni_functions_reachable:
        jni_descriptions = jni_functions_reachable[libpath]
        if len(jni_descriptions) == 0:
            continue

        main_bin   = libpath
        other_bins = list(map(lambda l: l.libpath, filter(lambda l: l.libpath != libpath, arm_libs)))

        proj_ghidra      = CEXProject(main_bin, other_bins, plugins=["Ghidra"])
        proj_ghidra_angr = CEXProject(main_bin, other_bins, plugins=["Ghidra", "AngrEmulated"])

        offsets = list()
        for jni in jni_descriptions:
            offsets.append(jni.offset)

        start = time.time()
        ghidra.define_functions(libpath, offsets)
        print("[GHIDRA] def funcs time %f" % (time.time() - start))

        for jni in jni_descriptions:
            print(jni)
            class_name, method_name, args_str = find_java_jni(jni, native_methods)
            if class_name is None:
                print("[ERR_NO_JAVA] Jni method not in Java world")
                continue

            demangled_name = apka.demangle(class_name, method_name, args_str)
            demangled_args = "Java.lang.Object," + demangled_name[demangled_name.find("(")+1:demangled_name.find(")")].replace(" ", "")

            start = time.time()
            icfg = icfg_gen_ghidra_wrapper(proj_ghidra, jni.offset & 0xfffffffe)
            ghidra_time    = time.time() - start
            ghidra_n_nodes = len(icfg.nodes)
            ghidra_n_edges = len(icfg.edges)
            ghidra_n_insns = n_distinct_instructions(icfg)
            print_err("ghidra OK")
            # with open("/dev/shm/ghidra_graph.dot", "w") as fout:
            #     fout.write(to_dot(icfg))
            # os.system("xdot /dev/shm/ghidra_graph.dot")

            start = time.time()
            try:
                icfg = icfg_gen_ghidra_wrapper(proj_ghidra_angr, jni.offset & 0xfffffffe)
            except Exception as e:
                print("[ERR_UNKNOWN] ghidra_angr; jni %s; msg %s" % (jni, e))
                print(traceback.format_exc())
                icfg = nx.DiGraph()

            ghidra_angr_time    = time.time() - start
            ghidra_angr_n_nodes = len(icfg.nodes)
            ghidra_angr_n_edges = len(icfg.edges)
            ghidra_angr_n_insns = n_distinct_instructions(icfg)
            print_err("ghidra_angr OK")
            # with open("/dev/shm/ghidra_angr_graph.dot", "w") as fout:
            #     fout.write(to_dot(icfg))
            # os.system("xdot /dev/shm/ghidra_angr_graph.dot")

            start = time.time()
            try:
                icfg = icfg_gen_angr_wrapper(main_bin, jni.offset, proj_ghidra._addresses, demangled_args)
            except NotImplementedError as e:
                print("[ERR_NOT_IMPLEMENTED] angr; jni %s; msg %s" % (jni, e))
                icfg = nx.DiGraph()
            except cle.CLEError as e:
                print("[ERR_CLE] angr; jni %s; msg %s" % (jni, e))
                icfg = nx.DiGraph()
            except Exception as e:
                print("[ERR_UNKNOWN] angr; jni %s; msg %s" % (jni, e))
                print(traceback.format_exc())
                icfg = nx.DiGraph()

            angr_time    = time.time() - start
            angr_n_nodes = len(icfg.nodes)
            angr_n_edges = len(icfg.edges)
            angr_n_insns = n_distinct_instructions(icfg)
            print_err("angr OK")
            # with open("/dev/shm/graph.dot", "w") as fout:
            #     fout.write(to_dot(icfg))
            # os.system("xdot /dev/shm/graph.dot")

            start = time.time()
            try:
                icfg = icfg_gen_angr_wrapper(main_bin, jni.offset, proj_ghidra._addresses, demangled_args, other_libs=other_bins)
            except NotImplementedError as e:
                print("[ERR_NOT_IMPLEMENTED] angr; jni %s; msg %s" % (jni, e))
                icfg = nx.DiGraph()
            except cle.CLEError as e:
                print("[ERR_CLE] angr; lib %s; msg %s" % (jni, e))
                icfg = nx.DiGraph()
            except Exception as e:
                print("[ERR_UNKNOWN] angr; jni %s; msg %s" % (jni, e))
                print(traceback.format_exc())
                icfg = nx.DiGraph()

            angr_all_time    = time.time() - start
            angr_all_n_nodes = len(icfg.nodes)
            angr_all_n_edges = len(icfg.edges)
            angr_all_n_insns = n_distinct_instructions(icfg)
            print_err("angr_all OK")
            # with open("/dev/shm/graph.dot", "w") as fout:
            #     fout.write(to_dot(icfg))
            # os.system("xdot /dev/shm/graph.dot")

            print("[CALLGRAPH] lib %s; fun %#x; ghidra nodes %d; ghidra edges %d; ghidra insns %d; ghidra time %f; ghidra angr nodes %d; ghidra angr edges %d; ghidra angr insns %d; ghidra angr time %f; angr nodes %d; angr edges %d; angr insns %d; angr time %f; angr_all nodes %d; angr_all edges %d; angr_all insns %d; angr_all time %f" % \
                (libpath, jni.offset, ghidra_n_nodes, ghidra_n_edges, ghidra_n_insns, ghidra_time, ghidra_angr_n_nodes, ghidra_angr_n_edges, ghidra_angr_n_insns, ghidra_angr_time, angr_n_nodes, angr_n_edges, angr_n_insns, angr_time, angr_all_n_nodes, angr_all_n_edges, angr_all_n_insns, angr_all_time))
