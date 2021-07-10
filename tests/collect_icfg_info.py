import networkx as nx
import traceback
import time
import angr
import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from apk_analyzer import APKAnalyzer
from apk_analyzer.utils import prepare_initial_state
from cex_src.cex import CEXProject
from cex_src.cex.cfg_extractors import CFGInstruction, CFGNodeData
from cex_src.cex.cfg_extractors.angr_plugin.common import AngrCfgExtractor

def usage():
    print(
        "USAGE: %s <apk_path> <jni_mappings_log> <mode {0, 1, 2, 3, 4, 5}>" % \
        sys.argv[0])
    exit(0)

def n_distinct_instructions(graph):
    instructions = set()
    for addr in graph.nodes:
        node = graph.nodes[addr]["data"]
        for i in node.insns:
            instructions.add(i.addr)
    return len(instructions)

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

def gen_icfgs_ghidra(main_lib, other_libs, off_args):
    proj_ghidra = CEXProject(main_lib, other_libs, plugins=["Ghidra"])
    ghidra      = CEXProject.pm.get_plugin_by_name("Ghidra")

    start = time.time()
    ghidra.define_functions(main_lib, list(map(lambda x: x[0], off_args)))
    elapsed = time.time() - start
    print("[GHIDRA DEF FUN] time %f" % elapsed)

    for off, _ in off_args:
        start   = time.time()
        icfg    = proj_ghidra.get_icfg(off)
        elapsed = time.time() - start
        n_nodes = len(icfg.nodes)
        n_edges = len(icfg.edges)
        n_insns = n_distinct_instructions(icfg)

        print("[ICFG DATA] method ghidra; lib %s; offset %#x; n_nodes %d; n_edges %d; n_insns %d; time %f" % \
            (main_lib, off, n_nodes, n_edges, n_insns, elapsed))

def gen_icfgs_ghidra_angr(main_lib, other_libs, off_args):
    proj_ghidra_angr = CEXProject(main_lib, other_libs, plugins=["Ghidra", "AngrEmulated"])
    ghidra           = CEXProject.pm.get_plugin_by_name("Ghidra")

    start = time.time()
    ghidra.define_functions(main_lib, list(map(lambda x: x[0], off_args)))
    elapsed = time.time() - start
    print("[GHIDRA DEF FUN] time %f" % elapsed)

    for off, _ in off_args:
        start   = time.time()
        icfg    = proj_ghidra_angr.get_icfg(off)
        elapsed = time.time() - start
        n_nodes = len(icfg.nodes)
        n_edges = len(icfg.edges)
        n_insns = n_distinct_instructions(icfg)

        print("[ICFG DATA] method ghidra_angr; lib %s; offset %#x; n_nodes %d; n_edges %d; n_insns %d; time %f" % \
            (main_lib, off, n_nodes, n_edges, n_insns, elapsed))

def gen_icfgs_ghidra_angr_refine_later(main_lib, other_libs, off_args):
    proj_ghidra_angr = CEXProject(main_lib, other_libs, plugins=["Ghidra", "AngrEmulated"])
    proj_ghidra      = CEXProject(main_lib, other_libs, plugins=["Ghidra"])
    ghidra           = CEXProject.pm.get_plugin_by_name("Ghidra")

    start = time.time()
    ghidra.define_functions(main_lib, list(map(lambda x: x[0], off_args)))
    elapsed = time.time() - start
    print("[GHIDRA DEF FUN] time %f" % elapsed)

    for off, _ in off_args:
        start   = time.time()
        icfg    = proj_ghidra.get_icfg(off)
        elapsed = time.time() - start
        n_nodes = len(icfg.nodes)
        n_edges = len(icfg.edges)
        n_insns = n_distinct_instructions(icfg)

        print("[ICFG DATA] method ghidra_angr_1; lib %s; offset %#x; n_nodes %d; n_edges %d; n_insns %d; time %f" % \
            (main_lib, off, n_nodes, n_edges, n_insns, elapsed))

    for off, _ in off_args:
        start   = time.time()
        icfg    = proj_ghidra_angr.get_icfg(off)
        elapsed = time.time() - start
        n_nodes = len(icfg.nodes)
        n_edges = len(icfg.edges)
        n_insns = n_distinct_instructions(icfg)

        # When Ghidra finished, let's refine the CFGs
        print("[ICFG DATA] method ghidra_angr_2; lib %s; offset %#x; n_nodes %d; n_edges %d; n_insns %d; time %f" % \
            (main_lib, off, n_nodes, n_edges, n_insns, elapsed))

def gen_icfgs_angr(main_lib, other_libs, off_args):
    def gen_icfg(offset, args):
        proj = angr.Project(
            main_lib,
            auto_load_libs = False,
            use_sim_procedures = True
        )
        hook_fp_functions(proj)

        if offset % 2 == 0 and AngrCfgExtractor.is_thumb(proj, offset):
            offset += 1

        state = prepare_initial_state(proj, args)

        try:
            cfg = proj.analyses.CFGEmulated(
                fail_fast=True, keep_state=True, starts=[offset],
                context_sensitivity_level=1, call_depth=5, initial_state=state)
        except Exception as e:
            print("[ERR] error during the genration of CFGEmulated of angr [ %s ]" % str(e))
            print(traceback.format_exc())
            return nx.DiGraph()

        g = nx.DiGraph()
        for node in cfg.graph.nodes:
            if node.block is None:
                continue
            try:
                capstone_insns = node.block.capstone.insns
            except KeyError:
                capstone_insns = list()
            if len(capstone_insns) == 0:
                continue

            g.add_node(node.addr, data=CFGNodeData(node.addr,
                [ CFGInstruction(a, 0, [], "???") for a in node.instruction_addrs ], []))

        for node_src, node_dst in cfg.graph.edges:
            if node_src.addr not in g.nodes or node_dst.addr not in g.nodes:
                continue
            g.add_edge(node_src.addr, node_dst.addr)

        if offset not in g.nodes:
            return nx.DiGraph()
        return nx.ego_graph(g, offset, radius=sys.maxsize)

    for off, args in off_args:
        start   = time.time()
        icfg    = gen_icfg(off, args)
        elapsed = time.time() - start
        n_nodes = len(icfg.nodes)
        n_edges = len(icfg.edges)
        n_insns = n_distinct_instructions(icfg)

        print("[ICFG DATA] method angr; lib %s; offset %#x; n_nodes %d; n_edges %d; n_insns %d; time %f" % \
            (main_lib, off, n_nodes, n_edges, n_insns, elapsed))

def gen_icfgs_angr_all_libs(main_lib, other_libs, off_args):
    def gen_icfg(offset, args, addresses):
        main_opts = { 'base_addr' : addresses[main_lib] }
        lib_opts  = {}
        for l in other_libs:
            lib_opts[os.path.basename(l)] = { "base_addr" : addresses[l] }

        proj = angr.Project(
                main_lib,
                main_opts = main_opts,
                use_system_libs     = False,
                auto_load_libs      = False,
                except_missing_libs = False,
                use_sim_procedures  = True,
                force_load_libs     = other_libs,
                lib_opts            = lib_opts
            )
        hook_fp_functions(proj)

        if offset % 2 == 0 and AngrCfgExtractor.is_thumb(proj, offset):
            offset += 1

        state = prepare_initial_state(proj, args)

        try:
            cfg = proj.analyses.CFGEmulated(
                fail_fast=True, keep_state=True, starts=[offset],
                context_sensitivity_level=1, call_depth=5, initial_state=state)
        except Exception as e:
            print("[ERR] error during the genration of CFGEmulated of angr_all_libs [ %s ]" % str(e))
            print(traceback.format_exc())
            return nx.DiGraph()

        g = nx.DiGraph()
        for node in cfg.graph.nodes:
            if node.block is None:
                continue
            try:
                capstone_insns = node.block.capstone.insns
            except KeyError:
                capstone_insns = list()
            if len(capstone_insns) == 0:
                continue

            g.add_node(node.addr, data=CFGNodeData(node.addr,
                [ CFGInstruction(a, 0, [], "???") for a in node.instruction_addrs ], []))

        for node_src, node_dst in cfg.graph.edges:
            if node_src.addr not in g.nodes or node_dst.addr not in g.nodes:
                continue
            g.add_edge(node_src.addr, node_dst.addr)

        if offset not in g.nodes:
            return nx.DiGraph()
        return nx.ego_graph(g, offset, radius=sys.maxsize)

    proj = CEXProject(main_lib, other_libs)
    for off, args in off_args:
        start   = time.time()
        icfg    = gen_icfg(off, args, proj._addresses)
        elapsed = time.time() - start
        n_nodes = len(icfg.nodes)
        n_edges = len(icfg.edges)
        n_insns = n_distinct_instructions(icfg)

        print("[ICFG DATA] method angr_all_libs; lib %s; offset %#x; n_nodes %d; n_edges %d; n_insns %d; time %f" % \
            (main_lib, off, n_nodes, n_edges, n_insns, elapsed))

def gen_icfgs_angr_all_libs_no_timeout(main_lib, other_libs, off_args):
    def gen_icfg(offset, args, addresses):
        main_opts = { 'base_addr' : addresses[main_lib] }
        lib_opts  = {}
        for l in other_libs:
            lib_opts[os.path.basename(l)] = { "base_addr" : addresses[l] }

        proj = angr.Project(
                main_lib,
                main_opts = main_opts,
                use_system_libs     = False,
                auto_load_libs      = False,
                except_missing_libs = False,
                use_sim_procedures  = True,
                force_load_libs     = other_libs,
                lib_opts            = lib_opts
            )
        hook_fp_functions(proj)

        if offset % 2 == 0 and AngrCfgExtractor.is_thumb(proj, offset):
            offset += 1

        state = prepare_initial_state(proj, args)

        try:
            cfg = proj.analyses.CFGEmulated(starts=[offset], initial_state=state)
        except Exception as e:
            print("[ERR] error during the genration of CFGEmulated of angr_all_libs_no_timeout [ %s ]" % str(e))
            print(traceback.format_exc())
            return nx.DiGraph()

        g = nx.DiGraph()
        for node in cfg.graph.nodes:
            if node.block is None:
                continue
            try:
                capstone_insns = node.block.capstone.insns
            except KeyError:
                capstone_insns = list()
            if len(capstone_insns) == 0:
                continue

            g.add_node(node.addr, data=CFGNodeData(node.addr,
                [ CFGInstruction(a, 0, [], "???") for a in node.instruction_addrs ], []))

        for node_src, node_dst in cfg.graph.edges:
            if node_src.addr not in g.nodes or node_dst.addr not in g.nodes:
                continue
            g.add_edge(node_src.addr, node_dst.addr)

        if offset not in g.nodes:
            return nx.DiGraph()
        return nx.ego_graph(g, offset, radius=sys.maxsize)

    proj = CEXProject(main_lib, other_libs)
    for off, args in off_args:
        start   = time.time()
        icfg    = gen_icfg(off, args, proj._addresses)
        elapsed = time.time() - start
        n_nodes = len(icfg.nodes)
        n_edges = len(icfg.edges)
        n_insns = n_distinct_instructions(icfg)

        print("[ICFG DATA] method angr_all_libs_no_timeout; lib %s; offset %#x; n_nodes %d; n_edges %d; n_insns %d; time %f" % \
            (main_lib, off, n_nodes, n_edges, n_insns, elapsed))

if __name__ == "__main__":
    # USAGE: %s <apk_path> <jni_mappings_log> <mode {0, 1, 2, 3, 4}>" % \
    if len(sys.argv) < 4:
        usage()

    apk_path        = sys.argv[1]
    jni_mapping_log = sys.argv[2]
    mode            = int(sys.argv[3])

    if mode not in {0,1,2,3,4,5}:
        usage()

    apka     = APKAnalyzer(apk_path)
    jni_data = dict()

    loaded_jni_functions = 0

    log = open(jni_mapping_log, "r")
    for line in log:
        line = line.strip()
        if not line.startswith("[MAPPING]"):
            continue

        _, libpath, class_name, method_name, args, off = line.split(" ")
        off = int(off, 16)

        if args == "???":
            for q_class_name, q_method_name, q_args in apka.find_native_methods():
                if q_class_name[1:-1].replace("/", ".") == class_name and q_method_name == method_name:
                    args = q_args
                    break

        if args == "???":
            print("[ERR] no args for %s %s %s %#x" % (libpath, class_name, method_name, off))
            continue

        if libpath not in jni_data:
            jni_data[libpath] = list()
        jni_data[libpath].append((off & 0xfffffffe, args))
        loaded_jni_functions += 1
    log.close()

    print("[INFO] loaded %d jni functions" % loaded_jni_functions)

    arm_libs = apka.get_armv7_libs()
    for libpath in jni_data:
        main_lib   = libpath
        other_bins = list(map(lambda l: l.libpath, filter(lambda l: l.libpath != libpath, arm_libs)))

        print("[INFO] processing %d jni functions for lib %s" % (len(jni_data[libpath]), libpath))

        if mode == 0:
            gen_icfgs_ghidra(main_lib, other_bins, jni_data[libpath])
        elif mode == 1:
            gen_icfgs_ghidra_angr(main_lib, other_bins, jni_data[libpath])
        elif mode == 2:
            gen_icfgs_angr(main_lib, other_bins, jni_data[libpath])
        elif mode == 3:
            gen_icfgs_angr_all_libs(main_lib, other_bins, jni_data[libpath])
        elif mode == 4:
            gen_icfgs_angr_all_libs_no_timeout(main_lib, other_bins, jni_data[libpath])
        elif mode == 5:
            gen_icfgs_ghidra_angr_refine_later(main_lib, other_bins, jni_data[libpath])
