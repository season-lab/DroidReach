from androguard.core.bytecodes.apk import APK
import networkx as nx
import traceback
import claripy
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
    print("USAGE: %s <apk_path> <vtable_log_path>" % sys.argv[0])
    exit(1)


def n_distinct_instructions(graph):
    instructions = set()
    for addr in graph.nodes:
        node = graph.nodes[addr]["data"]
        for i in node.insns:
            instructions.add(i.addr)
    return len(instructions)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()

    apk_path = sys.argv[1]
    log_path = sys.argv[2]

    apka       = APKAnalyzer(apk_path)
    armv7_libs = apka.get_armv7_libs()

    angr_emu = CEXProject.pm.get_plugin_by_name("AngrEmulated")

    # [MAPPING_PRODUCER_CONSUMER] libpath_consumer /dev/shm/apk_analyzer_data/b64726fee78fa5f448c1f242677b5942/lib/armeabi-v7a/libtwitchsdk.so; offset_consumer 0x63d74c; name_consumer Initialize; libpath_producer /dev/shm/apk_analyzer_data/b64726fee78fa5f448c1f242677b5942/lib/armeabi-v7a/libtwitchsdk.so; offset_producer 0x63d088; name_producer CreateNativeInstance; n_vtables 1; vtables 0x87ec4c
    fin = open(log_path, "r")
    for line in fin:
        line = line.strip()
        if line.startswith("[MAPPING_PRODUCER_CONSUMER] "):
            libpath, off, _, _, _, _, _, vtable = line.split(";")

            libpath = libpath.split(" ")[-1]
            off     = int(off.split(" ")[-1], 16)
            vtable  = int(vtable.split(" ")[-1], 16)

            def constructor(proj):
                s   = proj.factory.blank_state()
                obj = s.heap._malloc(4)
                s.memory.store(obj, claripy.BVV(vtable, 4*8), endness=proj.arch.memory_endness)
                s.regs.r2 = obj
                # print("built state:", s, s.regs.r2, s.mem[obj].uint32_t)
                return s

            off        -= off % 2
            main_lib    = libpath
            other_libs  = list(map(lambda l: l.libpath, filter(lambda l: l.libpath != main_lib, armv7_libs)))

            proj = CEXProject(libpath, libs=other_libs, plugins=["Ghidra", "AngrEmulated"])
            angr_emu.set_state_constructor(off, constructor)

            start   = time.time()
            icfg    = proj.get_icfg(off)
            elapsed = time.time() - start
            n_nodes = len(icfg.nodes)
            n_edges = len(icfg.edges)
            n_insns = n_distinct_instructions(icfg)

            angr_emu.del_state_constructor(off)
            print("[ICFG DATA] method ghidra_angr_vtable; lib %s; offset %#x; n_nodes %d; n_edges %d; n_insns %d; time %f" % \
                (main_lib, off, n_nodes, n_edges, n_insns, elapsed))
