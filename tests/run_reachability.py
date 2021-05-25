import rzpipe
import angr
import sys
import gc
import os

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from cex.cex import CEXProject
from timeout_decorator import timeout, TimeoutError

SCRIPTDIR = os.path.realpath(os.path.dirname(__file__))

LIBPDFIUM_PATH  = os.path.join(SCRIPTDIR, "argus-saf/libpdfium/libmodpdfium.so")

def print_stderr(*msg):
    sys.stderr.write(" ".join(map(str, msg)) + "\n")

def getExported(libpath):
    rz = rzpipe.open(libpath)
    exports = rz.cmdj("iEj")

    res = list()
    for export in exports:
        if export["type"] != "FUNC":
            continue
        res.append(export["vaddr"])
    return res

@timeout(60*15)
def getInstructionsCfgAngr(proj, addr):
    state = proj.factory.blank_state(mode="fastpath")
    cfg = proj.analyses.CFGEmulated(fail_fast=True, starts=[addr],
        initial_state=state, context_sensitivity_level=1,
        keep_state=True, normalize=True, call_depth=5)

    res = set()
    for node in cfg.graph.nodes:
        for addr in node.instruction_addrs:
            res.add(addr)
    return res

CEXProject.pm.get_plugin_by_name("Ghidra").use_accurate = True
@timeout(60*15)
def getInstructionsGhidra(libpath, addr):
    proj = CEXProject(libpath, plugins=["Ghidra"])
    cg = proj.get_callgraph(entry=addr)

    cfgs = list()
    for node in cg.nodes:
        cfg = proj.get_cfg(node)
        if cfg is not None:
            cfgs.append(cfg)

    res = set()
    for cfg in cfgs:
        for addr in cfg.nodes:
            data = cfg.nodes[addr]["data"]
            for insn in data.insns:
                res.add(insn.addr)
    return res

def angrCfgDot(proj, addr):
    state = proj.factory.blank_state(mode="fastpath")
    cfg = proj.analyses.CFGEmulated(fail_fast=True, starts=[addr],
        initial_state=state, context_sensitivity_level=1,
        keep_state=True, normalize=True, call_depth=5)

    res  = "digraph {\n\tnode [shape=box];\n"
    res += "\tgraph [fontname = \"monospace\"];\n"
    res += "\tnode  [fontname = \"monospace\"];\n"
    res += "\tedge  [fontname = \"monospace\"];\n"

    for node in cfg.graph.nodes():
        res += "\t%d [label = \"%s\"];\n" % (node.addr, hex(node.addr))

    added_edges = set()
    for src, dst in cfg.graph.edges():
        if (src.addr, dst.addr) in added_edges:
            continue
        added_edges.add((src.addr, dst.addr))
        res += "\t%d -> %d\n" % (src.addr, dst.addr)

    res += "}\n"
    return res

def run(libpath):
    exported = getExported(libpath)

    for funaddr in exported:
        gc.collect()

        proj    = angr.Project(libpath, auto_load_libs=False)
        funaddr = funaddr + 0x400000
        print_stderr("Processing %#x" % funaddr)
        try:
            nodesAngr   = getInstructionsCfgAngr(proj, funaddr)
            nodesGhidra = getInstructionsGhidra(libpath, funaddr)
        except TimeoutError:
            print_stderr("Timeout expired on %#x" % funaddr)
            continue
        except:
            print_stderr("Unknown error")
            continue

        print("%#x, %d, %d" % (funaddr, len(nodesAngr), len(nodesGhidra)))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # dbg mode
        proj  = angr.Project(LIBPDFIUM_PATH, auto_load_libs=False)
        addr  = int(sys.argv[1], 16)

        instructions_angr = getInstructionsCfgAngr(proj, addr)
        instructions_ghidra = getInstructionsGhidra(LIBPDFIUM_PATH, addr)

        only_angr = instructions_angr - instructions_ghidra
        only_ghidra = instructions_ghidra - instructions_angr

        print("Only angr:")
        for a in only_angr:
            print("  %#x" % a)

        print("Only ghidra:")
        for a in only_ghidra:
            print("  %#x" % a)

        dot_angr   = angrCfgDot(proj, addr)
        with open("/dev/shm/angr_graph.dot", "w") as fout:
            fout.write(dot_angr)

        import subprocess
        subprocess.Popen(["xdot", "/dev/shm/angr_graph.dot"])

    else:
        run(LIBPDFIUM_PATH)