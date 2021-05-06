import rzpipe
import angr
import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from cex.cex import CEX
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
def getNodesCfgAngr(proj, addr):
    state = proj.factory.blank_state(mode="fastpath")
    cfg = proj.analyses.CFGEmulated(fail_fast=True, starts=[addr],
        initial_state=state, context_sensitivity_level=1,
        keep_state=True, normalize=True, call_depth=5)

    nodes = set()
    for node in cfg.graph.nodes:
        nodes.add(node.addr)
    return nodes

cex = CEX()
@timeout(60*15)
def getNodesGhidra(libpath, addr):
    cg = cex.get_callgraph(libpath, entry=addr, plugins=["Ghidra"])

    cfgs = list()
    for node in cg.nodes:
        cfg = cex.get_cfg(libpath, node, plugins=["Ghidra"])
        if cfg is not None:
            cfgs.append(cfg)

    nodes = set()
    for cfg in cfgs:
        for addr in cfg.nodes:
            nodes.add(addr)
    return nodes

def run(libpath):
    proj     = angr.Project(libpath, auto_load_libs=False)
    exported = getExported(libpath)

    for funaddr in exported:
        funaddr = funaddr + 0x400000
        print_stderr("Processing %#x" % funaddr)
        try:
            nodesAngr   = getNodesCfgAngr(proj, funaddr)
            nodesGhidra = getNodesGhidra(libpath, funaddr)
        except TimeoutError:
            print_stderr("Timeout expired on %#x" % funaddr)
            continue

        print("%#x, %d, %d" % (funaddr, len(nodesAngr), len(nodesGhidra)))

if __name__ == "__main__":
    run(LIBPDFIUM_PATH)
