import angr
import sys

from nativedroid.analyses.resolver.annotation.java_type_annotations import JobjectAnnotation
from nativedroid.analyses.resolver.armel_resolver import ArmelResolver
from nativedroid.analyses.analysis_center import AnalysisCenter

MAXITER = 200

def checkTaintedLoads(proj, addr, args):
    resolver = ArmelResolver(proj, AnalysisCenter(None, "", ""))
    state, _ = resolver.prepare_initial_state(args)

    state.ip = addr

    tainted_load = False
    def checkTaint(state):
        global tainted_load
        read_addr = state.inspect.mem_read_expr
        for annotation in read_addr.annotations:
            if isinstance(annotation, JobjectAnnotation):
                if annotation.taint_info['is_taint']:
                    tainted_load = True

    state.inspect.b('mem_read', when=angr.BP_BEFORE, action=checkTaint)

    i    = 0
    smgr = proj.factory.simgr(state, veritesting=False, save_unsat=False)
    while len(smgr.active) > 0:
        if tainted_load or i > MAXITER:
            break

        smgr.explore(n=1)
        i += 1

    return tainted_load

if __name__ == "__main__":
    if len(sys.argv) < 4:
        exit(1)

    so_path = sys.argv[1]
    addr    = int(sys.argv[2]) if not sys.argv[2].startswith("0x") else int(sys.argv[2], 16)
    args    = sys.argv[3]
    proj    = angr.Project(so_path)

    print checkTaintedLoads(proj, addr, args)
