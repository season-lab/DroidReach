import claripy
import angr
import sys

from nativedroid.analyses.resolver.model.android_app_model import JNINativeInterface, JObject
from nativedroid.analyses.resolver.jni.java_type import get_type, get_type_size
from nativedroid.analyses.analysis_center import AnalysisCenter

MAXITER = 200
DEBUG   = False

def prepare_state(proj, addr, args):
    state = proj.factory.blank_state(addr=addr)
    state.regs.r0 = claripy.BVV(
        JNINativeInterface(proj, AnalysisCenter(None, "", "")).ptr,
        proj.arch.bits)
    state.regs.r1 = claripy.BVV(
        JObject(proj).ptr, proj.arch.bits)

    parsed_args = dict()
    for i, a in enumerate(args.split(",")):
        a = a.strip().replace(" ", "")
        parsed_args[i+2] = a

    for arg_id in parsed_args:
        arg_type = parsed_args[arg_id]
        if arg_type not in {"long", "int"}:
            typ       = get_type(proj, arg_type.replace('/', '.'))
            typ_size  = get_type_size(proj, arg_type)
            data      = claripy.BVV(typ.ptr, typ_size)
        elif arg_type == "long":
            data = claripy.BVS("long_arg_%d" % arg_id, proj.arch.bits)
        else:
            data = claripy.BVS("int_arg_%d" % arg_id, proj.arch.bits)

        if arg_id < 3:
            state.regs.__setattr__('r%d' % arg_id, data)
        else:
            state.stack_push(data)
    return state

def checkTaintedLoads(proj, addr, args):
    state = prepare_state(proj, addr, args)

    tainted_load = list()
    def checkTaint(state):
        read_addr = state.inspect.mem_read_address
        if read_addr is None:
            return
        for symb_name in read_addr.variables:
            if "long_arg_" in symb_name:
                tainted_load.append(symb_name)
                break
    state.inspect.b('mem_read', when=angr.BP_BEFORE, action=checkTaint)

    if DEBUG:
        print state.regs.r0
        print state.regs.r1
        print state.regs.r2

    i    = 0
    smgr = proj.factory.simgr(state, veritesting=False, save_unsat=False)
    while len(smgr.active) > 0:
        if len(tainted_load) > 0 or i > MAXITER:
            break

        if DEBUG:
            for s in smgr.active:
                print s
                s.block().pp()

        smgr.explore(n=1)
        if DEBUG: print smgr, smgr.errored, tainted_load
        i += 1

    return len(tainted_load) > 0

if __name__ == "__main__":
    if len(sys.argv) < 4:
        exit(1)

    so_path = sys.argv[1]
    addr    = int(sys.argv[2]) if not sys.argv[2].startswith("0x") else int(sys.argv[2], 16)
    args    = sys.argv[3]
    proj    = angr.Project(so_path)

    print checkTaintedLoads(proj, addr, args)
