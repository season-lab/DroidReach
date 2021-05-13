import claripy
import angr
import sys

from nativedroid.analyses.resolver.model.android_app_model import JNINativeInterface, JObject
from nativedroid.analyses.resolver.jni.java_type import get_type, get_type_size
from nativedroid.analyses.analysis_center import AnalysisCenter

MAXITER = 200
DEBUG   = False

def mk_cpp_obj(proj, state):
    obj    = JObject(proj)
    vtable = JObject(proj)

    if DEBUG:
        print "obj ptr:",    claripy.BVV(obj.ptr, proj.arch.bits)
        print "vtable ptr:", claripy.BVV(vtable.ptr, proj.arch.bits)
    state.memory.store(
        obj.ptr,
        claripy.BVV(vtable.ptr, proj.arch.bits),
        endness=proj.arch.memory_endness)
    for i in range(0, 300, proj.arch.bits / 8):
        state.memory.store(
            vtable.ptr + i,
            claripy.BVS("vtable_entry_%d" % i, proj.arch.bits),
            endness=proj.arch.memory_endness)

    if DEBUG:
        print "vtable ptr (load):", state.memory.load(obj.ptr, proj.arch.bits / 8, endness=proj.arch.memory_endness)
        print "first vtable entry (load):", state.memory.load(
            state.memory.load(obj.ptr, proj.arch.bits / 8, endness=proj.arch.memory_endness),
            proj.arch.bits / 8, endness=proj.arch.memory_endness)

    return claripy.BVV(obj.ptr, proj.arch.bits)

jni_interface_ptr = None
def prepare_state(proj, addr, args):
    global jni_interface_ptr
    if jni_interface_ptr is None:
        jni_interface_ptr = claripy.BVV(
            JNINativeInterface(proj, AnalysisCenter(None, "", "")).ptr,
            proj.arch.bits)

    state = proj.factory.blank_state(addr=addr)
    state.regs.r0 = jni_interface_ptr
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
            # data = claripy.BVS("long_arg_%d" % arg_id, proj.arch.bits)
            data = mk_cpp_obj(proj, state)
        else:
            data = claripy.BVS("int_arg_%d" % arg_id, proj.arch.bits)

        if arg_id < 3:
            state.regs.__setattr__('r%d' % arg_id, data)
        else:
            state.stack_push(data)
    return state

def checkTainted(proj, addr, args):
    state = prepare_state(proj, addr, args)

    tainted_load = list()
    def checkTaintedLoads(state):
        read_addr = state.inspect.mem_read_address
        if read_addr is None:
            return
        for symb_name in read_addr.variables:
            if "long_arg_" in symb_name:
                tainted_load.append(symb_name)
                break
    # state.inspect.b('mem_read', when=angr.BP_BEFORE, action=checkTaintedLoads)

    tainted_calls = list()
    def checkTaintedCall(state):
        exit_target = state.inspect.exit_target
        if DEBUG:
            print "checkTaintedCall: ", exit_target
        if exit_target is None:
            return
        for symb_name in exit_target.variables:
            if "vtable_entry_" in symb_name:
                tainted_calls.append(symb_name)
                break
    state.inspect.b('exit', when=angr.BP_BEFORE, action=checkTaintedCall)

    if DEBUG:
        print "entry r0", state.regs.r0
        print "entry r1", state.regs.r1
        print "entry r2", state.regs.r2

    i    = 0
    smgr = proj.factory.simgr(state, veritesting=False, save_unsat=False)
    while len(smgr.active) > 0:
        if len(tainted_calls) > 0 or i > MAXITER:
            break

        if DEBUG:
            for s in smgr.active:
                print s
                print s.regs.r0, s.regs.r2
                s.block().pp()
                raw_input()

        smgr.explore(n=1)
        if DEBUG: print smgr, smgr.errored, tainted_calls
        i += 1

    return len(tainted_calls) > 0

if __name__ == "__main__":
    if len(sys.argv) < 4:
        exit(1)

    assert len(sys.argv[2:]) % 2 == 0

    so_path = sys.argv[1]
    proj    = angr.Project(so_path, auto_load_libs=False)

    couples = list()
    for i in range(2, len(sys.argv), 2):
        v1 = sys.argv[i]
        v2 = sys.argv[i+1]
        couples.append((v1, v2))

    for addr, args in couples:
        addr = int(addr) if not addr.startswith("0x") else int(addr, 16)
        print checkTainted(proj, addr, args)
