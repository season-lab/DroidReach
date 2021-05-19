import logging
import claripy
import angr
import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
from apk_analyzer.utils.jni_stubs.java_type import get_type, get_type_size
from apk_analyzer.utils.angr_find_dynamic_jni import AnalysisCenter
from apk_analyzer.utils.jni_stubs.jni_type.jni_native_interface import JNINativeInterface, JObject

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from timeout_decorator import timeout, TimeoutError

# angr, shut the fuck up
angr_logger = logging.getLogger('angr')
angr_logger.propagate = False
cle_logger  = logging.getLogger('cle')
cle_logger.propagate = False
nativedroid_logger = logging.getLogger('nativedroid')
nativedroid_logger.propagate = False


class JLongAsCppObjFinder(object):
    DEBUG     = False
    MAXITER   = 100
    MAXSTATES = 200

    def __init__(self, libpath):
        self.libpath = libpath
        self.project = angr.Project(libpath, auto_load_libs=False)
        self.state   = self.project.factory.blank_state()  # general purpose state... Can be useful to read memory
        self.jni_ptr = claripy.BVV(
            JNINativeInterface(
                self.project,
                AnalysisCenter(None, "", "")).ptr,
                self.project.arch.bits)

    def mk_cpp_obj(self, state):
        obj    = JObject(self.project)
        vtable = JObject(self.project)

        if JLongAsCppObjFinder.DEBUG:
            print("obj ptr:",    claripy.BVV(obj.ptr, self.project.arch.bits))
            print("vtable ptr:", claripy.BVV(vtable.ptr, self.project.arch.bits))

        state.memory.store(
            obj.ptr,
            claripy.BVV(vtable.ptr, self.project.arch.bits),
            endness=self.project.arch.memory_endness)
        for i in range(0, 300, self.project.arch.bits // 8):
            state.memory.store(
                vtable.ptr + i,
                claripy.BVS("vtable_entry_%d" % i, self.project.arch.bits),
                endness=self.project.arch.memory_endness)

        if JLongAsCppObjFinder.DEBUG:
            print("vtable ptr (load):", state.memory.load(obj.ptr, self.project.arch.bits // 8, endness=self.project.arch.memory_endness))
            print("first vtable entry (load):", state.memory.load(
                state.memory.load(obj.ptr, self.project.arch.bits // 8, endness=self.project.arch.memory_endness),
                self.project.arch.bits // 8, endness=self.project.arch.memory_endness))

        return claripy.BVV(obj.ptr, self.project.arch.bits)

    def prepare_state(self, addr, args):
        state = self.project.factory.blank_state(addr=addr)
        state.regs.r0 = self.jni_ptr
        state.regs.r1 = claripy.BVV(
            JObject(self.project).ptr, self.project.arch.bits)

        parsed_args = dict()
        for i, a in enumerate(args.split(",")):
            a = a.strip().replace(" ", "")
            parsed_args[i+2] = a

        for arg_id in parsed_args:
            arg_type = parsed_args[arg_id]
            if arg_type not in {"long", "int"}:
                typ       = get_type(self.project, arg_type.replace('/', '.'))
                typ_size  = get_type_size(self.project, arg_type)
                data      = claripy.BVV(typ.ptr, typ_size)
            elif arg_type == "long":
                data = self.mk_cpp_obj(state)
            else:
                data = claripy.BVS("int_arg_%d" % arg_id, self.project.arch.bits)

            if data.size() < self.project.arch.bits:
                data = data.zero_extend(self.project.arch.bits - data.size())

            if arg_id < 3:
                state.regs.__setattr__('r%d' % arg_id, data)
            else:
                state.stack_push(data)
        state.solver._solver.timeout = 2000 # 2 seconds as timeout
        return state

    def _is_thumb(self, addr):
        if self.project.arch.name != "ARMEL":
            return False

        if addr % 2 != 0:
            return False

        self.state.ip = addr
        if self.state.block().size == 0:
            return True
        return False

    @timeout(60*5)  # Risky, let's try
    def _inner_check(self, addr, args):
        is_thumb = self._is_thumb(addr)
        if is_thumb:
            addr = addr + 1

        print(self.libpath, hex(addr), args)
        state = self.prepare_state(addr, args)

        tainted_calls = list()
        def checkTaintedCall(state):
            exit_target = state.inspect.exit_target
            if JLongAsCppObjFinder.DEBUG:
                print("checkTaintedCall: ", exit_target)
            if exit_target is None or isinstance(exit_target, int):
                return
            for symb_name in exit_target.variables:
                if "vtable_entry_" in symb_name:
                    tainted_calls.append(symb_name)
                    break
        state.inspect.b('exit', when=angr.BP_BEFORE, action=checkTaintedCall)

        if JLongAsCppObjFinder.DEBUG:
            print("entry r0", state.regs.r0)
            print("entry r1", state.regs.r1)
            print("entry r2", state.regs.r2)

        i    = 0
        smgr = self.project.factory.simgr(state, veritesting=False, save_unsat=False)
        while len(smgr.active) > 0:
            if len(tainted_calls) > 0 or i > JLongAsCppObjFinder.MAXITER:
                break

            if False and JLongAsCppObjFinder.DEBUG:
                for s in smgr.active:
                    print(s)
                    if self.project.is_hooked(s.addr):
                        print(s.regs.r0, s.regs.r1, s.regs.r2)
                        print(self.project.hooked_by(s.addr))
                    else:
                        s.block().pp()
                    print(s.step())
                    input("> Press a key to continue...")

            smgr.explore(n=1)
            if JLongAsCppObjFinder.DEBUG:
                print(i, smgr, smgr.errored, tainted_calls)
            if len(smgr.active) > JLongAsCppObjFinder.MAXSTATES:
                # Try to limit RAM usage
                break
            i += 1

        if len(smgr.errored) > 0:
            sys.stderr.write("WARNING: %s @ %#x\n" % (self.libpath, addr))
            sys.stderr.write("WARNING: %d errored: %s\n"  % (len(smgr.errored), smgr.errored[0]))
        if i < 5:
            sys.stderr.write("WARNING: %s @ %#x\n" % (self.libpath, addr))
            sys.stderr.write("WARNING: very few iterations (%d)\n" % i)
        if len(smgr.active) > JLongAsCppObjFinder.MAXSTATES:
            sys.stderr.write("WARNING: %s @ %#x\n" % (self.libpath, addr))
            sys.stderr.write("WARNING: killed for generating too many states\n")

        return len(tainted_calls) > 0

    def check(self, addr, args):
        try:
            res = self._inner_check(addr, args)
        except TimeoutError:
            sys.stderr.write("WARNING: timeout\n")
            return False
        except:
            sys.stderr.write("WARNING: unknown error\n")
            return False
        return res

if __name__ == "__main__":
    print("[+] Debug standalone script for JLongAsCppObjFinder")

    if len(sys.argv) < 4:
        exit(1)

    binary = sys.argv[1]
    addr   = int(sys.argv[2], 16) if sys.argv[2].startswith("0x") else int(sys.argv[2])
    args   = sys.argv[3]

    JLongAsCppObjFinder.DEBUG = True
    of = JLongAsCppObjFinder(binary)
    print(of.check(addr, args))
