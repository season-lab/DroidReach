import logging
import claripy
import time
import angr
import sys
import cle

from .jni_stubs.java_type import get_type, get_type_size
from .angr_find_dynamic_jni import AnalysisCenter
from .jni_stubs.jni_type.jni_native_interface import JNINativeInterface, JObject

from .timeout_decorator import timeout, TimeoutError

# angr, shut the fuck up
angr_logger = logging.getLogger('angr')
angr_logger.propagate = False
cle_logger  = logging.getLogger('cle')
cle_logger.propagate = False
nativedroid_logger = logging.getLogger('nativedroid')
nativedroid_logger.propagate = False

class DummyEmptyModel(angr.SimProcedure):
    def run(self, *args):
        return None

class NativeJLongAnalyzer(object):
    DEBUG     = True
    MAXITER   = sys.maxsize
    MAXSTATES = 10000

    def __init__(self, libpath):
        self.libpath = libpath
        self.project = angr.Project(libpath, auto_load_libs=False)
        self.state   = self.project.factory.blank_state()  # general purpose state... Can be useful to read memory
        self.jni_ptr = claripy.BVV(
            JNINativeInterface(
                self.project,
                AnalysisCenter(None, "", "")).ptr,
                self.project.arch.bits)

        NativeJLongAnalyzer._hook_fp_models(self.project)
        self.obj     = JObject(self.project)
        self.vtable  = JObject(self.project)
        self.struct  = JObject(self.project)

    @staticmethod
    def _hook_fp_models(proj):
        # Just an hack to avoid crashes
        def hook_with_dummy(name):
            proj.hook_symbol(name, DummyEmptyModel(), replace=True)

        float_functions = set()
        for s in proj.loader.symbols:
            if proj.is_hooked(s.rebased_addr):
                h = proj.hooked_by(s.rebased_addr)
                if h is None or h.cc is None:
                    continue
                fun_ty = h.prototype
                if fun_ty is None:
                    continue
                if "double" in fun_ty.returnty.c_repr() or "float" in fun_ty.returnty.c_repr():
                    float_functions.add(h.display_name)

        to_hook = float_functions
        for n in to_hook:
            hook_with_dummy(n)

        hook_with_dummy("clock_gettime")

    def mk_type(self, arg_id, arg_type):
        typ_size = get_type_size(self.project, arg_type)
        if arg_type in {'boolean', 'byte', 'char', 'short', 'int', 'long', 'float', 'double'}:
            return claripy.BVS("%s_%d" % (arg_type, arg_id), typ_size)
        return claripy.BVV(get_type(self.project, arg_type).ptr, typ_size)

    def mk_cpp_obj(self, state, param_i):        
        cpp_obj = JObject(self.project)
        if NativeJLongAnalyzer.DEBUG:
            print("Creating obj for arg ",  param_i)
            print("obj ptr:",    claripy.BVV(cpp_obj.ptr, self.project.arch.bits))
        
        # Recursive vtable+member list means any member dereference also ends up in the main object's entry point (itself!)
        for i in range(0, 500 * self.project.arch.bytes, self.project.arch.bytes):
            state.memory.store(
                cpp_obj.ptr + i,
                claripy.BVV(cpp_obj.ptr, self.project.arch.bits),
                endness=self.project.arch.memory_endness)

        if NativeJLongAnalyzer.DEBUG:
            print("vtable ptr (load):", state.memory.load(cpp_obj.ptr, self.project.arch.bits // 8, endness=self.project.arch.memory_endness))

        return (claripy.BVV(cpp_obj.ptr, self.project.arch.bits),cpp_obj.ptr)

    def prepare_state_cpp(self, addr, args):
        state = self.project.factory.blank_state(addr=addr)
        state.regs.r0 = self.jni_ptr
        state.regs.r1 = claripy.BVV(
            self.obj.ptr, self.project.arch.bits)

        parsed_args = dict()
        reverse_dict = dict()
        for i, a in enumerate(args.split(",")):
            a = a.strip().replace(" ", "")
            parsed_args[i+2] = a

        for arg_id in parsed_args:
            arg_type = parsed_args[arg_id]

            if arg_type == "long":
                data, ptr = self.mk_cpp_obj(state, arg_id-2)
                reverse_dict[ptr] = arg_id - 2
            else:
                data = self.mk_type(arg_id, arg_type)

            if data.size() < self.project.arch.bits:
                data = data.zero_extend(self.project.arch.bits - data.size())

            if arg_id < 3:
                state.regs.__setattr__('r%d' % arg_id, data)
            else:
                state.stack_push(data)
        state.solver._solver.timeout = 2000 # 2 seconds as timeout
        return (state, reverse_dict)

    def _is_thumb(self, addr):
        if self.project.arch.name != "ARMEL":
            return False

        if addr % 2 != 0:
            return False

        # Heuristic 1: check if the lifted block is empty
        try:
            b = self.project.factory.block(addr)
        except:
            return True
        if b.size == 0:
            return True

        # Heuristic 2: check number of instructions with capstone
        if len(b.capstone.insns) == 0:
            return True

        # Heuristic 3: check symbols
        for s in self.project.loader.symbols:
            if s.rebased_addr == addr + 1:
                return True
            elif s.rebased_addr == addr:
                return False

        return False

    def _inner_check_cpp_obj(self, addr, args):
        is_thumb = self._is_thumb(addr)
        if is_thumb:
            addr = addr + 1

        state, arg_data = self.prepare_state_cpp(addr, args)

        tainted_calls = set()

        def checkCallEntry(state):
            call_target = state.inspect.function_address
            if NativeJLongAnalyzer.DEBUG:
                print("checkCallEntry: ", call_target)
            if call_target is None:
                return
            try:
                if found_s.regs.r0._model_concrete.value in arg_data:
                    print("checkCallEntry: Found user value as first positional argument in class method, likely consumer")
                    tainted_calls.add(arg_data[found_s.regs.r0._model_concrete.value])
            except:
                sys.stderr.write("checkCallEntry: Failed to concretize R0 value")
            
        state.inspect.b('call', when=angr.BP_BEFORE, action=checkCallEntry)

        if NativeJLongAnalyzer.DEBUG:
            print("entry r0", state.regs.r0)
            print("entry r1", state.regs.r1)
            print("entry r2", state.regs.r2)

        max_time = 60 * 15
        start    = time.time()

        i    = 0
        smgr = self.project.factory.simgr(state, veritesting=True, save_unsat=False, save_unconstrained=True)
        smgr.use_technique(angr.exploration_techniques.MemoryWatcher(min_memory=None)) # Default: 95% of all available RAM

        # Hack: initialize found stash before "find" keyword is used in smgr.explore()
        smgr.stash(to_stash="found")
        smgr.unstash(from_stash="found")
        while len(smgr.active) > 0:
            if len(smgr.found) > 0 or len(tainted_calls) > 0 or i > NativeJLongAnalyzer.MAXITER:
                break

            if False and NativeJLongAnalyzer.DEBUG:
                for s in smgr.active:
                    print(s)
                    if self.project.is_hooked(s.addr):
                        print(s.regs.r0, s.regs.r1, s.regs.r2)
                        print(self.project.hooked_by(s.addr))
                    else:
                        s.block().pp()
                    print(s.step())
                    input("> Press a key to continue...")

            smgr.explore(n=1, find=list(arg_data.keys()))
            if NativeJLongAnalyzer.DEBUG:
                print(i, smgr, smgr.errored, tainted_calls)
            if len(smgr.active) > NativeJLongAnalyzer.MAXSTATES:
                # Try to limit RAM usage
                break
            if time.time() - start > max_time:
                # Limit time
                break
            i += 1

        if len(smgr.errored) > 0:
            sys.stderr.write("WARNING: %s @ %#x\n" % (self.libpath, addr))
            sys.stderr.write("WARNING: %d errored: %s\n"  % (len(smgr.errored), smgr.errored[0]))
        if len(smgr.found) > 0:
            for found_s in smgr.found:
                if found_s.regs.pc._model_concrete.value not in arg_data:
                    sys.stderr.write(f"WARNING: PC reg {found_s.regs.pc._model_concrete.value} not in map {arg_data}")
                else:
                    tainted_calls.add(arg_data[found_s.regs.pc._model_concrete.value])
        elif len(smgr.unconstrained)> 0:
            sys.stderr.write("WARNING: %s @ %#x\n" % (self.libpath, addr))
            sys.stderr.write("WARNING: %d states not found, but at least one unconstrained: PC value %x\n"  % (len(smgr.unconstrained), smgr.unconstrained[0].regs.pc._model_concrete.value))
        if i < 5:
            sys.stderr.write("WARNING: %s @ %#x\n" % (self.libpath, addr))
            sys.stderr.write("WARNING: very few iterations (%d)\n" % i)
        if len(smgr.active) > NativeJLongAnalyzer.MAXSTATES:
            sys.stderr.write("WARNING: %s @ %#x\n" % (self.libpath, addr))
            sys.stderr.write("WARNING: killed for generating too many states\n")

        return tainted_calls

    def check_cpp_obj(self, addr, args):
        try:
            res = self._inner_check_cpp_obj(addr, args)
        except cle.CLEError as e:
            # Most probably "Too many loaded modules for TLS to handle"
            sys.stderr.write("WARNING: CLEError %s\n" % str(e))
            return list()
        except Exception as e:
            sys.stderr.write("WARNING: unknown error [ %s ]\n" % str(e))
            return list()
        return res
