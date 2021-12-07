import os
import sys
import angr
import time
import shutil
import rzpipe
import claripy
import logging
import subprocess

SCRIPATH = os.path.realpath(os.path.dirname(__file__))

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from cex_src.cex import CEXProject
from cex_src.cex.cfg_extractors.angr_plugin.common import AngrCfgExtractor
from collections import namedtuple
from apk_analyzer.utils import md5_hash, find_jni_functions_angr
from apk_analyzer.utils.prepare_state import prepare_initial_state
from apk_analyzer.utils.timeout_decorator import TimeoutError, timeout
from apk_analyzer.utils.path_engine import PathEngine, generate_paths

# FIXME: get rid of "analyzer" in JniFunctionDescription and cache on disk
JniFunctionDescription = namedtuple("JniFunctionDescription", ["analyzer", "class_name", "method_name", "args", "offset"])
FunctionDescription = namedtuple("FunctionDescription", ["name", "offset", "is_exported"])


class NativeLibAnalyzer(object):

    log = logging.getLogger("ap.NativeLibAnalyzer")
    CMD_GHIDRA = [
        "$GHIDRA_HOME/support/analyzeHeadless",
        "$PROJ_FOLDER",
        "$PROJ_NAME",
        "-noanalysis",
        "-process",
        "$BINARY",
        "-postScript",
        "DetectJNIFunctions.java",
        "-scriptPath",
        os.path.realpath(os.path.join(os.path.dirname(__file__), "bin"))]

    def _open_rz(self):
        plugin_folder = subprocess.check_output(["rizin", "-H", "RZ_USER_PLUGINS"]).decode("ascii").strip()
        if not os.path.exists(plugin_folder):
            os.makedirs(plugin_folder, exist_ok=True)

        plugin_path = os.path.join(plugin_folder, "jni_finder.so")
        if not os.path.exists(plugin_path):
            local_plugin_dir  = os.path.join(SCRIPATH, "bin/rz_jni_finder")
            local_plugin_file = os.path.join(local_plugin_dir, "jni_finder.so")
            if not os.path.exists(local_plugin_file):
                os.system(f"cd {local_plugin_dir} && make")
            shutil.copy2(local_plugin_file, plugin_path)
        return rzpipe.open(self.libpath, flags=["-2"])

    def __init__(self, libpath, use_rizin=True, use_angr=False):
        self.use_rizin = use_rizin
        self.use_angr = use_angr
        if use_rizin:
            self.use_rizin = True
            self.ghidra    = None
        else:
            self.ghidra = CEXProject.pm.get_plugin_by_name("Ghidra")
        self.libname = os.path.basename(libpath)
        self.libpath = libpath
        self.libhash = md5_hash(self.libpath)

        if "/armeabi/" in libpath:
            self.arch = "armeabi"
        elif "/armeabi-v7a/" in libpath:
            self.arch = "armeabi-v7a"
        elif "/arm64-v8a/" in libpath:
            self.arch = "arm64-v8a"
        elif "/x86/" in libpath:
            self.arch = "x86"
        elif "/x86_64/" in libpath:
            self.arch = "x86_64"
        elif "/mips/" in libpath:
            self.arch = "mips"
        elif "/mips64/" in libpath:
            self.arch = "mips64"
        else:
            rz = self._open_rz()
            rz_info  = rz.cmdj("iIj")
            rz_arch  = rz_info["arch"]
            rz_class = rz_info["class"]
            if rz_arch == "arm" and rz_class == "ELF32":
                self.arch = "armeabi"
            elif rz_arch == "arm" and rz_class == "ELF64":
                self.arch = "arm64-v8a"
            elif rz_arch == "x86" and rz_class == "ELF32":
                self.arch = "x86"
            elif rz_arch == "x86" and rz_class == "ELF64":
                self.arch = "x86_64"
            else:
                self.arch = rz_arch + "_" + rz_class
            rz.quit()

        self._exported_functions   = None
        self._imported_functions   = None
        self._jni_functions        = None
        self._jni_functions_angr   = None
        self._jni_static_functions = None

    def __str__(self):
        return "<NativeLibAnalyzer %s [%s]>" % (self.libname, self.arch)

    __repr__ = __str__

    def _get_ghidra_detect_jni_cmd(self):
        proj_path = self.ghidra.get_project_path(self.libpath)
        proj_dir  = os.path.dirname(proj_path)
        proj_name = os.path.basename(proj_path)

        ghidra_home = os.environ["GHIDRA_HOME"]
        cmd = NativeLibAnalyzer.CMD_GHIDRA[:]
        for i in range(len(cmd)):
            cmd[i] = cmd[i]                                     \
                .replace("$GHIDRA_HOME", ghidra_home)           \
                .replace("$BINARY", self.libname)               \
                .replace("$PROJ_FOLDER", proj_dir)              \
                .replace("$PROJ_NAME", proj_name)
        return cmd

    def _gen_functions(self, rz=None):
        if self._imported_functions is not None:
            return

        should_quit = False

        self._imported_functions = list()
        self._exported_functions = list()
        if rz is None:
            should_quit = True
            rz = self._open_rz()
            # rz.cmd("aa")

        symbols = rz.cmdj("isj")
        for symbol in symbols:
            if symbol["type"] != "FUNC" or symbol["bind"] != "GLOBAL":
                continue
            if symbol["is_imported"]:
                self._imported_functions.append(
                    FunctionDescription(
                        name=symbol["name"].replace("imp.", ""),
                        offset=symbol["vaddr"] + 0x400000,
                        is_exported=False))
            else:
                self._exported_functions.append(
                    FunctionDescription(
                        name=symbol["name"],
                        offset=symbol["vaddr"] + 0x400000,
                        is_exported=True))
        if should_quit:
            rz.quit()

    def get_exported_functions(self):
        self._gen_functions()
        return self._exported_functions

    def get_imported_functions(self):
        self._gen_functions()
        return self._imported_functions

    def is_jni_lib(self):
        self._gen_functions()

        for fun in self._exported_functions:
            if fun.name.startswith("Java_") or fun.name == "JNI_OnLoad":
                return True
        return False

    @timeout(60*5)
    def _get_returned_vtable_angr_cfg_emulated(self, offset):
        class new(angr.SimProcedure):
            def run(self, sim_size):
                return self.state.heap._malloc(sim_size)

        def get_ret_vals(proj, cfg, addr):
            ret_vals = list()

            fun = proj.kb.functions[addr]
            for bb in fun.ret_sites:
                for node in cfg.model.get_all_nodes(bb.addr):
                    ret_vals.extend(map(lambda s: (s, s.regs.r0), node.final_states))

            return ret_vals

        def is_cpp_object(state, v):
            vtable_ptr = state.mem[v].uint32_t.resolved
            if vtable_ptr.symbolic:
                return False

            vtable_entry = state.mem[vtable_ptr].uint32_t.resolved
            if vtable_entry.symbolic:
                return False

            sec = state.project.loader.find_section_containing(vtable_entry.args[0])
            return sec is not None and sec.is_executable

        def get_vtable(state, v):
            return state.mem[v].uint32_t.concrete

        proj = angr.Project(self.libpath, auto_load_libs=False)
        proj.hook_symbol("_Znwm", new(), replace=True)
        proj.hook_symbol("_Znwj", new(), replace=True)
        AngrCfgExtractor._hook_fp_models(proj)

        if offset % 2 == 0 and AngrCfgExtractor.is_thumb(proj, offset):
            offset += 1

        # Set JNI SimProcedures
        state = prepare_initial_state(proj, "")

        try:
            cfg = proj.analyses.CFGEmulated(keep_state=True, starts=[offset],
                context_sensitivity_level=1, initial_state=state) # call_depth=5, fail_fast=True
            ret_vals = get_ret_vals(proj, cfg, offset)
        except Exception as e:
            NativeLibAnalyzer.log.warning("CFGEmulated failed in _get_returned_vtable_angr [ERR %s]" % str(e))
            return None

        vtables = list()
        for state, v in ret_vals:
            if is_cpp_object(state, v):
                vtables.append(get_vtable(state, v))

        if len(vtables) == 0:
            return None
        if len(vtables) > 1:
            NativeLibAnalyzer.log.warning("Detected more than one vtable on jni function @ %#x" % offset)
        return vtables[0]

    def _get_returned_vtable_angr(self, offset):
        MAXITER   = sys.maxsize
        MAXSTATES = 10000

        class new(angr.SimProcedure):
            def run(self, sim_size):
                return self.state.heap._malloc(sim_size)

        proj = angr.Project(self.libpath, auto_load_libs=False)
        proj.hook_symbol("_Znwm", new(), replace=True)
        proj.hook_symbol("_Znwj", new(), replace=True)
        AngrCfgExtractor._hook_fp_models(proj)

        if offset % 2 == 0 and AngrCfgExtractor.is_thumb(proj, offset):
            offset += 1

        # Set JNI SimProcedures
        state = prepare_initial_state(proj, "")
        state.ip = offset
        state.regs.lr = claripy.BVV(0xdeadbeee, 32)

        vtables = list()

        i        = 0
        max_time = 60 * 15
        start    = time.time()
        smgr     = proj.factory.simgr(state, veritesting=False, save_unsat=False)
        while len(smgr.active) > 0:
            if len(vtables) > 0 or i > MAXITER:
                break

            smgr.explore(n=1)
            for stash in smgr.stashes:
                q = smgr.stashes[stash]
                for s in q:
                    addr = None
                    try:
                        addr = s.addr
                    except:
                        pass
                    if addr is not None and addr == 0xdeadbeee:
                        vtable = s.mem[s.regs.r0].uint32_t.resolved
                        if not vtable.symbolic and vtable.args[0] > 0x400000:
                            first_entry = s.mem[vtable].uint32_t.resolved
                            if not first_entry.symbolic:
                                section = proj.loader.find_section_containing(first_entry.args[0])
                                if section is not None and section.name == ".text":
                                    vtables.append(vtable.args[0])
                                    break
            if len(smgr.active) > MAXSTATES:
                # Try to limit RAM usage
                break
            if time.time() - start > max_time:
                # Try to limit time
                break

            i += 1

        if len(smgr.errored) > 0:
            sys.stderr.write("WARNING: %s @ %#x\n" % (self.libpath, offset))
            sys.stderr.write("WARNING: %d errored: %s\n"  % (len(smgr.errored), smgr.errored[0]))
        if i < 5:
            sys.stderr.write("WARNING: %s @ %#x\n" % (self.libpath, offset))
            sys.stderr.write("WARNING: very few iterations (%d)\n" % i)
        if len(smgr.active) > MAXSTATES:
            sys.stderr.write("WARNING: %s @ %#x\n" % (self.libpath, offset))
            sys.stderr.write("WARNING: killed for generating too many states\n")

        if len(vtables) > 0:
            return vtables[0]
        return None

    def _get_returned_vtable_path_executor(self, offset):
        if self.arch in {"armeabi", "armeabi-v7a"}:
            offset -= offset % 2

        cex_proj = CEXProject(self.libpath, plugins=["Ghidra", "AngrEmulated"])

        # angr, shut the fuck up
        angr_logger = logging.getLogger('angr')
        angr_logger.propagate = False
        cle_logger = logging.getLogger('cle')
        cle_logger.propagate = False
        pyvex_logger = logging.getLogger('pyvex')
        pyvex_logger.propagate = False

        angr_proj = angr.Project(self.libpath, auto_load_libs=False)
        engine    = PathEngine(angr_proj)

        start = time.time()
        print("[INFO] building callgraph in _get_returned_vtable_path_executor...")
        CEXProject.pm.get_plugin_by_name("AngrEmulated").build_cfg = True
        _ = cex_proj.get_callgraph(offset)
        CEXProject.pm.get_plugin_by_name("AngrEmulated").build_cfg = False
        print("[INFO] callgraph OK (%f)" % (time.time() - start))

        found_vals = set()

        max_time = 60*5
        start    = time.time()
        for p in generate_paths(cex_proj, engine, offset, only_with_new=True, max_time=start + max_time):
            addrs = list()
            for addr, _ in p:
                addrs.append(addr & 0xfffffffe)

            opts = {
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                angr.options.AVOID_MULTIVALUED_READS,
                angr.options.AVOID_MULTIVALUED_WRITES
            }
            state = angr_proj.factory.blank_state(
                add_options=opts
            )
            state.regs.r2 = state.heap.allocate(256)

            ret_state = engine.process_path(state, p)
            if ret_state.regs.r0.args[0] != 0 and ret_state.mem[ret_state.regs.r0].uint32_t.resolved.args[0] > 0x400000:
                vtable_maybe = ret_state.mem[ret_state.regs.r0].uint32_t.resolved
                first_entry = ret_state.mem[vtable_maybe].uint32_t.resolved.args[0]
                s = angr_proj.loader.find_section_containing(first_entry)
                if s is not None and s.name == ".text":
                    found_vals.add(ret_state.mem[ret_state.regs.r0].uint32_t.resolved)
                    break
            if time.time() - start > max_time:
                break

        if len(found_vals) > 0:
            CEXProject.pm.get_plugin_by_name("AngrEmulated").build_cfg = True
            return list(found_vals)[0].args[0]
        CEXProject.pm.get_plugin_by_name("AngrEmulated").build_cfg = True
        return None

    def get_returned_vtable(self, offset, use_angr=False):
        # Check if a JNI Method that returns a JLong is creating a C++ Object,
        # and if so return the corresponding vtable

        vt = None
        try:
            if use_angr:
                vt = self._get_returned_vtable_angr(offset)
            else:
                vt = self._get_returned_vtable_path_executor(offset)
        except TimeoutError:
            CEXProject.pm.get_plugin_by_name("AngrEmulated").build_cfg = True
            NativeLibAnalyzer.log.warning("get_returned_vtable triggered a timeout (use_angr=%s)" % str(use_angr))
        except Exception as e:
            CEXProject.pm.get_plugin_by_name("AngrEmulated").build_cfg = True
            NativeLibAnalyzer.log.warning("get_returned_vtable failed (use_angr=%s), ERR: %s" % \
                (str(use_angr), str(e)))
        return vt

    def _get_jni_functions_ghidra(self):
        self._jni_functions = list()

        cmd = self._get_ghidra_detect_jni_cmd()
        methods_raw = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        methods_raw = methods_raw.decode("ASCII")
        for line in methods_raw.split("\n"):
            line = line.strip()
            if not line.startswith("INFO  Method: "):
                continue

            line = line.replace("INFO  Method: ", "").replace(" (GhidraScript)", "")
            method_info, offset = line.split(" @ ")
            offset = int(offset, 16)

            class_name, method_name, args = method_info.split(" ")
            self._jni_functions.append(
                JniFunctionDescription(
                    analyzer=self,
                    class_name=class_name,
                    method_name=method_name,
                    args=args,
                    offset=offset))

        NativeLibAnalyzer.log.info(f"found {len(self._jni_functions)} functions")
        return self._jni_functions

    @staticmethod
    def demangle_jni_name(name):
        assert name.startswith("Java_")

        def replace_tokens(s):
            return s \
                .replace("_0", "$$$0") \
                .replace("_1", "$$$1") \
                .replace("_2", "$$$2") \
                .replace("_3", "$$$3")

        def fix_mangling(s):
            s = s \
                .replace("$$$1", "_") \
                .replace("$$$2", ";") \
                .replace("$$$3", "[")

            while 1:
                i = s.find("$$$0")
                if i == -1:
                    break

                unicode_val = int(s[i+4:i+8], 16)
                unicode_str = chr(unicode_val)
                s = s[:i] + unicode_str + s[i+8:]
            return s

        args = "???"
        name = replace_tokens(name)
        if "__" in name:
            name, args = name.split("__")
            args = fix_mangling(args)
            args = "(" + args.replace("_", "/") # return type not present!

        tokens = name.split("_")[1:]

        method_name = fix_mangling(tokens[-1])
        class_name  = fix_mangling(".".join(tokens[0:-1]))
        return class_name, method_name, args

    def _get_jni_functions_rizin(self):
        self._jni_functions = list()

        rz = self._open_rz()
        # rz.cmd("aa")

        # Static Functions
        self._gen_functions(rz=rz)
        for fun in self._exported_functions:
            if fun.name.startswith("Java_"):
                class_name, method_name, args = NativeLibAnalyzer.demangle_jni_name(fun.name)
                self._jni_functions.append(
                    JniFunctionDescription(
                        analyzer=self,
                        class_name=class_name,
                        method_name=method_name,
                        args=args,
                        offset=fun.offset))

        # Dynamic Functions

        # ["bits"] seems unreliable...
        bits    = 32 if rz.cmdj("iIj")["class"] == "ELF32" else 64
        endness = rz.cmdj("iIj")["endian"]
        if endness == "LE":
            endness = "little"
        if endness == "BE":
            endness = "big"
        assert endness in {"big", "little"}

        sections = dict()

        def get_section_bytes(addr, size):
            return bytes(rz.cmdj(f"pxj {size} @ {addr:#x}"))

        def read_addr(data, off):
            return int.from_bytes(data[off:off+(bits//8)], endness)

        def read_byte(addr):
            for secname in sections:
                min_addr, max_addr, data = sections[secname]
                if min_addr <= addr < max_addr:
                    return data[addr - min_addr]
            return 255

        def read_string(addr):
            res = ""
            i = 0
            while i < 256:
                b = read_byte(addr+i)
                if b == 0:
                    break
                if not (32 <= b <= 126):
                    return None
                res += chr(b)
                i   += 1
            return res

        code_sections = list()
        data_sections = list()
        for sec in rz.cmdj("iSj"):
            if sec["name"] == ".bss":
                continue

            sections[sec["name"]] = \
                (sec["vaddr"], sec["vaddr"] + sec["vsize"], get_section_bytes(sec["vaddr"], sec["vsize"]))

            perm = sec["perm"]
            if perm[1] == "r" and perm[3] != "x":
                data_sections.append(
                    (sec["name"], sec["vaddr"], sec["vaddr"] + sec["vsize"])
                )
            if perm[3] == "x":
                code_sections.append(
                    (sec["name"], sec["vaddr"], sec["vaddr"] + sec["vsize"])
                )
        assert len(code_sections) > 0

        def is_in_text(addr):
            for _, min_addr, max_addr in code_sections:
                if min_addr <= addr < max_addr:
                    return True
            return False

        for name, min_addr, max_addr in data_sections:
            if max_addr == min_addr:
                continue

            data = sections[name][2]
            assert len(data) == max_addr - min_addr

            for addr in range(min_addr, max_addr - (bits//8 * 3) + 1):
                methodFuncPtr = read_addr(data, addr - min_addr + (bits // 8 * 2))

                if not is_in_text(methodFuncPtr):
                    continue

                methodNamePtr = read_addr(data, addr - min_addr)
                methodArgsPtr = read_addr(data, addr - min_addr + (bits // 8))

                methodName = read_string(methodNamePtr)
                if methodName is None or len(methodName) == 0:
                    continue

                methodArgs = read_string(methodArgsPtr)
                if methodArgs is None or len(methodArgs) == 0 or methodArgs[0] != "(" or ")" not in methodArgs:
                    continue

                self._jni_functions.append(
                    JniFunctionDescription(
                        analyzer=self,
                        class_name="???",
                        method_name=methodName,
                        args=methodArgs.replace(" ", ""),
                        offset=methodFuncPtr + 0x400000))

            # Force GC to delete the data (it can be big)
            del data

        rz.quit()
        return self._jni_functions

    def _get_static_functions(self, rz=None):
        if self._jni_static_functions is not None:
            return self._jni_static_functions

        to_close = False
        if rz is None:
            to_close = True
            rz = self._open_rz()

        self._jni_static_functions = list()
        self._gen_functions(rz=rz)
        for fun in self._exported_functions:
            if fun.name.startswith("Java_"):
                class_name, method_name, args = NativeLibAnalyzer.demangle_jni_name(fun.name)
                self._jni_static_functions.append(
                    JniFunctionDescription(
                        analyzer=self,
                        class_name=class_name,
                        method_name=method_name,
                        args=args,
                        offset=fun.offset))

        if to_close:
            rz.quit()
        return self._jni_static_functions

    def _get_jni_functions_rizin_native(self):
        self._jni_functions = list()

        rz = self._open_rz()
        # Static Functions
        self._get_static_functions(rz)
        self._jni_functions += self._jni_static_functions[:]

        # Dynamic Functions
        dyn_functions_raw = rz.cmdj("aJJj")
        if dyn_functions_raw is None:
            NativeLibAnalyzer.log.error("Unable to execute aJJj on %s" % self.libpath)
            dyn_functions_raw = dict()

        for jni_method in dyn_functions_raw:
            off    = jni_method["fnPtr"] + 0x400000
            to_add = None
            for i, jni_fun in enumerate(self._jni_functions):
                if jni_fun.offset == off:
                    # both static and dynamic! (yes, it can happen)
                    to_add = i
                    break

            if to_add is not None:
                self._jni_functions[to_add] = JniFunctionDescription(
                    analyzer=self,
                    class_name=self._jni_functions[to_add].class_name,
                    method_name=jni_method["name"],
                    args=jni_method["signature"].replace(" ", ""),
                    offset=jni_method["fnPtr"] + 0x400000)
            else:
                self._jni_functions.append(
                    JniFunctionDescription(
                        analyzer=self,
                        class_name="???",
                        method_name=jni_method["name"],
                        args=jni_method["signature"].replace(" ", ""),
                        offset=jni_method["fnPtr"] + 0x400000))

        rz.quit()
        return self._jni_functions

    def _get_jni_functions_angr(self, auto_load_libs=False):
        if self._jni_functions_angr is not None:
            return self._jni_functions_angr

        self._jni_functions_angr = list()
        try:
            jni_angr = find_jni_functions_angr(self.libpath, auto_load_libs)
        except TimeoutError:
            jni_angr = list()
        except Exception as e:
            NativeLibAnalyzer.log.warning("Unknown error in _get_jni_functions_angr: " + repr(e))
            jni_angr = list()

        for class_name, method_name, args, addr in jni_angr:
            class_name = class_name.replace("/", ".")
            self._jni_functions_angr.append(
                JniFunctionDescription(
                    analyzer=self,
                    class_name=class_name,
                    method_name=method_name,
                    args=args.replace(" ", ""),
                    offset=addr))
        return self._jni_functions_angr

    def get_jni_functions(self):
        if self._jni_functions is not None:
            return self._jni_functions

        NativeLibAnalyzer.log.info(f"generating JNI functions for lib {self.libname} [{self.arch}]")
        if not self.is_jni_lib():
            NativeLibAnalyzer.log.info("not a JNI lib")
            self._jni_functions = list()
            return self._jni_functions

        if not self.use_rizin:
            self._get_jni_functions_ghidra()
        else:
            self._get_jni_functions_rizin_native()

        if len(self._jni_functions) == 0 or self.use_angr:
            found_methods = set()
            for m in self._jni_functions:
                found_methods.add(m.method_name)

            jni_angr = self._get_jni_functions_angr()
            self._jni_functions.extend(jni_angr)
        return self._jni_functions

if __name__ == "__main__":
    import sys

    print("[+] NativeLibAnalyzer standalone script")

    if len(sys.argv) < 2:
        print("USAGE: %s <lib_path>" % sys.argv[0])
        exit(1)

    a = NativeLibAnalyzer(sys.argv[1])
    for fun in a.get_jni_functions():
        print(fun)
