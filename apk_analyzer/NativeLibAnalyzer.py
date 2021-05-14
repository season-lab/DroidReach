import os
import rzpipe
import logging
import subprocess

try:
    from .utils import md5_hash, find_jni_functions_angr
except:
    from utils import md5_hash, find_jni_functions_angr
from collections import namedtuple

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
        return rzpipe.open(self.libpath, flags=["-2"])

    def __init__(self, cex, libpath, use_rizin=False, use_angr=True):
        self.use_rizin = use_rizin
        self.cex = cex
        self.use_angr = use_angr
        if use_rizin or cex is None:
            self.use_rizin   = True
            self.ghidra = None
        else:
            self.ghidra = self.cex.pm.get_plugin_by_name("Ghidra")
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
            self.arch = rz.cmdj("iIj")["arch"]
            rz.quit()

        self._exported_functions = None
        self._imported_functions = None
        self._jni_functions      = None

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

    def _gen_functions(self):
        if self._imported_functions is not None:
            return

        self._imported_functions = list()
        self._exported_functions = list()
        rz = self._open_rz()
        rz.cmd("aa")

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

        name = name \
            .replace("_0", "$$$0") \
            .replace("_1", "$$$1") \
            .replace("_2", "$$$2") \
            .replace("_3", "$$$3")

        tokens = name.split("_")[1:]

        method_name = fix_mangling(tokens[-1])
        class_name  = fix_mangling(".".join(tokens[0:-1]))
        return class_name, method_name

    def _get_jni_functions_rizin(self):
        self._jni_functions = list()

        # Static Functions
        self._gen_functions()
        for fun in self._exported_functions:
            if fun.name.startswith("Java_"):
                class_name, method_name = NativeLibAnalyzer.demangle_jni_name(fun.name)
                self._jni_functions.append(
                    JniFunctionDescription(
                        analyzer=self,
                        class_name=class_name,
                        method_name=method_name,
                        args="???",
                        offset=fun.offset))

        # Dynamic Functions
        rz = self._open_rz()
        rz.cmd("aa")

        # ["bits"] seems unreliable...
        bits    = 32 if rz.cmdj("iIj")["class"] == "ELF32" else 64
        endness = rz.cmdj("iIj")["endian"]

        def get_section_bytes(addr, size):
            return bytes(rz.cmdj(f"pxj {size} @ {addr:#x}"))

        def read_addr(data, off):
            return int.from_bytes(data[off:off+(bits//8)], endness)

        def read_byte(addr):
            return rz.cmdj(f"pxj 1 @ {addr:#x}")[0]

        def read_string(addr):
            res = ""
            i = 0
            while i < 100:
                b = read_byte(addr+i)
                if b == 0:
                    break
                if not (32 <= b <= 126):
                    return None
                res += chr(b)
                i   += 1
            return res

        functions = set()
        for fun in rz.cmdj("aflj"):
            functions.add(fun["offset"])

        for sec in rz.cmdj("iSj"):
            if sec["name"] not in {".data.rel.ro", ".data", ".rodata"}:
                continue

            min_addr = sec["vaddr"]
            max_addr = min_addr + sec["vsize"]
            data     = get_section_bytes(min_addr, sec["vsize"])
            assert min_addr > 0 and max_addr > min_addr
            assert len(data) == sec["vsize"]

            for addr in range(min_addr, max_addr - (bits//8 * 3)):
                methodNamePtr = read_addr(data, addr - min_addr)
                methodArgsPtr = read_addr(data, addr - min_addr + (bits // 8))
                methodFuncPtr = read_addr(data, addr - min_addr + (bits // 8 * 2))

                if methodFuncPtr not in functions:
                    continue

                methodName = read_string(methodNamePtr)
                if methodName is None or len(methodName) == 0:
                    continue

                methodArgs = read_string(methodArgsPtr)
                if methodArgs is None or len(methodArgs) == 0 or "(" not in methodArgs or ")" not in methodArgs:
                    continue

                self._jni_functions.append(
                    JniFunctionDescription(
                        analyzer=self,
                        class_name="???",
                        method_name=methodName,
                        args=methodArgs.replace(" ", ""),
                        offset=methodFuncPtr + 0x400000))

        rz.quit()

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
            self._get_jni_functions_rizin()

        if self.use_angr:
            found_methods = set()
            for m in self._jni_functions:
                found_methods.add(m.method_name)

            jni_angr = find_jni_functions_angr(self.libpath)
            for class_name, method_name, args, addr in jni_angr:
                if method_name not in found_methods:
                    class_name = "L" + class_name + ";"
                    print("[!] Method", class_name, method_name, args.replace(" ", ""), "found only by angr")
                    self._jni_functions.append(
                        JniFunctionDescription(
                            analyzer=self,
                            class_name=class_name,
                            method_name=method_name,
                            args=args.replace(" ", ""),
                            offset=addr))
        return self._jni_functions

if __name__ == "__main__":
    import sys

    print("[+] NativeLibAnalyzer standalone script")

    if len(sys.argv) < 2:
        print("USAGE: %s <lib_path>" % sys.argv[0])
        exit(1)

    a = NativeLibAnalyzer(None, sys.argv[1])
    for fun in a.get_jni_functions():
        print(fun)
