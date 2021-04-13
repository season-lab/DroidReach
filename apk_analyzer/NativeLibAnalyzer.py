import os
import rzpipe
import logging
import subprocess

from .utils import md5_hash
from collections import namedtuple
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
        return rzpipe.open(self.libpath, flags=["-2", "-B 0x400000"])

    def __init__(self, cex, libpath):
        self.cex = cex
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
                        offset=symbol["vaddr"],
                        is_exported=False))
            else:
                self._exported_functions.append(
                    FunctionDescription(
                        name=symbol["name"],
                        offset=symbol["vaddr"],
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

    def get_jni_functions(self):
        if self._jni_functions is not None:
            return self._jni_functions

        NativeLibAnalyzer.log.info(f"generating JNI functions for lib {self.libname} [{self.arch}]")
        self._jni_functions = list()
        if not self.is_jni_lib():
            NativeLibAnalyzer.log.info("not a JNI lib")
            return self._jni_functions

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
