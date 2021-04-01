import os
import rzpipe
import logging
import subprocess

from .utils import md5_hash
from collections import namedtuple
JniFunctionDescription = namedtuple("JniFunctionDescription", ["analyzer", "class_name", "method_name", "args", "offset"])


class NativeLibAnalyzer(object):

    log = logging.getLogger("ap.NativeLibAnalyzer")
    CMD_GHIDRA = [
        "$GHIDRA_HOME/support/analyzeHeadless",
        "$PROJ_FOLDER",
        "$PROJ_NAME",
        "-process",
        "$BINARY",
        "-postScript",
        "DetectJNIFunctions.java",
        "-scriptPath",
        os.path.realpath(os.path.join(os.path.dirname(__file__), "bin"))]

    def __init__(self, cex, libpath):
        self.cex = cex
        self.ghidra = self.cex.pm.get_plugin_by_name("Ghidra")
        self.libname = os.path.basename(libpath)
        self.libpath = libpath
        self.libhash = md5_hash(self.libpath)

        self.function_names = None
        self.jni_functions  = None

    def _get_ghidra_cmd(self):
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

    def _get_functions(self):
        if self.function_names is not None:
            return self.function_names

        self.function_names = list()
        rz = rzpipe.open(self.libpath, flags=['-2'])  # -2: disable stderr
        rz.cmd("aa")

        functions = rz.cmdj("aflj")
        for function in functions:
            self.function_names.append(function["name"].replace("sym.", ""))
        return self.function_names

    def is_jni_lib(self):
        self._get_functions()

        for fun in self.function_names:
            if fun.startswith("Java_") or fun == "JNI_OnLoad":
                return True
        return False

    def get_jni_functions(self):
        if self.jni_functions is not None:
            return self.jni_functions

        NativeLibAnalyzer.log.info(f"generating JNI functions for lib {self.libname}")
        self.jni_functions = list()
        if not self.is_jni_lib():
            NativeLibAnalyzer.log.info("not a JNI lib")
            return self.jni_functions

        cmd = self._get_ghidra_cmd()
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
            self.jni_functions.append(
                JniFunctionDescription(
                    analyzer=self,
                    class_name=class_name,
                    method_name=method_name,
                    args=args,
                    offset=offset))

        NativeLibAnalyzer.log.info(f"found {len(self.jni_functions)} functions")
        return self.jni_functions
