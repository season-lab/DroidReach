import os
import tempfile
import subprocess

from collections import namedtuple
JniFunctionDescription = namedtuple("JniFunctionDescription", ["analyzer", "class_name", "method_name", "args", "offset"])

# TODO: prima scrematura con rizin

class NativeLibAnalyzer(object):

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

    def __init__(self, cex, native_name, native_raw):
        assert "/" not in native_name

        self.cex = cex
        self.ghidra = self.cex.pm.get_plugin_by_name("Ghidra")
        self.libname = native_name
        self.native_raw = native_raw
        self.jni_functions = None

    def _get_ghidra_cmd(self):
        with tempfile.TemporaryDirectory() as tmpdirname:
            native_f = open(os.path.join(tmpdirname, self.libname), "wb")
            native_f.write(self.native_raw)

            proj_path = self.ghidra.get_project_path(
                os.path.join(tmpdirname, self.libname))
            proj_name = os.path.basename(proj_path)
            proj_dir  = os.path.dirname(proj_path)

        ghidra_home = os.environ["GHIDRA_HOME"]
        cmd = NativeLibAnalyzer.CMD_GHIDRA[:]
        for i in range(len(cmd)):
            cmd[i] = cmd[i]                                     \
                .replace("$GHIDRA_HOME", ghidra_home)           \
                .replace("$BINARY", self.libname)               \
                .replace("$PROJ_FOLDER", proj_dir)              \
                .replace("$PROJ_NAME", proj_name)
        return cmd

    def get_jni_functions(self):
        if self.jni_functions is not None:
            return self.jni_functions

        self.jni_functions = list()

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

        return self.jni_functions
