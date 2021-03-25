import os
import logging

from collections import namedtuple
from androguard.misc import AnalyzeAPK
from .JavaNameDemangler import JavaNameDemangler
from .NativeLibAnalyzer import NativeLibAnalyzer

NativeMethod = namedtuple("NativeMethod", ["name", "signature", "lib", "offset"])

class APKAnalyzerError(Exception):
    pass

class FileNotFoundException(APKAnalyzerError):
    def __init__(self, fname):
        self.message = "%s not found" % fname
        super().__init__(self.message)

class APKAnalyzer(object):
    log = logging.getLogger("ptn.APKAnalyzer")
    log.setLevel(logging.INFO)

    def __init__(self, apk_path):
        if not os.path.exists(apk_path):
            APKAnalyzer.log.error(f"{apk_path} does not exist")
            raise FileNotFoundException(apk_path)

        self.apk_path = apk_path
        self.apk, self.dvm, self.analysis = AnalyzeAPK(apk_path)

        self.package_name = self.apk.get_package()
        self._jvm_demangler = JavaNameDemangler()
        self._native_lib_analysis = None
        self._native_methods = None

    def get_native_libs(self):
        res = list()
        for f in self.apk.get_files():
            if f.startswith("lib/"):
                res.append(f)
        return res

    def _analyze_native_libs(self):
        if self._native_lib_analysis is not None:
            return self._native_lib_analysis

        self._native_lib_analysis = dict()
        for lib in self.get_native_libs():
            self._native_lib_analysis[os.path.basename(lib)] = NativeLibAnalyzer(
                os.path.basename(lib), self.apk.get_file(lib))
        return self._native_lib_analysis

    def find_native_implementation(self, method_name):
        native_libs = self._analyze_native_libs()
        for lib in native_libs:
            jni_functions = native_libs[lib].get_jni_functions()
            for _, l_method_name, l_offset in jni_functions:
                if l_method_name == method_name:
                    return lib, l_offset
        return "unknown", 0

    def get_native_implementation(self, method_name):
        lib_name, off = self.find_native_implementation(method_name)
        if lib_name == "unknown":
            return None, None
        return self._native_lib_analysis[lib_name], off

    def get_native_methods(self):
        if self._native_methods is not None:
            return self._native_methods

        self._native_methods = list()
        for class_analysis in self.analysis.get_classes():
            for methodAnalysis in class_analysis.get_methods():
                if "native" in methodAnalysis.access:
                    m = methodAnalysis.method
                    signature = self._jvm_demangler.method_signature_demangler(
                        m.get_class_name(), m.name, m.get_descriptor())
                    lib_name, off = self.find_native_implementation(m.name)
                    if lib_name == "unknown" and off == 0:
                        APKAnalyzer.log.warning("{} implementation not found".format(m.name))
                    self._native_methods.append(
                        NativeMethod(
                            m.name, 
                            signature,
                            lib_name,
                            off
                        )
                    )
        return self._native_methods
