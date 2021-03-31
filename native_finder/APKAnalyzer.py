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
    log = logging.getLogger("ap.APKAnalyzer")
    log.setLevel(logging.WARNING)

    def __init__(self, cex, apk_path):
        if not os.path.exists(apk_path):
            APKAnalyzer.log.error(f"{apk_path} does not exist")
            raise FileNotFoundException(apk_path)

        APKAnalyzer.log.info("APKAnalyzer initialization")
        self.cex = cex
        self.apk_path = apk_path
        self.apk, self.dvm, self.analysis = AnalyzeAPK(apk_path)

        self.package_name = self.apk.get_package()
        self._jvm_demangler = JavaNameDemangler()
        self._native_lib_analysis = None
        self._native_jni_methods  = None
        APKAnalyzer.log.info("APKAnalyzer initialization done")

    def get_native_libs(self):
        res = list()
        visited_names = set()
        for f in self.apk.get_files():
            if f.startswith("lib/"):
                if os.path.basename(f) in visited_names:
                    if "x86" in f:
                        # If there is an x86 binary, substitute the previous one
                        new_res = list()
                        for el in res:
                            if os.path.basename(f) not in el:
                                new_res.append(el)
                        res = new_res
                    else:
                        # Keep only one binary per arch
                        continue
                res.append(f)
                visited_names.add(os.path.basename(f))
        return res

    def _analyze_native_libs(self):
        if self._native_lib_analysis is not None:
            return self._native_lib_analysis

        self._native_lib_analysis = dict()
        for lib in self.get_native_libs():
            self._native_lib_analysis[os.path.basename(lib)] = NativeLibAnalyzer(
                self.cex, os.path.basename(lib), self.apk.get_file(lib))
        return self._native_lib_analysis

    def find_native_implementation(self, method_name):
        APKAnalyzer.log.info(f"looking for native implementation of {method_name}")
        native_libs = self._analyze_native_libs()
        res = None
        for lib in native_libs:
            jni_functions = native_libs[lib].get_jni_functions()
            for jni_desc in jni_functions:
                if jni_desc.method_name == method_name:
                    res = jni_desc

        APKAnalyzer.log.info(f"native implementation: {res}")
        return res

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
                    jni_desc = self.find_native_implementation(m.name)
                    if jni_desc is None:
                        APKAnalyzer.log.warning("{} implementation not found".format(m.name))
                    self._native_methods.append(
                        NativeMethod(
                            m.name, 
                            signature,
                            jni_desc.analyzer.libname,
                            jni_desc.offset
                        )
                    )
        return self._native_methods
