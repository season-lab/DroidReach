import os
import json
import logging
import subprocess
import networkx as nx

from shutil import copyfile
from collections import namedtuple
from androguard.misc import AnalyzeAPK
from .JavaNameDemangler import JavaNameDemangler
from .NativeLibAnalyzer import NativeLibAnalyzer
from .utils import md5_hash, get_native_methods
from .utils.app_component import AppComponent

NativeMethod = namedtuple("NativeMethod", ["name", "signature", "lib", "offset"])

LOADLIB_TARGET = 'Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V'

class APKAnalyzerError(Exception):
    pass

class FileNotFoundException(APKAnalyzerError):
    def __init__(self, fname):
        self.message = "%s not found" % fname
        super().__init__(self.message)

class APKAnalyzer(object):
    log = logging.getLogger("ap.APKAnalyzer")
    log.setLevel(logging.WARNING)

    tmp_dir = "/dev/shm/apk_analyzer_data"

    def _create_dirs(self):
        if not os.path.exists(APKAnalyzer.tmp_dir):
            os.mkdir(APKAnalyzer.tmp_dir)
        if not os.path.exists(self.wdir):
            os.mkdir(self.wdir)

        copyfile(self.apk_path, os.path.join(self.wdir, os.path.basename(self.apk_path)))

    def __init__(self, cex, apk_path):
        if not os.path.exists(apk_path):
            APKAnalyzer.log.error(f"{apk_path} does not exist")
            raise FileNotFoundException(apk_path)

        APKAnalyzer.log.info("APKAnalyzer initialization")
        self.cex = cex
        self.apk_path = apk_path
        self.apk_name = os.path.basename(self.apk_path).replace(".apk", "")
        self.apk_hash = md5_hash(self.apk_path)
        self.wdir = os.path.join(APKAnalyzer.tmp_dir, self.apk_hash)
        self.apk, self.dvm, self.analysis = AnalyzeAPK(apk_path)

        self.callgraph_filename = os.path.join(self.wdir, "callgraph.gml")
        self.callgraph = None
        self.paths_json_filename = os.path.join(self.wdir, "paths.json")
        self.paths = None
        self._create_dirs()

        self.package_name = self.apk.get_package()
        self._jvm_demangler = JavaNameDemangler()
        self._native_libs = None
        self._native_lib_analysis = None

        APKAnalyzer.log.info("APKAnalyzer initialization done")

    def get_callgraph(self):
        if self.callgraph is not None:
            return self.callgraph

        APKAnalyzer.log.info("generating callgraph")
        if not os.path.exists(self.callgraph_filename):
            cg = subprocess.run(['androguard', 'cg', '-o', self.callgraph_filename, self.apk_path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            APKAnalyzer.log.info(f"callgraph generated in {self.callgraph_filename}")
        else:
            APKAnalyzer.log.info(f"callgraph found cached in {self.callgraph_filename}")

        APKAnalyzer.log.info("reading callgraph")
        self.callgraph = nx.read_gml(self.callgraph_filename)
        APKAnalyzer.log.info("callgraph read")
        return self.callgraph

    def get_paths_to_native(self):
        if self.paths is not None:
            return self.paths

        self.get_callgraph()
        APKAnalyzer.log.info("generating paths to native functions")
        if os.path.exists(self.paths_json_filename):
            with open(self.paths_json_filename, "r") as fin:
                self.paths = json.load(fin)
            APKAnalyzer.log.info("found cached")
            return self.paths

        acts  = AppComponent('a', self.apk.get_activities())
        provs = AppComponent('p', self.apk.get_providers())
        recvs = AppComponent('r', self.apk.get_receivers())
        servs = AppComponent('s', self.apk.get_services())

        components = [acts, provs, recvs, servs]
        sources = list()
        for comp in components:
            sources.extend(comp.get_sources(self.callgraph.nodes))

        # get all targets
        native_targets = get_native_methods(self.analysis,
                                            public_only=False)
        targets = [LOADLIB_TARGET, *native_targets]
        APKAnalyzer.log.info(f"found {len(targets)} targets and {len(sources)} sources")

        APKAnalyzer.log.info("looking for paths")
        paths = {}
        for t in targets:
            for s in sources:
                if s not in self.callgraph.nodes or t not in self.callgraph.nodes:
                    continue
                if nx.has_path(self.callgraph, source=s, target=t):
                    link = next(nx.all_simple_paths(self.callgraph, source=s, target=t))
                    paths[t] = link
                    break
        APKAnalyzer.log.info(f"found {len(paths)} paths")

        self.paths = {"md5": self.apk_hash, "paths": paths}

        with open(self.paths_json_filename, 'w+') as f_out:
            f_out.write(json.dumps(self.paths, indent=4))
        APKAnalyzer.log.info(f"paths dumped in {self.paths_json_filename}")
        return self.paths

    def get_native_libs(self):
        if self._native_libs is not None:
            return self._native_libs

        self._native_libs = list()
        for f in self.apk.get_files():
            if f.startswith("lib/"):
                lib_full_path = os.path.join(self.wdir, f)
                if not os.path.exists(lib_full_path):
                    os.makedirs(os.path.dirname(lib_full_path), exist_ok=True)
                    raw_data = self.apk.get_file(f)
                    with open(lib_full_path, "wb") as fout:
                        fout.write(raw_data)

                self._native_libs.append(lib_full_path)
        return self._native_libs

    def build_lib_dependency_graph(self):
        native_lib_analysis = self._analyze_native_libs()
        APKAnalyzer.log.info(f"building dependency graph on {len(native_lib_analysis)} libraries")

        lib_analisys_per_arch = dict()
        for libname in native_lib_analysis:
            a = native_lib_analysis[libname]
            if a.arch not in lib_analisys_per_arch:
                lib_analisys_per_arch[a.arch] = list()
            lib_analisys_per_arch[a.arch].append(a)

        APKAnalyzer.log.info(f"dependency graph clustered in {len(lib_analisys_per_arch)} archs")
        g = nx.MultiDiGraph()
        for arch in lib_analisys_per_arch:
            libs_a = lib_analisys_per_arch[arch]

            for a_src in libs_a:
                if a_src.libhash not in g.nodes:
                    g.add_node(a_src.libhash, path=a_src.libpath, analyzer=a_src)

                for fun in a_src.get_imported_functions():
                    for a_dst in libs_a:
                        exported_names = map(lambda f: f.name, a_dst.get_exported_functions())
                        if fun.name in exported_names:
                            if a_dst.libhash not in g.nodes:
                                g.add_node(a_dst.libhash, path=a_dst.libpath, analyzer=a_dst)
                            g.add_edge(a_src.libhash, a_dst.libhash, fun=fun.name)

        APKAnalyzer.log.info(f"returning dependency graph with {g.number_of_edges()} edges")
        return g

    def _analyze_native_libs(self):
        if self._native_lib_analysis is not None:
            return self._native_lib_analysis

        self._native_lib_analysis = dict()
        for lib in self.get_native_libs():
            self._native_lib_analysis[lib] = NativeLibAnalyzer(
                self.cex, lib)
        return self._native_lib_analysis

    def find_native_implementations(self, method_name, lib_whitelist=None):
        APKAnalyzer.log.info(f"looking for native implementation of {method_name}")
        native_libs = self._analyze_native_libs()
        res = list()
        for lib in native_libs:
            if lib_whitelist is not None and native_libs[lib].libhash not in lib_whitelist:
                continue
            jni_functions = native_libs[lib].get_jni_functions()
            for jni_desc in jni_functions:
                if jni_desc.method_name == method_name:
                    res.append(jni_desc)

        APKAnalyzer.log.info(f"native implementation: {res}")
        return res
