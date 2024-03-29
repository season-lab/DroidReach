import os
import sys
import angr
import time
import json
import logging
import claripy
import subprocess
import networkx as nx

from shutil import copyfile
from collections import namedtuple
from androguard.session import Session
from androguard.misc import AnalyzeAPK
from .JavaNameDemangler import JavaNameDemangler, FailedDemanglingError
from .NativeLibAnalyzer import NativeLibAnalyzer
from .utils import md5_hash, connected_nodes, get_native_methods, get_static_constructors_map, check_if_jlong_as_cpp_obj, check_malformed_elf, LCSubStr, iterate_files
from .utils.app_component import AppComponent
from .utils.path_engine import PathEngine, generate_paths
from .utils.timeout_decorator import TimeoutError, timeout

SCRIPTPATH = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(SCRIPTPATH, ".."))
from cex_src.cex import CEXProject
from cex_src.cex.cfg_extractors.angr_plugin.common import AngrCfgExtractor

NativeMethod = namedtuple("NativeMethod", ["class_name", "method_name", "args_str", "libpath", "libhash", "offset"])

LOADLIB_TARGET = 'Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V'

class APKAnalyzerError(Exception):
    pass

class FileNotFoundException(APKAnalyzerError):
    def __init__(self, fname):
        self.message = "%s not found" % fname
        super().__init__(self.message)

class APKAnalyzer(object):
    # FIXME: a refactoring is required
    #        probably we can use JNIFunctionDescription (defined by NativeLibAnalyzer) only locally
    #        and always return NativeMethod instances. Furthermore, we HAVE to get rid of 'analyzer'
    #        ptrs and only use the API get_native_analyzer

    log = logging.getLogger("ap.APKAnalyzer")
    log.setLevel(logging.WARNING)

    tmp_dir = "/dev/shm/apk_analyzer_data"

    def _create_dirs(self):
        if not os.path.exists(APKAnalyzer.tmp_dir):
            os.mkdir(APKAnalyzer.tmp_dir)
        if not os.path.exists(self.wdir):
            os.mkdir(self.wdir)

        if not os.path.exists(os.path.join(self.wdir, os.path.basename(self.apk_path))):
            copyfile(self.apk_path, os.path.join(self.wdir, os.path.basename(self.apk_path)))

    def __init__(self, apk_path, use_flowdroid=False):
        if not os.path.exists(apk_path):
            APKAnalyzer.log.error(f"{apk_path} does not exist")
            raise FileNotFoundException(apk_path)

        APKAnalyzer.log.info("APKAnalyzer initialization")
        self.use_flowdroid = use_flowdroid
        self.apk_path = apk_path
        self.apk_name = os.path.basename(self.apk_path).replace(".apk", "")
        self.apk_hash = md5_hash(self.apk_path)
        self.wdir = os.path.join(APKAnalyzer.tmp_dir, self.apk_hash)
        self.apk, self.dvm, self.analysis = None, None, None
        self.androguard_session = None

        self.callgraph_flowdroid_filename = os.path.join(self.wdir, "callgraph_flowdroid.json")
        self.callgraph_androguard_filename = os.path.join(self.wdir, "callgraph_androguard.gml")
        self.pruned_callgraph_filename = os.path.join(self.wdir, "pruned_callgraph_androguard.gml")
        self.cfgs_json_filename = os.path.join(self.wdir, "cfgs.json")
        self.callgraph_flowdroid = None
        self.callgraph_androguard = None
        self.paths_json_filename = \
            os.path.join(self.wdir, "androguard_paths.json") if not use_flowdroid else os.path.join(self.wdir, "flowdroid_paths.json")
        self.cfgs = None
        self.paths = None
        self.lib_dep_graph = None
        self._create_dirs()

        self.package_name = None
        self._jvm_demangler = JavaNameDemangler()
        self._native_libs = None
        self._native_lib_analysis = None
        self._native_methods = None
        self._native_methods_reachable = None

        APKAnalyzer.log.info("APKAnalyzer initialization done")

    def _lazy_apk_init(self):
        if self.apk is not None:
            return
        self.androguard_session = Session()
        self.apk, self.dvm, self.analysis = AnalyzeAPK(self.apk_path, session=self.androguard_session)
        self.package_name = self.apk.get_package()

    def get_cfgs(self):
        if self.cfgs is not None:
            return self.cfgs

        cfgs_json = None
        if not os.path.exists(self.cfgs_json_filename):
            self._lazy_apk_init()
            res = { "classes": dict() }
            for _, vm, vmx in self.androguard_session.get_objects_dex():
                for method in vm.get_methods():
                    class_name = str(method.get_class_name())
                    if class_name not in res["classes"]:
                        res["classes"][class_name] = {"methods": list()}
                    class_json = res["classes"][class_name]

                    method_name = str(method.get_name())
                    method_descriptor = str(method.get_descriptor())
                    method_json = {
                        "name": method_name,
                        "descriptor": method_descriptor,
                        "basic_blocks": list()
                    }
                    class_json["methods"].append(method_json)

                    am = vmx.get_method(method)
                    bbs = am.get_basic_blocks()
                    for bb in bbs.bb:
                        bb_json = {
                            "start": bb.start,
                            "instructions": list(),
                            "successors": [x[1] for x in bb.get_next()]
                        }
                        method_json["basic_blocks"].append(bb_json)

                        idx = bb.start
                        for insn in bb.get_instructions():
                            bb_json["instructions"].append({
                                "idx": idx,
                                "mnemonic": "%s %s" % (insn.get_name(), insn.get_output(0))
                            })
                            idx += insn.get_length()
            with open(self.cfgs_json_filename, "w") as fout:
                fout.write(json.dumps(res))
            cfgs_json = res

        if cfgs_json is None:
            with open(self.cfgs_json_filename, "r") as fin:
                cfgs_json = json.load(fin)

        self.cfgs = dict()
        for c in cfgs_json["classes"]:
            for m in cfgs_json["classes"][c]["methods"]:
                method_id = "%s->%s%s" % (c, m["name"], m["descriptor"])
                self.cfgs[method_id] = nx.DiGraph()
                cfg = self.cfgs[method_id]
                for bb in m["basic_blocks"]:
                    label = ""
                    if bb["start"] == 0:
                        label += "%s\n\n" % method_id
                    label += \
                        "\n".join(["%02d: %s" % (x["idx"], x["mnemonic"]) for x in bb["instructions"]])
                    cfg.add_node(
                        bb["start"],
                        ids=[x["idx"] for x in bb["instructions"]],
                        label=label)
                for bb in m["basic_blocks"]:
                    for s in bb["successors"]:
                        cfg.add_edge(bb["start"], s)
        return self.cfgs

    def get_callgraph_flowdroid(self):
        # Todo: add callsites
        if self.callgraph_flowdroid is None:
            flowdroid_bin = os.path.join(SCRIPTPATH, "bin/FlowdroidCGDumper.jar")
            platforms_dir = os.path.join(os.path.expanduser("~"), "Android/Sdk/platforms")
            if not os.path.exists(platforms_dir):
                platforms_dir = "/opt/android-sdk/platforms"
                if not os.path.exists(platforms_dir):
                    APKAnalyzer.log.error("unable to find android sdk for building the callgraph with flowdroid")
                    return None

            APKAnalyzer.log.info("generating Flowdroid callgraph")
            if not os.path.exists(self.callgraph_flowdroid_filename):
                fout = open(self.callgraph_flowdroid_filename, "w")
                cg = subprocess.run(['java', '-jar', flowdroid_bin, platforms_dir, self.apk_path],
                                    stdout=fout, stderr=subprocess.DEVNULL)
                fout.close()
                APKAnalyzer.log.info(f"callgraph generated in {self.callgraph_flowdroid_filename}")
            else:
                APKAnalyzer.log.info(f"callgraph found cached in {self.callgraph_flowdroid_filename}")

            with open(self.callgraph_flowdroid_filename, "r") as fin:
                cg = json.load(fin)

            APKAnalyzer.log.info("reading callgraph")
            self.callgraph_flowdroid = nx.MultiDiGraph()
            for edge in cg["edges"]:
                src = "L" + edge["src"][1:-1].replace(": ", ";->").replace(".", "/")
                dst = "L" + edge["dst"][1:-1].replace(": ", ";->").replace(".", "/")
                self.callgraph_flowdroid.add_edge(src, dst)
            APKAnalyzer.log.info("callgraph read")

        sources = list()
        for node in self.callgraph_flowdroid:
            if len(self.callgraph_flowdroid.in_edges(node)) == 0:
                sources.append(str(node))

        return self.callgraph_flowdroid, sources

    def get_callgraph_androguard(self):
        if self.callgraph_androguard is None:
            APKAnalyzer.log.info("generating androguard callgraph")
            if not os.path.exists(self.callgraph_androguard_filename):
                cg = subprocess.run(['androguard', 'cg', '-o', self.callgraph_androguard_filename, self.apk_path],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                APKAnalyzer.log.info(f"callgraph generated in {self.callgraph_androguard_filename}")
            else:
                APKAnalyzer.log.info(f"callgraph found cached in {self.callgraph_androguard_filename}")

            APKAnalyzer.log.info("reading callgraph")
            self.callgraph_androguard = nx.read_gml(self.callgraph_androguard_filename)

            def relable_function(name):
                return name.split(" ")[1]

            self.callgraph_androguard = nx.relabel_nodes(
                self.callgraph_androguard,
                relable_function)
            APKAnalyzer.log.info("callgraph read")

        self._lazy_apk_init()
        acts  = AppComponent('a', self.apk.get_activities())
        provs = AppComponent('p', self.apk.get_providers())
        recvs = AppComponent('r', self.apk.get_receivers())
        servs = AppComponent('s', self.apk.get_services())
        static_constructors = get_static_constructors_map(self.callgraph_androguard.nodes)

        components = [acts, provs, recvs, servs]
        sources = list()
        for comp in components:
            sources.extend(comp.get_sources(self.callgraph_androguard.nodes))

        n_sources = len(sources)
        connected_subgraph = self.callgraph_androguard.subgraph(
            connected_nodes(self.callgraph_androguard, sources))

        # Add static constructors of classes that are used by the application
        added_class = set()
        for node in connected_subgraph.nodes:
            node_str = str(node)
            class_name = node_str.split("->")[0]
            if class_name in added_class:
                continue
            added_class.add(class_name)
            if class_name in static_constructors:
                sources.append(static_constructors[class_name])
        n_added_static_sources = len(sources) - n_sources
        APKAnalyzer.log.info(f"added {n_added_static_sources} static constructors as sources")

        connected_subgraph = self.callgraph_androguard.subgraph(
            connected_nodes(self.callgraph_androguard, sources))
        nx.readwrite.gml.write_gml(connected_subgraph, self.pruned_callgraph_filename)

        return self.callgraph_androguard, sources

    def get_callgraph(self):
        if not self.use_flowdroid:
            cg, _ = self.get_callgraph_androguard()
        else:
            cg, _ = self.get_callgraph_flowdroid()
        return cg

    def get_paths_to_native(self):
        if self.paths is not None:
            return self.paths

        APKAnalyzer.log.info("generating paths to native functions")
        if os.path.exists(self.paths_json_filename):
            with open(self.paths_json_filename, "r") as fin:
                self.paths = json.load(fin)
            APKAnalyzer.log.info("found cached")
            return self.paths

        self._lazy_apk_init()
        if not self.use_flowdroid:
            cg, sources = self.get_callgraph_androguard()
        else:
            cg, sources = self.get_callgraph_flowdroid()

        # get all targets
        native_targets = self.find_native_methods()
        targets = [LOADLIB_TARGET, *list(map(lambda x: x[0] + "->" + x[1] + x[2], native_targets))]
        APKAnalyzer.log.info(
            f"found {len(targets)} targets and {len(sources)} sources")

        cg_reversed = cg.reverse()
        APKAnalyzer.log.info("looking for paths")
        paths = {}
        for t in targets:
            for s in sources:
                if s not in cg.nodes or t not in cg.nodes:
                    continue
                link = next(nx.all_simple_paths(cg_reversed, source=t, target=s), None)
                if link is None:
                    continue
                paths[t] = link[::-1]
                break
        APKAnalyzer.log.info(f"found {len(paths)} paths")

        self.paths = {"md5": self.apk_hash, "paths": paths}

        with open(self.paths_json_filename, 'w+') as f_out:
            f_out.write(json.dumps(self.paths, indent=4))
        APKAnalyzer.log.info(f"paths dumped in {self.paths_json_filename}")
        return self.paths

    def delete_callgraph(self):
        self.callgraph_androguard = None
        self.callgraph_flowdroid = None

    def get_native_libs(self):
        if self._native_libs is not None:
            return self._native_libs

        self._native_libs = list()

        if os.path.exists(os.path.join(self.wdir, "libs_analyzed")):
            for f in iterate_files(self.wdir, recursive=True):
                if not f.endswith(".so"):
                    continue
                self._native_libs.append(f)
            return self._native_libs

        self._lazy_apk_init()
        for f in self.apk.get_files():
            # Include libs in non-standard locations (this may introduce bugs later on, lets keep an eye on it)
            if f.startswith("lib/") or f.endswith(".so"):
                if len(self.apk.get_file(f)) == 0:
                    # Not a file, maybe a bug of androguard?
                    APKAnalyzer.log.warning("the file %s has size 0" % f)
                    continue
                if self.apk.get_file(f)[:4] != b"\x7fELF":
                    # Not an ELF?
                    APKAnalyzer.log.warning("the file %s is not an ELF" % f)
                    continue
                if check_malformed_elf(self.apk.get_file(f)):
                    APKAnalyzer.log.warning("the file %s if malformed" % f)
                    continue
                lib_full_path = os.path.join(self.wdir, f)
                if not os.path.exists(lib_full_path):
                    os.makedirs(os.path.dirname(lib_full_path), exist_ok=True)
                    raw_data = self.apk.get_file(f)
                    with open(lib_full_path, "wb") as fout:
                        fout.write(raw_data)

                self._native_libs.append(lib_full_path)

        open(os.path.join(self.wdir, "libs_analyzed"), "w").close()
        return self._native_libs

    def build_lib_dependency_graph(self):
        if self.lib_dep_graph is not None:
            return self.lib_dep_graph

        native_lib_analysis = self._analyze_native_libs()
        APKAnalyzer.log.info(f"building dependency graph on {len(native_lib_analysis)} libraries")

        lib_analysis_per_arch = dict()
        for libname in native_lib_analysis:
            a = native_lib_analysis[libname]
            if a.arch not in lib_analysis_per_arch:
                lib_analysis_per_arch[a.arch] = list()
            lib_analysis_per_arch[a.arch].append(a)

        APKAnalyzer.log.info(f"dependency graph clustered in {len(lib_analysis_per_arch)} archs")
        g = nx.MultiDiGraph()
        for arch in lib_analysis_per_arch:
            libs_a = lib_analysis_per_arch[arch]

            for a_src in libs_a:
                if a_src.libhash not in g.nodes:
                    g.add_node(a_src.libhash, path=a_src.libpath, analyzer=a_src)

                for fun_src in a_src.get_imported_functions():
                    for a_dst in libs_a:
                        for fun_dst in a_dst.get_exported_functions():
                            if fun_src.name != fun_dst.name:
                                continue
                            if a_dst.libhash not in g.nodes:
                                g.add_node(a_dst.libhash, path=a_dst.libpath, analyzer=a_dst)
                            g.add_edge(a_src.libhash, a_dst.libhash, fun=fun_src.name,
                                src_off=fun_src.offset, dst_off=fun_dst.offset)

        APKAnalyzer.log.info(f"returning dependency graph with {g.number_of_edges()} edges")
        self.lib_dep_graph = g
        return self.lib_dep_graph

    def _analyze_native_libs(self):
        if self._native_lib_analysis is not None:
            return self._native_lib_analysis

        APKAnalyzer.log.info("analyzing native libraries")
        self._native_lib_analysis = dict()
        for lib in self.get_native_libs():
            self._native_lib_analysis[lib] = NativeLibAnalyzer(lib)
        APKAnalyzer.log.info("analyzing native libraries done")
        return self._native_lib_analysis

    def get_analyzed_libs(self):
        self._analyze_native_libs()
        return list(self._native_lib_analysis.values())

    def get_armv7_libs(self):
        added_libs = dict()
        arm_libs   = list()
        libs       = self.get_analyzed_libs()
        for lib in libs:
            if lib.arch in {"armeabi", "armeabi-v7a"}:
                # Relaxed a little bit... If the library is not in a standard location, analyze it
                if lib.libname in added_libs and ("lib/"+lib.arch) in lib.libpath:
                    # Prefer "armeabi" over "armeabi-v7a" (just to have determinism)
                    if added_libs[lib.libname] == "armeabi":
                        continue
                    else:
                        # thus, delete the old lib from the list
                        new_libs = list()
                        for l in arm_libs:
                            if l.libname == lib.libname:
                                continue
                            new_libs.append(l)
                        arm_libs = new_libs

                added_libs[lib.libname] = lib.arch
                arm_libs.append(lib)
        return arm_libs

    def get_libpath_from_hash(self, lib_hash):
        self._analyze_native_libs()
        for lib_path in self._native_lib_analysis:
            a = self._native_lib_analysis[lib_path]
            if a.libhash == lib_hash:
                return a.libpath
        return None

    def get_libname_from_hash(self, lib_hash):
        return os.path.basename(self.get_libpath_from_hash(lib_hash))

    def get_native_analyzer(self, lib_hash):
        return self._native_lib_analysis[self.get_libpath_from_hash(lib_hash)]

    def find_native_implementations(self, method_name, class_name, args_str, lib_whitelist=None, resolve_clashes_with_angr=True):
        APKAnalyzer.log.info(f"looking for native implementation of {method_name} of class {class_name}")
        native_libs = self._analyze_native_libs()
        res = list()
        for lib in native_libs:
            if lib_whitelist is not None and native_libs[lib].libhash not in lib_whitelist:
                continue
            jni_functions = native_libs[lib].get_jni_functions()
            for jni_desc in jni_functions:
                if (jni_desc.method_name == method_name) and                                                       \
                   (jni_desc.class_name == "???" or jni_desc.class_name == class_name[1:-1].replace("/", ".")) and \
                   (jni_desc.args == "???" or args_str.startswith(jni_desc.args)):
                   # in Java_* mangling, if args are present, the return value is not, so the string will be cutted (e.g. "(III" instead of "(III)V").
                   # for this reason, I will only check if the first part of the argument string matches with jni_desc.args

                    res.append(jni_desc)

        if len(res) > 1 and resolve_clashes_with_angr:
            APKAnalyzer.log.info(f"executing angr fallback, len(res)={len(res)}")
            # Look only in the libraries where the clashing functions was found
            angr_lib_whitelist = set()
            for j in res:
                angr_lib_whitelist.add(j.analyzer.libhash)
            angr_jnis = self.find_native_implementations_angr(
                method_name, class_name, args_str, lib_whitelist=angr_lib_whitelist)
            if len(angr_jnis) == 1:
                res = angr_jnis
            APKAnalyzer.log.info(f"after angr fallback, len(res)={len(res)}")

        APKAnalyzer.log.info(f"native implementation: {res}")
        return res

    def find_native_static_implementation(self, method_name, class_name, args_str, lib_whitelist=None):
        APKAnalyzer.log.info(f"looking for native static implementation of {method_name} of class {class_name}")
        native_libs = self._analyze_native_libs()
        res = None
        for lib in native_libs:
            if lib_whitelist is not None and native_libs[lib].libhash not in lib_whitelist:
                continue
            jni_functions = native_libs[lib]._get_static_functions()
            for jni_desc in jni_functions:
                if (jni_desc.method_name == method_name) and                                                       \
                   (jni_desc.class_name == "???" or jni_desc.class_name == class_name[1:-1].replace("/", ".")) and \
                   (jni_desc.args == "???" or args_str.startswith(jni_desc.args)):
                   # in Java_* mangling, if args are present, the return value is not, so the string will be cutted (e.g. "(III" instead of "(III)V").
                   # for this reason, I will only check if the first part of the argument string matches with jni_desc.args

                    res = jni_desc

        APKAnalyzer.log.info(f"native implementation: {res}")
        return res

    def find_native_implementations_angr(self, method_name, class_name, args_str, lib_whitelist=None):
        APKAnalyzer.log.info(f"looking for native implementation of {method_name} of class {class_name} (angr)")
        native_libs = self._analyze_native_libs()
        res = list()
        for lib in native_libs:
            if lib_whitelist is not None and native_libs[lib].libhash not in lib_whitelist:
                continue
            jni_functions = native_libs[lib]._get_jni_functions_angr()
            for jni_desc in jni_functions:
                if (jni_desc.method_name == method_name) and                                                       \
                   (jni_desc.class_name == "???" or jni_desc.class_name == class_name[1:-1].replace("/", ".")) and \
                   (jni_desc.args == "???" or args_str.startswith(jni_desc.args)):
                   # in Java_* mangling, if args are present, the return value is not, so the string will be cutted (e.g. "(III" instead of "(III)V").
                   # for this reason, I will only check if the first part of the argument string matches with jni_desc.args

                    res.append(jni_desc)

        APKAnalyzer.log.info(f"native implementations (angr): {res}")
        return res

    def demangle(self, class_name, method_name, arg_str):
        try:
            return self._jvm_demangler.method_signature_demangler(class_name, method_name, arg_str)
        except FailedDemanglingError:
            return None

    def find_native_methods(self):
        if self._native_methods is not None:
            return self._native_methods

        if os.path.exists(os.path.join(self.wdir, "native_methods.txt")):
            self._native_methods = list()
            with open(os.path.join(self.wdir, "native_methods.txt"), "r") as fin:
                for line in fin:
                    line = line.strip()
                    if line == "":
                        continue
                    class_name, native_name, args_str = line.split(" @@@ ")
                    self._native_methods.append((class_name, native_name, args_str))
            return self._native_methods

        self._lazy_apk_init()

        native_signatures = get_native_methods(self.analysis, public_only=False)
        native_names = list(map(
            lambda x: x.split(";->")[1].split("(")[0],
            native_signatures))
        class_names  = list(map(
            lambda x: "L" + x.split(" L")[1].split(";->")[0] + ";",
            native_signatures))
        args_strings = list(map(
            lambda x: ("(" + x.split("(")[1].split(" [access")[0]).replace(" ", ""),
            native_signatures))

        self._native_methods = list(zip(class_names, native_names, args_strings))

        with open(os.path.join(self.wdir, "native_methods.txt"), "w") as fout:
            for class_name, native_name, args_str in self._native_methods:
                fout.write("%s @@@ %s @@@ %s\n" % (class_name, native_name, args_str))

        return self._native_methods

    def find_reachable_native_methods(self):
        if self._native_methods_reachable is not None:
            return self._native_methods_reachable

        paths_result = self.get_paths_to_native()
        native_signatures = list(paths_result["paths"].keys())
        native_names = list(map(
            lambda x: x.split(";->")[1].split("(")[0],
            native_signatures))
        class_names  = list(map(
            lambda x: x.split(";->")[0] + ";",
            native_signatures))
        args_strings = list(map(
            lambda x: ("(" + x.split("(")[1]).replace(" ", ""),
            native_signatures))

        self._native_methods_reachable = list(zip(class_names, native_names, args_strings))
        return self._native_methods_reachable

    def get_path_to_native_method(self, method):
        paths_result = self.get_paths_to_native()
        for n in paths_result["paths"]:
            native_name = n.split(";->")[1].split("(")[0]
            class_name  = n.split(";->")[0] + ";"
            if class_name == method.class_name and native_name == method.method_name:
                java_path = list()
                for j in paths_result["paths"][n]:
                    native_name = j.split(";->")[1].split("(")[0]
                    class_name  = j.split(";->")[0] + ";"
                    args = "(" + j.split(";->")[1].split("(")[1]
                    java_path.append(class_name + "->" + native_name + args)
                return java_path
        return None

    def find_native_methods_implementations(self, lib_whitelist=None, reachable=False):
        # Among all the native methods detected in Java, return the subset
        # of them for which we can find the native implementation
        # if reachable is True, then return the ones that are reachable from the defined sources

        res = list()

        methods = None
        if reachable:
            methods = self.find_reachable_native_methods()
        else:
            methods = self.find_native_methods()

        added_methods = set()
        for class_name, method_name, args_str in methods:
            native_impls = self.find_native_implementations(method_name, class_name, args_str, lib_whitelist)
            if len(native_impls) == 0:
                continue

            for n in native_impls:
                native_impl = n
                if (native_impl.analyzer.libpath, native_impl.offset) in added_methods:
                    continue
                added_methods.add((native_impl.analyzer.libpath, native_impl.offset))

                res.append(
                    NativeMethod(
                        class_name, method_name, args_str, native_impl.analyzer.libpath, native_impl.analyzer.libhash, native_impl.offset)
                )

        return res

    @timeout(60*30) # Just a double check
    def _check_if_jlong_as_cpp_obj_pexe(self, libpath, offset, args):
        def mk_cpp_obj(state, param_i):
            n_entries_cpp = 50

            cpp_obj = state.heap.allocate(state.project.arch.bytes)
            _       = state.heap.allocate(0x1000)  # redzone
            vtable  = state.heap.allocate(state.project.arch.bytes * n_entries_cpp)

            state.memory.store(
                cpp_obj, claripy.BVV(vtable, state.project.arch.bits),
                endness=state.project.arch.memory_endness)

            for i in range(0, n_entries_cpp * state.project.arch.bytes, state.project.arch.bytes):
                state.memory.store(
                    vtable + i,
                    claripy.BVS("obj_%d_vtable_entry_%d" % (param_i, i), state.project.arch.bits),
                    endness=state.project.arch.memory_endness)
            return claripy.BVV(cpp_obj, state.project.arch.bits)

        def prepare_state_cpp(state, args):
            parsed_args = dict()
            for i, a in enumerate(args.split(",")):
                a = a.strip().replace(" ", "")
                parsed_args[i+2] = a

            for arg_id in parsed_args:
                arg_type = parsed_args[arg_id]

                if arg_type != "long":
                    continue
                data = mk_cpp_obj(state, arg_id-2)

                if arg_id < 3:
                    state.regs.__setattr__('r%d' % arg_id, data)
                else:
                    state.stack_push(data)
            # We should never call the solver
            state.solver._solver.timeout = 500
            return state

        tainted_calls = set()
        def checkTaintedCall(state, target):
            if target is None or isinstance(target, int):
                return
            for symb_name in target.variables:
                if "vtable_entry_" in symb_name:
                    print("[FOUND VCALL] libpath %s; offset %#x; state %s; target %s" % (libpath, offset, str(state), str(target)))
                    tainted_calls.add(symb_name)
                    break

        cex_proj  = CEXProject(libpath, plugins=["Ghidra"])
        angr_proj = angr.Project(libpath, auto_load_libs=False)
        engine    = PathEngine(angr_proj, monitor_target=checkTaintedCall)

        offset -= offset % 2
        CEXProject.pm.get_plugin_by_name("AngrEmulated").build_cfg = True
        _ = cex_proj.get_callgraph(offset)
        CEXProject.pm.get_plugin_by_name("AngrEmulated").build_cfg = False

        max_time = 60 * 5
        start    = time.time()
        for p in generate_paths(cex_proj, engine, offset, only_with_indirect_call=True, max_time=start + max_time):
            tainted_calls.clear()
            opts = {
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                angr.options.AVOID_MULTIVALUED_READS,
                angr.options.AVOID_MULTIVALUED_WRITES
            }
            state = angr_proj.factory.blank_state(
                add_options=opts
            )
            prepare_state_cpp(state, args)
            _ = engine.process_path(state, p)

            if len(tainted_calls) > 0:
                # print(tainted_calls)
                break
            if time.time() - start > max_time:
                break

        CEXProject.pm.get_plugin_by_name("AngrEmulated").build_cfg = True
        return list(set(map(lambda s: int(s.split("_")[1]), tainted_calls)))

    def jlong_as_cpp_obj(self, native_method: NativeMethod, use_angr=False):
        # Check whether the native method has a jlong that is used as a C++ ptr (we detect vcalls)

        demangled_name = self.demangle(native_method.class_name, native_method.method_name, native_method.args_str)
        assert demangled_name is not None

        demangled_args = demangled_name[demangled_name.find("(")+1:demangled_name.find(")")]
        demangled_args = demangled_args.replace(" ", "")
        if "long" not in demangled_args:
            return list()

        try:
            if use_angr:
                return check_if_jlong_as_cpp_obj(native_method.libpath, native_method.offset, demangled_args)
            return self._check_if_jlong_as_cpp_obj_pexe(native_method.libpath, native_method.offset, demangled_args)
        except TimeoutError:
            CEXProject.pm.get_plugin_by_name("AngrEmulated").build_cfg = True
            APKAnalyzer.log.warning("Timeout in jlong_as_cpp_obj (use_angr=%s)" % str(use_angr))
            return list()
        except Exception as e:
            CEXProject.pm.get_plugin_by_name("AngrEmulated").build_cfg = True
            APKAnalyzer.log.warning("Unknown error in jlong_as_cpp_obj (use_angr=%s) [ %s ]" % (str(use_angr), str(e)))
            return list()

    def methods_jlong_ret_for_class(self, class_name, lib_whitelist=None, reachable=False):
        res = list()
        for method in self.find_native_methods_implementations(lib_whitelist, reachable):
            if method.class_name == class_name:
                if method.args_str[-1] == "J":
                    res.append(method)

        return res

    def methods_jlong(self, lib_whitelist=None, reachable=False):
        res = list()
        for method in self.find_native_methods_implementations(lib_whitelist, reachable):
            if method.args_str[-1] == "J":
                res.append(method)

        return res

    def find_potential_producers(self, consumer, lib_whitelist=False, reachable=False):
        def _sort_heuristic(x):
            # Prefer methods of the same lib
            lib_score = 0 if x.libhash == consumer.libhash else 1

            # Prefer methods that have a substring in common
            common_substring_score = -LCSubStr(x.method_name, consumer.method_name)

            # Prefer methods with these tokens
            name_score = sys.maxsize
            tokens = ["getinstance", "builder", "newentry", "new", "ctor"]
            for i, token in enumerate(tokens):
                if token in x.method_name.lower():
                    name_score = i
                    break

            return lib_score, name_score + common_substring_score

        potential_producers = self.methods_jlong_ret_for_class(consumer.class_name, lib_whitelist=lib_whitelist, reachable=reachable)
        potential_producers = sorted(potential_producers, key=_sort_heuristic)

        if len(potential_producers) == 0:
            print("WARNING: relaxing same class heuristic")
            potential_producers = self.methods_jlong(lib_whitelist=lib_whitelist, reachable=reachable)
            potential_producers = sorted(potential_producers, key=_sort_heuristic)

        return potential_producers

    def vtable_from_jlong_ret(self, native_method: NativeMethod, use_angr=False):
        # Check whether the return value of the native method is a C++ obj ptr, and if so it returns
        # the pointer to the vtable corresponding to the obj (polymorfism is required). Otherwise returns None

        demangled_name = self.demangle(native_method.class_name, native_method.method_name, native_method.args_str)
        ret_type = demangled_name.split(": ")[1].split(" ")[0]
        if ret_type != "long":
            return None

        a = self.get_native_analyzer(native_method.libhash)
        return a.get_returned_vtable(native_method.offset, use_angr)
