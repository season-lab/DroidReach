import time
import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from apk_analyzer import APKAnalyzer
from cex_src.cex import CEXProject

def usage():
    print("%s <apk_path>" % sys.argv[0])
    exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()

    apk_path = sys.argv[1]
    apka     = APKAnalyzer(apk_path)

    armv7_libs = apka.get_armv7_libs()
    arm_hashes = list(map(lambda l: l.libhash, armv7_libs))
    reachable_native_methods = \
        apka.find_native_methods_implementations(lib_whitelist=arm_hashes, reachable=True)

    print("[INFO] %s methods" % len(reachable_native_methods))
    offsets_per_lib = dict()
    for m in reachable_native_methods:
        if m.libpath not in offsets_per_lib:
            offsets_per_lib[m.libpath] = set()
        offsets_per_lib[m.libpath].add(m.offset)

    ghidra = CEXProject.pm.get_plugin_by_name("Ghidra")
    processed_libs = set()

    for method in reachable_native_methods:
        print("[INFO] processing", method)

        demangled_name = apka.demangle(method.class_name, method.method_name, method.args_str)
        ret_type = demangled_name.split(": ")[1].split(" ")[0]
        if ret_type != "long":
            print("[INFO] does not return long")
            continue

        # cache CFG
        if method.libpath not in processed_libs:
            processed_libs.add(method.libpath)
            start = time.time()
            ghidra.define_functions(method.libpath, offsets_per_lib[method.libpath])
            proj = CEXProject(method.libpath, plugins=["Ghidra"])
            proj.get_callgraph(method.offset)
            elapsed = time.time() - start
            print("[GHIDRA_CG] time %f" % elapsed)

        start = time.time()
        vtable_angr = apka.vtable_from_jlong_ret(method, use_angr=True)
        elapsed = time.time() - start
        print("[ANGR_VTABLE] %#x; time %f" % (vtable_angr if vtable_angr is not None else -1, elapsed))

        start = time.time()
        vtable_pexe = apka.vtable_from_jlong_ret(method, use_angr=False)
        elapsed = time.time() - start
        print("[PEXE_VTABLE] %#x; time %f" % (vtable_pexe if vtable_pexe is not None else -1, elapsed))
