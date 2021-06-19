import shutil
import rzpipe
import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from apk_analyzer import APKAnalyzer
from cex_src.cex import CEXProject
from apk_analyzer.utils.timeout_decorator import TimeoutError, timeout
from datetime import date, datetime

def usage():
    print(f"USAGE: {sys.argv[0]} <apk_path>")
    exit(1)

def clear_cex_cache(ghidra):
    shutil.rmtree("/dev/shm/cex_projects")
    os.mkdir("/dev/shm/cex_projects")
    ghidra.clear_cache()

@timeout(1800)
def load_cfg_ghidra_wrapper(ghidra, lib):
    ghidra._load_cfg_raw(lib)
    return ghidra.data[armv7_lib.libpath].cfg_raw

def backup_native_code_counter(lib):
    rz = rzpipe.open(lib, ["-2"])
    rz.cmd("aaa")

    counter = 0
    functions = rz.cmdj("aflj")
    for fun in functions:
        try:
            cfg = rz.cmdj("agj @ %#x" % fun["offset"])[0]
            for block in cfg["blocks"]:
                counter += len(block["ops"])
        except Exception as e:
            print(datetime.now(), "error in rizin [", str(e), "]")

    rz.quit()
    return counter

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()

    print(datetime.now(), "init")

    n_java_instructions         = 0
    n_native_instructions       = 0
    n_java_native_methods       = 0
    n_armv7_libs                = 0
    n_libs_that_links_other_lib = 0
    n_lib_with_cpp_context      = 0

    apka = APKAnalyzer(sys.argv[1])

    print(datetime.now(), "apka created")

    # Number of libraries
    armv7_libs   = apka.get_armv7_libs()
    n_armv7_libs = len(armv7_libs)

    print(datetime.now(), "n arm libs:", n_armv7_libs)

    # Number of libs that link another lib
    lib_depgraph = apka.build_lib_dependency_graph()
    for armv7_lib in armv7_libs:
        if len(lib_depgraph.out_edges(armv7_lib.libhash)) > 0:
            n_libs_that_links_other_lib += 1

    print(datetime.now(), "n wrapper libs:", n_libs_that_links_other_lib)

    # Number of JAVA instructions
    for vm in apka.dvm:
        for method in vm.get_methods():
            if method.get_code() is None:
                continue
            n_java_instructions += len(list(method.get_code().code.get_instructions()))

    print(datetime.now(), "n java instructions:", n_java_instructions)

    # Number of native instructions
    ghidra = CEXProject.pm.get_plugin_by_name("Ghidra")
    rizin  = CEXProject.pm.get_plugin_by_name("Rizin")
    for armv7_lib in armv7_libs:
        print(datetime.now(), "analyzing lib", armv7_lib.libpath)
        try:
            functions = load_cfg_ghidra_wrapper(ghidra, armv7_lib.libpath)
        except Exception as e:
            print(datetime.now(), "ghidra analysis failed [", str(e), "]")
            functions = list()

        for fun in functions:
            for block in fun["blocks"]:
                n_native_instructions += len(block["instructions"])
        if len(functions) == 0:
            print(datetime.now(), "using rizin backup")
            n_native_instructions += backup_native_code_counter(armv7_lib.libpath)
        clear_cex_cache(ghidra)

    print(datetime.now(), "n native instructions:", n_native_instructions)

    # Number of java native methods
    n_java_native_methods = len(apka.find_native_methods())

    print(datetime.now(), "n native methods:", n_java_native_methods)

    # Number of lib with at least one method with "context"
    lib_with_native_mappings = set()
    for native in apka.find_native_methods_implementations(lib_whitelist=list(map(lambda l: l.libhash, armv7_libs))):
        if native.libhash in lib_with_native_mappings:
            continue

        try:
            if len(apka.jlong_as_cpp_obj(native)) > 0:
                lib_with_native_mappings.add(native.libhash)
                print("[INFO] found jlong_as_cpp_obj in", native)
        except TimeoutError:
            print("[WARNING] jlong_as_cpp_obj timeout on", native)
        except Exception as e:
            print("[WARNING] jlong_as_cpp_obj unknown error [", str(e), "]")
    n_lib_with_cpp_context = len(lib_with_native_mappings)

    print(f"[APK_STATISTICS_RESULT] {n_java_instructions}, {n_native_instructions}, {n_java_native_methods}, {n_armv7_libs}, {n_libs_that_links_other_lib}, {n_lib_with_cpp_context}")
