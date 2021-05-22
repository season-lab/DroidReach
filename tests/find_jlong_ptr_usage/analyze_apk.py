import subprocess
import sys
import os
import gc

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
from apk_analyzer import APKAnalyzer
from cex.cex import CEX
try:
    from .NativeJLongAnalyzer import NativeJLongAnalyzer
except:
    from NativeJLongAnalyzer import NativeJLongAnalyzer

def usage():
    print("USAGE: %s <apk_path>" % sys.argv[0])
    exit(1)

def print_stderr(*msg):
    sys.stderr.write(" ".join(map(str, msg)) + "\n")

def does_it_use_jlong_as_ptr_angr7(lib, arguments):
    # OLD FUNCTION: used only to check consistency with angr7
    ptr_from_java = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../argus-saf/run_pointers_from_java.sh")

    filtered_arguments = list()
    filtered_indexes   = list()

    i = 0
    for addr, args in arguments:
        if "long" in args:
            filtered_arguments.append(addr)
            filtered_arguments.append("\"" + args + "\"")
            filtered_indexes.append(i)
        i += 1

    if len(filtered_arguments) == 0:
        return False

    # print("running: ", " ".join([ptr_from_java, lib] + filtered_arguments))

    tmp = subprocess.check_output(
        [ptr_from_java, lib] + filtered_arguments
    )

    # FIXME: I feel ashemed looking at this code
    tmp = list(
        map(
            lambda x: "true" in x.lower(),
            filter(
                lambda x: x.lower() in {"true", "false"},
                map(
                    lambda x: x.strip(),
                        tmp.decode("ASCII").strip().split("\n")))))
    assert len(tmp) == len(filtered_arguments) // 2

    out = list(map(lambda _: "False", range(0, len(arguments))))
    for i, j in enumerate(filtered_indexes):
        out[j] = tmp[i]

    return out

def does_it_use_jlong_as_ptr(lib, arguments):
    res = list()

    for addr, args in arguments:
        if isinstance(addr, str):
            addr = int(addr, 16) if addr.startswith("0x") else int(addr)
        if "long" not in args:
            res.append((False, False, False))
            continue

        # Rebuild it every time... To avoid the creation of
        # too many JObjects that makes CLE crash.
        # This will impact the performance for sure
        of = NativeJLongAnalyzer(lib)
        res.append(
            (
                of.check_jlong_as_ptr(addr, args),
                of.check_jlong_as_fun_ptr(addr, args),
                of.check_cpp_obj(addr, args),
            )
        )

    return res

def build_args(class_name, args):
    return args.replace(" ", "")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()

    apk_path = sys.argv[1]

    # cex  = CEX()
    cex  = None  # Use Rizin for finding JNI functions (faster, but probably less accurate)
    apka = APKAnalyzer(cex, apk_path)

    added_libs = set()
    arm_libs   = list()
    libs = apka.get_analyzed_libs()
    for lib in libs:
        if lib.arch in {"armeabi", "armeabi-v7a"}:
            # Relaxed a little bit... If the library is not in a standard location, analyze it
            if lib.libname in added_libs and ("lib/"+lib.arch) in lib.libpath:
                continue
            added_libs.add(lib.libname)
            arm_libs.append(lib.libhash)

    if len(arm_libs) == 0:
        print("No arm libs")
        exit(0)

    native_methods = apka.find_native_methods()
    if len(native_methods) == 0:
        print("No native methods")
        exit(0)

    print_stderr("[INFO]", "found %d native methods and %d armv7 libs" % (len(native_methods), len(arm_libs)))

    native_libs       = dict()
    clustered_methods = dict()
    for native_method in native_methods:
        class_name, method_name, arg_str = native_method
        demangled_name = apka.demangle(class_name, method_name, arg_str)
        if demangled_name is None:
            print_stderr("Unable to demangle", class_name, method_name, arg_str, native_method)
            continue

        demangled_class_name = demangled_name[:demangled_name.find(":")]
        demangled_args = demangled_name[demangled_name.find("(")+1:demangled_name.find(")")]
        native_impls = apka.find_native_implementations(
            method_name, demangled_class_name, arg_str, lib_whitelist=arm_libs)

        native_lib  = None
        native_addr = None
        for native_impl in native_impls:
            if native_impl.analyzer.arch in {"armeabi", "armeabi-v7a"}:
                native_addr = native_impl.offset
                native_lib  = native_impl.analyzer.libpath
                if native_impl.analyzer.libhash not in native_libs:
                    native_libs[native_impl.analyzer.libhash] = native_impl.analyzer.libpath
                break
        if native_addr is None:
            print_stderr("WARNING: No native implementation for %s %s %s\n" % (class_name, method_name, arg_str))
            continue

        lib  = native_lib
        addr = hex(native_addr)
        args = build_args(demangled_class_name, demangled_args)

        if lib not in clustered_methods:
            clustered_methods[lib] = list()
        clustered_methods[lib].append((demangled_name, addr, args))

    lib_dep_graph = apka.build_lib_dependency_graph()
    for native_hash in native_libs:
        native_path = native_libs[native_hash]
        if lib_dep_graph.out_degree(native_hash) > 0:
            print_stderr("[NATIVE_LIB_INFO] JNI native library", native_path, "calls another lib")

    for native_lib in clustered_methods:
        print_stderr(native_lib)
        arguments = clustered_methods[native_lib]

        args  = list()
        addrs = list()
        names = list()
        for name, addr, a in arguments:
            args.append((addr, a))
            names.append(name)
            addrs.append(addr)

        for name, addr, jlong_as_ptr in zip(names, addrs, does_it_use_jlong_as_ptr(native_lib, args)):
            jlong_as_ptr, jlong_as_fun_ptr, jlong_as_cpp_obj = jlong_as_ptr
            print_stderr("[JNI_METHOD_INFO]", name, "@", addr, ":", jlong_as_ptr, jlong_as_fun_ptr, jlong_as_cpp_obj)
            gc.collect()
