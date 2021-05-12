import subprocess
import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
from apk_analyzer import APKAnalyzer
from cex.cex import CEX

ptr_from_java = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../argus-saf/run_pointers_from_java.sh")

def usage():
    print("USAGE: %s <apk_path>" % sys.argv[0])
    exit(1)

def print_stderr(*msg):
    sys.stderr.write(" ".join(msg) + "\n")

def does_it_use_jlong_as_ptr(lib, addr, args):
    if "long" not in args:
        return False

    out = subprocess.check_output(
        [ptr_from_java, lib, addr, args]
    )
    return b"true" in out.lower()

def build_args(class_name, args):
    return args.replace(" ", "")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()

    apk_path = sys.argv[1]

    cex  = CEX()
    apka = APKAnalyzer(cex, apk_path)

    added_libs = set()
    arm_libs   = list()
    libs = apka.get_analyzed_libs()
    for lib in libs:
        if lib.arch in {"armeabi", "armeabi-v7a"}:
            if lib.libname in added_libs:
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
    for native_method in native_methods:
        class_name, method_name, arg_str = native_method
        demangled_name = apka.demangle(class_name, method_name, arg_str)
        if demangled_name is None:
            print("Unable to demangle", class_name, method_name, arg_str, native_method)
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
                break
        if native_addr is None:
            continue

        lib  = native_lib
        addr = hex(native_addr)
        args = build_args(demangled_class_name, demangled_args)

        print(native_lib)
        print(demangled_name, "@", addr, ":", does_it_use_jlong_as_ptr(lib, addr, args))
