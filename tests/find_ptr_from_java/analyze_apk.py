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

    arm_libs = list()
    libs = apka.get_analyzed_libs()
    for lib in libs:
        if lib.arch in {"armeabi-v7a"}:
            arm_libs.append(lib.libhash)

    native_methods = apka.find_native_methods()
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
            if native_impl.analyzer.arch in {"armeabi-v7a"}:
                native_addr = native_impl.offset
                native_lib  = native_impl.analyzer.libpath
                break
        if native_addr is None:
            continue

        lib  = native_lib
        addr = hex(native_addr)
        args = build_args(demangled_class_name, demangled_args)

        print(method_name, does_it_use_jlong_as_ptr(lib, addr, args))
