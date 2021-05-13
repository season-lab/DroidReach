import subprocess
import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
from apk_analyzer import APKAnalyzer
from cex.cex import CEX
try:
    from .JLongAsCppObjFinder import JLongAsCppObjFinder
except:
    from JLongAsCppObjFinder import JLongAsCppObjFinder

def usage():
    print("USAGE: %s <apk_path>" % sys.argv[0])
    exit(1)

def print_stderr(*msg):
    sys.stderr.write(" ".join(msg) + "\n")

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
    of  = JLongAsCppObjFinder(lib)
    res = list()

    for addr, args in arguments:
        if isinstance(addr, str):
            addr = int(addr, 16) if addr.startswith("0x") else int(addr)
        if "long" not in args:
            res.append(False)
            continue
        res.append(of.check(addr, args))

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
    clustered_methods = dict()
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
            print("No native implementation for", native_method)
            continue

        lib  = native_lib
        addr = hex(native_addr)
        args = build_args(demangled_class_name, demangled_args)

        if lib not in clustered_methods:
            clustered_methods[lib] = list()
        clustered_methods[lib].append((demangled_name, addr, args))

    for native_lib in clustered_methods:
        print(native_lib)
        arguments = clustered_methods[native_lib]

        args  = list()
        addrs = list()
        names = list()
        for name, addr, a in arguments:
            args.append((addr, a))
            names.append(name)
            addrs.append(addr)

        for name, addr, jlong_as_ptr in zip(names, addrs, does_it_use_jlong_as_ptr(native_lib, args)):
            print(name, "@", addr, ":", jlong_as_ptr)
