import time
import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from apk_analyzer import APKAnalyzer


def usage():
    print("python3 %s <apk_path>" % sys.argv[0])
    exit(1)

def find_native_from_pool(apka, print_label, libs, method_pool):
    found_mapping          = 0
    found_dynamic_rizin    = 0
    found_static           = 0
    found_dynamic_angr     = 0
    rizin_clash            = 0
    angr_clash             = 0
    clash_resolved_by_angr = 0

    arm_hashes = list(map(lambda l: l.libhash, libs))

    angr_found_methods = set()
    start              = time.time()
    for class_name, native_name, args_string in method_pool:
        # NOTE: angr has a timeout of 15 minutes per lib
        jnis = apka.find_native_implementations_angr(native_name, class_name, args_string, lib_whitelist=arm_hashes)
        if len(jnis) > 0:
            found_dynamic_angr += 1
            angr_found_methods.add((class_name, native_name, args_string))
        elif len(jnis) > 1:
            found_dynamic_angr += 1
            angr_clash         += 1
            angr_found_methods.add((class_name, native_name, args_string))
    time_angr = time.time() - start

    # clear angr cache to have usable times
    for lib in apka.get_analyzed_libs():
        lib._jni_functions_angr = None

    jni_functions = dict()
    def add_to_jni_functions(jni):
        if jni.analyzer.libpath not in jni_functions:
            jni_functions[jni.analyzer.libpath] = list()
        jni_functions[jni.analyzer.libpath].append(jni)

    rizin_found_methods = set()
    start               = time.time()
    for class_name, native_name, args_string in method_pool:
        jnis = apka.find_native_implementations(native_name, class_name, args_string, lib_whitelist=arm_hashes)
        if len(jnis) == 1:
            found_mapping += 1

            jni = jnis[0]
            if jni.class_name != "???":
                found_static += 1
            else:
                found_dynamic_rizin += 1
                rizin_found_methods.add((class_name, native_name, args_string))
            add_to_jni_functions(jni)

        elif len(jnis) > 1:
            rizin_clash         += 1
            found_dynamic_rizin += 1
            found_mapping       += 1

            rizin_found_methods.add((class_name, native_name, args_string))

            angr_jnis = apka.find_native_implementations_angr(native_name, class_name, args_string, lib_whitelist=arm_hashes)
            if len(angr_jnis) == 1:
                clash_resolved_by_angr += 1
                add_to_jni_functions(angr_jnis[0])
            else:
                # add all jni methods (even with clash)
                for jni in jnis:
                    add_to_jni_functions(jni)
    time_rizin = time.time() - start

    rizin_unique = len(rizin_found_methods - angr_found_methods)
    angr_unique  = len(angr_found_methods - rizin_found_methods)

    # Add angr unique (cached! This should be fast)
    for class_name, native_name, args_string in (angr_found_methods - rizin_found_methods):
        jnis = apka.find_native_implementations_angr(native_name, class_name, args_string, lib_whitelist=arm_hashes)
        add_to_jni_functions(jnis[0])

    print("[%s] apk_jni: %d; found_jni %d; static_jni %d; dyn angr %d; angr unique %d; angr clashes %d; time angr %f; dyn rizin %d; rizin unique %d; rizin clashes %d; rizin time %f; clash resolved by angr %d" % \
        (print_label, len(method_pool), found_mapping, found_static, found_dynamic_angr, angr_unique, angr_clash, time_angr, found_dynamic_rizin, rizin_unique, rizin_clash, time_rizin, clash_resolved_by_angr))
    return jni_functions


if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()

    apk_path = sys.argv[1]
    apka     = APKAnalyzer(apk_path)

    arm_libs = apka.get_armv7_libs()
    if len(arm_libs) == 0:
        print("[ERR] No arm libs")
        exit(0)

    reachable_native_methods = apka.find_reachable_native_methods()
    jni_functions_reachable  = find_native_from_pool(apka, "JNI_MAPPING_REACHABLE", arm_libs, reachable_native_methods)
