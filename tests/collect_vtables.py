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
        apka.find_native_methods_implementations(lib_whitelist=arm_hashes, reachable=False)  # Lets begin with reachable=False, to have more methods

    print("[INFO] %s methods" % len(reachable_native_methods))
    offsets_per_lib = dict()
    for m in reachable_native_methods:
        if m.libpath not in offsets_per_lib:
            offsets_per_lib[m.libpath] = set()
        offsets_per_lib[m.libpath].add(m.offset)

    ghidra = CEXProject.pm.get_plugin_by_name("Ghidra")
    processed_libs      = set()
    processed_producers = dict()

    for consumer in reachable_native_methods:
        print("[INFO] checking consumer", consumer)

        demangled_name = apka.demangle(consumer.class_name, consumer.method_name, consumer.args_str)
        demangled_args = demangled_name[demangled_name.find("(")+1:demangled_name.find(")")]
        demangled_args = demangled_args.replace(" ", "")
        if "long" not in demangled_args:
            print("[INFO] does not have long as parameter")
            continue

        # cache CFG
        if consumer.libpath not in processed_libs:
            processed_libs.add(consumer.libpath)
            start = time.time()
            ghidra.define_functions(consumer.libpath, offsets_per_lib[consumer.libpath])
            proj = CEXProject(consumer.libpath, plugins=["Ghidra"])
            proj.get_callgraph(consumer.offset & 0xfffffffe)
            elapsed = time.time() - start
            print("[GHIDRA_CG] time %f" % elapsed)

        start     = time.time()
        args_angr = apka.jlong_as_cpp_obj(consumer, use_angr=True)
        elapsed   = time.time() - start
        print("[ANGR_JLONG_AS_PTR] %s; time %f" % (str(args_angr), elapsed))

        start     = time.time()
        args_pexe = apka.jlong_as_cpp_obj(consumer, use_angr=False)
        elapsed   = time.time() - start
        print("[PEXE_JLONG_AS_PTR] %s; time %f" % (str(args_pexe), elapsed))

        if len(args_angr) > 0 or len(args_pexe) > 0:
            print("[JLONG_AS_PTR]", consumer)

            found_vtables = set()
            for producer in apka.methods_jlong_ret_for_class(consumer.class_name, lib_whitelist=arm_hashes):
                if producer in processed_producers:
                    found_vtables |= processed_producers[producer]
                    continue
                print("[INFO] checking producer", producer)

                # cache CFG
                if producer.libpath not in processed_libs:
                    processed_libs.add(producer.libpath)
                    start = time.time()
                    ghidra.define_functions(producer.libpath, offsets_per_lib[producer.libpath])
                    proj = CEXProject(producer.libpath, plugins=["Ghidra"])
                    proj.get_callgraph(producer.offset & 0xfffffffe)
                    elapsed = time.time() - start
                    print("[GHIDRA_CG] time %f" % elapsed)

                start = time.time()
                vtable_angr = apka.vtable_from_jlong_ret(producer, use_angr=True)
                elapsed = time.time() - start
                print("[ANGR_VTABLE] %#x; time %f" % (vtable_angr if vtable_angr is not None else -1, elapsed))

                start = time.time()
                vtable_pexe = apka.vtable_from_jlong_ret(producer, use_angr=False)
                elapsed = time.time() - start
                print("[PEXE_VTABLE] %#x; time %f" % (vtable_pexe if vtable_pexe is not None else -1, elapsed))

                processed_producers[producer] = set()

                if vtable_angr is not None:
                    found_vtables.add(vtable_angr)
                    processed_producers[producer].add(vtable_angr)
                if vtable_pexe is not None:
                    found_vtables.add(vtable_pexe)
                    processed_producers[producer].add(vtable_pexe)

            print("[VTABLES_FOR_CONSUMER]", len(found_vtables), ";", ",".join(map(hex, found_vtables)))
