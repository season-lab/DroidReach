import time
import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from apk_analyzer import APKAnalyzer
from cex_src.cex import CEXProject

def usage():
    print("%s <apk_path> <mode {0: pexe, 1: angr}>" % sys.argv[0])
    exit(1)

offsets_per_lib = dict()
processed_libs  = set()
def cache_ghidra_analysis(libpath, off):
    if libpath not in processed_libs:
        processed_libs.add(libpath)
        start = time.time()
        ghidra.define_functions(libpath, offsets_per_lib[libpath])
        proj = CEXProject(libpath, plugins=["Ghidra", "AngrEmulated"])
        proj.get_callgraph(off & 0xfffffffe)
        elapsed = time.time() - start
        print("[GHIDRA_CG] time %f" % elapsed)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()

    apk_path = sys.argv[1]
    mode     = int(sys.argv[2])
    if mode not in {0, 1}:
        usage()

    apka = APKAnalyzer(apk_path)
    use_angr = mode == 1

    armv7_libs = apka.get_armv7_libs()
    arm_hashes = list(map(lambda l: l.libhash, armv7_libs))
    reachable_native_methods = \
        apka.find_native_methods_implementations(lib_whitelist=arm_hashes, reachable=True)

    print("[INFO] %d reachable methods" % len(reachable_native_methods))
    for m in reachable_native_methods:
        if m.libpath not in offsets_per_lib:
            offsets_per_lib[m.libpath] = set()
        offsets_per_lib[m.libpath].add(m.offset)

    ghidra = CEXProject.pm.get_plugin_by_name("Ghidra")
    processed_producers = dict()

    for consumer in reachable_native_methods:
        demangled_name = apka.demangle(consumer.class_name, consumer.method_name, consumer.args_str)
        demangled_args = demangled_name[demangled_name.find("(")+1:demangled_name.find(")")]
        demangled_args = demangled_args.replace(" ", "").split(",")
        if "long" not in demangled_args:
            # Cannot be a consumer since it has not jlong as parameter
            print("[INFO] %s does not have long as argument" % consumer.method_name)
            continue

        # cache CFG
        if not use_angr:
            cache_ghidra_analysis(consumer.libpath, consumer.offset)

        start   = time.time()
        args    = apka.jlong_as_cpp_obj(consumer, use_angr=use_angr)
        elapsed = time.time() - start
        print("[CONSUMER] libpath %s; offset %#x; name %s; args %s; time %f" % (consumer.libpath, consumer.offset, consumer.method_name, str(args), elapsed))

        if len(args) > 0:
            found_vtables = set()
            for producer in apka.methods_jlong_ret_for_class(consumer.class_name, lib_whitelist=arm_hashes):
                if producer in processed_producers:
                    found_vtables |= processed_producers[producer]
                    continue

                if not use_angr:
                    cache_ghidra_analysis(producer.libpath, producer.offset)

                start   = time.time()
                vtable  = apka.vtable_from_jlong_ret(producer, use_angr=use_angr)
                elapsed = time.time() - start
                print("[PRODUCER] libpath %s; offset %#x; name %s; vtable %#x; time %f" % (producer.libpath, producer.offset, producer.method_name, vtable if vtable is not None else -1, elapsed))

                processed_producers[producer] = set()
                if vtable is not None:
                    found_vtables.add(vtable)
                    processed_producers[producer].add(vtable)
                    break

            if len(found_vtables) > 0:
                print("[MAPPING_PRODUCER_CONSUMER] libpath_consumer %s; offset_consumer %#x; name_consumer %s; libpath_producer %s; offset_producer %#x; name_producer %s; n_vtables %d; vtables %s" % \
                    (consumer.libpath, consumer.offset, consumer.method_name, producer.libpath, producer.offset, producer.method_name, len(found_vtables), ",".join(map(hex, found_vtables))))
