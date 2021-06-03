import claripy
import sys
import os

from apk_analyzer import APKAnalyzer
import cex_src.cex as cex

SHOW_GRAPHS = False

def usage():
    print("USAGE: %s <apk>" % sys.argv[0])
    exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()

    apk_path = sys.argv[1]
    apka     = APKAnalyzer(apk_path)
    angr_emu = cex.CEXProject.pm.get_plugin_by_name("AngrEmulated")

    armv7_libs = apka.get_armv7_libs()

    native_methods = apka.find_native_methods_implementations(lib_whitelist=list(map(lambda lib: lib.libhash, armv7_libs)))

    jlong_as_ptrs = list()
    for native_method in native_methods:
        arg_ids = apka.jlong_as_cpp_obj(native_method)
        if len(arg_ids) > 0:
            jlong_as_ptrs.append(
                (native_method, arg_ids)
            )

    jlong_as_ptrs_with_constructors = list()
    for native_method, arg_ids in jlong_as_ptrs:
        class_name = native_method.class_name
        vtable = None
        for constructor_method in native_methods:
            if constructor_method == native_method:
                continue
            if constructor_method.class_name != class_name:
                continue

            vtable = apka.vtable_from_jlong_ret(constructor_method)
            if vtable is not None:
                break

        if vtable is not None:
            jlong_as_ptrs_with_constructors.append(
                (native_method, arg_ids, vtable)
            )

    for native_method, arg_ids, vtable in jlong_as_ptrs_with_constructors:
        print(native_method, arg_ids, hex(vtable))

        def constructor(proj):
            s   = proj.factory.blank_state()
            obj = s.heap._malloc(4)
            s.memory.store(obj, claripy.BVV(vtable, 4*8), endness=proj.arch.memory_endness)
            s.regs.r2 = obj
            return s

        proj = cex.CEXProject(native_method.libpath, plugins=["Ghidra", "AngrEmulated"])
        angr_emu.set_state_constructor(native_method.offset, constructor)

        cg_with_state = proj.get_callgraph(native_method.offset)

        angr_emu.del_state_constructor(native_method.offset)
        cg_without_state = proj.get_callgraph(native_method.offset)

        print("[CG_DATA] lib %s; off %#x; cg state %d; cg no state %d" % (native_method.libpath, native_method.offset, len(cg_with_state.nodes), len(cg_without_state.nodes)))

        if SHOW_GRAPHS:
            dot_str = cex.to_dot(cg_with_state)
            with open("/dev/shm/graph_state.dot", "w") as fout:
                fout.write(dot_str)
            os.system("xdot /dev/shm/graph_state.dot")

            dot_str = cex.to_dot(cg_without_state)
            with open("/dev/shm/graph_no_state.dot", "w") as fout:
                fout.write(dot_str)
            os.system("xdot /dev/shm/graph_no_state.dot")
