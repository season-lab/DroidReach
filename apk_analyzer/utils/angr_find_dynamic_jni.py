import logging
import claripy
import angr
import sys

from .jni_stubs.jni_type.jni_native_interface import RegisterNatives
from .jni_stubs.jni_type.jni_invoke_interface import JNIInvokeInterface
from .jni_stubs.jni_type.jni_native_interface import NativeDroidSimProcedure
from .timeout_decorator import timeout

__author__ = "Xingwei Lin"
__copyright__ = "Copyright 2018, The Argus-SAF Project"
__license__ = "Apache v2.0"

nativedroid_logger = logging.getLogger('RegisterNativeMethods')
nativedroid_logger.setLevel(logging.INFO)


class AnalysisCenter(object):
    """
    This class is used to hold nativedroid analysis related util classes.

    :param str signature: method signature
    :param JNSafClient jnsaf_client: JNSaf client
    :param SourceAndSinkManager ssm:
    """
    def __init__(self, signature, jnsaf_client, ssm):
        self._signature = signature
        self._jnsaf_client = jnsaf_client
        self._ssm = ssm
        self._dynamic_register_map = dict()

    def get_signature(self):
        return self._signature

    def get_jnsaf_client(self):
        return self._jnsaf_client

    def get_source_sink_manager(self):
        return self._ssm

    def get_dynamic_register_map(self):
        return self._dynamic_register_map

def to_dot_icfg(g):
    # Debug function
    header  = "digraph {\n\tnode [shape=box];\n"
    header += "\tgraph [fontname = \"monospace\"];\n"
    header += "\tnode  [fontname = \"monospace\"];\n"
    header += "\tedge  [fontname = \"monospace\"];\n"
    footer  = "}\n"

    body = ""
    for node in g.nodes:
        addr  = node.addr
        label = ""
        if node.block is None:
            print("block for addr " + hex(addr) + " is None!")
            continue

        for insn in node.block.disassembly.insns:
            label += str(insn) + "\l"

        body += "\t\"" + hex(addr) + "\" [label = \"" + label + "\"];\n"

    for src, dst in g.edges:
        body += "\t\"" + hex(src.addr) + "\" -> \"" + hex(dst.addr) + "\";\n"

    return header + body + footer

def dynamic_register_resolve(project, analysis_center):
    """
    Resolve the dynamic register process and get the native methods mapping
    :param analysis_center: Analysis Center
    :param project: Angr project
    :return: dynamic_register_methods_dict: native methods mapping information
    """
    jni_on_load_symb = project.loader.main_object.get_symbol('JNI_OnLoad')
    if jni_on_load_symb is None:
        nativedroid_logger.info("JNI_OnLoad method not found.")
        return dict()
    else:
        nativedroid_logger.info('Dynamic register resolution begins on %s.' % project.loader.main_object.binary)
        state = project.factory.blank_state(addr=jni_on_load_symb.rebased_addr)
        java_vm = JNIInvokeInterface(project, analysis_center)
        state.regs.r0 = claripy.BVV(java_vm.ptr, project.arch.bits)
        if 'jniRegisterNativeMethods' in project.loader.main_object.imports or \
                '_ZN7android14AndroidRuntime21registerNativeMethodsEP7_JNIEnvPKcPK15JNINativeMethodi' in \
                project.loader.main_object.imports:
            project.hook_symbol('jniRegisterNativeMethods', RegisterNatives(analysis_center), replace=True)

        cfg = project.analyses.CFGEmulated(fail_fast=True, initial_state=state, starts=[jni_on_load_symb.rebased_addr],
                                     context_sensitivity_level=3, enable_function_hints=False, keep_state=True,
                                     enable_advanced_backward_slicing=False, enable_symbolic_back_traversal=False,
                                     normalize=True, iropt_level=1)

        if False:
            dot_str = to_dot_icfg(cfg.graph)
            with open("/dev/shm/g.dot", "w") as fout:
                fout.write(dot_str)
            import os; os.system("xdot /dev/shm/g.dot")

        return analysis_center.get_dynamic_register_map()

@timeout(seconds=900)
def find_jni_functions_angr(binary, auto_load_libs=False):
    # angr, shut the fuck up
    angr_logger = logging.getLogger('angr')
    angr_logger.propagate = False
    cle_logger  = logging.getLogger('cle')
    cle_logger.propagate = False
    nativedroid_logger = logging.getLogger('nativedroid')
    nativedroid_logger.propagate = False

    analysis_center = AnalysisCenter("", None, None)
    project = angr.Project(binary, auto_load_libs=auto_load_libs)

    tmp = dynamic_register_resolve(project, analysis_center)

    res = list()
    for name, addr in tmp.items():
        class_name, method_name, args = name.split(":")
        res.append((class_name, method_name, args, addr))

    return res
