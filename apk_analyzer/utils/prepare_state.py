import claripy
from .jni_stubs.jni_type.jni_native_interface import JNINativeInterface
from .jni_stubs.java_type import get_type, get_type_size

def prepare_initial_state(proj, arguments):
    """
    Prepare initial state for CFGAccurate.
    :param str arguments: Arguments (with taint flags) need to put to the state.
    :return: Initial state and arguments summary
    :rtype: angr.sim_type.SimState and dict
    """
    # JNI signature arguments
    arguments = arguments.replace('.', '/').split(',')
    # arguments = arguments.split(',')
    if len(arguments) == 1 and arguments[0] == '':
        arguments = list()

    if len(arguments) > 15:
        raise ValueError("Param num is limited to 15 for armel.")

    state = proj.factory.blank_state(mode="fastpath")
    state.regs.r0 = claripy.BVV(JNINativeInterface(proj, None).ptr,
                                proj.arch.bits)
    # state.regs.r1 = claripy.BVV(JObject(self._project).ptr, self._project.arch.bits)
    i = 1

    arguments_summary = dict()
    arguments_native = list()
    for idx, argument_type in enumerate(arguments):
        argument_name = 'arg' + str(idx)
        if argument_type == 'long' or argument_type == 'double':
            argument_type_l = argument_type + '_l'
            argument_name_l = argument_name + '_l'
            argument_type_h = argument_type + '_h'
            argument_name_h = argument_name + '_h'
            arguments_native.append([argument_name_l, argument_type_l])
            arguments_native.append([argument_name_h, argument_type_h])
        else:
            arguments_native.append([argument_name, argument_type])
    # In armel arch, arguments are stored in two parts, registers and stack.
    reg_args = list()
    stack_args = list()
    for index, argument in enumerate(arguments_native):
        if index < 3:
            reg_args.append(argument)
        else:
            stack_args.append(argument)

    for idx, argument in enumerate(reg_args):
        argument_name = argument[0]
        argument_type = argument[1]
        typ      = get_type(proj, argument_type.replace('/', '.'))
        typ_size = get_type_size(proj, argument_type)
        data     = claripy.BVV(typ.ptr, typ_size)
        state.regs.__setattr__('r%d' % (idx + i), data)
        # store the argument summary
        arguments_summary[argument_name] = data

    for idx, argument in enumerate(reversed(stack_args)):
        argument_name = argument[0]
        argument_type = argument[1]
        typ = get_type(proj, argument_type.replace('/', '.'))
        typ_size = get_type_size(proj, argument_type)
        data = claripy.BVV(typ.ptr, proj.arch.bits)
        state.stack_push(data)
        # store the argument summary
        arguments_summary[argument_name] = data

    return state
