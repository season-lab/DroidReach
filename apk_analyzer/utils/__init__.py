import hashlib
import re
import io

from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFParseError

from androguard.core.analysis.analysis import Analysis
from networkx.classes.reportviews import NodeView

from .angr_find_dynamic_jni import find_jni_functions_angr
from .prepare_state import prepare_initial_state
from .NativeJLongAnalyzer import NativeJLongAnalyzer
from .timeout_decorator import timeout

def reformat_comp(raw_comp: str):
    """
    Format dot-separated class names into slash-separated ones
    :param raw_comp:
    :return:
    """
    return raw_comp.replace('.', '/')


def find_nodes_from_class(cl: str, nodes: NodeView):
    """
    get nodes in the graph associated with input class
    :param cl:
    :param nodes:
    :return:
    """
    return [str(n) for n in nodes if cl in n.split(';->')[0]]


def get_native_methods(dx: Analysis, public_only: bool = False):
    """
    Get JNI methods
    :param dx:
    :param public_only:
    :return:
    """
    if public_only:
        cg = dx.get_call_graph(accessflags='.*public.*native.*')
    else:
        cg = dx.get_call_graph(accessflags='.*native.*')

    tmp = [str(n) for n in cg.nodes]

    res = list()
    for m in tmp:
        # Filter out nodes that are not native
        access_flag = re.findall(r"\[access_flags=(.*)\]", m)
        assert len(access_flag) == 1
        access_flag = access_flag[0]

        if "native" in access_flag:
            res.append(m)
    return res

def md5_hash(f):
    with open(f,'rb') as f_binary:
        md5 = hashlib.md5(f_binary.read()).hexdigest()
    return md5

def check_malformed_elf(data):
    f = io.BytesIO(data)
    try:
        ELFFile(f)
    except ELFParseError:
        return True
    return False

def check_if_jlong_as_cpp_obj(lib, offset, demangled_args):
    a = NativeJLongAnalyzer(lib)
    return a.check_cpp_obj(offset, demangled_args)

def LCSubStr(X, Y):
    # Create a table to store lengths of
    # longest common suffixes of substrings.
    # Note that LCSuff[i][j] contains the
    # length of longest common suffix of
    # X[0...i-1] and Y[0...j-1]. The first
    # row and first column entries have no
    # logical meaning, they are used only
    # for simplicity of the program.
    m = len(X)
    n = len(Y)
 
    # LCSuff is the table with zero
    # value initially in each cell
    LCSuff = [[0 for k in range(n+1)] for l in range(m+1)]
 
    # To store the length of
    # longest common substring
    result = 0
 
    # Following steps to build
    # LCSuff[m+1][n+1] in bottom up fashion
    for i in range(m + 1):
        for j in range(n + 1):
            if (i == 0 or j == 0):
                LCSuff[i][j] = 0
            elif (X[i-1] == Y[j-1]):
                LCSuff[i][j] = LCSuff[i-1][j-1] + 1
                result = max(result, LCSuff[i][j])
            else:
                LCSuff[i][j] = 0
    return result
