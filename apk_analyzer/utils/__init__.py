import hashlib
import re

from androguard.core.analysis.analysis import Analysis
from networkx.classes.reportviews import NodeView


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
