from networkx.classes.reportviews import NodeView

from . import reformat_comp, find_nodes_from_class


class AppComponent:
    """
    Small convenience class for some component's attributes and methods
    """

    def __init__(self, name, vals):
        self.name = name
        self.vals = [reformat_comp(v) for v in vals]

    def get_sources(self, graph_nodes: NodeView):
        """
        Get nodes associated with the components. These will represent the starting points within paths

        :param graph_nodes:
        :return:
        """
        tmp = [find_nodes_from_class(v, graph_nodes) for v in self.vals]
        return list(set([item for sublist in tmp for item in sublist]))
