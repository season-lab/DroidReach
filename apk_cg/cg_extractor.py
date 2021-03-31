import subprocess
import hashlib
import logging
import json
import os

import networkx as nx
from androguard.misc import AnalyzeAPK

from .app_component import AppComponent
from .utils import get_native_methods

log = logging.getLogger("ap.cg_extractor")

LOADLIB_TARGET = 'Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V'

result_dir = 'calls_data'
graph_dir = 'graph_data'
json_graph_dir = 'json_graph_data'

def find_paths(input_dir, out_dir):
    # file list
    sample_list = [f for f in os.listdir(input_dir) if os.path.isfile(os.path.join(input_dir, f))]
    log.info(f"found {len(sample_list)} samples")

    for sample in sample_list:
        input_file = os.path.join(input_dir, sample)
        hash_chks = hashlib.sha256(open(input_file, 'rb').read()).hexdigest()

        sample_name = sample.replace('.apk', '')
        log.info(f"processing {sample_name}")

        json_calls_file = os.path.join(out_dir, result_dir, f'{sample_name}.json')
        if os.path.exists(json_calls_file):
            print('Sample already analysed. Skipped.')
            continue

        log.info("generating callgraph")

        # generate call graph
        # supported formats: gml, gexf, gpickle, graphml, yaml and net
        # todo check again if it is possible to create graphs correctly through
        #  get_call_graph from Androguard's AnalyzeAPK python package
        #  (at the moment the graph is computed twice). If so, the step below can be removed
        graph_out_file = os.path.join(out_dir, graph_dir, f'{sample_name}.gml')
        if not os.path.exists(graph_out_file):
            cg = subprocess.run(['androguard', 'cg', '-o', graph_out_file, input_file],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log.info(f"callgraph generated in {graph_out_file}")

        # read it
        log.info("reading callgraph")
        try:
            g = nx.read_gml(graph_out_file)
        except:
            log.error("error while reading the callgraph")
            continue  # todo implement file check
        log.info("callgraph read")

        # convert to json
        log.info("converting the graph to json")
        json_graph_file = os.path.join(out_dir, json_graph_dir, f'{sample_name}.json')
        if not os.path.exists(json_graph_file):
            ser = nx.adjacency_data(g)
            with open(json_graph_file, 'w+') as j_out:
                j_out.write(json.dumps(ser))
        log.info(f"graph converted to json in {json_graph_file}")

        # analyse apk
        log.info(f"analyzing the APK {input_file}")
        a, _, dx = AnalyzeAPK(input_file)  # <- the graph can be generated from dx, potentially
        log.info("APK analyzed")

        # get components (activities, providers, receivers, services)
        acts = AppComponent('a', a.get_activities())
        provs = AppComponent('p', a.get_providers())

        recvs = AppComponent('r', a.get_receivers())
        servs = AppComponent('s', a.get_services())

        components = [acts, provs, recvs, servs]

        # get all targets
        native_targets = get_native_methods(dx,
                                            public_only=False)  # by default, "public native" methods are selected
        targets = [LOADLIB_TARGET, *native_targets]
        log.info(f"found {len(targets)} targets")

        paths = {}

        log.info("looking for paths")
        for t in targets:
            path_found = False
            for comp in components:
                # get sources associated with the component
                sources = comp.get_sources(g.nodes)

                for s in sources:
                    # get only one path
                    if s not in g.nodes or t not in g.nodes:
                        continue
                    if nx.has_path(g, source=s, target=t):
                        link = list(nx.shortest_path(g, source=s, target=t))
                        paths[t] = link
                        path_found = True
                        break

                if path_found:
                    # One path per target is enough
                    break

        final_dict = {'sha256': hash_chks, 'paths': paths}
        log.info(f"found {len(paths)} paths")

        pbar.set_description('Writing output...')
        with open(json_calls_file, 'w+') as f_out:
            f_out.write(json.dumps(final_dict, indent=4))
        log.info(f"paths dumped in {json_calls_file}")

        # todo implement cleaner json:
        #  - source component only
        #  - no repeated target in each path
        #  - formatted class names
