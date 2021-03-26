import hashlib
import json
import os
import subprocess

import networkx as nx
import sys
from androguard.misc import AnalyzeAPK
from tqdm import tqdm

from app_component import AppComponent
from utils import get_native_methods

LOADLIB_TARGET = 'Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V'

#####

args = sys.argv[1:]
# input directory with APK samples
input_dir = os.path.abspath(args[0])
# base out dir for results
out_dir = os.path.abspath(args[1])

result_dir = 'calls_data'
graph_dir = 'graph_data'
json_graph_dir = 'json_graph_data'

# file list
sample_list = [f for f in os.listdir(input_dir) if os.path.isfile(os.path.join(input_dir, f))]

pbar = tqdm(sample_list)
for sample in pbar:
    input_file = os.path.join(input_dir, sample)
    hash_chks = hashlib.sha256(open(input_file, 'rb').read()).hexdigest()

    sample_name = sample.replace('.apk', '')

    json_calls_file = os.path.join(out_dir, result_dir, f'{sample_name}.json')
    if os.path.exists(json_calls_file):
        print('Sample already analysed. Skipped.')
        continue

    pbar.set_description(f'Processing {input_file}')

    # generate call graph
    # supported formats: gml, gexf, gpickle, graphml, yaml and net
    # todo check again if it is possible to create graphs correctly through
    #  get_call_graph from Androguard's AnalyzeAPK python package
    #  (at the moment the graph is computed twice). If so, the step below can be removed
    graph_out_file = os.path.join(out_dir, graph_dir, f'{sample_name}.gml')
    if not os.path.exists(graph_out_file):
        pbar.set_description('Generating call graph...')
        cg = subprocess.run(['androguard', 'cg', '-o', graph_out_file, input_file],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # read it
    try:
        g = nx.read_gml(graph_out_file)
    except:
        continue  # todo implement file check

    # convert to json
    json_graph_file = os.path.join(out_dir, json_graph_dir, f'{sample_name}.json')
    if not os.path.exists(json_graph_file):
        ser = nx.adjacency_data(g)
        with open(json_graph_file, 'w+') as j_out:
            j_out.write(json.dumps(ser))

    # analyse apk
    pbar.set_description('Analysing apk...')
    a, _, dx = AnalyzeAPK(input_file)  # <- the graph can be generated from dx, potentially

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

    pbar.set_description('Looking for paths...')
    paths = {}

    inner_pbar = tqdm(targets)
    for t in inner_pbar:
        inner_pbar.set_description(f'\tTarget: {t}')

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

    final_dict = {'sha256': hash_chks, 'paths': paths}

    pbar.set_description('Writing output...')
    with open(json_calls_file, 'w+') as f_out:
        f_out.write(json.dumps(final_dict, indent=4))

    # todo implement cleaner json:
    #  - source component only
    #  - no repeated target in each path
    #  - formatted class names
