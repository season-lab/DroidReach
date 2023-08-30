# DroidReach

Framework for testing the reachability of native functions in Android applications.

## Repository Description
- `apk_analyzer/`: main analysis classes of DroidReach.
- `benchmarks/`: submodule that points to our microbenchmarks.
- `cex_src/`: submodule that points to our library CEX. It implements the CFG extraction functionalities of DroidReach for the native code.
- `bin/`: contains the `dreach` executable.
- `docker/`: contains the Dockerfile and some scripts to build an image and use it.
- `data/`: contains information about the experimental evaluation described in the paper.

## Installation

DroidReach can be used through docker.
From the `docker` subdirectory of this repository, run the following command to build the `droidreach` image:

``` bash
$ ./build_docker.sh
```

After building the image, you can use the `start_docker.sh` script to start a container with DroidReach installed and ready to use.
Note that the code is _mounted_ inside the container, so modifications to the source code will affect any running container.

The `start_docker.sh` script will also mount the directory `/tmp/dreach` of the host in `~/shared`: you can use this directory to share APKs with the container.

## Usage

The `dreach` executable is the entry point of the tool. It takes the following command line arguments:

``` bash
$ dreach -h

usage: dreach [-h] [--cfg-dot [CFG_DOT]] [--print-native-functions] [--check-consumer [CHECK_CONSUMER]] [--find-producer [FIND_PRODUCER]] [--find-vtable [FIND_VTABLE]] [--reachable] [--use-flowdroid] [--disable-multilib] [--disable-angr]
              [--disable-ghidra] [--ghidra-timeout [sec]] [--angr-timeout [sec]] [--angr-max-memory [sec]] [--angr-max-calldepth [val]] [--angr-ctx-sensitivity [val]] [--angr-bb-iterations [val]] [--all-archs] [--print-full-icfg-path]
              [--find-path-to [libpath.so@offset/name]] [--find-path-to-csv [file.csv]] [--find-path-to-csv2 [file.csv]] [--show-lib-dep-graph] [--verbose] [--save-graphs] [--full-analysis]
              apk

DroidReach APK analyzer

positional arguments:
  apk                   The binary to analyze

optional arguments:
  -h, --help            show this help message and exit
  --cfg-dot [CFG_DOT]   Print the CFG of the function in dot format (either class;->method(args), or lib.so@offset/name)
  --print-native-functions
                        Print native functions
  --check-consumer [CHECK_CONSUMER]
                        Check if the method is a consumer
  --find-producer [FIND_PRODUCER]
                        Look for a producer given a consumer
  --find-vtable [FIND_VTABLE]
                        Find the returned vtable of a producer
  --reachable           Analyze only reachable functions
  --use-flowdroid       Use flowdroid to generate the Java callgraph
  --disable-multilib    Disable the reasoning on multiple libraries
  --disable-angr        Disable Angr plugin
  --disable-ghidra      Disable Ghidra plugin
  --ghidra-timeout [sec]
                        Set timeout for Ghidra on a single binary [seconds] (default 20 min)
  --angr-timeout [sec]  Set timeout for Angr on a iCFG [seconds] (default 30 min)
  --angr-max-memory [sec]
                        Set maximum memory usage for Angr on a iCFG [MiB] (default None)
  --angr-max-calldepth [val]
                        Set maximum calldepth for Angr (default 5)
  --angr-ctx-sensitivity [val]
                        Set context sensitivity for Angr (default 1)
  --angr-bb-iterations [val]
                        Set maximum iterations on a basic block for Angr (default 1)
  --all-archs           Analyze all archs (not only armv7) [Experimental]
  --print-full-icfg-path
                        Print the full path in the iCFG when executing --find-path-*
  --find-path-to [libpath.so@offset/name]
                        Find path to native function
  --find-path-to-csv [file.csv]
                        Find path to the native functions specified in the CSV (lib.so,offset)
  --find-path-to-csv2 [file.csv]
                        Internal use only
  --show-lib-dep-graph  Print the library dependency graph in dot to stdout
  --verbose             Verbose mode
  --save-graphs         Save graphs (debug mode)
  --full-analysis       Run the complete analysis (slow)
```

You can start using the tool running it on our __microbenchmarks__. Insider the docker container, run:
```
$ cd /home/ubuntu/droidreach/benchmarks/apks
$ ./run.sh
[...]
```

#### APIs

DroidReach offers also Python APIs. The main analysis class is `APKAnalyzer` located under the `apk_analyzer` directory.

The CFG extraction functionalities, instead, are implemented in the `CEX` subproject. You can find more information in [its own directory](https://github.com/season-lab/cex).

## Experimental data

* The dataset contains APKs taken from the Google Play Store. The detailed list is available [here](data/dataset.csv).
* A more detailed discussion of the false negatives is available [here](data/results-false-negatives.md).
* A more detailed discussion of the false positives is available [here](data/results-false-positives.csv).
* The benchmark suite discussed in "Microbenchmarks" is available [here](https://github.com/season-lab/DroidReachBenchmarks/tree/master). The repository contains the source code, compiled APKs, and the results of an expermental evaluation when analyzing the benchmarks with different tools.

## Cite

```
@inproceedings{DROIDREACH-ESORICS22,
 author={Borzacchiello, Luca and Coppa, Emilio and Maiorca, Davide and Columbu, Andrea and Demetrescu, Camil and Giacinto, Giorgio},
 title={{Reach Me if You Can: On Native Vulnerability Reachability in Android Apps}},
 booktitle={Proceedings of the 27th European Symposium on Research in Computer Security},
 series={ESORICS '22},
 year={2022},
}
```

## Preprint of the paper

A preprint of the paper is available [here](https://github.com/ecoppa/ecoppa.github.io/raw/master/assets/pdf/droidreach-preprint.pdf).
