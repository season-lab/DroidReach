# DroidReach

Framework for testing the reachability of native functions in Android applications.

### Installation

DroidReach can be installed using docker.
From the `docker` subdirectory of this repository:

``` bash
$ ./build_docker.sh
[...]
$ ./run_docker.sh
```

After starting the docker container for the first time, execute (within the container):
```
$ dreach_install_plugins.sh
```
The scripts will compile and install the rizin __JNI finder plugin__ and a Java demangler.

### How to Use

The `dreach` binary is the entry point of the tool. It takes the following command line arguments:

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

You can start using the tool running it on our __microbenchmarks__:
```
$ cd /home/ubuntu/droidreach/benchmarks/apks
$ ./run.sh
[...]
```