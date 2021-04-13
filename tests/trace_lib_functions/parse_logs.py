import yaml
import sys
import os


def usage():
    sys.stderr.write(f"{sys.argv[0]} <yaml> <frida-log> <android-paths-log>\n")
    exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()

    yaml_file         = sys.argv[1]
    log_frida         = sys.argv[2]
    log_android_paths = sys.argv[3]

    with open(yaml_file, "r") as fin:
        vulns = yaml.load(fin, Loader=yaml.FullLoader)

    targets = set()
    for lib in vulns["libs"]:
        for off in lib["offsets"]:
            targets.add(off + 0x400000)

    frida_functions         = set()
    android_paths_functions = set()
    with open(log_frida, "r") as fin:
        for line in fin:
            if line.startswith(" - "):
                start_i = line.find("[") + 1
                end_i   = line.find("]")
                faddr   = line[start_i:end_i]
                faddr   = int(faddr, 16) + 0x400000

                if faddr not in targets:
                    continue
                frida_functions.add(faddr)

    with open(log_android_paths, "r") as fin:
        lines = fin.readlines()
        for i in range(len(lines)):
            line = lines[i]
            if "path found" in line:
                prev_line = lines[i-1]

                start_i = prev_line.find("checking path to ") + len("checking path to ")
                end_i   = prev_line.find(" @ ")
                faddr   = prev_line[start_i:end_i]
                faddr   = int(faddr, 16)

                assert faddr in targets
                android_paths_functions.add(faddr)

    print("Functions found by frida:   ", len(frida_functions))
    print("Functions found statically: ", len(android_paths_functions))
    print()
    print("Functions found only by frida:   ", len(frida_functions - android_paths_functions))
    print("Functions found only statically: ", len(android_paths_functions - frida_functions))

    input()
    for el in frida_functions - android_paths_functions:
        print(hex(el - 0x400000))
