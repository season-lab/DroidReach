import frida
import time
import sys
import os

SCRIPTDIR = os.path.dirname(os.path.realpath(__file__))
LOGFILE = "/dev/shm/frida-trace.log"

def usage():
    sys.stderr.write(f"USAGE: {sys.argv[0]} <app_name> <lib1> [<lib2> ...]\n")
    exit(1)

def get_messages_from_js(msg, data):
    if msg["type"] == "error":
        print(msg["stack"])
    else:
        print(msg["payload"])

def gen_js_script(libs):
    MODULES_PLACEHOLDER = "$$MODULES$$"

    with open(os.path.join(SCRIPTDIR, "instrument.js"), "r") as fin:
        data = fin.read()

    return data.replace(MODULES_PLACEHOLDER, str(libs))

if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()

    app_name = sys.argv[1]
    libs     = sys.argv[2:]

    device  = frida.get_usb_device()
    # pid     = device.spawn([app_name])
    process = device.attach(app_name)

    script_source = gen_js_script(libs)
    script        = process.create_script(script_source)
    # print(script_source)

    script.on("message", get_messages_from_js)
    script.load()
    # device.resume(pid)

    # Just wait
    while 1:
        try:
            input()
        except EOFError:
            print("getting data from Frida...")
            data = script.exports.modinfo()
            print("writing output data in", LOGFILE, "...")
            with open(LOGFILE, "w") as fout:
                fout.write(data)
            print("done")
            break

    process.detach()
