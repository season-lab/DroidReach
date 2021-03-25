import os
import rzpipe
import tempfile

from collections import namedtuple
FunctionDescription = namedtuple("FunctionDescription", ["name", "offset"])
JniFunctionDescription = namedtuple("JniFunctionDescription", ["class_name", "method_name", "offset"])

class NativeLibAnalyzer(object):
    def __init__(self, native_name, native_raw):
        self.name = native_name
        self.native_raw = native_raw
        self.functions = None
        self.jni_functions = None

    def get_functions(self):
        if self.functions is not None:
            return self.functions

        with tempfile.TemporaryDirectory() as tmpdirname:
            native_f = open(os.path.join(tmpdirname, self.name), "wb")
            native_f.write(self.native_raw)

            rz = rzpipe.open(native_f.name, flags=['-2'])
            rz.cmd("aa")
            self.functions = list(map(
                lambda x: FunctionDescription(
                    name=x["name"], offset=int(x["offset"])),
                rz.cmdj("aflj")))

            rz.quit()
            native_f.close()

        return self.functions

    def get_jni_functions(self):
        if self.jni_functions is not None:
            return self.jni_functions

        self.get_functions()
        self.jni_functions = list()
        for f, off in self.get_functions():
            f = f.replace("sym.", "")
            if f.startswith("Java_"):
                # What if the method name has underscore?
                method_name = f.split("_")[-1]
                class_name = ".".join(f.replace("Java_", "").split("_")[:-1])
            if "JNIEnv" in f:
                method_name = f.split("__JNIEnv__")[0].split(".")[-1]
                class_name  = ".".join(f.split("__JNIEnv__")[0].split(".")[:-1])
            else:
                continue

            self.jni_functions.append(
                JniFunctionDescription(
                    class_name=class_name,
                    method_name=method_name,
                    offset=off
                )
            )
        return self.jni_functions
