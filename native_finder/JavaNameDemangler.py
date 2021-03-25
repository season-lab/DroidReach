import os
import logging
import subprocess

PATHNAME = os.path.dirname(os.path.abspath(__file__))
LIB_PATH = os.path.join(PATHNAME, "bin")
JAVADEMANGLER_CMD = "java @@ -cp @@ {lib_path}/asm-9.0.jar:{lib_path} @@ JavaDemangler @@ {method_class} @@ {method_name} @@ {method_args}"


class JavaNameDemanglerError(Exception):
    pass


class FailedDemanglingError(JavaNameDemanglerError):
    def __init__(self, class_name, method_name, signature):
        self.message = "failed to demangle:\n\tclass_name\t%s\n\tmethod_name\t%s\n\tsignature\t%s" % \
            (class_name, method_name, signature)
        super().__init__(self.message)


class JavaNameDemangler(object):
    log = logging.getLogger("ptn.JavaNameDemangler")
    log.addHandler(logging.StreamHandler())
    log.setLevel(logging.INFO)

    def __init__(self):
        self.cmd = JAVADEMANGLER_CMD

    def method_signature_demangler(self, class_name, method_name, signature):
        JavaNameDemangler.log.debug("demangling: class_name: {cn}, method_name: {mn}, signature: {s}".format(
            cn=class_name,
            mn=method_name,
            s=signature))

        signature = signature.replace(" ", "")
        try:
            demangled_method_name = subprocess.check_output(
                self.cmd.format(
                    lib_path=LIB_PATH,
                    method_class=class_name,
                    method_name=method_name,
                    method_args=signature).split(" @@ ")
            ).strip().decode("ASCII")
        except subprocess.CalledProcessError:
            raise FailedDemanglingError(class_name, method_name, signature)

        assert demangled_method_name != ""
        return demangled_method_name
