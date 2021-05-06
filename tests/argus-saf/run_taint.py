import os

from nativedroid.analyses.nativedroid_analysis import gen_summary
from nativedroid.jawa.utils import *

SCRIPTDIR = os.path.realpath(os.path.dirname(__file__))

NATIVELEAK_PATH    = os.path.join(SCRIPTDIR, "nativeleak/libleak.so")
LIBAVIARY_ARM_PATH = os.path.join(SCRIPTDIR, "libaviary/libaviary_native.so")
LIBJNIPDFIUM_PATH  = os.path.join(SCRIPTDIR, "libpdfium/libjniPdfium.so")
NATIVE_SS_FILE     = os.path.join(SCRIPTDIR, "/tmp/nativeSs.txt")
JAVA_SS_FILE       = os.path.join(SCRIPTDIR, "javaSs.txt")

def mkSink(sinks):
    data = ""
    for sink in sinks:
        data += "%s -> _SINK_\n" % sink

    with open("/tmp/nativeSs.txt", "w") as fout:
        fout.write(data)

def run_nativedroid(so_path, addr, signature, args):
    jnsaf_client = None
    taint_analysis_report, safsu_report, total_instructions = gen_summary (
        jnsaf_client, so_path, addr, signature, args, NATIVE_SS_FILE, JAVA_SS_FILE)
    return taint_analysis_report

if __name__ == "__main__":
    # *** nativeleak ***
    signature = "Lorg/arguslab/native_leak/MainActivity;.send:(Ljava/lang/String;)V"
    arguments = "org.arguslab.native_leak.MainActivity,java.lang.String"
    address   = "Java_org_arguslab_native_1leak_MainActivity_send"

    mkSink(["__android_log_print"])
    print run_nativedroid(NATIVELEAK_PATH, address, signature, arguments)
    # "Lorg/arguslab/native_leak/MainActivity;.send:(Ljava/lang/String;)V -> _SINK_ 1"


    # *** libaviary ***
    signature = "Lcom/aviary/android/feather/headless/filters/NativeToolFilter;.nativeCtor:(Ljava/lang/String;)J"
    arguments = "com.aviary.android.feather.headless.filters.NativeToolFilter,android.content.Context,java.lang.String"
    address   = long(0x834b0)

    mkSink(["strcmp"])
    print run_nativedroid(LIBAVIARY_ARM_PATH, address, signature, arguments)
    # "Lcom/aviary/android/feather/headless/filters/NativeToolFilter;.nativeCtor:(Ljava/lang/String;)J -> _SINK_ 1"

    mkSink(["_ZN3moa12MoaJavaToolsC1E11MoaToolType"])
    print run_nativedroid(LIBAVIARY_ARM_PATH, address, signature, arguments)
    # ""

    # *** libjniPdfium ***
    signature = "Lcom/shockwave/pdfium/PdfiumCore;->nativeLoadPages(JII)[J"
    arguments = "com/shockwave/pdfium/PdfiumCore,android.content.Context,long,int,int"
    address   = long(0x3a74)

    mkSink(["FPDF_LoadPage"])
    print run_nativedroid(LIBJNIPDFIUM_PATH, address, signature, arguments)
    # ""
