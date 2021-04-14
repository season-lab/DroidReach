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

    skipped = 0

    frida_functions         = set()
    android_paths_functions = set()
    with open(log_frida, "r") as fin:
        lines = fin.readlines()
    for i in range(len(lines)):
        line = lines[i]
        if line.startswith(" - "):
            # Skip if string in backtrace
            blacklisted_entries = []
                # "0x2c8407",
                # "0x2c831a",
                # "_ZN14CPDF_DIBSource13LoadJpxBitmapEv+0xa0",
                # "_ZN24CPDF_StreamContentParser10OnOperatorEPKc+0xe2",
                # "_ZN11CPDF_Parser10StartParseEP12IFX_FileReadii+0x157",
                # "_ZN19CFX_AndroidFontInfo4InitEP12IFPF_FontMgr+0x2c",
                # "_ZN16CFX_RenderDevice15SetDeviceDriverEP22IFX_RenderDeviceDriver+0x40",
                # "_ZN16CPDF_CharPosList4LoadEiPjPfP9CPDF_Fontf+0xe3",
                # "_ZN14CPDF_DIBSource13LoadJpxBitmapEv+0x35b",
                # "0x2c8afd",
                # "_ZN16CFX_RenderDevice8DrawPathEPK12CFX_PathDataPK10CFX_MatrixPK18CFX_GraphStateDatajjiiPvi+0x706",
                # "_Z24FPDFAPI_FlateOrLZWDecodeiPKhjP15CPDF_DictionaryjRPhRj+0x1f0",
                # "_ZN14CStretchEngine11StretchVertEv+0xfea",
                # "_ZN16CFX_RenderDevice12SetClip_RectEPK7FX_RECT+0x8c",
                # "_ZN20CPDF_ImageCacheEntry23ContinueGetCachedBitmapEv+0x71",
                # "_ZN16CFX_RenderDevice11StartDIBitsEPK13CFX_DIBSourceijPK10CFX_MatrixjRPviS6_i+0x65",
                # "_ZNK13CFX_DIBSource5CloneEPK7FX_RECT+0x55c",
                # "_ZN16CFX_RenderDevice14DrawNormalTextEiPK14FXTEXT_CHARPOSP8CFX_FontP13CFX_FontCachefPK10CFX_MatrixjjiPv+0xa7",
                # "_ZN16CFX_RenderDevice9SaveStateEv+0x24",
                # "_ZN17CPDF_RenderStatus20ContinueSingleObjectEPK15CPDF_PageObjectPK10CFX_MatrixP9IFX_Pause+0x266",
                # "_ZN9CPDF_PageD2Ev+0x40",
                # "_ZN11CPDF_Parser10StartParseEP12IFX_FileReadii+0x7c",
                # "_ZN14CRenderContextD1Ev+0x57",
                # "_ZN16CFX_RenderDevice9GetDIBitsEP12CFX_DIBitmapiiPv+0x54",
                # "_ZN16CFX_RenderDevice14ContinueDIBitsEPvP9IFX_Pause+0x33",
                # "_ZN15CPDF_ColorSpace10GetStockCSEi+0x2e",
                # "_ZN16CFX_RenderDevice8FillRectEPK7FX_RECTjiPvi+0x53",
                # "_ZN12CFX_GEModule12InitPlatformEv+0x2e",
                # "_ZN17CPDF_RenderStatus20ContinueSingleObjectEPK15CPDF_PageObjectPK10CFX_MatrixP9IFX_Pause+0x1c4",
                # "_ZN16CFX_RenderDevice15SetDeviceDriverEP22IFX_RenderDeviceDriver+0xad",
                # "_ZN13CPDF_DocumentC2EP11CPDF_Parser+0xb4",
                # "_ZN16CFX_RenderDevice12RestoreStateEi+0x2c",
                # "_ZN16CFX_RenderDeviceD2Ev+0x33",
                # "_ZN16CPDF_CharPosList4LoadEiPjPfP9CPDF_Fontf+0x10b",
                # "_ZN14CRenderContextD1Ev+0x80",
                # "_ZN16CFX_RenderDevice9SetDIBitsEPK13CFX_DIBSourceiiiPv+0x424" ]
            to_skip = False
            j = 0
            next_line = line.strip()
            while next_line != "":
                for b in blacklisted_entries:
                    if b in next_line:
                        to_skip = True
                        skipped += 1
                        break
                if to_skip:
                    break
                j += 1
                if i+j >= len(lines):
                    break
                next_line = lines[i+j].strip()
            if to_skip:
                continue
            # **************************

            start_i = line.find("[") + 1
            end_i   = line.find("]")
            faddr   = line[start_i:end_i]
            faddr   = int(faddr, 16) + 0x400000

            if faddr not in targets:
                continue
            frida_functions.add(faddr)

    print(skipped)

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
