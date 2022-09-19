# Fine-grained analysis: debugging false negatives

| APK (hashes can be found [here](https://github.com/season-lab/DroidReach/blob/main/dataset.csv))                               | Why false negatives? |
|-----------------------------------|-------------|
| com.sec.android.easyMover         | -           |
| com.jb.zcamera                    | -           |
| com.mi.android.globalFileexplorer | One edge is lost due to an indirect jump not resolved by angr. Some edges are lost in angr due to the calldepth. |
| com.space.cleaner.smart.tool      | Some indirect calls are resolved by angr (e.g. `libun7zip.so+0x303c` -> `libun7zip.so+0x633c`). Some destinations are not found by angr due to calldepth. |
| com.soundcloud.android            | Indirect calls not resolved by angr. Angr looses some edges due to the maximum calldepth. |
| video.like                        | Due to nested libs, Ghidra looses some edges. Some indirect jumps are not resolved by angr (e.g., `libfiletransfer.so+0x39606`). |
| com.zentertain.photocollage       | Due to nested libs, Ghidra looses some edges. Ghidra fails in detecting correctly thumb mode in some cases in `libaviary_native2.so`. Some indirect jumps are not resolved by angr (e.g., `libencoders.so+0x26406`). |
| com.picsart.studio                | Angr misses some targets due to calldepth. Ghidra (erroeusly) detects some functions as not returning (e.g., `libpicore.so+0x271360`, losing the (fallthrough) edge `libpicore.so+0x2dd1d8` -> `libpicore.so+0x2dd1da`). |
| shareit.lite                      | Angr misses some targets due to calldepth. Some indirect calls are not resolved (e.g., `libstp.so+0x50238`). |
| com.imangi.templerun              | Due to nested libs, Ghidra looses some edges. Some targets are called through untracked callbacks (e.g., `ASensorManager_createEventQueue, mono_add_internal_call)` and other targets that are indirectly called by Mono/.NET runtime. |
| com.amazon.mp3                    | Due to nested libs, Ghidra looses some edges. Angr resolves some indirect jmps (e.g., `libdmengine.so+0x5e9718` -> `libdmengine.so+0x10054c`). Other indirect jmps are not resolved. |
| com.cam001.selfie                 | Due to nested libs, Ghidra looses some edges. Some targets are not found due to indirect calls not resolved by angr (e.g., `libFacialOutline.so+0x24a88`), some others due to calls through `pthread_once` (support could be added but it still at a very deep calldepth). |
| com.tripadvisor.tripadvisor       | Angr crashes when analyzing one lib (e.g., during the analysis of `libtdm-5.0-91-jni.so+0x405b69`). Some targets are missed due to indirect jmps. |
| com.yodo1.crossyroad              | The application uses a custom pattern for loading some libraries (see `dlopen` and `dlsym` over `libil2cpp.so`). Support for custom loaders could be added to handle these scenarios. |
| com.king.candycrushjellysaga      | Indirect calls through global context initialized by previous calls (jni function is not stateless) |