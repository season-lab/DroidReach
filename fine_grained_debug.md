# Fine-Grained Debug

| hash                                                             | apk                               | debug brief |
|------------------------------------------------------------------|-----------------------------------|-------------|
| 030ACAAD1A0A91FB2F86974B86F3DD795D4DD68F74F7E9204FD8587B1531E26D | com.sec.android.easyMover         | -           |
| 5588A89EBA88B035608E8A62C44647A98E5561EACB66A54ABFF7D90A905185E9 | com.jb.zcamera                    | -           |
| F64F9711387525167433D9583F88B17B2C706208ED56A6FB1675D6757E2BB5C2 | com.mi.android.globalFileexplorer | One edge is lost due to an indirect jmp not resolved by angr. Some edges are lost in angr due to the calldepth. |
| F6966B79BF3492088E5D6536D0C06ED99435D0F066EE14CE59D567C320A066B4 | com.space.cleaner.smart.tool      | Some indirect calls are resolved by angr (e.g. libun7zip.so+0x303c -> libun7zip.so+0x633c). Some destinations are not found by angr due to calldepth. |
| 323E7FF4AA889EEF3322F6520E372393C98585C9334EA03768EFD88028C505C9 | com.soundcloud.android            | Indirect calls not resolved by angr. Angr looses some edges due to the maximum calldepth. |
| 46ACF4B3C819C975A5880373955F604D42FB3B5E6C32E81B5EE5E0B6AE538744 | video.like                        | Due to nested libs, Ghidra looses some edges. Some indirect jmps are not resolved by angr (e.g., libfiletransfer.so+0x39606). |
| 4979F94DBA7A59774D0D0C76959C01281F9429A17E0E3B10C303B8D44F3D0F43 | com.zentertain.photocollage       | Due to nested libs, Ghidra looses some edges. Ghidra fails in detecting correctly thumb mode in some cases in libaviary_native2.so. Some indirect jmps are not resolved by angr (e.g., libencoders.so+0x26406). |
| 5D7B7E84C6BCCE6F9796F27D1FEDCF51CEE629F542A41972D9F59D782D059704 | com.picsart.studio                | Angr misses some targets due to calldepth. Ghidra (erroeusly) detects some functions as not returning (e.g., libpicore.so+0x271360, losing the (fallthrough) edge libpicore.so+0x2dd1d8 -> libpicore.so+0x2dd1da). |
| 7BDFD305F55791031BBC1D5B6D1520A34FDD28E5459AF34742EF55ED328297B2 | shareit.lite                      | Angr misses some targets due to calldepth. Some indirect calls are not resolved (e.g., libstp.so+0x50238). |
| 99BDEC46F5D941BAD74C2BA9993A1D0080C0BF132D25D375EF39712752CFD04E | com.imangi.templerun              | Due to nested libs, Ghidra looses some edges. Some targets are called through callbacks (e.g., ASensorManager_createEventQueue, mono_add_internal_call). |
| D39599A3E26402E352D5B29B69A20170232BAC88289AD13874EA8432A861ABAF | com.amazon.mp3                    | Due to nested libs, Ghidra looses some edges. Angr resolves some indirect jmps (e.g., libdmengine.so+0x5e9718 -> libdmengine.so+0x10054c). Other indirect jmps are not resolved. |
| D9CA842E8F60916D30D256721C010DAB5E910E9B83A44F6E18AE500A97592C76 | com.cam001.selfie                 | Due to nested libs, Ghidra looses some edges. Some targets are not found due to indirect calls not resolved by angr (e.g., libFacialOutline.so+0x24a88), some others due to calls through pthread_once (with high calldepth). |
| F0B61C5BA52FEC1EFC059C331E4B4067769B76DFEB377C715374656B931599AF | com.tripadvisor.tripadvisor       | Angr crashes when analyzing the lib (e.g., during the analysis of libtdm-5.0-91-jni.so+0x405b69). Some targets are missed due to indirect jmps. |
| 1AD8BED1353B36A953C020C1562A519ADCEDA02E4B4E98AFA8EAF0DB87643AFB | com.yodo1.crossyroad              | dlopen + dlsym to load and call functions of a libil2cpp.so. |
| D6DE1A5F16470F56A2AF97008A99CE04D28126373F12AC7CE183252F51C52ED2 | com.king.candycrushjellysaga      | Indirect calls through global context initialized by previous calls (jni function is not stateless) |
