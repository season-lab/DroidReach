import org.xmlpull.v1.XmlPullParserException;
import soot.Scene;
import soot.SootMethod;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.toolkits.callgraph.Edge;

import java.io.IOException;
import java.util.Iterator;

import static java.lang.System.exit;

public class Main {
    public static void main(String[] args) throws IOException, XmlPullParserException {
        if (args.length < 2)
            exit(1);

        String platforms_dir = args[0];
        String apk_path = args[1];

        InfoflowAndroidConfiguration config = new InfoflowAndroidConfiguration();
        config.getAnalysisFileConfig().setAndroidPlatformDir(platforms_dir);
        config.getAnalysisFileConfig().setTargetAPKFile(apk_path);
        config.setMergeDexFiles(true);

        SetupApplication analyzer = new SetupApplication(config);
        analyzer.constructCallgraph();

        // Iterate over the callgraph
        System.out.println("{ \"edges\" : [");
        for (Iterator<Edge> edgeIt = Scene.v().getCallGraph().iterator(); edgeIt.hasNext(); ) {
            Edge edge = edgeIt.next();
            SootMethod smSrc = edge.src();
            SootMethod smDest = edge.tgt();
            System.out.print(
                    "    { \"src\": \"" + smSrc.getBytecodeSignature() + "\", " +
                          "\"dst\": \"" + smDest.getBytecodeSignature() + "\" }");
            if (edgeIt.hasNext())
                System.out.println(",");
            else
                System.out.println("");
        }
        System.out.println("  ]\n}");
    }
}
