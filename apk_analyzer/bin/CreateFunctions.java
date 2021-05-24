import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class CreateFunctions extends GhidraScript {

	private void createIfMissing(Address addr) {
		Function f = getFunctionAt(addr);
		if (f == null)
			createFunction(addr, null);
	}

	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length == 0) {
			System.err.println("Missing filename");
			return;
		}

		AddressSpace as = currentProgram.getLanguage().getDefaultSpace();

		String path = args[0];
		BufferedReader reader;
		try {
			reader = new BufferedReader(new FileReader(path));
			String line = reader.readLine();
			while (line != null) {
				Long addr = Long.parseLong(line.strip().substring(2), 16);
				createIfMissing(as.getAddress(addr));

				// read next line
				line = reader.readLine();
			}
			reader.close();
		} catch (IOException e) {
			System.err.println(path + " is not a valid filename");
		}
	}
}
