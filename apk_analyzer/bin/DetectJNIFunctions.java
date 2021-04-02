//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.util.headless.HeadlessScript;

import java.util.ArrayList;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

public class DetectJNIFunctions extends HeadlessScript {

	private int bits = 0;
	private boolean is_little_endian = true;
	Long max_addr = 0L;
	private AddressSpace as = null;
	private Memory memory = null;

	private boolean isAsciiPrintable(char c) {
		return c >= 32 && c <= 126;
	}

	private Address readAddr(Address addr) {
		byte[] raw_data = new byte[bits / 8];
		try {
			memory.getBytes(addr, raw_data, 0, bits / 8);
		} catch (MemoryAccessException e) {
			return null;
		}

		Long res = 0L;
		for (int i = 0; i < bits / 8; ++i) {
			Long off = (long) raw_data[i] & 0xff;
			if (is_little_endian)
				off = off << (i * 8);
			else
				off = off << ((bits / 8 - i - 1) * 8);

			res |= off;
		}
		if (Long.compareUnsigned(res, max_addr) > 0) {
			return null;
		}

		return as.getAddress(res);
	}

	private String readString(Address addr) {
		String res = "";

		int i = 0;
		while (true) {
			if (i > 100)
				return null;

			char b = 128;
			try {
				b = (char) memory.getByte(addr.add(i));
			} catch (MemoryAccessException e) {
				return null;
			} catch (AddressOutOfBoundsException e) {
				return null;
			}
			if (b == 0)
				break;
			if (!isAsciiPrintable(b))
				return null;

			res += b;
			i += 1;
		}
		return res;
	}

	private void printMethodsInSection(MemoryBlock mb) {
		for (int i = 0; i < mb.getSize() - (bits / 8) * 3; ++i) {
			Address methodNamePtrPtr = mb.getStart().add(i);
			Address methodArgsPtrPtr = mb.getStart().add(i + bits / 8);
			Address methodFuncPtrPtr = mb.getStart().add(i + (bits / 8) * 2);

			Address methodNamePtr = readAddr(methodNamePtrPtr);
			if (methodNamePtr == null) {
				continue;
			}
			Address methodArgsPtr = readAddr(methodArgsPtrPtr);
			if (methodArgsPtr == null) {
				continue;
			}
			Address methodFuncPtr = readAddr(methodFuncPtrPtr);
			if (methodFuncPtr == null) {
				continue;
			}

			// printf("[DEBUG] Processing address: %#x\n\t%#x\n\t%#x\n\t%#x\n", methodNamePtrPtr.getOffset(),
			// 		methodNamePtr.getOffset(), methodArgsPtr.getOffset(), methodFuncPtr.getOffset());

			String methodName = readString(methodNamePtr);
			if (methodName == null) {
				continue;
			}
			String methodArgs = readString(methodArgsPtr);
			if (methodArgs == null || !methodArgs.contains("(") || !methodArgs.contains(")")) {
				continue;
			}
			Function methodFunc = getFunctionAt(methodFuncPtr);
			if (methodFunc == null) {
				continue;
			}

			printf("Method: ??? %s %s @ %#x\n", methodName, methodArgs, methodFuncPtr.getOffset());
		}
	}

/*
https://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/design.html

Table 2-1 Unicode Character Translation
  Escape Sequence      Denotes

  _0XXXX               a Unicode character XXXX.
                       Note that lower case is used
                       to represent non-ASCII
                       Unicode characters, e.g.,
                       _0abcd as opposed to
                       _0ABCD.

  _1                   the character “_”
  _2                   the character “;” in signatures
  _3                   the character “[“ in signatures
*/

	private String demangle(String s) {
        // NOTE _X replaced with $$$X

        while (s.contains("$$$0")) {
            int idx = s.indexOf("$$$0");
            assert (idx != -1);

            String code_str = s.substring(idx+4, idx+8);
            int code_int    = Integer.valueOf(code_str, 16);
            s = s.replace(
                "$$$0" + code_str, Character.toString((char)code_int));
        }

        s = s
            .replace("$$$1", "_")
            .replace("$$$2", ";")
            .replace("$$$3", "[");
        return s;
	}

	private void printMethodsJava() {
	      Listing listing = currentProgram.getListing();
	      FunctionIterator iter_functions = listing.getFunctions(true);
	      while (iter_functions.hasNext() && !monitor.isCancelled()) {
	    	  Function f = iter_functions.next();
	    	  String name = f.getName();
	    	  if (name.startsWith("Java_")) {
                  name = name
                    .replace("_0", "$$$0")
                    .replace("_1", "$$$1")
                    .replace("_2", "$$$2")
                    .replace("_3", "$$$3");
	    		  String[] tokens = name.split("_");
	    		  String methodName = tokens[tokens.length-1];
	    		  String className = "";
	    		  for (int i=1; i<tokens.length-1; ++i) {
	    			  className += tokens[i];
	    			  if (i < tokens.length-2)
	    				  className += ".";
	    		  }
                  methodName = demangle(methodName);
                  className  = demangle(className);
	    		  printf("Method: %s %s ??? @ %#x\n", className, methodName, f.getEntryPoint().getOffset());
	    	  }
	      }
	}

	public void run() throws Exception {
		Language arch = currentProgram.getLanguage();
		as = arch.getDefaultSpace();
		bits = arch.getDefaultSpace().getSize();
		is_little_endian = !arch.isBigEndian();
		max_addr = (2L << (bits - 1)) - 1;

		printf("[DEBUG] bits: %d, is_little_endian: %s, max_addr: %#x\n", bits, is_little_endian, max_addr);

		memory = currentProgram.getMemory();
		MemoryBlock[] sections = memory.getBlocks();
		ArrayList<MemoryBlock> data_sections = new ArrayList<>();
		for (MemoryBlock mb : sections) {
			if (mb.getName().contains(".data"))
				data_sections.add(mb);
		}

		for (MemoryBlock mb : data_sections) {
			printf("[DEBUG] Found \"%s\" section: %#x - %#x\n", mb.getName(), mb.getStart().getOffset(),
					mb.getStart().getOffset() + mb.getSize());
			printMethodsInSection(mb);
		}
		printMethodsJava();
	}
}
