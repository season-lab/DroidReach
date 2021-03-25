import java.util.Arrays;
import java.util.Iterator;
import java.util.stream.Stream;
import java.lang.reflect.Method;
import org.objectweb.asm.Type;

class JavaDemangler {

	private static<T> Iterable<T> iteratorToIterable(Iterator<T> iterator) {
		return () -> iterator;
	}

	private static void iterateMethodsDbg()
	{
		Method[] methods = JavaDemangler.class.getMethods();
		for (Method m : methods) {
			System.out.println(Type.getMethodDescriptor(m));
		}
	}

	public static void main(String[] args) 
	{
		if (args.length != 3)
			System.exit(1);

		String method_class = args[0];
		String method_name  = args[1];
		String method_args  = args[2];

		String method_class_demangled = Type.getType(method_class).getClassName();

		Type[] m_args = Type.getArgumentTypes(method_args);
		String method_args_demangled = 
			"(" +
			String.join(", ", iteratorToIterable(Arrays.stream(m_args).map(x -> x.getClassName()).iterator())) +
			")";
		String method_rett_demangled = Type.getReturnType(method_args).getClassName();

		System.out.println(method_class_demangled + ": " + method_rett_demangled + " " + method_name + method_args_demangled);
	}
}
