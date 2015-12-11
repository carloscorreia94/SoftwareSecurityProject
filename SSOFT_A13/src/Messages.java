
public final class Messages {

	public static String MISSING_ARGUMENTS = "ERROR: Missing arguments\n" +
											 "Use -help for input details\n";
	
	public static String HELP_MESSAGE = "Usage : <ConfigFile> <DebugFile> <FollowsDataFlow>\n" +
										"FollowsDataFlow -> true/false\n" +
										"(true if you want the Anaylzer to follow arguments in sanitize functions until sensitive sink funcs) \n" +
										"ConfigFile is the configuration file where structure lies in the following format:\n" +
										"LINE 0: Vulnerability Type\n" +
										"LINE 1: Entry points separated by commas\n" +
										"LINE 2: Sanitize Funcs separated by commas\n" +
										"LINE 3: Sensitive Sinks separated\n";
	public static String INVALID_FLOW_ARG = "ERROR: Invalid data flow argument\n" +
											"Use -help for input details\n";
	
	public static String EXCEPTION_CONFIG_FILE = "Exception occured with config File. Fatal Error, Terminating\n";
	
	public static String EXCEPTION_DEBUG_FILE = "Exception occured with debug File. Fatal Error, Terminating\n";
	
}
