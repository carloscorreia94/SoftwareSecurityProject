import java.util.List;

public class Main {
	

	public static void main(String[] args) {
		System.out.println("=== XDEBUG OUTPUT SIMPLE ANALYZER === ");
		if(args.length == 0) {
			System.out.println(Messages.MISSING_ARGUMENTS);
			return;
		}
		if(args[0].equals("-help")) {
			System.out.println(Messages.HELP_MESSAGE);
			return;
		}
		
		
		if (args.length != 3) {
			System.out.println(Messages.MISSING_ARGUMENTS);
			return;
		}
		
		if(!args[2].equals("false") && !args[2].equals("true")) {
			System.out.println(Messages.INVALID_FLOW_ARG);
			return;
		}
		
		
		Config config = new Config(args[0]);
		List<Pattern> patterns = config.getPatterns();

		if(!config.checkStatus()) {
			System.out.println(Messages.EXCEPTION_CONFIG_FILE);
        	return;
		}
		
		System.out.println("\n@@ PATTERNS INFO @@\n");
		for(int i=0;i<patterns.size();i++) {
			System.out.println("__Pattern NR " + i + "__");
			System.out.println(patterns.get(i));
			System.out.println();
		}
		
		System.out.println("\n@@ END PATTERNS INFO @@\n@@ BEGIN VULNERABILITES INFO @@\n");

		Analyzer.readFile(args[1]);
		Analyzer.dataFlow(args[2]);
		if(!Analyzer.checkStatus()) {
			System.out.println(Messages.EXCEPTION_DEBUG_FILE);
        	return;
		}
		
		for(Pattern p : patterns) {
			Analyzer analyzer = new Analyzer(p);
			if(!analyzer.toString().isEmpty())
				System.out.println(analyzer);
		}
		
		System.out.println("\n@@ END VULNERABILITES INFO @@");
	}

}