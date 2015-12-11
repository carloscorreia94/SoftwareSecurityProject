import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Analyzer {

	private static List<String> lines;

	private static boolean status = true;

	public Pattern pattern;
	public List<String> output;
	public static boolean followsData = false;

	public static void dataFlow(String type) {
		if(type.equals("true"))
			followsData = true;
	}

	public static void readFile(String name) {

		try {
			FileReader fileReader = new FileReader(name);
			BufferedReader bufferedReader = new BufferedReader(fileReader);
			lines = new ArrayList<String>();
			String line = null;

			int counter = 0;
			while((line = bufferedReader.readLine()) != null) {
				if(!line.isEmpty() && !(line.split(" ").length<1) && counter>=3)
					lines.add(line);
				counter++;
			}   

			bufferedReader.close();
		}
		catch(FileNotFoundException ex) {
			System.out.println(
					"ERROR: Unable to open file '" + name + "'");
			status = false;
		}
		catch(IOException ex) {
			System.out.println(
					"ERROR: Reading file '"    + name + "'");                  
			status = false;
		}

	}


	public Analyzer(Pattern p) {
		this.pattern = p;
		output = new ArrayList<>();
		if(!followsData)
			blindAnalyze();
		else 
			flowAnalyze();

	}

	public static boolean checkStatus() {
		return status;
	}

	class Sanitize {
		public String function;
		public String ret;
		public String file;
		public int line;

		@Override
		public String toString() {
			return "Function: " + function + "\n" + "Return: " + ret + "\nFile: " + file + "\nLine: " + line;
		}

	}

	/**
	 * This function only has working guarantees if we're processing SQL INJECTION vulnerabilities
	 */
	public void flowAnalyze() {
		List<Sanitize> list = new ArrayList<>();
		int linescounter=0;
		String[] exceptionXDebug = {"require","require_once","include"};

		try {
			for(String i : lines){

				String[] line = i.split("\\s+"); //Split tabs and white spaces

				//If trace is entering a function
				if(line[2].equals("0")) { 
					String funcName = line[5];


					if(pattern.isSanitizeFunc(funcName)) {
						Sanitize s = new Sanitize();
						s.file = line[7];
						s.function = line[5];
						s.line = Integer.parseInt(line[8]);

						String[] ret = lines.get(linescounter+2).split("\\s+");
						if(ret[2].equals("R"))
							s.ret = ret[3].substring(1, ret[3].length()-1);

						list.add(s);
					}

					if(pattern.isSensitiveFunc(funcName)){
						boolean warning = true;
						if(!list.isEmpty()){
							for(Sanitize san : list){
								if(i.contains(san.ret)){
									/**
									 * For the cases xDebug handles differently, where a string for the argument is added after argument 6
									 */
									String out = "";
									if(!Arrays.asList(exceptionXDebug).contains(funcName)) {
										out = "ALERT: There is probably no vulnerability! \n" +
												"--> File: " + line[7] + " Line: " + line[8] + "\n" +
												"--> Function " + line[5] + "\n" +
												"--> Arguments: ";
										
										int argsNr = Integer.parseInt(line[9]);
										
										//args are splitten differently regarding spaces inside them...
										String[] args = i.split("\'");
										for(int j=0;j<argsNr;j++) {
											out += args[1+2*j] + " ";
										}
										
									} else {
										out = "ALERT: There is probably no vulnerability! \n" +
												"--> File: " + line[8] + " Line: " + line[9] + "\n" +
												"--> Function " + line[5] + "\n" +
												"--> Arguments: "+ line[7];
										
									}
									
									warning = false;
									
							

									out += "\nSanitize Function used: " + san.function + "\n" +
											"--> File: " + san.file +" Line: "+san.line +"\n" +
											"--> Sanitized args: "+ san.ret +"\n";

									output.add(out);
									break;
								}
							}
						}

						if(warning){
							/**
							 * Same thing with the XDebug exception thing...
							 */
							String out = "";
							if(!Arrays.asList(exceptionXDebug).contains(funcName)) { 
								 out = "WARNING: There is probably a vulnerability! \n" +
										"--> File: " + line[7] + " Line: " + line[8] + "\n" +
										"--> Function " + line[5] + "\n" +
										"--> Arguments: ";
								int argsNr = Integer.parseInt(line[9]);
								//args are splitten differently regarding spaces inside them...
								String[] args = i.split("\'");
								for(int j=0;j<argsNr;j++) {
									out += args[1+2*j] + " ";
								}
								
							} else {
								 out = "WARNING: There is probably a vulnerability! \n" +
											"--> File: " + line[8] + " Line: " + line[9] + "\n" +
											"--> Function " + line[5] + "\n" +
											"--> Arguments: " + line[7];
							}

							out += "\nSUGGESTION: Use one of these sanitize functions:\n--> ";
							for(String k : pattern.getSanitizeFuncs())
								out+= k + " ";
							out+= "\n";
							output.add(out);
						} 


					} 
				}
				linescounter++;
			}

		} catch (IndexOutOfBoundsException e) {
			System.out.println("ERROR: Debug File Malformated");
			return;
		} catch (NumberFormatException e) {
			System.out.println("ERROR: Debug File Malformated");
			return;
		}
	}


	public void blindAnalyze() {
		boolean safe = false;
		int safeLine = 0;
		String safeFunc = "";
		String safeFile = "";
		String[] exceptionXDebug = {"require","require_once","include"};

		try {
			for(String i : lines) {

				String[] line = i.split("\\s+"); //Split tabs and white spaces

				//If trace is entering a function
				if(line[2].equals("0")) { 
					String funcName = line[5];


					if(pattern.isSanitizeFunc(funcName)) {
						safe = true;
						safeFunc = funcName;
						safeLine = Integer.parseInt(line[8]);
						safeFile = line[7];

					}

					if(pattern.isSensitiveFunc(funcName))
						if(safe){
							String out = "";
							/**
							 * For the cases xDebug handles differently, where a string for the argument is added after argument 6
							 */
							if(!Arrays.asList(exceptionXDebug).contains(funcName)) { 
								out = "ALERT: There is probably no vulnerability! \n" +
									"--> File: " + line[7] + " Line: " + line[8] + "\n" +
									"--> Function " + line[5] + "\n" +
									"--> Arguments: ";
								int argsNr = Integer.parseInt(line[9]);
								//args are splitten differently regarding spaces inside them...
								String[] args = i.split("\'");
								for(int j=0;j<argsNr;j++) {
									out += args[1+2*j] + " ";
								}
							} else {
								out = "ALERT: There is probably no vulnerability! \n" +
										"--> File: " + line[8] + " Line: " + line[9] + "\n" +
										"--> Function " + line[5] + "\n" +
										"--> Arguments: " + line[7];
							}

							out += "\nSanitize Function used: " + safeFunc + "\n" +
									"--> File: " + safeFile +" Line: "+safeLine +"\n";

							output.add(out);

							safe = false;
							safeLine = 0;
							safeFunc = "";
							safeFile = "";
						}else {
							String out = "";
							/**
							 * Same thing with the XDebug exception thing...
							 */
							if(!Arrays.asList(exceptionXDebug).contains(funcName)) { 
								out = "WARNING: There is probably a vulnerability! \n" +
										"--> File: " + line[7] + " Line: " + line[8] + "\n" +
										"--> Function " + line[5] + "\n" +
										"--> Arguments: ";
								int argsNr = Integer.parseInt(line[9]);
								//args are splitten differently regarding spaces inside them...
								String[] args = i.split("\'");
								for(int j=0;j<argsNr;j++) {
									out += args[1+2*j] + " ";
								}
							} else {
								out = "WARNING: There is probably a vulnerability! \n" +
										"--> File: " + line[8] + " Line: " + line[9] + "\n" +
										"--> Function " + line[5] + "\n" +
										"--> Arguments: " + line[7];
							}

							out += "\nSUGGESTION: Use one of these sanitize functions:\n--> ";
							for(String k : pattern.getSanitizeFuncs())
								out+= k + " ";
							output.add(out);
						}


				}
			}
		} catch (IndexOutOfBoundsException e) {
			System.out.println("ERROR: Debug File Malformated");
			return;
		} catch (NumberFormatException e) {
			System.out.println("ERROR: Debug File Malformated");
			return;
		}
	}

	@Override
	public String toString() {
		String temp = "";
		for(String i: output) {
			temp += i + "\n";
		}
		return temp;
	}
}
