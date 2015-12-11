import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Config {

	private boolean status;
	private List<String> configs;

	public Config(String fileName) {
		this.status = true;

		try {
			FileReader fileReader = new FileReader(fileName);
			BufferedReader bufferedReader = new BufferedReader(fileReader);
			configs = new ArrayList<String>();
			String line = null;

			while((line = bufferedReader.readLine()) != null) {
				if(!line.isEmpty() && !(line.split(" ").length<1))
					configs.add(line);
			}   

			bufferedReader.close();
			double s = ((double) configs.size())/4;
			if((s % 1)!=0) {
				status = false; 
				System.out.println("ERROR: Invalid Config File Format (Lines number) ");
			}
		}
		catch(FileNotFoundException ex) {
			System.out.println(
					"ERROR: Unable to open file '" + fileName + "'");
			status = false;
		}
		catch(IOException ex) {
			System.out.println(
					"ERROR: Reading file '"    + fileName + "'");                  
			status = false;
		}
	}

	public boolean checkStatus() {
		return status;
	}

	public List<Pattern> getPatterns() {
		List<Pattern> pList = new ArrayList<>();

		for(int i=0;i<configs.size();i+=4) {

			Pattern temp = new Pattern(configs.get(i));
			String[] entryPoints = configs.get(i+1).split(",");
			String[] sanitizeFuncs = configs.get(i+2).split(",");
			String[] sensitiveSinks = configs.get(i+3).split(",");

			if(entryPoints.length==0 || sanitizeFuncs.length==0 || sensitiveSinks.length==0) {
				System.out.println("ERROR: Invalid Pattern Element Format (0 zero entry points, sanitizeFuncs, or SensitiveSinks) ");
				status = false;
				continue;
			}

			List<String> entryPointsList = new ArrayList<String>(Arrays.asList(entryPoints));
			temp.setEntryPoints(entryPointsList);

			List<String> sanitizeFuncsList = new ArrayList<String>(Arrays.asList(sanitizeFuncs));
			temp.setSanitizeFuncs(sanitizeFuncsList);

			List<String> sensitiveSinksList = new ArrayList<String>(Arrays.asList(sensitiveSinks));
			temp.setSensitiveSinks(sensitiveSinksList);

			pList.add(temp);
		}

		if(pList.size()==0) {
			status = false;
			System.out.println("ERROR: No Pattern Vulnerabilities were added");
			return null;
		}


		return pList;
	}


}