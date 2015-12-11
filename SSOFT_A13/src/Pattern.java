import java.util.List;

public class Pattern {

	private String vulnType;
	private List<String> entryPoints;
	private List<String> sanitizeFuncs;
	private List<String> sensitiveSinks;
	
	
	public Pattern(String vulnType) {
		this.vulnType = vulnType;
	}
	
	
	
	public String getVulnType() {
		return vulnType;
	}
	
	
	public boolean isSanitizeFunc(String func){
		return sanitizeFuncs.contains(func);
	}
	
	public boolean isSensitiveFunc(String func){
		return sensitiveSinks.contains(func);
	}


	public void setEntryPoints(List<String> entryPoints) {
		this.entryPoints = entryPoints;
	}
	
	public void setSanitizeFuncs(List<String> sanitizeFuncs) {
		this.sanitizeFuncs = sanitizeFuncs;
	}

	public void setSensitiveSinks(List<String> sensitiveSinks) {
		this.sensitiveSinks = sensitiveSinks;
	}
	
	public List<String> getSanitizeFuncs() {
		return sanitizeFuncs;
	}
	
	@Override
	public String toString() {
		String temp = "=== Vulnerability Type : " + vulnType.toUpperCase() + "  === \n";
		
		temp += ":: 1.Entry Points: \n ---> ";
		for(String s : entryPoints) {
			temp +=  s + " ";
		}
		temp += "\n";
		
		temp += ":: 2.Sanitize Funcs \n --> ";
		for(String s : sanitizeFuncs) {
			temp +=  s + " ";
		}
		temp += "\n";

		temp += ":: 3.Sensitive Sinks \n --> ";
		for(String s : sensitiveSinks) {
			temp += s + " ";
		}
		temp += "\n";

		return temp;
	}
	
}
