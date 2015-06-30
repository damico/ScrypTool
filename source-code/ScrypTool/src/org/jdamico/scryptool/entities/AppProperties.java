package org.jdamico.scryptool.entities;

public class AppProperties {
	
	
	private String libPath = null;
	private String verbose = null;
	private String log = null;

	public static final String[] KEY_NAMES = new String[]{"libpath", "verbose", "log"};
	
	public AppProperties(String libPath, String verbose, String log) {
		super();
		this.libPath = libPath;
		this.verbose = verbose;
		this.log = log;
	}

	public String getLibPath() {
		return libPath;
	}

	public void setLibPath(String libPath) {
		this.libPath = libPath;
	}

	public String getVerbose() {
		return verbose;
	}

	public void setVerbose(String verbose) {
		this.verbose = verbose;
	}

	public String getLog() {
		return log;
	}

	public void setLog(String log) {
		this.log = log;
	}


}
