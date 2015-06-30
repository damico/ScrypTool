package org.jdamico.scryptool.commons;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.jdamico.scryptool.entities.AppProperties;



public class ManageProperties {
	
	private ManageProperties(){}
	
	private static ManageProperties INSTANCE = null;
	
	public static ManageProperties getInstance(){
		if(INSTANCE == null) INSTANCE = new ManageProperties();
		return INSTANCE;
	}
	
	public AppProperties getAppProperties(String propertiesFilePath) throws TopLevelException {
		
		AppProperties appProperties = null;
		
		
			appProperties = new AppProperties(getPropertyByName(propertiesFilePath, AppProperties.KEY_NAMES[0]),
					getPropertyByName(propertiesFilePath, AppProperties.KEY_NAMES[1]),
					getPropertyByName(propertiesFilePath, AppProperties.KEY_NAMES[2]));
		
		
		
		
		return appProperties;
		
	}
	
	public String getPropertyByName(String propertiesFilePath, String propertyName) throws TopLevelException{
		
		String propertyValue = null;
		Properties prop = new Properties();
		InputStream inputStream = null;
		try {
			inputStream = new FileInputStream(propertiesFilePath);
			
			if (inputStream != null) {
				prop.load(inputStream);
				propertyValue = prop.getProperty(propertyName);
				if(propertyValue == null || propertyValue.equals("")) throw new TopLevelException(null, "Impossible to read property \""+propertyName+"\" file at: "+propertiesFilePath); 
			}
		} catch (IOException e) {
			throw new TopLevelException(e);
		} finally {
			if(inputStream != null) try {
				inputStream.close();
			} catch (Exception e) {
				throw new TopLevelException(e);
			}
		}
		
		
		
		return propertyValue;
	}

}
