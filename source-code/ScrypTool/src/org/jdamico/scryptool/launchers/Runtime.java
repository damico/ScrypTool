package org.jdamico.scryptool.launchers;

import java.io.File;
import java.io.IOException;

import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.RollingFileAppender;
import org.jdamico.scryptool.commons.Constants;
import org.jdamico.scryptool.commons.ManageProperties;
import org.jdamico.scryptool.commons.TopLevelException;
import org.jdamico.scryptool.commons.Utils;
import org.jdamico.scryptool.crypto.PKCS11_Helper;
import org.jdamico.scryptool.entities.AppProperties;

public class Runtime {

	public static AppProperties appProperties = null;
	
	public static void main(String[] args) {


		Logger rootLogger = Logger.getRootLogger();
		rootLogger.setLevel(Level.INFO);
		PatternLayout layout = new PatternLayout("%d{ISO8601} [%t] %-5p %c %x - %m%n");
		rootLogger.addAppender(new ConsoleAppender(layout));
		try {

			RollingFileAppender fileAppender = new RollingFileAppender(layout, Constants.LOG_FILE);
			rootLogger.addAppender(fileAppender);
		} catch (IOException e) {
			System.err.println("Failed to find/access "+Constants.LOG_FILE+" !");
			System.exit(1);
		}


		if(args!=null && args.length > 3){
			String propertiesFilePath = args[0];
			
			try {
				appProperties = ManageProperties.getInstance().getAppProperties(propertiesFilePath);
			} catch (TopLevelException e) {
				System.err.println("********************************************************************************************");
				System.err.println("Unable to find properties file: "+propertiesFilePath);
				System.err.println("********************************************************************************************");
				System.exit(1);
			}

			String scPasswd = args[1];
			String strOperation = args[2];
			int operation = -1;
			try {
				operation = Integer.parseInt(strOperation);
			} catch (NumberFormatException e) {
				System.err.println("The third argument must be an integer (operation type)!");
				System.exit(1);
			}

			String srcFilePath = args[3];

			File srcFile = new File(srcFilePath);

			if(!srcFile.isDirectory() && srcFile.exists()){

				PKCS11_Helper pki = new PKCS11_Helper();

				switch (operation) {
				case 0:
					try {
						pki.signSelectedFile(srcFile, scPasswd, appProperties.getLibPath());
					} catch (TopLevelException e1) {
						Utils.getInstance().handleVerboseLog(appProperties, 'e', e1.getMessage());
						System.exit(1);
					}
					break;

				case 1:
					String signature = null;
					try {
						signature = args[4];
						pki.verifyDocumentSignature(appProperties.getLibPath(), scPasswd, srcFile, signature);
					} catch (IndexOutOfBoundsException e) {
						Utils.getInstance().handleVerboseLog(appProperties, 'e', "The fifth argument must be a b64 string (signature)!");
						System.exit(1);
					} catch (TopLevelException e) {
						
					}
					
					break;
					
				case 2:
					try {
						pki.encryptSelectedFile(srcFile, scPasswd, appProperties.getLibPath());
					} catch (TopLevelException e) {
						Utils.getInstance().handleVerboseLog(appProperties, 'e', e.getMessage());
						System.exit(1);
					}
					break;
					
				case 3:
					try {
						pki.decryptSelectedFile(srcFile, scPasswd, appProperties.getLibPath());
					} catch (TopLevelException e) {
						Utils.getInstance().handleVerboseLog(appProperties, 'e', e.getMessage());
						System.exit(1);
					}
					break;
					
				default:
					break;
				}

			}else{
				System.err.println("The forth argument must be a valid file!");
				System.exit(1);
			}

		}else{
			System.err.println("Wrong arguments.");
			System.exit(1);
		}
		
		//String lib = "c:/windows/system32/aetcsss1.dll";
		//String lib2 = "c:/windows/system32/aetpkss1.dll";
		//String lib3 = "c:/windows/system32/aetjcss1.dll";

	}

}
