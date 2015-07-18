package org.jdamico.scryptool.launchers;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.Certificate;

import org.apache.commons.codec.binary.Base64;
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

	public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
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
			
			String strOperation = args[1];
			String scPasswd = null;
			
			int operation = -1;
			try {
				operation = Integer.parseInt(strOperation);
			} catch (NumberFormatException e) {
				System.err.println("The third argument must be an integer (operation type)!");
				System.exit(1);
			}

			String srcFilePath = args[2];

			File srcFile = new File(srcFilePath);

			if(!srcFile.isDirectory()){

				PKCS11_Helper pki = new PKCS11_Helper();

				String signatureFilePath = null;
				switch (operation) {
				case 0:
					
					Utils.getInstance().handleVerboseLog(appProperties, 'i', Constants.OPER_0);
					try {
						scPasswd = args[3];
						pki.signSelectedFile(srcFile, scPasswd, appProperties.getLibPath());
					} catch (TopLevelException e1) {
						Utils.getInstance().handleVerboseLog(appProperties, 'e', e1.getMessage());
						System.exit(1);
					}
					break;

				case 1:
					
					Utils.getInstance().handleVerboseLog(appProperties, 'i', Constants.OPER_1);
					try {
						scPasswd = args[3];
						signatureFilePath = args[4];
						pki.verifyDocumentSignature(appProperties.getLibPath(), scPasswd, srcFile, signatureFilePath);
					} catch (IndexOutOfBoundsException e) {
						Utils.getInstance().handleVerboseLog(appProperties, 'e', "The fifth argument must be a b64 string (signature)!");
						System.exit(1);
					} catch (TopLevelException e) {

					}

					break;

				case 2:
					Utils.getInstance().handleVerboseLog(appProperties, 'i', Constants.OPER_2);
					try {
						scPasswd = args[3];
						pki.encryptSelectedFile(srcFile, scPasswd, appProperties.getLibPath());
					} catch (TopLevelException e) {
						Utils.getInstance().handleVerboseLog(appProperties, 'e', e.getMessage());
						System.exit(1);
					}
					break;

				case 3:
					Utils.getInstance().handleVerboseLog(appProperties, 'i', Constants.OPER_3);
					try {
						scPasswd = args[3];
						pki.decryptSelectedFile(srcFile, scPasswd, appProperties.getLibPath());
					} catch (TopLevelException e) {
						Utils.getInstance().handleVerboseLog(appProperties, 'e', e.getMessage());
						System.exit(1);
					}
					break;


				case 4:
					Utils.getInstance().handleVerboseLog(appProperties, 'i', Constants.OPER_4);
					try {
						scPasswd = args[3];
						pki.setCertificateByFile(srcFilePath, scPasswd, appProperties.getLibPath());
					} catch (TopLevelException e) {
						Utils.getInstance().handleVerboseLog(appProperties, 'e', e.getMessage());
						System.exit(1);
					}
					break;

				case 5:
					signatureFilePath = args[4];
					String signedFileFilePath =  args[3];
					Utils.getInstance().handleVerboseLog(appProperties, 'i', Constants.OPER_5);
					Certificate cert = pki.getCertificateByFile(srcFilePath);
					String strB64File = Utils.getInstance().readFile(new File(signatureFilePath));
					byte[] sig = Base64.decodeBase64(strB64File);
					byte[] doc = Utils.getInstance().readFileInByteArray(signedFileFilePath);
					boolean b = pki.verifyDocumentSignature(cert, doc, sig);
					System.out.println(b);
					break;

				default:
					break;

				}
			}else{
				System.err.println("The <source-file> must be a valid file path!");
				System.exit(1);
			}

		}else{
			System.err.println("Wrong arguments.");
			help();
			System.exit(1);
		}

		

	}

	public static void help(){
		String help		 = "This program has 6 operations:\n\n\n"
						 + Constants.OPER_0 + "\n\n"
						 + Constants.OPER_1 + "\n\n"
						 + Constants.OPER_2 + "\n\n"
						 + Constants.OPER_3 + "\n\n"
						 + Constants.OPER_4 + "\n\n"
						 + Constants.OPER_5 + "\n\n\n"
						 		+ "Remember, the program will not work without a configuration file. See an example of this kind o file, bellow:\n\n"
						 		+ "libpath=c:/windows/system32/aetcsss1.dll\n"
						 		+ "verbose=yes\n"
						 		+ "log=yes\n";
		
		System.out.println(help);
	}
	
}
