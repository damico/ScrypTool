package org.jdamico.scryptool.commons;

public interface Constants {
	public static final String PKCS11_KEYSTORE_TYPE = "PKCS11";
	public static final String X509_CERTIFICATE_TYPE = "X.509";
	public static final String CERTIFICATION_CHAIN_ENCODING = "PkiPath";
	public static final String DIGITAL_SIGNATURE_ALGORITHM_NAME = "SHA1withRSA";
	public static final String SUN_PKCS11_PROVIDER_CLASS = "sun.security.pkcs11.SunPKCS11";
    public static final String PKCS12_KEYSTORE_TYPE = "PKCS12";
	public static final String APP_NAME = "Cryptool";
	public static final String APP_VERSION = "0.0.1";
	public static final String LOG_NAME = APP_NAME+".log";
	public static final String LOG_FOLDER = "./";
	public static final String LOG_FILE = LOG_FOLDER+LOG_NAME;
	
	public static final String BASIC_PARAMS = "<path-to-conf-file> <operation-number> <source-file>";
	
	public static final String OPER_0 =  "OPERATION 0: Sign using smart card. [Parameters: "+BASIC_PARAMS+" <smart-card-pin> ] In this case, <source-file> is the file to be signed.";
	public static final String OPER_1 =  "OPERATION 1: Verify signature using smart card. [Parameters: "+BASIC_PARAMS+" <smart-card-pin> <path-to-base64-signature-file>] In this case, <source-file> is the file signed.";
	public static final String OPER_2 =  "OPERATION 2: Encrypt using smart card. [Parameters: "+BASIC_PARAMS+" <smart-card-pin> ] In this case, <source-file> is the file to be encrypted.";
	public static final String OPER_3 =  "OPERATION 3: Decrypt using smart card. [Parameters: "+BASIC_PARAMS+" <smart-card-pin> ] In this case, <source-file> is the file to be decrypted.";
	public static final String OPER_4 =  "OPERATION 4: Get certificate from smart card and save to a file. [Parameters: "+BASIC_PARAMS+" <smart-card-pin> ] In this case, <source-file> is the file path where the certificate will be saved.";
	public static final String OPER_5 =  "OPERATION 5: Verify signature using saved certificate. [Parameters: "+BASIC_PARAMS+" <path-to-file-signed> <path-to-base64-signature-file>] In this case, <source-file> is the file path where the certificate was saved.";

}
