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

}
