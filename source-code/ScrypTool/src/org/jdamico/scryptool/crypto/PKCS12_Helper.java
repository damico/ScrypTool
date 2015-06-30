package org.jdamico.scryptool.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

import org.jdamico.scryptool.commons.Base64Utils;
import org.jdamico.scryptool.commons.Constants;
import org.jdamico.scryptool.commons.TopLevelException;
import org.jdamico.scryptool.commons.Utils;
import org.jdamico.scryptool.entities.CertificationChainAndSignatureBase64;
import org.jdamico.scryptool.entities.PrivateKeyAndCertChain;

public class PKCS12_Helper implements PkiGeneric {

    public void signSelectedFile(File fileName, String password, String keyStoreFileName) throws TopLevelException {
        try {


            // Perform the actual file signing
            CertificationChainAndSignatureBase64 signingResult = signFile(fileName, password, keyStoreFileName);
            if (signingResult != null) {
               
            	System.out.println("signingResult.mSignature: "+signingResult.mSignature);
            	System.out.println("signingResult.mCertificationChain: "+signingResult.mCertificationChain);
            	
            } else {
                // User canceled signing
            }
        }

        catch (SecurityException se) {
            throw new TopLevelException(se);

        }
        
    }
	
    public CertificationChainAndSignatureBase64 signFile(File file, String password, String keyStoreFileName) throws TopLevelException {

    	        // Load the file for signing
    	        byte[] documentToSign = null;
    	        try {
    	            documentToSign = Utils.getInstance().readFileInByteArray(file);
    	        } catch (IOException ioex) {
    	            String errorMsg = "Can not read the file for signing " + file.getAbsolutePath() + ".";
    	            throw new TopLevelException(errorMsg, ioex);
    	        }


    	        
    	            if (keyStoreFileName.length() == 0) {
    	                String errorMessage = "It is mandatory to select a certificate " +
    	                	"keystore (.PFX or .P12 file)!";
    	                throw new TopLevelException(errorMessage);
    	            }

    	            KeyStore userKeyStore = null;
    	            try {
    	                userKeyStore = loadKeyStore(keyStoreFileName, password);
    	            } catch (Exception ex) {
    	                String errorMessage = "Can not read certificate keystore file (" +
    	                    keyStoreFileName + ").\nThe file is either not in PKCS#12 format" +
    	                    " (.P12 or .PFX) or is corrupted or the password is invalid.";
    	                throw new TopLevelException(errorMessage, ex);
    	            }

    	            // Get the private key and its certification chain from the keystore
    	            PrivateKeyAndCertChain privateKeyAndCertChain = null;
    	            privateKeyAndCertChain =
					    getPrivateKeyAndCertChain(userKeyStore, password);

    	            // Check if a private key is available in the keystore
    	            PrivateKey privateKey = privateKeyAndCertChain.mPrivateKey;
    	            if (privateKey == null) {
    	                String errorMessage = "Can not find the private key in the " +
    	                    "specified file " + keyStoreFileName + ".";
    	                throw new TopLevelException(errorMessage);
    	            }

    	            // Check if X.509 certification chain is available
    	            Certificate[] certChain =
    	                privateKeyAndCertChain.mCertificationChain;
    	            if (certChain == null) {
    	                String errorMessage = "Can not find neither certificate nor " +
    	                    "certification chain in the file " + keyStoreFileName + ".";
    	                throw new TopLevelException(errorMessage);
    	            }

    	            // Create the result object
    	            CertificationChainAndSignatureBase64 signingResult = new CertificationChainAndSignatureBase64();

    	            signingResult.mCertificationChain = encodeX509CertChainToBase64(certChain);

    	            byte[] digitalSignature = signDocument(documentToSign, privateKey);
					signingResult.mSignature = Base64Utils.base64Encode(digitalSignature);

    	            // Document signing completed succesfully
    	            return signingResult;
    	       
    	    }

    	    
    		public byte[] signDocument(byte[] aDocument, PrivateKey aPrivateKey) throws TopLevelException {
    	        Signature signatureAlgorithm =null ;
				try {
					signatureAlgorithm = Signature.getInstance(Constants.DIGITAL_SIGNATURE_ALGORITHM_NAME);
				} catch (NoSuchAlgorithmException e) {
					throw new TopLevelException(e);
				}
    	        try {
					signatureAlgorithm.initSign(aPrivateKey);
				} catch (InvalidKeyException e) {
					throw new TopLevelException(e);
				}
    	        try {
					signatureAlgorithm.update(aDocument);
				} catch (SignatureException e) {
					throw new TopLevelException(e);
				}
    	        byte[] digitalSignature;
				try {
					digitalSignature = signatureAlgorithm.sign();
				} catch (SignatureException e) {
					throw new TopLevelException(e);
				}
    	        return digitalSignature;
    	    }
    	    /**
    	     * Loads a keystore from .PFX or .P12 file (file format should be PKCS#12)
    	     * using given keystore password.
    	     */
    	    public KeyStore loadKeyStore(String aFileName, String aKeyStorePasswd) throws TopLevelException {
    	        KeyStore keyStore;
				try {
					keyStore = KeyStore.getInstance(Constants.PKCS12_KEYSTORE_TYPE);
				} catch (KeyStoreException e) {
					throw new TopLevelException(e);
				}
    	        FileInputStream keyStoreStream =null;
				try {
					keyStoreStream = new FileInputStream(aFileName);
				} catch (FileNotFoundException e) {
					throw new TopLevelException(e);
				}
    	        char[] password = aKeyStorePasswd.toCharArray();
    	        try {
					keyStore.load(keyStoreStream, password);
				} catch (NoSuchAlgorithmException e) {
					throw new TopLevelException(e);
				} catch (CertificateException e) {
					throw new TopLevelException(e);
				} catch (IOException e) {
					throw new TopLevelException(e);
				}
    	        return keyStore;
    	    }

    	    /**
    	     * @return private key and certification chain corresponding to it, extracted from
    	     * given keystore using given password to access the keystore and the same password
    	     * to access the private key in it. The keystore is considered to have only one
    	     * entry that contains both certification chain and the corresponding private key.
    	     * If the certificate has no entries, an exception is trown. It the keystore has
    	     * several entries, the first is used.
    	     */
    	    public PrivateKeyAndCertChain getPrivateKeyAndCertChain(KeyStore aKeyStore, String aKeyPassword) throws TopLevelException {
    	        char[] password = aKeyPassword.toCharArray();
    	        Enumeration<String> aliasesEnum = null;
				try {
					aliasesEnum = aKeyStore.aliases();
				} catch (KeyStoreException e) {
					throw new TopLevelException(e);
				}
    	        if (aliasesEnum.hasMoreElements()) {
    	            String alias = (String)aliasesEnum.nextElement();
    	            Certificate[] certificationChain = null;
					try {
						certificationChain = aKeyStore.getCertificateChain(alias);
					} catch (KeyStoreException e) {
						throw new TopLevelException(e);
					}
    	            PrivateKey privateKey = null;
					try {
						privateKey = (PrivateKey) aKeyStore.getKey(alias, password);
					} catch (UnrecoverableKeyException e) {
						throw new TopLevelException(e);
					} catch (KeyStoreException e) {
						throw new TopLevelException(e);
					} catch (NoSuchAlgorithmException e) {
						throw new TopLevelException(e);
					}
    	            PrivateKeyAndCertChain result = new PrivateKeyAndCertChain();
    	            result.mPrivateKey = privateKey;
    	            result.mCertificationChain = certificationChain;
    	            return result;
    	        } else {
    	            throw new TopLevelException("The keystore is empty!");
    	        }
    	    }

    	    /**
    	     * @return Base64-encoded ASN.1 DER representation of given X.509 certification
    	     * chain.
    	     */
    	    public String encodeX509CertChainToBase64(Certificate[] aCertificationChain) throws TopLevelException {
    	        List<Certificate> certList = Arrays.asList(aCertificationChain);
    	        CertificateFactory certFactory = null;
				try {
					certFactory = CertificateFactory.getInstance(Constants.X509_CERTIFICATE_TYPE);
				} catch (CertificateException e) {
					throw new TopLevelException(e);
				}
    	        CertPath certPath = null;
				try {
					certPath = certFactory.generateCertPath(certList);
				} catch (CertificateException e) {
					throw new TopLevelException(e);
				}
    	        byte[] certPathEncoded = null;
				try {
					certPathEncoded = certPath.getEncoded(Constants.CERTIFICATION_CHAIN_ENCODING);
				} catch (CertificateEncodingException e) {
					throw new TopLevelException(e);
				}
    	        String base64encodedCertChain = Base64Utils.base64Encode(certPathEncoded);
    	        return base64encodedCertChain;
    	    }

			@Override
			public void encryptSelectedFile(File file, String password,
					String keyStoreFileNameOrKeyStoreFileName) throws TopLevelException {
				// TODO Auto-generated method stub
				
			}

			@Override
			public void decryptSelectedFile(File file, String password,
					String keyStoreFileNameOrKeyStoreFileName) throws TopLevelException {
				// TODO Auto-generated method stub
				
			}

    	    
    	    
}
