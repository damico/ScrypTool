package org.jdamico.scryptool.crypto;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
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

import javax.crypto.Cipher;

import org.jdamico.scryptool.commons.Base64Utils;
import org.jdamico.scryptool.commons.Constants;
import org.jdamico.scryptool.commons.TopLevelException;
import org.jdamico.scryptool.commons.Utils;
import org.jdamico.scryptool.entities.CertificationChainAndSignatureBase64;
import org.jdamico.scryptool.entities.PrivateKeyAndCertChain;
import org.jdamico.scryptool.launchers.Runtime;

public class PKCS11_Helper implements PkiGeneric {
	
	
	public static final String ALGORITHM = "RSA";
	
	public void signSelectedFile(File file, String password, String pkcs11LibraryFileName) throws TopLevelException {
        try {


            // Perform the actual file signing
            CertificationChainAndSignatureBase64 signingResult = signFile(file, pkcs11LibraryFileName, password);
            if (signingResult != null) {

            	System.out.println("signingResult.mSignature: "+signingResult.mSignature);
            	System.out.println("signingResult.mCertificationChain: "+signingResult.mCertificationChain);
            	
            	
            	
            } else {
            	throw new TopLevelException("Error at signFile(file, pkcs11LibraryFileName, password)");
            }
        }
        
        catch (SecurityException se) {
            throw new TopLevelException(se);

        }
        catch (Exception e) {
        	throw new TopLevelException(e);
        }
    }

    /**
     * Signs given local file. The certificate and private key to be used for signing
     * come from the locally attached smart card. The user is requested to provide a
     * PKCS#11 implementation library and the PIN code for accessing the smart card.
     * @param aFileName the name of the file to be signed.
     * @return the digital signature of the given file and the certification chain of
     * the certificatie used for signing the file, both Base64-encoded or null if the
     * signing process is canceled by the user.
     * @throws DocumentSignException when a problem arised during the singing process
     * (e.g. smart card access problem, invalid certificate, invalid PIN code, etc.)
     */
    public CertificationChainAndSignatureBase64 signFile(File file, String pkcs11LibraryFileName,  String pinCode) throws TopLevelException {

        // Load the file for signing
        byte[] documentToSign = null;
        try {
            documentToSign = Utils.getInstance().readFileInByteArray(file);
        } catch (IOException ioex) {
            String errorMessage = "Can not read the file for signing " + file.getAbsolutePath() + ".";
            throw new TopLevelException(errorMessage, ioex);
        }

        
           
                

                // Do the actual signing of the document with the smart card
                CertificationChainAndSignatureBase64 signingResult = signDocument(documentToSign, pkcs11LibraryFileName, pinCode);
                return signingResult;
            
        
    }

    
    public Certificate[] getCertificates(KeyStore userKeyStore) throws KeyStoreException{
    	Certificate[] certificationChain = null;
    	Enumeration<String> aliasesEnum = userKeyStore.aliases();
        if (aliasesEnum.hasMoreElements()) {
            String alias = aliasesEnum.nextElement();
            System.out.println(alias);
            certificationChain = userKeyStore.getCertificateChain(alias);
            
        } else {
            throw new KeyStoreException("The keystore is empty!");
        }
        return certificationChain;
    }
    
    
    
    private CertificationChainAndSignatureBase64 signDocument(byte[] aDocumentToSign, String aPkcs11LibraryFileName, String aPinCode) throws TopLevelException {
        if (aPkcs11LibraryFileName.length() == 0) {
            String errorMessage = "It is mandatory to choose a PCKS#11 native " +
                "implementation library for for smart card (.dll or .so file)!";
            throw new TopLevelException(errorMessage);
        }

        // Load the keystore from the smart card using the specified PIN code
        KeyStore userKeyStore = null;
        try {
            userKeyStore = loadKeyStore(aPkcs11LibraryFileName, aPinCode);
        } catch (Exception ex) {
            String errorMessage = "Can not read the keystore from the smart card.\n" +
                "Possible reasons:\n" +
                " - The smart card reader in not connected.\n" +
                " - The smart card is not inserted.\n" +
                " - The PKCS#11 implementation library is invalid.\n" +
                " - The PIN for the smart card is incorrect.\n" +
                "Problem details: " + ex.getMessage();
            throw new TopLevelException(errorMessage, ex);
        }

        // Get the private key and its certification chain from the keystore
        PrivateKeyAndCertChain privateKeyAndCertChain = null;
        privateKeyAndCertChain = getPrivateKeyAndCertChain(userKeyStore, null);

        // Check if the private key is available
        PrivateKey privateKey = privateKeyAndCertChain.mPrivateKey;
        if (privateKey == null) {
            String errorMessage = "Can not find the private key on the smart card.";
            throw new TopLevelException(errorMessage);
        }

        // Check if X.509 certification chain is available
        Certificate[] certChain = privateKeyAndCertChain.mCertificationChain;
        if (certChain == null) {
            String errorMessage = "Can not find the certificate on the smart card.";
            throw new TopLevelException(errorMessage);
        }

        // Create the result object
        CertificationChainAndSignatureBase64 signingResult = new CertificationChainAndSignatureBase64();

        signingResult.mCertificationChain = encodeX509CertChainToBase64(certChain);

        byte[] digitalSignature = signDocument(aDocumentToSign, privateKey);
		signingResult.mSignature = Base64Utils.base64Encode(digitalSignature);

        return signingResult;
    }

    /**
     * Loads the keystore from the smart card using its PKCS#11 implementation
     * library and the Sun PKCS#11 security provider. The PIN code for accessing
     * the smart card is required.
     */
    public KeyStore loadKeyStore(String aPKCS11LibraryFileName, String aSmartCardPIN) throws TopLevelException {
        // First configure the Sun PKCS#11 provider. It requires a stream (or file)
        // containing the configuration parameters - "name" and "library".
        String pkcs11ConfigSettings = "name = SmartCard\n" + "library = " + aPKCS11LibraryFileName;
        byte[] pkcs11ConfigBytes = pkcs11ConfigSettings.getBytes();
        ByteArrayInputStream confStream = new ByteArrayInputStream(pkcs11ConfigBytes);

        // Instantiate the provider dynamically with Java reflection
        try {
            Class sunPkcs11Class = Class.forName(Constants.SUN_PKCS11_PROVIDER_CLASS);
            Constructor pkcs11Constr = sunPkcs11Class.getConstructor(java.io.InputStream.class);
            Provider pkcs11Provider = (Provider) pkcs11Constr.newInstance(confStream);
            Security.addProvider(pkcs11Provider);
        } catch (Exception e) {
        	e.printStackTrace();
            throw new TopLevelException("Can initialize Sun PKCS#11 security " +
                "provider. Reason: " + e.getCause().getMessage());
        }

        // Read the keystore form the smart card
        char[] pin = aSmartCardPIN.toCharArray();
        KeyStore keyStore = null;
		try {
			keyStore = KeyStore.getInstance(Constants.PKCS11_KEYSTORE_TYPE);
		} catch (KeyStoreException e) {
			throw new TopLevelException(e);
		}
        try {
			keyStore.load(null, pin);
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
     * given keystore. The keystore is considered to have only one entry that contains
     * both certification chain and its corresponding private key. If the keystore has
     * no entries, an exception is thrown.
     */
    public PrivateKeyAndCertChain getPrivateKeyAndCertChain(KeyStore aKeyStore, String aKeyPassword) throws TopLevelException {
        Enumeration<String> aliasesEnum = null;
		try {
			aliasesEnum = aKeyStore.aliases();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        if (aliasesEnum.hasMoreElements()) {
            String alias = aliasesEnum.nextElement();
            System.out.println(alias);
            Certificate[] certificationChain = null;
			try {
				certificationChain = aKeyStore.getCertificateChain(alias);
			} catch (KeyStoreException e) {
				throw new TopLevelException(e);
			}
            PrivateKey privateKey = null;
			try {
				privateKey = (PrivateKey) aKeyStore.getKey(alias, null);
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
            System.out.println("certificationChain: "+certificationChain.length);
            
            for (int i = 0; i < certificationChain.length; i++) {
				System.out.println(certificationChain[i].toString());
			}
            
            return result;
        } else {
            throw new TopLevelException("The keystore is empty!");
        }
    }

    /**
     * @return Base64-encoded ASN.1 DER representation of given X.509 certification
     * chain.
     * @throws java.security.cert.CertificateException 
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

    

    /**
     * Signs given document with a given private key.
     */
    public byte[] signDocument(byte[] aDocument, PrivateKey aPrivateKey) throws TopLevelException {
        Signature signatureAlgorithm = null;
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
        byte[] digitalSignature = null;
		try {
			digitalSignature = signatureAlgorithm.sign();
		} catch (SignatureException e) {
			throw new TopLevelException(e);
		}
        return digitalSignature;
    }
    
    
    public  byte[] encrypt(byte[] in, Certificate certificate) {
    	
    	PublicKey pubKey = certificate.getPublicKey();
    	
        byte[] cipherText = null;
        try {
          // get an RSA cipher object and print the provider
          final Cipher cipher = Cipher.getInstance(ALGORITHM);
          // encrypt the plain text using the public key
          cipher.init(Cipher.ENCRYPT_MODE, pubKey);
          cipherText = cipher.doFinal(in);
        } catch (Exception e) {
          e.printStackTrace();
        }
        return cipherText;
      }
    
    public static String decrypt(byte[] text, PrivateKey key) {
        byte[] dectyptedText = null;
        try {
          // get an RSA cipher object and print the provider
          final Cipher cipher = Cipher.getInstance(ALGORITHM);

          // decrypt the text using the private key
          cipher.init(Cipher.DECRYPT_MODE, key);
          dectyptedText = cipher.doFinal(text);

        } catch (Exception ex) {
          ex.printStackTrace();
        }

        return new String(dectyptedText);
      }
    
    
    public void verifyDocumentSignature(String aPKCS11LibraryFileName, String aSmartCardPIN, File docFile, String signString) throws TopLevelException {
    	KeyStore keyStore = loadKeyStore(aPKCS11LibraryFileName, aSmartCardPIN);
    	Certificate[] certs = null;
		try {
			certs = getCertificates(keyStore);
		} catch (KeyStoreException e) {
			throw new TopLevelException(e);
		}
    	
    	byte[] doc = null;
        try {
            doc = Utils.getInstance().readFileInByteArray(docFile);
        } catch (IOException ioex) {
            ioex.printStackTrace();
        }
    	
        byte[] bSign = Base64Utils.base64Decode(signString);
        
        boolean isV = false;
		try {
			isV = verifyDocumentSignature(certs[0], doc, bSign);
		} catch (InvalidKeyException e) {
			throw new TopLevelException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new TopLevelException(e);
		} catch (SignatureException e) {
			throw new TopLevelException(e);
		}
        
		Utils.getInstance().handleVerboseLog(Runtime.appProperties, 'i', String.valueOf(isV));

    }
    
    public boolean verifyDocumentSignature(Certificate certificate, byte[] aDocument, byte[] signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException{
    	
    	
    	boolean ret = false;
    	Signature signatureAlgorithm = Signature.getInstance(Constants.DIGITAL_SIGNATURE_ALGORITHM_NAME);
    	signatureAlgorithm.initVerify(certificate);
    	signatureAlgorithm.update(aDocument);
    	ret = signatureAlgorithm.verify(signature);
    	return ret;
    }

	@Override
	public void encryptSelectedFile(File file, String password, String keyStoreFileNameOrKeyStoreFileName) throws TopLevelException {
		KeyStore keyStore = null;
		Certificate[] certs = null;
		byte[]  doc = null;
		try {
			keyStore = loadKeyStore(keyStoreFileNameOrKeyStoreFileName, password);
			certs = getCertificates(keyStore);
			doc = Utils.getInstance().readFileInByteArray(file);
			byte[] cyphered = encrypt(doc, certs[0]);
			Utils.getInstance().byteArrayToFile(cyphered, file.getAbsolutePath()+".bin");
		} catch (GeneralSecurityException e) {
			throw new TopLevelException(e);
		} catch (IOException e) {
			throw new TopLevelException(e);
		}
    	
		
	}

	@Override
	public void decryptSelectedFile(File file, String password, String keyStoreFileNameOrKeyStoreFileName) throws TopLevelException {
		
		KeyStore keyStore = null;
		Certificate[] certs = null;
		byte[]  doc = null;
		try {
			
			keyStore = loadKeyStore(keyStoreFileNameOrKeyStoreFileName, password);
			PrivateKeyAndCertChain privateKeyAndCertChain = getPrivateKeyAndCertChain(keyStore, password);
			doc = Utils.getInstance().readFileInByteArray(file);
			
			String plainBytes = decrypt(doc, privateKeyAndCertChain.mPrivateKey);
			
			Utils.getInstance().handleVerboseLog(Runtime.appProperties, 'i', plainBytes);
			

		} catch (IOException e) {
			throw new TopLevelException(e);
		}
		
	}



	/*

	public static byte[] encrypt(byte[] unencryptedByteData, String keyAlias) throws IOException, CertificateException {

        byte[] encryptedMimeData;

        try {
            KeyStore ks = KeyStore.getInstance(CRYPT_TYPE, CRYPT_PROVIDER);
            ks.load(null, null);
            X509Certificate cert = (X509Certificate) ks.getCertificate(keyAlias);
            
            SMIMEEnvelopedGenerator generator = new SMIMEEnvelopedGenerator();
            generator.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(cert));
            //.setProvider("SunPKCS11-verinice")
            byte[] unencryptedByteData_0 = Base64.encode(unencryptedByteData);
            MimeBodyPart unencryptedContent = SMIMEUtil.toMimeBodyPart(unencryptedByteData_0);

            // Encrypt the byte data and make a MimeBodyPart from it
            MimeBodyPart encryptedMimeBodyPart = generator.generate(
            		unencryptedContent,
            		new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider(BouncyCastleProvider.PROVIDER_NAME).build());

            // Finally get the encoded bytes from the MimeMessage and return
            // them
            ByteArrayOutputStream byteOutStream = new ByteArrayOutputStream();
            encryptedMimeBodyPart.writeTo(byteOutStream);
            encryptedMimeData = byteOutStream.toByteArray();
            
        } catch (GeneralSecurityException e) {
           
        } catch (SMIMEException smimee) {
           
        } catch (MessagingException e) {
            
        } catch (IOException ioe) {
            
        } catch (IllegalArgumentException e) {
            
		} catch (CMSException e) {
           
		}
        encryptedMimeData = (encryptedMimeData == null) ? new byte[] {} : encryptedMimeData;
        return encryptedMimeData;
    }
*/
	
}
