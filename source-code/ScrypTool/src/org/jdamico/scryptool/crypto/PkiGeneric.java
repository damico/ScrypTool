package org.jdamico.scryptool.crypto;

import java.io.File;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import org.jdamico.scryptool.commons.TopLevelException;
import org.jdamico.scryptool.entities.CertificationChainAndSignatureBase64;
import org.jdamico.scryptool.entities.PrivateKeyAndCertChain;

public interface PkiGeneric {
	public void setCertificateByFile(String certFileLocation, String password, String keyStoreFileNameOrKeyStoreFileName) throws TopLevelException;
	public Certificate getCertificateByFile(String srcFilePath) throws TopLevelException;
	public String encodeX509CertChainToBase64(Certificate[] aCertificationChain) throws TopLevelException;
	public PrivateKeyAndCertChain getPrivateKeyAndCertChain(KeyStore aKeyStore, String aKeyPassword) throws TopLevelException;
	public KeyStore loadKeyStore(String aPKCS11LibraryFileNameOrKeyStoreFileName, String aSmartCardPIN) throws TopLevelException;
	public byte[] signDocument(byte[] aDocument, PrivateKey aPrivateKey) throws TopLevelException;
	public CertificationChainAndSignatureBase64 signFile(File file, String pkcs11LibraryFileNameOrKeyStoreFileName,  String pinCode) throws TopLevelException;
	public void signSelectedFile(File file, String password, String keyStoreFileNameOrKeyStoreFileName) throws TopLevelException;
	public void encryptSelectedFile(File file, String password, String keyStoreFileNameOrKeyStoreFileName) throws TopLevelException;
	public void decryptSelectedFile(File file, String password, String keyStoreFileNameOrKeyStoreFileName) throws TopLevelException;
}
