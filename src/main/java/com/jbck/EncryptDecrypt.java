package com.jbck;

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;

public class EncryptDecrypt {

    public static final String KEYSTORE = "src/main/resources/ks";
    public static final String KS_PASS = "123456";
    public static final String KS_ALIAS = "demo";
    protected KeyStore ks;

    public EncryptDecrypt(String keystore, String ks_pass) throws GeneralSecurityException, IOException {
        initKeyStore(keystore, ks_pass);
    }

    public void initKeyStore(String keystore, String ks_pass) throws GeneralSecurityException, IOException {
        ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(keystore), ks_pass.toCharArray());
    }

    public X509Certificate getCertificate(String alias) throws KeyStoreException {
        return (X509Certificate) ks.getCertificate(alias);
    }

    public Key getPublicKey(String alias) throws GeneralSecurityException, IOException {
        return getCertificate(alias).getPublicKey();
    }

    public Key getPrivateKey(String alias, String pk_pass) throws GeneralSecurityException, IOException {
        return ks.getKey(alias, pk_pass.toCharArray());
    }

    public byte[] encrypt(Key key, String message) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherData = cipher.doFinal(message.getBytes());
        return cipherData;
    }

    public String decrypt(Key key, byte[] message) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] cipherData = cipher.doFinal(message);
        return new String(cipherData);
    }

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        EncryptDecrypt app = new EncryptDecrypt(KEYSTORE, KS_PASS);
        Key publicKey = app.getPublicKey(KS_ALIAS);
        Key privateKey = app.getPrivateKey(KS_ALIAS, KS_PASS);

        System.out.println("Let's encrypt 'jaja' with a public key");
        byte[] encrypted = app.encrypt(publicKey, "jaja");
//        System.out.println("Encrypted message: " + new BigInteger(1, encrypted).toString(16));

        System.out.println("Let's decrypt it with the corresponding private key");
        String decrypted = app.decrypt(privateKey, encrypted);
        System.out.println(decrypted);

        System.out.println("You can also encrypt the message with a private key");
        encrypted = app.encrypt(privateKey, "jaja");
//        System.out.println("Encrypted message: " + new BigInteger(1, encrypted).toString(16));

        System.out.println("Now you need the public key to decrypt it");
        decrypted = app.decrypt(publicKey, encrypted);
        System.out.println(decrypted);

    }
}
