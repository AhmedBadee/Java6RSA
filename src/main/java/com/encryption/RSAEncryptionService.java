package com.encryption;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Properties;

public class RSAEncryptionService {

    private final String publicKey;
    private final String privateKey;

    public RSAEncryptionService() throws IOException {
        InputStream input = new FileInputStream("src/main/resources/config.properties");
        Properties prop = new Properties();
        prop.load(input);

        publicKey = prop.getProperty("rsa.public-key");
        privateKey = prop.getProperty("rsa.private-key");
    }

    String encryptTransaction(String property) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidKeySpecException, IOException {
        if (property != null) {
            property = encrypt(property);
        }
        return property;
    }

     String decryptTransaction(String property) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        if (property != null) {
            property = decrypt(property);
        }
        return property;
    }

    private String encrypt(String property) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        BASE64Decoder decoder = new BASE64Decoder();
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decoder.decodeBuffer(publicKey));
        PublicKey certificate = keyFactory.generatePublic(publicKeySpec);
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, certificate);
        BASE64Encoder encoder = new BASE64Encoder();
        return encoder.encode(cipher.doFinal(property.getBytes()));
    }

    private String decrypt(String property) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        java.security.Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider()
        );

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        BASE64Decoder decoder = new BASE64Decoder();
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(decoder.decodeBuffer(privateKey));
        PrivateKey privateKeyCertificate = keyFactory.generatePrivate(privateKeySpec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        cipher.init(Cipher.DECRYPT_MODE, privateKeyCertificate);
        byte[] bytes = decoder.decodeBuffer(property);
        byte[] decryptedBytes = cipher.doFinal(bytes);
        return new String(decryptedBytes);
    }
}