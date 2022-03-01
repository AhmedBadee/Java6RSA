package com.encryption;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class Main {

    public static void main(String[] args) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidKeySpecException, IOException {

        String text = "Hello core team";
        System.out.println("Original Text: \n" + text + "\n");

        RSAEncryptionService encryption = new RSAEncryptionService();
        String encrypted = encryption.encryptTransaction(text);
        System.out.println("Encrypted Text: \n" + encrypted + "\n");

        String decrypted = encryption.decryptTransaction(encrypted);
        System.out.println("Decrypted Text: \n" + decrypted + "\n");
    }
}
