package org.gonzalad.crypto.sample.aes;

import org.apache.commons.io.FileUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

;

public class AESEncrypt {
    private static final String SRC_FILE = "target/classes/somefile.txt";
    private static final String DST_FILE = "target/classes/somefile.enc";

    public static void main(String args[]) throws Exception {
        byte[] src = FileUtils.readFileToByteArray(new File(SRC_FILE));

        byte[] encrypted = encrypt(src);

        writeToFile(encrypted, new File(DST_FILE));
    }

    private static void writeToFile(byte[] encrypted, File targetFile) throws IOException {
        if (targetFile.exists()) {
            targetFile.delete();
        }
        FileUtils.writeByteArrayToFile(new File(DST_FILE), encrypted);
    }

    private static byte[] encrypt(byte[] src) throws Exception {
        SecureRandom secureRandom = new SecureRandom();
        byte[] key = getKey();
        SecretKey secretKey = new SecretKeySpec(key, "AES");

        byte[] iv = new byte[12]; //NEVER REUSE THIS IV WITH SAME KEY
        secureRandom.nextBytes(iv);

        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv); //256 bit auth tag length
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        byte[] cipherText = cipher.doFinal(src);
        ByteBuffer byteBuffer = ByteBuffer.allocate(4 + iv.length + cipherText.length);
        byteBuffer.putInt(iv.length);
        byteBuffer.put(iv);
        byteBuffer.put(cipherText);
        byte[] cipherMessage = byteBuffer.array();
        return cipherMessage;
    }

    private static byte[] getKey() {
        return KeyValue.KEY;
    }
}