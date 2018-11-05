package org.gonzalad.crypto.sample.aes;

import org.apache.commons.io.FileUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;

;

public class AESDecrypt {
    private static final String SRC_FILE = "target/classes/somefile.enc";
    private static final String DST_FILE = "target/classes/somefile.decrypted";

    public static void main(String args[]) throws Exception {
        byte[] src = FileUtils.readFileToByteArray(new File(SRC_FILE));

        byte[] encrypted = decrypt(src);

        writeToFile(encrypted, new File(DST_FILE));
    }

    private static void writeToFile(byte[] encrypted, File targetFile) throws IOException {
        if (targetFile.exists()) {
            targetFile.delete();
        }
        FileUtils.writeByteArrayToFile(new File(DST_FILE), encrypted);
    }

    private static byte[] decrypt(byte[] cipherMessage) throws Exception {
        ByteBuffer byteBuffer = ByteBuffer.wrap(cipherMessage);
        int ivLength = byteBuffer.getInt();
        if (ivLength < 12 || ivLength >= 16) { // check input parameter
            throw new IllegalArgumentException("invalid iv length");
        }
        byte[] iv = new byte[ivLength];
        byteBuffer.get(iv);
        byte[] cipherText = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherText);
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(getKey(), "AES"), new GCMParameterSpec(128, iv));
        byte[] plainText = cipher.doFinal(cipherText);
        return plainText;
    }

    private static byte[] getKey() {
        return KeyValue.KEY;
    }
}