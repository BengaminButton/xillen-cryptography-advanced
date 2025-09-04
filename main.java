package xillencryptography;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;

public class Main {
    public static void main(String[] args) {
        System.out.println("Автор: t.me/Bengamin_Button t.me/XillenAdapter");
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey key = keyGen.generateKey();
            Cipher cipher = Cipher.getInstance("AES");
            String plaintext = "Секретное сообщение";
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes());
            String encryptedText = Base64.getEncoder().encodeToString(encrypted);
            System.out.println("Зашифрованный текст: " + encryptedText);
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
            System.out.println("Расшифрованный текст: " + new String(decrypted));
        } catch (Exception e) {
            System.out.println("Ошибка: " + e.getMessage());
        }
    }
}

