package Encryption;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Scanner;

public class Blowfish {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Choose an option:");
        System.out.println("1. Encrypt");
        System.out.println("2. Decrypt");
        System.out.print("Enter your choice: ");
        int choice = scanner.nextInt();
        scanner.nextLine(); // Consume newline

        switch (choice) {
            case 1:
                encryptText("abc", "asds");
                break;
            case 2:
                decryptText("sjh", "afgs");
                break;
            default:
                System.out.println("Invalid choice.");
        }

        scanner.close();
    }

    public static String encryptText(String s1, String key) {
        try {
            String originalText = s1;

            String keyString = key;
            SecretKey secretKey = new SecretKeySpec(keyString.getBytes(), "Blowfish");

            Cipher cipher = Cipher.getInstance("Blowfish");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            byte[] encryptedBytes = cipher.doFinal(originalText.getBytes());
            String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);
            return encryptedText;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return "";
    }

    public static String decryptText(String s1, String key) {
        try {
            String encryptedText = s1;

            String keyString = key;
            SecretKey secretKey = new SecretKeySpec(keyString.getBytes(), "Blowfish");

            Cipher cipher = Cipher.getInstance("Blowfish");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
            String decryptedText = new String(decryptedBytes);
            return decryptedText;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return "";
    }
}
