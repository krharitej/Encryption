import java.util.*;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import Encryption.Blowfish;
public class Main {
    static Scanner sc = new Scanner(System.in);
    public static void main(String[] args) throws Exception{
        String key = "1212500101698301", in;
        String initVector = "RandomInitVector";
        Blowfish bfish = new Blowfish();
        System.out.println("1-Encode\n2-Decode\n");
        int ch = Integer.parseInt(sc.nextLine());
        if(ch == 1) {
            System.out.println("Enter the String: \t");
            in = sc.nextLine();
            String s1 = b64Encode(in);
            String s2 = AESencrypt(s1, key, initVector);
            String encoded = Blowfish.encryptText(s2, key);
            System.out.printf("Encrypted Hash: %s\t", encoded);
        }
        else if(ch == 2) {
            System.out.println("Enter the Hash: \t");
            in = sc.nextLine();
            String s1 = Blowfish.decryptText(in, key);
            String s2 = AESdecrypt(Base64.getDecoder().decode(s1), key, initVector);
            String decoded = b64Decode(s2);
            System.out.printf("Decrypted String: %s\t", decoded);
        }
        else{
            System.out.println("Invalid");
        }
    }
    public static String b64Encode(String St1){
        Base64.Encoder encoder = Base64.getEncoder();
        byte[] encodedString = encoder.encode(St1.getBytes());
        return new String(encodedString);
    }
    public static String b64Decode(String St2){
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] decodedString = decoder.decode(St2);
        return new String(decodedString);
    }
    public static String sha256Hash(String St1) throws Exception{
        MessageDigest h = MessageDigest.getInstance("SHA-256");
        h.update(St1.getBytes());
        return byteArrayToHex(h.digest());
    }
    public static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for(byte b: a)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }
    public static String AESencrypt(String plainText, String key, String initVector) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        byte[] enc = cipher.doFinal(plainText.getBytes());
        String encrypted = Base64.getEncoder().encodeToString(enc);
        return encrypted;
    }

    public static String AESdecrypt(byte[] cipherText, String key, String initVector) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

        byte[] decryptedBytes = cipher.doFinal(cipherText);
        return new String(decryptedBytes);
    }
}