package eu.giovannicandotti.aes256;

import org.apache.cordova.*;
import org.json.JSONArray;
import org.json.JSONException;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.spec.KeySpec;
import java.util.Base64;

public class AES256 extends CordovaPlugin {

    // -------------------------------------------------------------------
    // Inizializzazione dei parametri per PBKDF2 e AES
    // -------------------------------------------------------------------
    // Il numero di iterazioni per PBKDF2
    private static final int PBKDF2_ITERATIONS = 10000;
    // Salt fisso per la derivazione (deve essere uguale a quello usato in iOS)
    private static final String PBKDF2_SALT = "someSaltValue";
    // Algoritmo per PBKDF2: usiamo HMAC-SHA256
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    // Lunghezza della chiave AES256: 256 bit (32 byte)
    private static final int AES_KEY_LENGTH = 256;
    // Lunghezza dell’IV: 16 byte (AES block size)
    private static final int IV_LENGTH = 16;
    
    // Il padding usato è PKCS5Padding (equivalente a PKCS7Padding in ambiente iOS)
    // -------------------------------------------------------------------

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
         if (action.equals("encrypt")) {
             String plaintext = args.getString(0);
             String password = args.getString(1);
             encrypt(plaintext, password, callbackContext);
             return true;
         } else if (action.equals("decrypt")) {
             String ciphertext = args.getString(0);
             String password = args.getString(1);
             decrypt(ciphertext, password, callbackContext);
             return true;
         }
         return false;
    }
    
    // Esegue l’operazione di encrypt in modo asincrono
    private void encrypt(final String plaintext, final String password, final CallbackContext callbackContext) {
         cordova.getThreadPool().execute(new Runnable() {
             public void run() {
                 try {
                     String encrypted = encryptText(plaintext, password);
                     callbackContext.success(encrypted);
                 } catch (Exception e) {
                     callbackContext.error("Cifratura fallita: " + e.getMessage());
                 }
             }
         });
    }
    
    // Esegue l’operazione di decrypt in modo asincrono
    private void decrypt(final String ciphertext, final String password, final CallbackContext callbackContext) {
         cordova.getThreadPool().execute(new Runnable() {
             public void run() {
                 try {
                     String decrypted = decryptText(ciphertext, password);
                     callbackContext.success(decrypted);
                 } catch (Exception e) {
                     callbackContext.error("Decifratura fallita: " + e.getMessage());
                 }
             }
         });
    }
    
    // Funzione interna per cifrare il testo
    private String encryptText(String plaintext, String password) throws Exception {
         KeyAndIV keyAndIV = deriveKeyAndIV(password);
         Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
         SecretKeySpec keySpec = new SecretKeySpec(keyAndIV.key, "AES");
         IvParameterSpec ivSpec = new IvParameterSpec(keyAndIV.iv);
         cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
         byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes("UTF-8"));
         return Base64.getEncoder().encodeToString(encryptedBytes);
    }
    
    // Funzione interna per decifrare il testo
    private String decryptText(String ciphertext, String password) throws Exception {
         KeyAndIV keyAndIV = deriveKeyAndIV(password);
         Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
         SecretKeySpec keySpec = new SecretKeySpec(keyAndIV.key, "AES");
         IvParameterSpec ivSpec = new IvParameterSpec(keyAndIV.iv);
         cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
         byte[] decodedCiphertext = Base64.getDecoder().decode(ciphertext);
         byte[] decryptedBytes = cipher.doFinal(decodedCiphertext);
         return new String(decryptedBytes, "UTF-8");
    }
    
    // Classe helper per contenere la chiave e l’IV derivati
    private class KeyAndIV {
         public byte[] key;
         public byte[] iv;
         public KeyAndIV(byte[] key, byte[] iv) {
             this.key = key;
             this.iv = iv;
         }
    }
    
    // Deriva la chiave e l’IV utilizzando PBKDF2 con HMAC-SHA256
    private KeyAndIV deriveKeyAndIV(String password) throws Exception {
         int totalKeyLength = AES_KEY_LENGTH / 8 + IV_LENGTH; // 32 + 16 = 48 byte
         KeySpec spec = new PBEKeySpec(password.toCharArray(), PBKDF2_SALT.getBytes("UTF-8"), PBKDF2_ITERATIONS, totalKeyLength * 8);
         SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
         byte[] keyAndIVBytes = factory.generateSecret(spec).getEncoded();
         byte[] key = new byte[AES_KEY_LENGTH / 8];
         byte[] iv = new byte[IV_LENGTH];
         System.arraycopy(keyAndIVBytes, 0, key, 0, key.length);
         System.arraycopy(keyAndIVBytes, key.length, iv, 0, iv.length);
         return new KeyAndIV(key, iv);
    }
}
