package com.ideas2it.aes256;

import android.util.Base64;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONException;

import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import shaded.org.apache.commons.codec.binary.Hex;

/**
 * This class used to perform AES encryption and decryption.
 */
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




    private static final String ENCRYPT = "encrypt";
    private static final String DECRYPT = "decrypt";
    private static final String GENERATE_SECURE_KEY = "generateSecureKey";
    private static final String GENERATE_SECURE_IV = "generateSecureIV";
/*
    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5PADDING";
    private static final int PBKDF2_ITERATION_COUNT = 10100;
    private static final int PBKDF2_KEY_LENGTH = 256;
    private static final int SECURE_IV_LENGTH = 64;
    private static final int SECURE_KEY_LENGTH = 128;
*/
    //private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    //private static final String PBKDF2_SALT = "hY0wTq6xwc6MaRiO";
    //cando
    //private static final String PBKDF2_SALT = "01234567890123456789012345678901";

    private static final Random RANDOM = new SecureRandom();

    @Override
    public boolean execute(final String action, final JSONArray args,  final CallbackContext callbackContext) throws JSONException {
        try {
            cordova.getThreadPool().execute(new Runnable() {
                @Override
                public void run() {
                    try {
                        if (ENCRYPT.equalsIgnoreCase(action)) {
                            String secureKey = args.getString(0);
                            String iv = args.getString(1);
                            String value = args.getString(2);
                            callbackContext.success(encrypt(secureKey, value, iv));
                        } else if (DECRYPT.equalsIgnoreCase(action)) {
                            String secureKey = args.getString(0);
                            String iv = args.getString(1);
                            String value = args.getString(2);
                            callbackContext.success(decrypt(secureKey, value, iv));
                        } else if (GENERATE_SECURE_KEY.equalsIgnoreCase(action)) {
                            String password = args.getString(0);
                            callbackContext.success(generateSecureKey(password));
                        } else if (GENERATE_SECURE_IV.equalsIgnoreCase(action)) {
                            String password = args.getString(0);
                            callbackContext.success(generateSecureIV(password));
                        } else {
                            callbackContext.error("Invalid method call");
                        }
                    } catch (Exception e) {
                        System.out.println("Error occurred while performing " + action + " : " + e.getMessage());
                        callbackContext.error("Error occurred while performing " + action);
                    }
                }
            });
        } catch (Exception e) {
            System.out.println("Error occurred while performing " + action + " : " + e.getMessage());
            callbackContext.error("Error occurred while performing " + action);
        }
        return  true;
    }

    /**
     * <p>
     * To perform the AES256 encryption
     * </p>
     *
     * @param secureKey A 32 bytes string, which will used as input key for AES256 encryption
     * @param value     A string which will be encrypted
     * @param iv        A 16 bytes string, which will used as initial vector for AES256 encryption
     * @return AES Encrypted string
     * @throws Exception
     */
    /*
    private String encrypt(String secureKey, String value, String iv) throws Exception {
        byte[] pbkdf2SecuredKey = generatePBKDF2(secureKey.toCharArray(), PBKDF2_SALT.getBytes("UTF-8"),
                PBKDF2_ITERATION_COUNT, PBKDF2_KEY_LENGTH);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
        SecretKeySpec secretKeySpec = new SecretKeySpec(pbkdf2SecuredKey, "AES");
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(value.getBytes());
        return Base64.encodeToString(encrypted, Base64.DEFAULT);
    }
    */


    // Esegue l’operazione di encrypt
    //private String encrypt(String plaintext, String password) throws Exception {
    private String encrypt(String password, String plaintext, String iv ) throws Exception {
         KeyAndIV keyAndIV = deriveKeyAndIV(password);
         Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
         SecretKeySpec keySpec = new SecretKeySpec(keyAndIV.key, "AES");
         //IvParameterSpec ivSpec = new IvParameterSpec(keyAndIV.iv);
         IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
         cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
         byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes("UTF-8"));
      //return Base64.getEncoder().encodeToString(encryptedBytes);
      return Base64.encodeToString(encryptedBytes, Base64.DEFAULT);
    }



/**
     * <p>
     * To perform the AES256 decryption
     * </p>
     *
     * @param secureKey A 32 bytes string, which will used as input key for AES256 decryption
     * @param value     A 16 bytes string, which will used as initial vector for AES256 decryption
     * @param iv        An AES256 encrypted data which will be decrypted
     * @return AES Decrypted string
     * @throws Exception
     */
    /*
    private String decrypt(String secureKey, String value, String iv) throws Exception {
        byte[] pbkdf2SecuredKey = generatePBKDF2(secureKey.toCharArray(), PBKDF2_SALT.getBytes("UTF-8"),
                PBKDF2_ITERATION_COUNT, PBKDF2_KEY_LENGTH);

        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
        SecretKeySpec secretKeySpec = new SecretKeySpec(pbkdf2SecuredKey, "AES");

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] original = cipher.doFinal(Base64.decode(value, Base64.DEFAULT));

        return new String(original);
    }
    */

    // Funzione per decifrare il testo
    private String decrypt(String password, String ciphertext, String iv) throws Exception {
        KeyAndIV keyAndIV = deriveKeyAndIV(password);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(keyAndIV.key, "AES");
        //IvParameterSpec ivSpec = new IvParameterSpec(keyAndIV.iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
      //byte[] decodedCiphertext = Base64.getDecoder().decode(ciphertext);
      byte[] decodedCiphertext = Base64.decode(ciphertext, Base64.DEFAULT);
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





    /**
     * @param password       The password
     * @param salt           The salt
     * @param iterationCount The iteration count
     * @param keyLength      The length of the derived key.
     * @return PBKDF2 secured key
     * @throws Exception
     * @see <a href="https://docs.oracle.com/javase/8/docs/api/javax/crypto/spec/PBEKeySpec.html">
     * https://docs.oracle.com/javase/8/docs/api/javax/crypto/spec/PBEKeySpec.html</a>
     */
    private static byte[] generatePBKDF2(char[] password, byte[] salt, int iterationCount,
                                         int keyLength) throws Exception {
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        KeySpec keySpec = new PBEKeySpec(password, salt, iterationCount, keyLength);
        SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
        return secretKey.getEncoded();
    }

    /**
     * <p>
     * This method used to generate the secure key based on the PBKDF2 algorithm
     * </p>
     *
     * @param password The password
     * @return SecureKey
     * @throws Exception
     */
    //private static String generateSecureKey(String password) throws Exception {
    private String generateSecureKey(String password) throws Exception {
        /*
        byte[] secureKeyInBytes = generatePBKDF2(password.toCharArray(), generateRandomSalt(),
            PBKDF2_ITERATION_COUNT, SECURE_KEY_LENGTH);
        return Hex.encodeHexString(secureKeyInBytes);
        */

        KeyAndIV keyAndIV = deriveKeyAndIV(password);
        return Hex.encodeHexString(keyAndIV.key); // <-- pay attention to coding, see next row
        //return Hex.encodeHexString(new String(decryptedBytes, "UTF-8"));
    }

    /**
     * <p>
     * This method used to generate the secure IV based on the PBKDF2 algorithm
     * </p>
     *
     * @param password The password
     * @return SecureIV
     * @throws Exception
     */
    //private static String generateSecureIV(String password) throws Exception {
    private String generateSecureIV(String password) throws Exception {
        /*
        byte[] secureIVInBytes = generatePBKDF2(password.toCharArray(), generateRandomSalt(),
            PBKDF2_ITERATION_COUNT, SECURE_IV_LENGTH);
        return Hex.encodeHexString(secureIVInBytes);
        */
        KeyAndIV keyAndIV = deriveKeyAndIV(password);
        return Hex.encodeHexString(keyAndIV.key); // <-- pay attention to coding, see next row
        //return Hex.encodeHexString(new String(decryptedBytes, "UTF-8"));
    }

    /**
     * <p>
     * This method used to generate the random salt
     * </p>
     *
     * @return

    private static byte[] generateRandomSalt() {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        return salt;
    }
    */
}
