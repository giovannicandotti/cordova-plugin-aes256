<?php

class AES256 {
    // Parametri per PBKDF2 e AES
    private static $PBKDF2_ITERATIONS = 10000;
    private static $PBKDF2_SALT = "someSaltValue";
    private static $PBKDF2_ALGORITHM = "sha256"; // In PHP, per PBKDF2 si usa "sha256" per HMAC-SHA256
    private static $AES_KEY_LENGTH = 256; // in bit (256 bit = 32 byte)
    private static $IV_LENGTH = 16;       // 16 byte per AES (block size)

    /**
     * Cifra il testo in chiaro usando AES-256-CBC.
     *
     * @param string $password La password da cui derivare la chiave.
     * @param string $plaintext Il testo in chiaro da cifrare.
     * @param string $iv Il vettore di inizializzazione (IV) (deve essere lungo 16 byte).
     * @return string Il testo cifrato codificato in Base64.
     * @throws Exception
     */
    public static function encrypt($password, $plaintext, $iv) {
         // Deriva la chiave (e l'IV interno, non usato in seguito) dalla password
         $keyAndIV = self::deriveKeyAndIV($password);
         $key = $keyAndIV['key'];

         // Si utilizza il IV fornito come parametro, che deve essere una stringa di 16 byte.
         $encrypted = openssl_encrypt($plaintext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
         if ($encrypted === false) {
              throw new Exception("Encryption failed");
         }
         return base64_encode($encrypted);
    }

    /**
     * Decifra il testo cifrato usando AES-256-CBC.
     *
     * @param string $password La password da cui derivare la chiave.
     * @param string $ciphertext Il testo cifrato codificato in Base64.
     * @param string $iv Il vettore di inizializzazione (IV) (deve essere lungo 16 byte).
     * @return string Il testo in chiaro decifrato.
     * @throws Exception
     */
    public static function decrypt($password, $ciphertext, $iv) {
         $keyAndIV = self::deriveKeyAndIV($password);
         $key = $keyAndIV['key'];

         $decodedCiphertext = base64_decode($ciphertext);
         $decrypted = openssl_decrypt($decodedCiphertext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
         if ($decrypted === false) {
              //throw new Exception("Decryption failed");
              $decrypted='n.a.';
         }
         return $decrypted;
    }

    /**
     * Genera la "secure key" derivata dalla password usando PBKDF2.
     *
     * @param string $password La password.
     * @return string La secure key in formato esadecimale.
     * @throws Exception
     */
    public static function generateSecureKey($password) {
         $keyAndIV = self::deriveKeyAndIV($password);
         return bin2hex($keyAndIV['key']);
    }

    /**
     * Genera la "secure IV" derivata dalla password usando PBKDF2.
     *
     * @param string $password La password.
     * @return string La secure IV in formato esadecimale.
     * @throws Exception
     *
     * @note Nel codice Java originale anche questo metodo restituisce il valore derivato dalla chiave.
     * Se si desidera restituire l'IV derivato, modificare il return in:
     * return bin2hex($keyAndIV['iv']);
     */
    public static function generateSecureIV($password) {
         $keyAndIV = self::deriveKeyAndIV($password);
         return bin2hex($keyAndIV['key']);
    }

    /**
     * Deriva la chiave AES e l'IV dalla password usando PBKDF2 con HMAC-SHA256.
     *
     * @param string $password La password.
     * @return array Un array associativo contenente 'key' e 'iv'.
     * @throws Exception
     */
    private static function deriveKeyAndIV($password) {
         // Lunghezza totale in byte = chiave (32 byte) + IV (16 byte) = 48 byte.
         $totalLength = (self::$AES_KEY_LENGTH / 8) + self::$IV_LENGTH; // 32 + 16 = 48

         // Deriva il materiale della chiave con PBKDF2
         $derived = hash_pbkdf2(
             self::$PBKDF2_ALGORITHM,
             $password,
             self::$PBKDF2_SALT,
             self::$PBKDF2_ITERATIONS,
             $totalLength,
             true  // output in formato binario (raw)
         );

         if ($derived === false || strlen($derived) !== $totalLength) {
              throw new Exception("Key derivation failed");
         }
         $key = substr($derived, 0, self::$AES_KEY_LENGTH / 8);
         $iv = substr($derived, self::$AES_KEY_LENGTH / 8, self::$IV_LENGTH);
         return ['key' => $key, 'iv' => $iv];
    }
}

/*
----------------------------
   Esempio di utilizzo:

try {
    $password  = "password123";
    $plaintext = "Akuna matata: tutta frenesia";
    $iv        = "1234567890123456"; // Deve essere lungo 16 byte


    echo "Testo da cifrare: ".$plaintext."\n";
    echo "Password: ".$password."\n";
    echo "IV: ".$iv."\n\n";

    // Cifratura
    $ciphertext = AES256::encrypt($password, $plaintext, $iv);
    echo "Testo cifrato: " . $ciphertext . "\n";

    // Decifratura
    $decrypted = AES256::decrypt($password, $ciphertext, $iv);
    echo "Testo decifrato: " . $decrypted . "\n";

    // Genera secure key e secure IV
    echo "Secure Key: " . AES256::generateSecureKey($password) . "\n";
    echo "Secure IV: "  . AES256::generateSecureIV($password) . "\n";
} catch (Exception $e) {
    echo "Errore: " . $e->getMessage() . "\n";
}
-------------------------------
*/


?>
