import Foundation
import CommonCrypto

// La classe AES256, che estende CDVPlugin, espone le funzioni encrypt e decrypt
@objc(AES256)
class AES256: CDVPlugin {
    
    // MARK: - Parametri di inizializzazione PBKDF2 e AES
    // I parametri di derivazione della chiave devono essere identici in entrambi gli ambienti.
    
    /// Numero di iterazioni per la derivazione (PBKDF2)
    private static let iterations: Int = 10000
    /// Salt utilizzato per la derivazione; deve essere lo stesso in iOS ed Android per l’interoperabilità
    private static let salt: String = "someSaltValue"
    /// Algoritmo usato per PBKDF2 (HMAC-SHA256)
    private static let algorithm: String = "sha256" // Informativo: usato in CommonCrypto
    /// Lunghezza della chiave derivata in byte (256 bit = 32 byte)
    private static let keyLength: Int = 32
    /// Lunghezza dell’IV (AES block size: 16 byte)
    private static let ivLength: Int = 16

    /// Coda di esecuzione asincrona per le operazioni crittografiche
    private static let aes256Queue = DispatchQueue(label: "AESQUEUE", qos: .background, attributes: .concurrent)
    
    
    // MARK: - Funzioni di interfaccia Cordova

    /// Metodo di encrypt chiamato da JavaScript
    @objc(encrypt:)
    func encrypt(command: CDVInvokedUrlCommand) {
        AES256.aes256Queue.async {
            guard let args = command.arguments as? [Any],
                  args.count >= 2,
                  let plaintext = args[0] as? String,
                  let password = args[1] as? String else {
                let pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: "Parametri non validi")
                self.commandDelegate.send(pluginResult, callbackId: command.callbackId)
                return
            }
            if let encrypted = self.encryptText(plaintext: plaintext, password: password) {
                let pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: encrypted)
                self.commandDelegate.send(pluginResult, callbackId: command.callbackId)
            } else {
                let pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: "Cifratura fallita")
                self.commandDelegate.send(pluginResult, callbackId: command.callbackId)
            }
        }
    }
    
    /// Metodo di decrypt chiamato da JavaScript
    @objc(decrypt:)
    func decrypt(command: CDVInvokedUrlCommand) {
        AES256.aes256Queue.async {
            guard let args = command.arguments as? [Any],
                  args.count >= 2,
                  let ciphertext = args[0] as? String,
                  let password = args[1] as? String else {
                let pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: "Parametri non validi")
                self.commandDelegate.send(pluginResult, callbackId: command.callbackId)
                return
            }
            if let decrypted = self.decryptText(ciphertext: ciphertext, password: password) {
                let pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: decrypted)
                self.commandDelegate.send(pluginResult, callbackId: command.callbackId)
            } else {
                let pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: "Decifratura fallita")
                self.commandDelegate.send(pluginResult, callbackId: command.callbackId)
            }
        }
    }
    
    
    // MARK: - Funzioni interne per encrypt e decrypt

    /// Cifra il testo in chiaro usando AES256 in modalità CBC con padding PKCS7.
    /// - Parametri:
    ///   - plaintext: Il testo in chiaro da cifrare.
    ///   - password: La password da cui derivare chiave ed IV.
    /// - Restituisce: Il testo cifrato in Base64 oppure nil in caso di errore.
    func encryptText(plaintext: String, password: String) -> String? {
        // Deriva chiave e IV usando PBKDF2
        guard let keyAndIV = self.deriveKeyAndIV(password: password) else { return nil }
        let key = keyAndIV.key
        let iv = keyAndIV.iv
        
        guard let dataToEncrypt = plaintext.data(using: .utf8) else { return nil }
        let bufferSize = dataToEncrypt.count + kCCBlockSizeAES128
        var buffer = Data(count: bufferSize)
        var numBytesEncrypted: size_t = 0
        
        // Il padding PKCS7 è usato e garantisce interoperabilità
        let cryptStatus = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                dataToEncrypt.withUnsafeBytes { dataBytes in
                    buffer.withUnsafeMutableBytes { bufferBytes in
                        CCCrypt(CCOperation(kCCEncrypt),
                                CCAlgorithm(kCCAlgorithmAES),
                                CCOptions(kCCOptionPKCS7Padding),
                                keyBytes.baseAddress, key.count,
                                ivBytes.baseAddress,
                                dataBytes.baseAddress, dataToEncrypt.count,
                                bufferBytes.baseAddress, bufferSize,
                                &numBytesEncrypted)
                    }
                }
            }
        }
        
        if cryptStatus == kCCSuccess {
            buffer.count = numBytesEncrypted
            return buffer.base64EncodedString()
        } else {
            return nil
        }
    }
    
    /// Decifra il testo cifrato in Base64 usando AES256 in modalità CBC con padding PKCS7.
    /// - Parametri:
    ///   - ciphertext: Il testo cifrato in Base64.
    ///   - password: La password da cui derivare chiave ed IV.
    /// - Restituisce: Il testo decifrato oppure nil in caso di errore.
    func decryptText(ciphertext: String, password: String) -> String? {
        guard let keyAndIV = self.deriveKeyAndIV(password: password) else { return nil }
        let key = keyAndIV.key
        let iv = keyAndIV.iv
        
        guard let dataToDecrypt = Data(base64Encoded: ciphertext) else { return nil }
        let bufferSize = dataToDecrypt.count + kCCBlockSizeAES128
        var buffer = Data(count: bufferSize)
        var numBytesDecrypted: size_t = 0
        
        let cryptStatus = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                dataToDecrypt.withUnsafeBytes { dataBytes in
                    buffer.withUnsafeMutableBytes { bufferBytes in
                        CCCrypt(CCOperation(kCCDecrypt),
                                CCAlgorithm(kCCAlgorithmAES),
                                CCOptions(kCCOptionPKCS7Padding),
                                keyBytes.baseAddress, key.count,
                                ivBytes.baseAddress,
                                dataBytes.baseAddress, dataToDecrypt.count,
                                bufferBytes.baseAddress, bufferSize,
                                &numBytesDecrypted)
                    }
                }
            }
        }
        
        if cryptStatus == kCCSuccess {
            buffer.count = numBytesDecrypted
            return String(data: buffer, encoding: .utf8)
        } else {
            return nil
        }
    }
    
    /// Deriva una chiave e un IV utilizzando PBKDF2 con HMAC-SHA256.
    /// - Parametro password: La password di input.
    /// - Restituisce: Una tupla contenente (key, iv) oppure nil in caso di errore.
    func deriveKeyAndIV(password: String) -> (key: Data, iv: Data)? {
        // I parametri di derivazione (iterations, salt, keyLength, ivLength) sono DEVE ESSERE IDENTICI in entrambi gli ambienti!
        guard let passwordData = password.data(using: .utf8),
              let saltData = AES256.salt.data(using: .utf8) else { return nil }
        
        var derivedBytes = Data(count: AES256.keyLength + AES256.ivLength)
        let derivationStatus = derivedBytes.withUnsafeMutableBytes { derivedBytesPtr in
            passwordData.withUnsafeBytes { passwordBytes in
                saltData.withUnsafeBytes { saltBytes in
                    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                         password, passwordData.count,
                                         saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), saltData.count,
                                         CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                                         UInt32(AES256.iterations),
                                         derivedBytesPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                         derivedBytes.count)
                }
            }
        }
        if derivationStatus != kCCSuccess {
            return nil
        }
        let key = derivedBytes.subdata(in: 0..<AES256.keyLength)
        let iv = derivedBytes.subdata(in: AES256.keyLength..<(AES256.keyLength + AES256.ivLength))
        return (key, iv)
    }
}
