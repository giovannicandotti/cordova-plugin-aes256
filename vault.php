
<!DOCTYPE html>
<html lang="it">
<head>
  <meta charset="UTF-8">
  <title>AES256 Demo - Configurabile</title>
  <style>
    /* Impostazioni di base */
    body {
      margin: 0;
      padding: 0;
      font-family: Arial, Helvetica, sans-serif;
      background-color: white; /* Sfondo bianco */
      background-repeat: no-repeat;
      background-position: center center;
      background-size: contain;
    }
    /* Header: contenitore flessibile con due sezioni (sinistra e destra) */
    #header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 10px 20px;
      background-color: transparent;
    }
    /* Contenitore a sinistra: logo e titolo */
    .left-header {
      display: flex;
      align-items: center;
    }
    .left-header img {
      height: 50px;
      margin-right: 20px;
    }
    .left-header h1 {
      font-size: 24px;
      margin: 0;
      color: #003366;
    }
    /* Immagine in alto a destra */
    #right-header-image {
      height: 50px;
    }
    /* Container flessibile per i due box dei parametri */
    .parameters-container {
      display: flex;
      flex-direction: row;
      justify-content: space-between;
      align-items: stretch;  /* I box avranno la stessa altezza */
      margin: 20px;
    }
    .left-parameters {
      flex: 0 0 40%;
      box-sizing: border-box;
      padding-right: 10px;
    }
    .right-parameters {
      flex: 0 0 60%;
      box-sizing: border-box;
      padding-left: 10px;
      display: flex;
      flex-direction: column;
    }
    fieldset {
      border: 1px solid #003366;
      padding: 10px;
      background-color: #ffffff;
      height: 100%;  /* Il fieldset occupa l'altezza disponibile */
    }
    legend {
      font-weight: bold;
      color: #D71921;
      /* Ingrandimento del 30% rispetto al default */
      font-size: 1.3em;
    }
    label {
      display: block;
      margin: 10px 0;
      cursor: help;
    }
    /* Nuova classe per ingrandire del 50% le etichette richieste */
    .big-label {
      font-size: 150%;
    }
    input, textarea {
      width: 100%;
      padding: 5px;
      box-sizing: border-box;
      font-family: Arial, Helvetica, sans-serif;
      /* Sfondo grigio al 15% */
      background-color: rgba(128,128,128,0.15);
    }
    /* Regole per il box di destra, per far espandere il campo Testo da codificare */
    .right-parameters fieldset {
      display: flex;
      flex-direction: column;
    }
    /* I primi due label (Password e IV) occupano solo lo spazio necessario */
    .right-parameters label:not(:last-child) {
      flex: 0 0 auto;
    }
    /* L'ultimo label (Testo da codificare) si espande per occupare lo spazio residuo */
    .right-parameters label:last-child {
      flex: 1;
      display: flex;
      flex-direction: column;
    }
    .right-parameters label:last-child textarea {
      flex: 1;
      resize: vertical;
    }
    /* Stile per l'area di output log */
    #logOutput {
      width: 100%;
      height: 200px;
      border: 1px solid #003366;
      overflow-y: auto;
      padding: 10px;
      font-family: monospace;
      white-space: pre-wrap;
      box-sizing: border-box;
      background-color: #ffffff;
      margin: 20px;
    }
    button {
      padding: 10px 20px;
      background-color: #D71921;
      border: none;
      color: #ffffff;
      font-size: 16px;
      cursor: pointer;
      margin: 20px;
    }
    button:hover {
      background-color: #b5141a;
    }
    /* Nuovo fieldset per la decrittazione separata */
    .decrypt-container fieldset {
      border: 1px solid #003366;
      background-color: #ffffff;
      padding: 10px;
      margin: 20px;
    }
    .decrypt-container label {
      display: block;
      margin: 10px 0;
    }
    .decrypt-container textarea {
      width: 100%;
      padding: 5px;
      box-sizing: border-box;
      font-family: Arial, Helvetica, sans-serif;
      background-color: rgba(128,128,128,0.15);
    }
  </style>
</head>
<body>
  <!-- Header: sezione sinistra con logo e titolo, sezione destra con immagine aggiuntiva -->
  <div id="header">
    <div class="left-header">
      <h1>AES256 Demo - Configurabile</h1>
    </div>
  </div>
  
  <!-- Container per i box dei parametri -->
  <div class="parameters-container">
    <!-- Box di sinistra: Parametri di derivazione (40% larghezza) -->
    <div class="left-parameters">
      <fieldset>
        <legend>Parametri di derivazione</legend>
        <label title="Numero di iterazioni per l'algoritmo PBKDF2. Maggiore è il valore, maggiore sarà la sicurezza (ma anche il tempo di calcolo).">
          PBKDF2 Iterations:
          <input type="number" id="iterationsInput" value="10000">
        </label>
        <label title="Valore salt utilizzato per la derivazione della chiave. Deve rimanere costante per garantire la riproducibilità.">
          PBKDF2 Salt:
          <input type="text" id="saltInput" value="someSaltValue">
        </label>
        <label title="Algoritmo di hashing per PBKDF2 (es. SHA-256).">
          PBKDF2 Algorithm:
          <input type="text" id="algorithmInput" value="SHA-256">
        </label>
        <label title="Lunghezza della chiave AES in bit (es. 256 bit equivale a 32 byte).">
          AES Key Length (bit):
          <input type="number" id="aesKeyLengthInput" value="256">
        </label>
        <label title="Lunghezza del vettore di inizializzazione in byte (solitamente 16 per AES).">
          IV Length (byte):
          <input type="number" id="ivLengthInput" value="16">
        </label>
      </fieldset>
    </div>
    <!-- Box di destra: Parametri operativi (60% larghezza) -->
    <div class="right-parameters">
      <fieldset>
        <legend>Parametri operativi</legend>
        <label title="La password da cui verrà derivata la chiave di cifratura.">
          Password:
          <input type="text" id="passwordInput" value="laTuaPassword">
        </label>
        <label title="Il vettore di inizializzazione (IV) per AES. Deve produrre 16 byte in UTF-8.">
          IV (deve produrre 16 byte in UTF-8):
          <input type="text" id="ivInput" value="1234567890123456">
        </label>
        <label class="big-label" title="Il testo in chiaro da codificare.">
          Testo da codificare:
          <textarea id="plaintextInput">Testo da cifrare</textarea>
        </label>
      </fieldset>
    </div>
  </div>
  
  <div style="margin: 20px;">
    <button id="processButton">Elabora</button>
  </div>
  
  <!-- Output log -->
  <fieldset style="margin: 20px;">
    <legend>Output Log</legend>
    <div id="logOutput"></div>
  </fieldset>
  
  <!-- Nuovo fieldset per la decrittazione separata -->
  <div class="decrypt-container">
    <fieldset>
      <legend>Operazione di Decrypt Separata</legend>
      <label class="big-label" title="Campo che contiene il testo cifrato (ottenuto dall'operazione di encrypt).">
        Testo Cifrato:
        <textarea id="cipherTextField" rows="3"></textarea>
      </label>
      <button id="decryptButton">Decrypt</button>
      <label class="big-label" title="Campo in cui viene mostrato il testo decifrato (risultato dell'operazione di decrypt).">
        Testo Decifrato:
        <textarea id="decryptedTextField" rows="3" readonly></textarea>
      </label>
    </fieldset>
  </div>
  
  <script>
    class AES256 {
      // Valori di default: verranno sovrascritti dai campi di input
      static PBKDF2_ITERATIONS = 10000;
      static PBKDF2_SALT = "someSaltValue";
      static PBKDF2_ALGORITHM = "SHA-256";
      static AES_KEY_LENGTH = 256;
      static IV_LENGTH = 16;
      
      /**
       * Deriva la chiave AES e l'IV dalla password usando PBKDF2 con HMAC-SHA256.
       * @param {string} password La password.
       * @returns {Promise<{key: Uint8Array, iv: Uint8Array}>} Oggetto con 'key' e 'iv'.
       */
      static async deriveKeyAndIV(password) {
        const enc = new TextEncoder();
        const passwordKey = await window.crypto.subtle.importKey(
          "raw",
          enc.encode(password),
          { name: "PBKDF2" },
          false,
          ["deriveBits"]
        );
        const saltBuffer = enc.encode(this.PBKDF2_SALT);
        // Lunghezza totale in byte = (AES_KEY_LENGTH/8) + IV_LENGTH
        const totalLength = (this.AES_KEY_LENGTH / 8) + this.IV_LENGTH;
        const derivedBits = await window.crypto.subtle.deriveBits(
          {
            name: "PBKDF2",
            salt: saltBuffer,
            iterations: this.PBKDF2_ITERATIONS,
            hash: this.PBKDF2_ALGORITHM,
          },
          passwordKey,
          totalLength * 8
        );
        const derivedBytes = new Uint8Array(derivedBits);
        const keyBytes = derivedBytes.slice(0, this.AES_KEY_LENGTH / 8);
        const ivBytes = derivedBytes.slice(this.AES_KEY_LENGTH / 8, totalLength);
        return { key: keyBytes, iv: ivBytes };
      }
      
      /**
       * Cifra il testo in chiaro usando AES-256-CBC.
       * @param {string} password La password da cui derivare la chiave.
       * @param {string} plaintext Testo in chiaro da cifrare.
       * @param {string} iv Il vettore di inizializzazione (deve produrre 16 byte in UTF-8).
       * @returns {Promise<string>} Testo cifrato in Base64.
       * @throws {Error} Se l'IV non ha la lunghezza corretta o la cifratura fallisce.
       */
      static async encrypt(password, plaintext, iv) {
        const { key } = await this.deriveKeyAndIV(password);
        const enc = new TextEncoder();
        const plaintextBuffer = enc.encode(plaintext);
        const ivBytes = enc.encode(iv);
        if (ivBytes.length !== this.IV_LENGTH) {
          throw new Error("IV must be " + this.IV_LENGTH + " bytes (lunghezza non corretta)");
        }
        const aesKey = await window.crypto.subtle.importKey(
          "raw",
          key,
          { name: "AES-CBC" },
          false,
          ["encrypt"]
        );
        const encryptedBuffer = await window.crypto.subtle.encrypt(
          { name: "AES-CBC", iv: ivBytes },
          aesKey,
          plaintextBuffer
        );
        return AES256.arrayBufferToBase64(encryptedBuffer);
      }
      
      /**
       * Decifra il testo cifrato usando AES-256-CBC.
       * @param {string} password La password da cui derivare la chiave.
       * @param {string} ciphertext Testo cifrato in Base64.
       * @param {string} iv Il vettore di inizializzazione (deve produrre 16 byte in UTF-8).
       * @returns {Promise<string>} Testo in chiaro oppure "n.a." in caso di errore.
       */
      static async decrypt(password, ciphertext, iv) {
        const { key } = await this.deriveKeyAndIV(password);
        const enc = new TextEncoder();
        const ivBytes = enc.encode(iv);
        if (ivBytes.length !== this.IV_LENGTH) {
          throw new Error("IV must be " + this.IV_LENGTH + " bytes (lunghezza non corretta)");
        }
        const aesKey = await window.crypto.subtle.importKey(
          "raw",
          key,
          { name: "AES-CBC" },
          false,
          ["decrypt"]
        );
        const ciphertextBuffer = AES256.base64ToArrayBuffer(ciphertext);
        try {
          const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: "AES-CBC", iv: ivBytes },
            aesKey,
            ciphertextBuffer
          );
          const dec = new TextDecoder();
          return dec.decode(decryptedBuffer);
        } catch (e) {
          return "n.a.";
        }
      }
      
      /**
       * Genera la secure key derivata dalla password in formato esadecimale.
       * @param {string} password La password.
       * @returns {Promise<string>} Secure key esadecimale.
       */
      static async generateSecureKey(password) {
        const { key } = await this.deriveKeyAndIV(password);
        return AES256.arrayBufferToHex(key);
      }
      
      /**
       * Genera la secure IV derivata dalla password in formato esadecimale.
       * @param {string} password La password.
       * @returns {Promise<string>} Secure IV esadecimale.
       * @note In questa versione viene restituito lo stesso valore della secure key (come nel codice originale).
       * Se si desidera l'IV derivato, sostituire "key" con "iv".
       */
      static async generateSecureIV(password) {
        const { key } = await this.deriveKeyAndIV(password);
        return AES256.arrayBufferToHex(key);
      }
      
      // --- Funzioni helper ---
      static arrayBufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        for (let i = 0; i < bytes.byteLength; i++) {
          binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
      }
      
      static base64ToArrayBuffer(base64) {
        const binary = window.atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
          bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
      }
      
      static arrayBufferToHex(buffer) {
        const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
        let hex = '';
        for (let i = 0; i < bytes.length; i++) {
          hex += bytes[i].toString(16).padStart(2, '0');
        }
        return hex;
      }
    }
    
    // Funzione per aggiungere messaggi nell'area di output formattata in HTML
    function logMessage(message) {
      const logOutput = document.getElementById('logOutput');
      let formattedMessage = message;
      const colonIndex = message.indexOf(":");
      if (colonIndex !== -1) {
        const leftPart = message.substring(0, colonIndex + 1);
        const rightPart = message.substring(colonIndex + 1);
        formattedMessage = `<strong>${leftPart}</strong>${rightPart}`;
      }
      const p = document.createElement('p');
      p.innerHTML = formattedMessage;
      logOutput.appendChild(p);
      // Scroll automatico verso il fondo
      logOutput.scrollTop = logOutput.scrollHeight;
    }
    
    // Gestione del click sul bottone "Elabora"
    document.getElementById('processButton').addEventListener('click', async () => {
      // Leggi i valori dagli input
      const iterations = Number(document.getElementById('iterationsInput').value);
      const salt = document.getElementById('saltInput').value;
      const algorithm = document.getElementById('algorithmInput').value;
      const aesKeyLength = Number(document.getElementById('aesKeyLengthInput').value);
      const ivLength = Number(document.getElementById('ivLengthInput').value);
      const password = document.getElementById('passwordInput').value;
      const plaintext = document.getElementById('plaintextInput').value;
      const iv = document.getElementById('ivInput').value;
      
      // Aggiorna le variabili statiche della classe AES256
      AES256.PBKDF2_ITERATIONS = iterations;
      AES256.PBKDF2_SALT = salt;
      AES256.PBKDF2_ALGORITHM = algorithm;
      AES256.AES_KEY_LENGTH = aesKeyLength;
      AES256.IV_LENGTH = ivLength;
      
      // Pulisci l'area di output e i box "Testo Cifrato" e "Testo Decifrato"
      document.getElementById('logOutput').innerHTML = "";
      document.getElementById('cipherTextField').value = "";
      document.getElementById('decryptedTextField').value = "";
      
      try {
        // Cifratura
        const ciphertext = await AES256.encrypt(password, plaintext, iv);
        logMessage("Testo cifrato: " + ciphertext);
        // Inserisci il testo cifrato nel campo dedicato
        document.getElementById('cipherTextField').value = ciphertext;
        
        // Decifratura (già eseguita anche in "Elabora", ma viene mostrata in Output Log)
        const decrypted = await AES256.decrypt(password, ciphertext, iv);
        logMessage("Testo decifrato: " + decrypted);
        
        // Genera secure key e secure IV
        const secureKey = await AES256.generateSecureKey(password);
        logMessage("Secure Key: " + secureKey);
        
        const secureIV = await AES256.generateSecureIV(password);
        logMessage("Secure IV: " + secureIV);
      } catch (err) {
        logMessage("Errore: " + err.message);
      }
    });
    
    // Gestione del click sul pulsante "Decrypt" (operazione separata)
    document.getElementById('decryptButton').addEventListener('click', async () => {
      const ciphertext = document.getElementById('cipherTextField').value;
      const password = document.getElementById('passwordInput').value;
      const iv = document.getElementById('ivInput').value;
      
      try {
        const decrypted = await AES256.decrypt(password, ciphertext, iv);
        document.getElementById('decryptedTextField').value = decrypted;
      } catch (err) {
        document.getElementById('decryptedTextField').value = "Errore: " + err.message;
      }
    });
  </script>
</body>
</html>
