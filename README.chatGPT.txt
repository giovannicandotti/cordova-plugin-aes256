

Di seguito il prompt che è stato usato per generare la nuova versione inter-operabile fra Android ed iOS.
Verificato il funzionamento tramite i test che sono stati generati, si è provveduto ad adattare il codice sorgente, Swift e Java, nei due progetti già esistenti, ove è installato il plugin originale
[
Repository: https://github.com/Ideas2IT/cordova-aes256 
Cordova install: ionic cordova plugin add cordova-plugin-aes256-encryption
Node installation: npm i cordova-plugin-aes256-encryption
]

La versione definitiva, modificata e testata, è disponibile su:
Https://github.com/giovannicandotti/cordova-plugin-aes256



######################################################################################
######################################################################################
##			scrittura del plugin cordova e della pubblicazione npm
######################################################################################
######################################################################################

scrivi un plugin cordova per codifica e decodifica aes256, che supporti gli ambienti ios ed android.
assumi che il nome del plugin sia “cordova-plugin-aes256”.
I nomi delle classi principali, in entrambi gli ambienti, deve essere “AES256”.
Devono essere disponibili due funzioni, encrypt e decrypt, per codificare e decodificare del testo.
I risultati prodotti dai due ambienti devono essere interscambiabili, ovvero codificati con un sistema e decodificabili con entrambi 
Usa la pbkdf2 per derivare una chiave ed un iv sicuri. 

All’inizio delle implementazioni evidenzia, ed inizializza con dei valori, le variabili rilevanti, ovvero: - numero di iterazioni, salt, algoritmo e lunghezza della chiave per il PDFK2;
 - Inoltre la lunghezza di secure_IV e secure_key per la specificità della codifica AES256
Aggiungi dei commenti prolissi per definire con precisione le caratteristiche necessarie alla corretta inizializzazione delle variabili rilevanti di cui sopra.
Verifica che le inizializzazioni siano le stesse per i due ambienti iOS ed android, in modo da garantire l’interoperabilità.
Poni attenzione al padding, ed evidenzia con dei commenti che la scelta fatta è interoperabile. 


Per l’implementazione iOS:
-  usa il linguaggio swift.
- Utilizza un approccio con strutture asincrone: ad esempio in una classe nominata AES256 potresti definire:
”    private static let aes256Queue = DispatchQueue(label: "AESQUEUE", qos: DispatchQoS.background, attributes: .concurrent)
”
E nelle funzioni potresti racchiudere tutte le operazioni all’interno di un 
“
        AES256.aes256Queue.async {
	….
	}
“

Scrivi dettagliatamente le istruzioni da eseguire per utilizzare il plugin tramite GitHub, in particolare usando visual studio code ed il relativo plugin per GitHub
La radice della pubblicazione deve essere “https://github.com/giovannicandotti/“

Nel file ‘plugin.xml’ utilizza <target-dir="src/eu/giovannicandotti/aes256”> per la piattaforma android, ma mantieni la directory “src/android”, con file di nome “AES256.java” nella directory del plugin.
Nella directory “www” il nome del file deve essere “aes256.js”




Separatamente scrivi le istruzioni ed i file per la pubblicazione in ambito npm.
Non utilizzare ng-packagr per distribuire il modulo.
Crea una struttura di file a tale scopo, documenta come devono essere organizzati in directory, completamente separata da quella del plugin di cui sopra.
Il namespace di riferimento deve essere “@giovannicandotti”.
il nome del pacchetto deve essere “cordova-plugin-aes256”.
Organizza il pacchetto affinché sia utilizzabile con il seguente comando di import nel file principale del progetto ionic, ovvero in ‘app.module.ts’
“
import { AES256 } from ‘@giovannicandotti/cordova-plugin-aes256/ngx';
“
Utilizza un approccio per cui l’utilizzo in un ambiente ionic, nei file typescript dei singoli moduli, avvenga con la dichiarazione di un provide nel costruttore del modulo, ad esempio
“
private aes256: AES256,
“
Le funzioni saranno quindi utilizzate con la sintassi seguente
“
aes256.encrypt(…)
“
Oppure se necessario con
“
this.aes256.encrypt(…)“

######################################################################################
######################################################################################
##			test di funzionamento
######################################################################################
######################################################################################


Scrivi il codice per testare il funzionamento del plugin tramite comandi impartiti da command line. 
In particolare, serve il codice per verificare che i due ambienti siano interoperabili, quindi descrivi due test:
 - uno che preveda encrypt tramite Java e il decrypt tramite Swift
 - uno che preveda encrypt tramite swift e decrypt tramite java


######################################################################################
######################################################################################
##			modifica al plugin per aggiungere funzioni di debug
######################################################################################
######################################################################################

Adatta il codice sia java che swift introducendo funzionalità di debug e tracciamento degli errori.
Organizza il codice in modo che queste funzionalità possano essere attivate o disattivate con una variabile booleana, definita ed inizializzata all’inizio del codice, con un nome uguale ‘myDebug’.
La visualizzazione all’utente deve essere verbosa, con informazioni raccolte man man che si eseguono le funzioni
La visualizzazione deve avvenire solo nel momento in cui qualcosa non funziona
Deve essere presente la lista delle operazioni che invece sono andate a buon fine.
Nel momento dell’errore, utilizza un popup ove sono visualizzate le informazioni raccolte a scopo debug, ovvero quanto evidenziato sopra circa le funzioni che sono state eseguite con successo.