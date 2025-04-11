# Biblioteca Digitale

Il progetto consiste nella creazione di un'applicazione web per una biblioteca digitale che consente agli utenti di **caricare**, **scaricare** e **visualizzare** file PDF. Il sistema è protetto da un'autenticazione sicura tramite LDAP, con l'aggiunta di crittografia per garantire la protezione dei file. L'accesso alle risorse è strettamente controllato per evitare l'accesso non autorizzato ai documenti sensibili, proteggendo al contempo la privacy e la sicurezza degli utenti.
 
 SCERMATA screen PROGETTO:

 
 
## Tecnologie Utilizzate

### Backend
Python con il framework Flask, utilizzato per lo sviluppo dell'applicazione web e la gestione delle API.

### Database:
PostgreSQL, un sistema di gestione di database relazionali robusto e scalabile, impiegato per archiviare i dati relativi agli utenti e altre informazioni.

### Autenticazione
Utilizzo del protocollo LDAP per la gestione dell'autenticazione utente, tramite la libreria ldap3, che consente una connessione sicura e verifiche delle credenziali contro un server LDAP.

### Storage
I file PDF vengono gestiti e archiviati nel file system locale, con una gestione sicura e strutturata.

### Sicurezza:
Implementazione della crittografia AES-256 per proteggere i file PDF e garantire la sicurezza dei documenti sensibili, insieme all'uso di bcrypt per l'hashing delle password e la protezione dei dati degli utenti.

## Framework e Librerie

### Flask:
Framework leggero e potente per lo sviluppo di applicazioni web, usato per la creazione delle API e la gestione delle richieste HTTP.

### ldap3
Libreria Python per interagire con server LDAP, usata per implementare il sistema di autenticazione sicura basato su LDAP.

### Flask-Login 
Estensione di Flask per gestire in modo sicuro le sessioni degli utenti e l'autenticazione nelle applicazioni web.

### pycryptodome 
Libreria Python per la cifratura dei file, utilizzata per implementare l'algoritmo di crittografia AES-256 che protegge i file PDF caricati dagli utenti.

## Problemi di Sicurezza

### Accesso non autorizzato
Rischio che utenti non autenticati accedano ai documenti sensibili.

### Furto di credenziali
Vulnerabilità agli attacchi di phishing o brute-force.

### Condivisione non autorizzata dei file 
Possibilità di distribuzione illegale dei file PDF.

### Attacchi informatici vari
Rischio di attacchi come SQL Injection e Cross-Site Scripting (XSS) per compromettere la sicurezza del sistema.

## Soluzioni di Sicurezza

### Autenticazione sicura tramite LDAP
Gli utenti devono autenticarsi tramite LDAP prima di accedere al sistema, riducendo il rischio di accesso non autorizzato.

### Crittografia dei file
I file PDF sono cifrati con AES-256, impedendo l'accesso non autorizzato ai contenuti.

### Protezione contro attacchi di brute-force
Implementazione di un sistema di blocco account in caso di tentativi di accesso sospetti.

### Hashing delle password con bcrypt
Le password degli utenti sono protette tramite hashing sicuro, prevenendo la compromissione delle credenziali in caso di attacco.

### Validazione degli input e protezione contro SQL Injection e XSS
Uso di query parametrizzate per evitare SQL Injection e sanificazione dell'input per prevenire XSS.

## Struttura progetto

| Nome File/Cartella  | Descrizione                                                   |
|---------------------|---------------------------------------------------------------|
| `app.py`            | File principale dell'app Flask                                |
| `config.py`         | Configurazione dell'applicazione                              |
| `models.py`         | Modelli ORM del database (SQLAlchemy)                         |
| `auth.py`           | Gestione dell'autenticazione (LDAP + JWT)                     |
| `encryption.py`     | Funzioni di crittografia dei file PDF                         |
| `routes.py`         | Definizione delle rotte per upload/download PDF               |
| `database.db`       | Database locale SQLite (se non usi PostgreSQL)                |
| `uploads/`          | Directory che contiene i file PDF cifrati                     |
| `.env`              | File per la configurazione delle variabili d'ambiente         |
| `requirements.txt`  | Elenco delle dipendenze Python da installare                  |


## Procedura per l'avvio dell'applicazione

1. Creazione dell'ambiente e installazione delle dipendenze:

Utilizzando una WSL da Windows, creo una directory locale "biblioteca-digitale":
```sh
mkdir biblioteca-digitale
cd biblioteca-digitale
```

2. Installazione Python:
```sh
apt update
apt install python3
```

3. Creazione dell'ambiente virtuale Python:  
```sh
python3 -m venv venv 
```
#questo creerà una cartella "venv";

```sh
source venv/bin/activate   
```
#avvia l'ambiente virtuale;
4. Installa le dipendenze necessarie:
```sh
sudo apt install python3-pip #add comment
pip3 install flask_sqlalchemy
pip3 install Flask-Login
pip3 install ldap3
pip3 install flask_jwt_extended
pip3 install Flask
pip3 install bcrypt
pip3 install dotenv
pip3 install pycryptodome
pip install psycopg2-binary
```

5. VARIABILI D'AMBIENTE
Creiamo un file .env per gestire le variabili di ambiente:
```sh
touch .env
```

Nel file .env, aggiungiamo le configurazioni: 
```sh
SECRET_KEY=una_chiave_segreta
JWT_SECRET=your_jwt_secret
LDAP_URL=ldap://localhost:389
LDAP_BIND_DN=cn=admin,dc=library,dc=com
LDAP_PASSWORD=raffa
LDAP_SEARCH_BASE=ou=users,dc=library,dc=com
DATABASE_URL=postgresql://admin:db_admin_library@localhost:5432/biblioteca_db
ENCRYPTION_KEY=0123456789abcdef0123456789abcdef
SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')
SQLALCHEMY_TRACK_MODIFICATIONS = False
```
6. INSTALLAZIONE LDAP:
-   Installare ldap3 (client LDAP in Python)
-   Installare un server LDAP (OpenLDAP su Linux o Windows)

1️) Installare ldap3 (Client LDAP in Python):
```sh
pip3 install ldap3 (Già eseguito sopra)
```

Verifica l'installazione:
```sh
python -c "import ldap3; print(ldap3.__version__)"
```

2) Installare un Server LDAP
```sh
sudo apt update
sudo apt install slapd ldap-utils
```
Durante l'installazione, ci chiedereà una password l'amministratore LDAP da conservare.

Per riconfigurare il server LDAP (se necessario):
```sh
sudo dpkg-reconfigure slapd 
```
(inizializzo il diminio dove verranno creati gli utenti)

Installare un LDAP Browser su windows:
```sh
https://directory.apache.org/studio/download/download-windows.html (Per creare utenti e usare ldap da interfaccia grafica)
```

In **/home/raffa/ldap** della WSL ci sono dei file per inizializzare l'LDAP:
prima lanciare

| Comando                                                                                                     | Descrizione                                                       |
|-------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------|
| `ldapadd -x -D "cn=admin,dc=library,dc=com" -W -f userandgroup.ldif`                                        | Aggiunge gli oggetti *user* e *group* alla struttura LDAP         |
| `ldapadd -x -D "cn=admin,dc=library,dc=com" -W -f user.ldif`                                                | Crea gli utenti specificati nel file `user.ldif`                  |
| `ldapdelete -x -D "cn=admin,dc=library,dc=com" -W "uid=test1,ou=users,dc=library,dc=com"`                   | Cancella un utente dalla directory LDAP                           |


Se mi connetto da gui vedo i risultati.

7. Creazione dell'app Flask e configurazione di LDAP
Crea il file app.py e inizializza Flask e le configurazioni per LDAP: (tutto in **app.py**)
Aggiungere codice **app.py** (verificare se è cosi o spostati in altri file)
    
8. Crittografia dei file PDF
La funzione encrypt_file utilizza la libreria **pycryptodome** per cifrare i file PDF. Ogni volta che un file viene caricato, viene cifrato con AES-256 prima di essere salvato sul server.

9. Configurazione del Database PostgreSQL
Installa PostgreSQL su WSL (mettere versone psql --version)
```sh
sudo apt update
sudo apt install postgresql postgresql-contrib
```
Questo installerà PostgreSQL e i pacchetti aggiuntivi necessari.

Configura il servizio PostgreSQL su WSL
A differenza di Windows, su WSL il servizio PostgreSQL viene gestito tramite **systemctl**.

Avvia il servizio PostgreSQL con:
```sh
sudo service postgresql start
```
Per fermare il servizio:
```sh
sudo service postgresql stop
```
Per verificare lo stato del servizio:
```sh
sudo service postgresql status
```
Accedere a PostgreSQL su WSL
Per connetterti al server PostgreSQL su WSL, esegui il comando:
```sh
sudo -u postgres psql
```
Questo ti porterà nel prompt di PostgreSQL come utente postgres.

Se vuoi uscire dalla sessione psql, puoi usare il comando:
```sh
\q
```
Crea un database chiamato **biblioteca_db**
Una volta dentro **psql**, puoi creare utente e il tuo database biblioteca_db con il comando:
```sh
CREATE DATABASE biblioteca_db;
```
Puoi verificare che il database sia stato creato correttamente con:
```sh
\l
```
- Creazione utente:
 Creare un utente per il tuo database
Per utilizzare il database biblioteca_db, è consigliabile creare un nuovo utente. Esegui i seguenti comandi:
```sh
CREATE USER username WITH PASSWORD 'password';
```

- Trasferire la proprietà del database:
Per trasferire la proprietà del database biblioteca_db all'utente admin, esegui il comando:
```sh
ALTER DATABASE biblioteca_db OWNER TO username;
```
Questo comando cambierà il proprietario del database a admin.

- Concedere tutti i privilegi sull'intero database a admin:
Ora che l'utente admin è il proprietario del database, dobbiamo assicurarci che abbia tutti i privilegi. 
Puoi concedere i privilegi con il comando:
```sh
GRANT ALL PRIVILEGES ON DATABASE biblioteca_db TO admin;
```
Concedere privilegi su tutte le tabelle e oggetti:
Poiché l'utente admin deve avere privilegi su tutte le tabelle e oggetti all'interno dello schema public (e eventualmente su altri schemi), esegui i seguenti comandi per concedere i privilegi su tutte le tabelle, sequenze e funzioni:

-- Concedi tutti i privilegi sulle tabelle
```sh
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO admin;
```
-- Concedi tutti i privilegi sulle sequenze
```sh
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO admin;
```
-- Concedi tutti i privilegi sulle funzioni
```sh
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO admin;
```
Concedere privilegi sulle future tabelle, sequenze e funzioni:
Affinché l'utente admin possa avere privilegi anche su oggetti futuri creati nel database, esegui i seguenti comandi:
```sh
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO admin;
```

**Creo le colonne per bloccare le utenze nella tabella user:**
```sh
ALTER TABLE public.user
ADD COLUMN failed_login_count INT DEFAULT 0,
ADD COLUMN account_locked BOOLEAN DEFAULT FALSE;
```

10. Esecuzione del Server Flask e quindi avvio dell'appicazione:
```sh
python app.py
```

## SICUREZZA
L’applicazione implementa una serie di misure di sicurezza per garantire l’accesso controllato, la protezione dei file e l’integrità delle informazioni scambiate tra client e server. Di seguito le principali misure adottate.

**Autenticazione LDAP**

L'applicazione implementa un sistema di autenticazione basato su LDAP, utilizzando la libreria ldap3.
Quando un utente effettua il login, inserisce il proprio username e password. Queste credenziali vengono validate tramite il metodo ldap_authenticate, che stabilisce una connessione LDAP con il server configurato (i parametri sono definiti nel file .env).
Se la connessione ha successo e le credenziali sono corrette, l’utente viene considerato autenticato.

Questo meccanismo garantisce che solo utenti autorizzati e presenti nel sistema centrale possano accedere all'applicazione, migliorando il controllo e la sicurezza dell’accesso.

Codice: **auth.py**
```sh
def ldap_authenticate(username, password):
...
# Connessione al server LDAP
        server = Server(ldap_url, use_ssl=True, get_info=ALL)
        conn = Connection(server, user=bind_dn, password=bind_password)
    ...
    except Exception as e:
        logging.error(f"❌ Errore LDAP: {e}")
        return False
```

Se le credenziali sono valide, l'utente riceve un JWT (JSON Web Token) che può essere utilizzato per accedere alle aree protette.

**Hashing delle Password**
Per garantire la sicurezza delle credenziali, le password degli utenti non vengono mai salvate in chiaro nel database. Utilizziamo l'algoritmo bcrypt per proteggere le password da attacchi di tipo dizionario e brute force. Quando un utente accede per la prima volta (ad esempio, durante il primo login), la sua password viene automaticamente hashata tramite bcrypt prima di essere salvata.
Anche se l'autenticazione LDAP è gestita in modo sicuro senza la necessità di memorizzare la password nel database, abbiamo comunque implementato il salvataggio dell'utente nel database. Questo permette di tenere traccia degli utenti che accedono all'applicazione, pur mantenendo la sicurezza delle credenziali.

Codice: **auth.py**
```sh
@auth_bp.route('/login', methods=['POST'])
def login():
...
if ldap_authenticate(username, password):
        # Controlla se l'utente esiste nel database
        user = User.query.filter_by(username=username).first()
    ...
  return jsonify({"msg": "Credenziali non valide"}), 401
```

**Autorizzazione tramite JWT**
Il sistema utilizza JSON Web Token (JWT) per proteggere l'accesso alle risorse. Dopo l'autenticazione tramite LDAP, un JWT viene emesso per l'utente. Questo token deve essere incluso in tutte le richieste alle API protette, come quelle per caricare, scaricare o eliminare file.
Ogni rotta protetta è decorata con il decoratore @jwt_required, che garantisce che solo gli utenti autenticati possano accedere a queste funzionalità, evitando di dover passare le credenziali in ogni richiesta.

Dopo aver autenticato l'utente tramite LDAP, viene generato un JWT per l'accesso alle risorse:
Codice: **auth.py**
```sh
access_token = create_access_token(identity=username)
return jsonify(access_token=access_token), 200
```
I percorsi protetti sono decorati con @jwt_required(), che verifica che l'utente abbia un JWT valido per accedere alle risorse:
Codice: **routes.py**
```sh
routes_bp.route('/download/<filename>', methods=['GET'])
@jwt_required()
def download_file(filename):
    # Logica per scaricare e decriptare il file
    ...
```
**Crittografia dei File (AES-256)**
I file PDF caricati dagli utenti sono cifrati utilizzando AES-256 prima di essere salvati nel sistema. Questo algoritmo garantisce una protezione robusta dei dati sensibili, rendendo i file illeggibili senza la chiave di decrittazione. I file rimangono crittografati anche a riposo e vengono decrittografati solo quando un utente autorizzato li scarica.
In questo modo, anche se un attaccante dovesse ottenere l'accesso al filesystem, i contenuti dei file non sarebbero leggibili.

Codice: **encryption.py**
```sh
def encrypt_file(file_data):
    cipher = AES.new(KEY, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
    return cipher.iv + encrypted_data

def decrypt_file(encrypted_data):
    iv = encrypted_data[:16]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)
```

**Sicurezza nelle richieste**
Autenticazione basata su sessione: La libreria Flask-Login gestisce la sessione dell'utente in modo sicuro.


**Protezione contro attacchi SQL Injection e xss**
Poiché stiamo utilizzando SQLAlchemy come ORM, tutte le query al database sono preparate in modo sicuro, evitando vulnerabilità di SQL Injection.

Nel codice, viene utilizzato SQLAlchemy come ORM per interagire con il database. SQLAlchemy gestisce automaticamente le query SQL in modo sicuro, evitando vulnerabilità come l'SQL Injection. Le query al database, come **User.query.filter_by(username=username).first()**, sono protette in modo sicuro poiché SQLAlchemy costruisce le query in modo parametrizzato, evitando che gli input degli utenti vengano trattati come parte del codice SQL.

Per quanto riguarda l'XSS, Flask (tramite Jinja2), eseguirà automaticamente l'escape del contenuto, trattandolo come testo, non come HTML o JavaScript. Quindi, se l'utente invia un valore che contiene codice JavaScript (ad esempio, **<script>alert('XSS')</script>**), questo verrà visualizzato come testo nel browser e non come codice eseguito.
Nel codice, la protezione contro XSS è gestita in tutte le route che restituiscono template HTML. Per esempio, nella route /dashboard.

**Accesso controllato ai PDF**
I file PDF vengono protetti dall'accesso non autorizzato tramite l'uso di JWT. Solo gli utenti autenticati (con un token JWT valido) possono scaricare i file PDF, come mostrato nell'endpoint /pdf/<filename>:

@app.route('/pdf/<filename>', methods=['GET'])
@login_required
def get_pdf(filename):
    file_path = os.path.join('uploads', filename)
    
    if os.path.exists(file_path):
        return send_from_directory('uploads', filename)
    else:
        return jsonify({"msg": "File non trovato"}), 404
Se un utente non è autenticato, non potrà accedere a questa risorsa.


**Protezione contro attacchi di brute-force**
Implementazione di un sistema di blocco account in caso di tentativi di accesso sospetti.

*Implementazione*
Database: Aggiunta delle colonne **failed_login_count** (tentativi falliti) e **account_locked** (blocco account).

Login: Se la password è errata, incrementiamo **failed_login_count**. Se supera una soglia (es. 3 tentativi), blocchiamo l'account.

Reset tentativi: Dopo un login corretto, azzeriamo **failed_login_count**.

Blocco account: Impediamo l'accesso se **account_locked** è vero, fino a sblocco manuale.

Messaggi: Errore generico per login fallito, informazioni dettagliate solo per account bloccato

**Logout**
Il logout è gestito esclusivamente lato **client**, senza modifiche al backend.
Quando l'utente effettua il logout, il token di autenticazione viene semplicemente rimosso dal `localStorage` del browser. Questo significa che non è necessario aggiungere alcuna logica specifica nel file `route.py`.
Alla successiva ricarica della pagina, l'assenza del token farà sì che l'utente venga considerato non autenticato.
