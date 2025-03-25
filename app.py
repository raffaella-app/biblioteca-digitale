from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from ldap3 import Server, Connection, ALL
import os
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token
import bcrypt
from dotenv import load_dotenv
import pycryptodome
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# Carica variabili di ambiente
load_dotenv()

# Inizializzazione app Flask
app = Flask(_name_)

# Configurazione del database e altre configurazioni
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(24)  # Chiave segreta per sessioni
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET')  # Chiave segreta per JWT

# Inizializzazione dei componenti
db = SQLAlchemy(app)
login_manager = LoginManager(app)
jwt = JWTManager(app)

# Modello per gli utenti nel database
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Configurazione di LDAP
def ldap_authenticate(username, password):
    server = Server(os.getenv('LDAP_URL'), get_info=ALL)
    conn = Connection(server, user=os.getenv('LDAP_BIND_DN'), password=os.getenv('LDAP_PASSWORD'))
    if not conn.bind():
        raise Exception("Impossibile connettersi a LDAP")

    search_filter = f"(uid={username})"
    conn.search(os.getenv('LDAP_SEARCH_BASE'), search_filter, attributes=['uid', 'dn'])
    
    if len(conn.entries) == 0:
        return False
    
    conn = Connection(server, user=conn.entries[0].dn, password=password)
    if conn.bind():
        return True
    return False

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    if ldap_authenticate(username, password):
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username, password=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
        
        login_user(user)
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token)

    return jsonify({"msg": "Credenziali non valide"}), 401

# Protezione della route con JWT
@app.route('/protected', methods=['GET'])
@login_required
def protected():
    return jsonify(message="Benvenuto nell'area protetta!")

# Caricamento dei file
@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    file = request.files['file']
    file_path = os.path.join('uploads', file.filename)
    
    # Cifra il file prima di salvarlo
    encrypt_file(file, file_path)
    
    return jsonify({"message": "File caricato e cifrato con successo!"}), 200

# Funzione per cifrare il file
def encrypt_file(file, file_path):
    key = os.urandom(32)  # AES-256 key
    cipher = AES.new(key, AES.MODE_CBC)
    
    with open(file_path, 'wb') as out_file:
        data = file.read()
        encrypted_data = cipher.encrypt(pad(data, AES.block_size))
        out_file.write(cipher.iv + encrypted_data)

# Scaricamento del file PDF
@app.route('/pdf/<filename>', methods=['GET'])
@login_required
def get_pdf(filename):
    file_path = os.path.join('uploads', filename)
    
    if os.path.exists(file_path):
        return send_from_directory('uploads', filename)
    else:
        return jsonify({"msg": "File non trovato"}), 404

# Inizializza il login_manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Avvia l'applicazione
if _name_ == '_main_':
    db.create_all()  # Crea il database se non esiste
    app.run(debug=True)