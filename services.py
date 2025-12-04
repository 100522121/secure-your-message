""" Módulo de servicios de gestión de usuarios, chats y mensajes. """

import sqlite3
import pki
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from recursos.constantes import DB_PATH, print_and_log, print_in_log, _to_bytes, SESSION_PRIV_KEYS
from database import (
    _get_user_row, _get_user_row_by_id, user_exists,
    get_certificate_by_username, get_user_credentials_row
)
from cripto import (
    hash_password, verify_password, generate_rsa_keypair, serialize_keys,
    rsa_encrypt_for_user, generate_aes_key, encrypt_message, decrypt_message,
    encrypt_private_key_with_password, verify_signature_with_public_bytes,
    decrypt_private_key_with_password, rsa_decrypt_with_privatekey, sign_with_private_key_obj
)

# ------------------- PKI -------------------
def ensure_pki_initialized():
    """ Inicializa PKI correctamente usando únicamente pki.init_pki().
    :return: None """
    try:
        pki.init_pki()
        print_and_log("[CERT-PKI] 🔄 PKI cargada o inicializada correctamente.")
    except Exception as e:
        print_and_log(f"[CERT-PKI] ❌ Error inicializando PKI: {e}")


def ensure_bot_exists():
    """ Inicializa PKI y asegura que Bob exista y esté logueado.
    :return: None """
    ensure_pki_initialized()

    if not user_exists("bob"):
        add_user("bob", "bob123")

    try:
        unlock_private_key("bob", "bob123")
        print_and_log("[AESGCM]   🔑 Clave privada de Bob desbloqueada.")
    except Exception as e:
        print_and_log(f"[AESGCM] ❌ Error desbloqueando clave privada de Bob: {e}")


# ---------------- Gestión de usuarios ----------------
def add_user(username: str, password: str):
    """ Crea un nuevo usuario en la base de datos con las credenciales dadas.
    :param username: Nombre de usuario.
    :param password: Contraseña.
    :return: None """
    if user_exists(username):
        print(f"👤 Usuario '{username}' ya existe.")
        return

    salt, pwdkey = hash_password(password)
    priv, pub = generate_rsa_keypair()
    priv_b, pub_b = serialize_keys(priv, pub)
    enc_priv_blob = encrypt_private_key_with_password(priv_b, password)

    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO users (username, password_hash, password_salt, private_key, public_key)
        VALUES (?, ?, ?, ?, ?)
    """, (
        username, pwdkey, salt,
        sqlite3.Binary(enc_priv_blob),
        sqlite3.Binary(pub_b)
    ))
    conn.commit()
    conn.close()

    print_and_log(f"[SISTEMA]  👤 Usuario '{username}' creado.")

    try:
        pki.issue_certificate_for_user(username)
    except Exception as e:
        print_and_log(f"[CERT-PKI] ❌ Error emitiendo certificado: {e}")


def verify_login(username: str, password: str) -> bool:
    """ Verifica las credenciales de un usuario e intenta desbloquear su clave privada.
    :param username: Nombre de usuario.
    :param password: Contraseña.
    :return: True si las credenciales son correctas, False en caso contrario. """
    creds = get_user_credentials_row(username)
    if not creds:
        print_and_log("[ERROR] ❌ Usuario no encontrado.")
        return False

    stored_key, stored_salt = creds
    ok = verify_password(stored_salt, stored_key, password)

    print("\n\n--- Avisos del sistema ---")

    if not ok:
        print_and_log("[PBKDF2] ❌ Credenciales incorrectas.")
        return False

    print_and_log(f"[PBKDF2]   ✅ Usuario '{username}' autenticado.")

    try:
        unlock_private_key(username, password)
    except Exception as e:
        print_and_log(f"[AESGCM] ❌ Error desbloqueando clave: {e}")
        return False

    try:
        cert_pem = get_certificate_by_username(username)
        if cert_pem:
            if not pki.verify_certificate_chain(cert_pem):
                print_and_log(f"[CERT-PKI] ❌ Certificado de {username} NO válido.")
                return False
    except Exception as e:
        print_and_log(f"[CERT-PKI] ❌ Error verificando certificado: {e}")
        return False

    return True


# ---------------- Claves privadas ----------------
def unlock_private_key(username: str, password: str):
    """ Desbloquea la clave privada de un usuario y la almacena en sesión.
    :param username: Nombre de usuario.
    :param password: Contraseña.
    :return: None """
    row = _get_user_row(username)
    if not row:
        raise ValueError("Usuario no encontrado")

    enc_priv_blob = row[1]
    priv_bytes = decrypt_private_key_with_password(_to_bytes(enc_priv_blob), password)
    priv_obj = serialization.load_pem_private_key(priv_bytes, password=None)

    SESSION_PRIV_KEYS[username] = priv_obj
    print_in_log(f"[AESGCM] 🔓 Clave privada desbloqueada para '{username}'")


# ----------------- Gestión de chats ----------------
def create_chat(user1: str, user2: str):
    """ Crea un chat cifrado entre dos usuarios.
    :param user1: Nombre del primer usuario.
    :param user2: Nombre del segundo usuario.
    :return: None """
    row1 = _get_user_row(user1)
    row2 = _get_user_row(user2)
    id1, id2 = row1[0], row2[0]

    conn = sqlite3.connect(DB_PATH)
    existing = conn.execute("""
        SELECT id FROM chats
        WHERE (user1_id=? AND user2_id=?) OR (user1_id=? AND user2_id=?)
        """, (id1, id2, id2, id1)).fetchone()

    if existing:
        conn.close()
        return  # Chat ya existe

    aes_key = generate_aes_key()
    key1 = rsa_encrypt_for_user(user1, aes_key)
    key2 = rsa_encrypt_for_user(user2, aes_key)

    conn.execute("""
        INSERT INTO chats (user1_id,user2_id,key_for_user1,key_for_user2)
        VALUES (?,?,?,?)
        """, (id1, id2, sqlite3.Binary(key1), sqlite3.Binary(key2)))
    conn.commit()
    conn.close()
    print(f"💬 Chat creado entre '{user1}' y '{user2}'.")


def get_chat_id(user1: str, user2: str):
    """ Obtiene el ID del chat entre dos usuarios.
    :param user1: Nombre del primer usuario.
    :param user2: Nombre del segundo usuario.
    :return: ID del chat o None si no existe. """
    row1 = _get_user_row(user1)
    row2 = _get_user_row(user2)
    id1, id2 = row1[0], row2[0]

    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("""
        SELECT id FROM chats
        WHERE (user1_id=? AND user2_id=?) OR (user1_id=? AND user2_id=?)
        """, (id1, id2, id2, id1)).fetchone()
    conn.close()
    return row[0] if row else None


def get_chat_key_for_user(username: str, user1: str, user2: str):
    """ Obtiene la clave AES del chat para un usuario específico.
    :param username: Nombre del usuario que solicita la clave.
    :param user1: Nombre del primer usuario del chat.
    :param user2: Nombre del segundo usuario del chat.
    :return: Clave AES descifrada o None si no se encuentra. """
    row1 = _get_user_row(user1)
    row2 = _get_user_row(user2)
    id1, id2 = row1[0], row2[0]

    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("""
        SELECT user1_id,user2_id,key_for_user1,key_for_user2
        FROM chats
        WHERE (user1_id=? AND user2_id=?) OR (user1_id=? AND user2_id=?)
        """, (id1, id2, id2, id1)).fetchone()
    conn.close()

    if not row:
        return None

    stored_user1_id, stored_user2_id, key_blob1, key_blob2 = row
    try:
        priv_obj = SESSION_PRIV_KEYS.get(username)
        if not priv_obj:
            raise RuntimeError(f"Clave privada de '{username}' no desbloqueada.")

        if _get_user_row(username)[0] == stored_user1_id and key_blob1:
            return rsa_decrypt_with_privatekey(priv_obj, _to_bytes(key_blob1))

        if _get_user_row(username)[0] == stored_user2_id and key_blob2:
            return rsa_decrypt_with_privatekey(priv_obj, _to_bytes(key_blob2))

    except Exception as e:
        print_and_log(f"[AES128-GCM] ❌ Al descifrar AES para {username}: {e}")
    return None


# ------- Envío de mensajes (firma + cifrado) -------
def send_message(sender: str, receiver: str, message: str):
    """ Envía un mensaje cifrado de un usuario a otro.
    :param sender: Nombre del usuario remitente.
    :param receiver: Nombre del usuario receptor.
    :param message: Mensaje en texto plano.
    :return: None """
    chat_id = get_chat_id(sender, receiver)
    aes_key = get_chat_key_for_user(sender, sender, receiver)

    if aes_key is None:
        return print_and_log(f"[AES128-GCM] ❌ '{sender}' no posee la clave AES para este chat.")

    signature = None
    priv_obj = SESSION_PRIV_KEYS.get(sender)
    if priv_obj:
        try:
            signature = sign_with_private_key_obj(priv_obj, message.encode())
        except Exception as e:
            print_and_log(f"[FIRMA] ❌ No se pudo firmar el mensaje: {e}")

    enc = encrypt_message(aes_key, message)
    sender_id = _get_user_row(sender)[0]
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO messages (chat_id, sender_id, nonce, ciphertext, aad, signature)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            chat_id, sender_id,
            sqlite3.Binary(enc["nonce"]),
            sqlite3.Binary(enc["ciphertext"]),
            sqlite3.Binary(enc["aad"]),
            sqlite3.Binary(signature) if signature else None
        ))
    conn.commit()
    conn.close()
    print_and_log(f"[SISTEMA]    💬 Mensaje enviado de '{sender}' a '{receiver}'.")


# ---- Lectura de mensajes (descifrado + firma) -----
def read_messages(reader: str, user1: str, user2: str):
    """ Lee y descifra los mensajes de un chat entre dos usuarios.
    :param reader: Nombre del usuario que lee los mensajes.
    :param user1: Nombre del primer usuario del chat.
    :param user2: Nombre del segundo usuario del chat.
    :return: None """
    chat_id = get_chat_id(user1, user2)
    aes_key = get_chat_key_for_user(reader, user1, user2)

    if aes_key is None:
        return print(f"[ERROR] ❌ '{reader}' no posee la clave AES para este chat.")

    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("""
        SELECT sender_id, nonce, ciphertext, aad, signature, timestamp
        FROM messages WHERE chat_id=?
        """, (chat_id,)).fetchall()
    conn.close()

    print(f"\n--- Chat cifrado ---")
    for r in rows:
        sender_name = _get_user_row_by_id(r[0])
        nonce, ciphertext, aad = _to_bytes(r[1]), _to_bytes(r[2]), _to_bytes(r[3])
        signature_blob = _to_bytes(r[4])
        raw_ts = r[5][:16] if r[5] else "????"
        timestamp = raw_ts[11:16] if raw_ts else "????"

        try:
            msg = decrypt_message(aes_key, {
                "nonce": nonce, "ciphertext": ciphertext, "aad": aad
            })
            verified = False
            cert_pem = get_certificate_by_username(sender_name)
            if cert_pem and signature_blob:
                cert = x509.load_pem_x509_certificate(cert_pem)
                pub_bytes = cert.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo
                )
                verified = verify_signature_with_public_bytes(pub_bytes, msg.encode(), signature_blob, log=False)

            sig_status = "? Firma"
            if signature_blob:
                sig_status = "✓ Firma" if verified else "✗ Firma"

            print(f"({'✓' if msg else '✗'} Dec {sig_status}) [{timestamp}] {sender_name}: {msg}")
        except Exception as e:
            print(f"[{timestamp}] {sender_name}: [AES128-GCM] ❌ Descifrando/Verificando mensaje: {e}")
