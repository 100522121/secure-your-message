""" Módulo de servicios de gestión de usuarios, chats y mensajes. """

import sqlite3
from recursos.constantes import DB_PATH, print_and_log, _to_bytes
from cripto import hash_password, verify_password, generate_rsa_keypair, serialize_keys, rsa_encrypt_for_user, generate_aes_key, encrypt_message, decrypt_message, rsa_decrypt_for_user
from database import _get_user_row, _get_user_row_by_id, user_exists

    
def add_user(username: str, password: str):
    """
    Registra un nuevo usuario con contraseña y genera su par de claves y certificado.
    :param username:
    :param password:
    :return:
    """
    if user_exists(username):
        print(f"👤 Usuario '{username}' ya existe.")
        return
    salt, pwdkey = hash_password(password)  # pwdkey = password key derivada con KDF
    priv, pub = generate_rsa_keypair()
    priv_b, pub_b = serialize_keys(priv, pub)

    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO users (username, password_hash, password_salt, private_key, public_key)
        VALUES (?, ?, ?, ?, ?)
        """, (username, pwdkey, salt, sqlite3.Binary(priv_b), sqlite3.Binary(pub_b)))
    conn.commit()                           # En cada cambio a la db, confirmar con commit()
    conn.close()                            # Luego, cerrar la conexión
    print_and_log(f"[SISTEMA]  💬 Usuario '{username}' creado.")


def user_exists(username: str) -> bool:
    """
    Verifica si un usuario ya está registrado.
    :param username:
    :return:
    """
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("""
        SELECT 1
        FROM users WHERE username=?
        """, (username,)).fetchone()
    conn.close()
    return bool(row)

def verify_login(username: str, password: str) -> bool:
    """
    Verifica las credenciales de un usuario.
    :param username:
    :param password:
    :return:
    """
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("""
        SELECT password_hash, password_salt
        FROM users WHERE username=?
        """, (username,)).fetchone()
    conn.close()
    if not row:
        print_and_log("[ERROR] ⚠️ Usuario no encontrado.")
        return False
    stored_key, stored_salt = row
    ok = verify_password(stored_salt, stored_key, password)
    if ok:
        print_and_log(f"[PBKDF2]  ✅ Usuario '{username}' autenticado")
    else:
        print_and_log(f"[PBKDF2] ❌ Credenciales incorrectas. Reinténtalo o escribe 'salir' para salir.")
    return ok

def create_chat(user1: str, user2: str):
    """
    Crea un chat entre dos usuarios generando y almacenando la clave AES cifrada para cada uno.
    :param user1:
    :param user2:
    :return:
    """
    row1 = _get_user_row(user1)
    row2 = _get_user_row(user2)
    id1, id2 = row1[0], row2[0]

    conn = sqlite3.connect(DB_PATH)
    existing = conn.execute("""
        SELECT id
        FROM chats WHERE (user1_id=? AND user2_id=?) OR (user1_id=? AND user2_id=?)
        """, (id1, id2, id2, id1)).fetchone()
    if existing:
        conn.close()
        return print_and_log("[SISTEMA] 💬 Chat ya existente.")

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
    """
    Obtiene el ID del chat entre dos usuarios.
    :param user1:
    :param user2:
    :return:
    """
    row1 = _get_user_row(user1)
    row2 = _get_user_row(user2)
    id1, id2 = row1[0], row2[0]
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("""
        SELECT id
        FROM chats WHERE (user1_id=? AND user2_id=?) OR (user1_id=? AND user2_id=?)
        """, (id1, id2, id2, id1)).fetchone()
    conn.close()
    return row[0] if row else None

def get_chat_key_for_user(username: str, user1: str, user2: str):
    """
    Obtiene y descifra la clave AES del chat para un usuario específico.
    :param username:
    :param user1:
    :param user2:
    :return:
    """
    row1 = _get_user_row(user1)
    row2 = _get_user_row(user2)
    id1, id2 = row1[0], row2[0]
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("""
        SELECT user1_id,user2_id,key_for_user1,key_for_user2
        FROM chats WHERE (user1_id=? AND user2_id=?) OR (user1_id=? AND user2_id=?)
        """, (id1, id2, id2, id1)).fetchone()
    conn.close()
    if not row:
        return None
    stored_user1_id, stored_user2_id, key_blob1, key_blob2 = row
    try:
        if _get_user_row(username)[0] == stored_user1_id and key_blob1:
            return rsa_decrypt_for_user(username, _to_bytes(key_blob1))
        if _get_user_row(username)[0] == stored_user2_id and key_blob2:
            return rsa_decrypt_for_user(username, _to_bytes(key_blob2))
    except Exception as e:
        print_and_log(f"[AES-128-GCM] ❌  Al descifrar AES para {username}: {e}")
    return

def send_message(sender: str, receiver: str, message: str):
    """
    Envía un mensaje cifrado de un usuario a otro dentro de un chat.
    :param sender:
    :param receiver:
    :param message:
    :return:
    """
    chat_id = get_chat_id(sender, receiver)
    aes_key = get_chat_key_for_user(sender, sender, receiver)
    if aes_key is None:
        return print_and_log(f"[AES-128-GCM] ❌ '{sender}' no posee la clave AES para este chat.")

    enc = encrypt_message(aes_key, message)
    sender_id = _get_user_row(sender)[0]

    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO messages (chat_id, sender_id, nonce, ciphertext, aad)
        VALUES (?, ?, ?, ?, ?)
        """, (chat_id, sender_id, sqlite3.Binary(enc["nonce"]),
              sqlite3.Binary(enc["ciphertext"]), sqlite3.Binary(enc["aad"])))
    conn.commit()
    conn.close()
    print_and_log(f"[SISTEMA]     💬 Mensaje enviado de '{sender}' a '{receiver}'.")

def read_messages(reader: str, user1: str, user2: str):
    """
    Lee y descifra todos los mensajes en un chat entre dos usuarios.
    :param reader:
    :param user1:
    :param user2:
    :return:
    """
    chat_id = get_chat_id(user1, user2)
    aes_key = get_chat_key_for_user(reader, user1, user2)
    if aes_key is None:
        return print(f"[DEBUG] ❌ '{reader}' no posee la clave AES para este chat.")

    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("""
        SELECT sender_id, nonce, ciphertext, aad, signature, timestamp
        FROM messages WHERE chat_id=?
        """, (chat_id,)).fetchall()
    conn.close()

    print(f"\n--- Mensajes entre '{user1}' y '{user2}' leídos por '{reader}' ---")
    for r in rows:
        sender_name = _get_user_row_by_id(r[0])
        nonce, ciphertext, aad = _to_bytes(r[1]), _to_bytes(r[2]), _to_bytes(r[3])
        try:
            msg = decrypt_message(aes_key, {"nonce": nonce, "ciphertext": ciphertext, "aad": aad})
            timestamp = r[5][:16]  # Ejemplo: 2025-10-22 13:23
            print(f"[{timestamp}] [{'✅' if msg else '❌'} Decifrado]  {sender_name}: {msg}")
        except Exception as e:
            print(f"[{timestamp}] {sender_name}: [AES-128-GCM] ❌ Descifrando mensaje: {e}")

def ensure_bot_exists():
    """
    Asegura que el usuario 'bob' exista en la base de datos
    :return:
    """
    if not user_exists("bob"):
        add_user("bob", "bob123")
