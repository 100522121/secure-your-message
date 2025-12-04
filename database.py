""" Módulo para la gestión de la base de datos SQLite. """

import os
import sqlite3
from recursos.constantes import DB_PATH

def init_db():
    """ Crea las tablas necesarias en la base de datos SQLite si no existen.
    Sistema de gestión: SQLite, Lenguaje de programación: SQL
    :return: None """
    # Dato: BLOB = Binary Large Object (datos binarios)
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Usuarios
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password_hash BLOB,
        password_salt BLOB,
        private_key BLOB,
        public_key BLOB
    )""")

    # Chats
    c.execute("""
        CREATE TABLE IF NOT EXISTS chats (
        id INTEGER PRIMARY KEY,
        user1_id INTEGER,
        user2_id INTEGER,
        key_for_user1 BLOB,
        key_for_user2 BLOB
    )""")

    # Mensajes
    c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY,
        chat_id INTEGER,
        sender_id INTEGER,
        nonce BLOB,
        ciphertext BLOB,
        aad BLOB,
        signature BLOB,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")

    # Certificados (PKI)
    c.execute("""
        CREATE TABLE IF NOT EXISTS certificates (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        certificate BLOB,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )""")
    conn.commit()
    conn.close()


# --------------- Gestión de usuarios ---------------
def user_exists(username: str) -> bool:
    """ Verifica si un usuario ya está registrado.
    :param username:
    :return: True si el usuario existe, False en caso contrario. """
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("""
        SELECT 1
        FROM users WHERE username=?
        """, (username,)).fetchone()
    conn.close()
    return bool(row)

def _get_user_row(username: str):
    """ Obtiene la fila completa del usuario: (id, private_key, public_key)
    :param username:
    :return: Tupla con los datos del usuario o None si no existe. """
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("""
        SELECT id, private_key, public_key
        FROM users WHERE username=?
        """, (username,)).fetchone()
    conn.close()
    return row

def _get_user_row_by_id(user_id: int):
    """ Obtiene el nombre de usuario a partir de su ID.
    :param user_id:
    :return: Nombre de usuario o "UsuarioDesconocido" si no existe. """
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("""
        SELECT username
        FROM users WHERE id=?
        """, (user_id,)).fetchone()
    conn.close()
    return row[0] if row else "UsuarioDesconocido"


# ---------- Gestión de certificados (PKI) ----------
def add_certificate(username: str, cert_pem: bytes):
    """ Añade un certificado PEM para el usuario indicado.
    :param username:
    :param cert_pem:
    :return: None """
    conn = sqlite3.connect(DB_PATH)
    user_row = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if not user_row:
        conn.close()
        raise ValueError("Usuario no encontrado al añadir certificado")
    user_id = user_row[0]
    conn.execute("""INSERT INTO certificates (user_id, certificate) VALUES (?, ?)""", (user_id, sqlite3.Binary(cert_pem)))
    conn.commit()
    conn.close()

def get_certificate_by_username(username: str):
    """ Recupera el certificado más reciente (PEM) del usuario o None.
    :param username:
    :return: Certificado PEM o None. """
    conn = sqlite3.connect(DB_PATH)
    user_row = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if not user_row:
        conn.close()
        return None
    uid = user_row[0]
    row = conn.execute("SELECT certificate FROM certificates WHERE user_id=? ORDER BY id DESC LIMIT 1", (uid,)).fetchone()
    conn.close()
    return row[0] if row else None

def get_user_credentials_row(username: str):
    """ Devuelve (password_hash, password_salt) para el usuario.
    :param username:
    :return: Tupla (password_hash, password_salt) o None si no existe. """
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("""
        SELECT password_hash, password_salt
        FROM users
        WHERE username=?
    """, (username,)).fetchone()
    conn.close()
    return row

def get_user_keys_row(username: str):
    """ Devuelve (private_key, public_key) para un usuario.
    :param username:   
    :return: Tupla (private_key, public_key) o None si no existe. """
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("""
        SELECT private_key, public_key
        FROM users
        WHERE username=?
    """, (username,)).fetchone()
    conn.close()
    return row
