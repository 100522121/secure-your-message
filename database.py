""" Módulo para la gestión de la base de datos SQLite. """

import os
import sqlite3
from recursos.constantes import DB_PATH


def init_db():
    """
    Crea las tablas necesarias en la base de datos SQLite si no existen.
    Sistema de gestión: SQLite, Lenguaje de programación: SQL
    :return:
    """
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)                              # Conectar a la base de datos y crear tablas
    c = conn.cursor()
    # BLOB = Binary Large Object (datos binarios)
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password_hash BLOB,
        password_salt BLOB,
        private_key BLOB,
        public_key BLOB
    )""")
    c.execute("""
        CREATE TABLE IF NOT EXISTS chats (
        id INTEGER PRIMARY KEY,
        user1_id INTEGER,
        user2_id INTEGER,
        key_for_user1 BLOB,
        key_for_user2 BLOB
    )""")
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
    conn.commit()
    conn.close()

def user_exists(username: str) -> bool:
    """
    Verifica si un usuario ya está registrado.
    :param username:
    :return:
    """
    conn = sqlite3.connect(DB_PATH)
    # Signo de interrogación (?) es un placeholder
    row = conn.execute("""
        SELECT 1
        FROM users WHERE username=?
        """, (username,)).fetchone()
    conn.close()
    return bool(row)

def _get_user_row(username: str):
    """
    Obtiene la fila completa del usuario de la base de datos.
    :param username:
    :return:
    """
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("""
        SELECT id, private_key, public_key
        FROM users WHERE username=?
        """, (username,)).fetchone()
    conn.close()
    return row

def _get_user_row_by_id(user_id: int):
    """
    Obtiene el nombre de usuario a partir de su ID.
    :param user_id:
    :return:
    """
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("""
        SELECT username
        FROM users WHERE id=?
        """, (user_id,)).fetchone()
    conn.close()
    return row[0] if row else "UsuarioDesconocido"
