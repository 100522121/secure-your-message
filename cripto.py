""" Módulo de criptografía: hash (SHA-256 + PBKDF2), cifrado simétrico (AES-GCM) y asimétrico (RSA) """

import os
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from database import _get_user_row  # para obtener keys de la db
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from recursos.constantes import KDF_ITERATIONS, SALT_SIZE, print_and_log, _to_bytes  


# ------------ Autenticación del usuario ------------
# Algoritmo: SHA-256 + KDF (Key Derivation Function)

def hash_password(password: str):
    """
    Genera una sal aleatoria y deriva una clave a partir de la contraseña.
    :param password:
    :return:
    """
    salt = os.urandom(SALT_SIZE)                                 # 32 bytes = sal aleatoria de 256 bits
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, KDF_ITERATIONS)  # PBKDF2 = Password-Based Key Derivation Function 2
    key = kdf.derive(password.encode())
    print_and_log("\n[PBKDF2]   ✅ Contraseña hasheada con SHA-256 y clave derivada")
    return salt, key

def verify_password(stored_salt, stored_key, password_attempt: str) -> bool:
    """
    Verifica una contraseña intentando derivar la misma clave.
    :param stored_salt:
    :param stored_key:
    :param password_attempt:
    :return:
    """
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, stored_salt, KDF_ITERATIONS)
    try:
        kdf.verify(password_attempt.encode(), stored_key)
        return True
    except Exception:
        return False
    

# ---------------- Cifrado simétrico ----------------
# Algoritmo: AES-128, modo de operación: GCM

def generate_aes_key() -> bytes:
    """
    Genera una clave AES-128 aleatoria.
    :return:
    """
    print_and_log("[AES-128]  ✅ Clave generada: ", AESGCM.generate_key(128))
    return AESGCM.generate_key(128)

def encrypt_message(key: bytes, message: str, aad: bytes = b"") -> dict:
    """
    Cifra un mensaje usando AES-128-GCM.
    :param key:
    :param message:
    :param aad:
    :return:
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, message.encode(), aad)
    print_and_log("[AES-128-GCM] ✅ Mensaje cifrado: ", ct)
    return {"ciphertext": ct, "nonce": nonce, "aad": aad}

def decrypt_message(key: bytes, enc: dict) -> str:
    """
    Descifra un mensaje usando AES-128-GCM.
    :param key:
    :param enc:
    :return:
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(enc["nonce"], enc["ciphertext"], enc["aad"]).decode()


# --------------- Cifrado asimétrico ----------------
# Algoritmo: RSA-2048, padding: OAEP

def generate_rsa_keypair():
    """
    Genera un par de claves RSA (privada y pública).
    :return:
    """
    # Siempre se usa 65537 como exponente público
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    print_and_log(f"[RSA-2048] ✅ Claves privada y pública generadas")
    return priv, priv.public_key()

def serialize_keys(priv, pub):
    """
    Serializa las claves RSA a bytes PEM.
    :param priv:
    :param pub:
    :return:
    """
    priv_bytes = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,                  # PCKS 8 = Public-Key Cryptography Standards #8
        encryption_algorithm=serialization.NoEncryption()   # es un formato estándar para claves privadas
    )
    pub_bytes = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_bytes, pub_bytes

def rsa_encrypt_for_user(recipient_username: str, data: bytes) -> bytes:
    """
    Cifra datos usando la clave pública RSA del usuario destinatario.
    :param recipient_username:
    :param data:
    :return:"""
    row = _get_user_row(recipient_username)
    pub_bytes = row[2]
    pub = serialization.load_pem_public_key(pub_bytes)
    print_and_log(f"[RSA-2048] ✅ Datos cifrados para usuario '{recipient_username}'")
    return pub.encrypt(data, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                          algorithm=hashes.SHA256(), label=None))

def rsa_decrypt_for_user(username: str, encrypted_data: bytes) -> bytes:
    row = _get_user_row(username)
    priv_bytes = row[1]
    priv = serialization.load_pem_private_key(priv_bytes, password=None)
    return priv.decrypt(encrypted_data, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                     algorithm=hashes.SHA256(), label=None))
