""" Módulo de criptografía: hash (SHA-256 + PBKDF2), cifrado simétrico (AES-GCM) y asimétrico (RSA)
Incluye funciones para cifrar/descifrar claves privadas con contraseña, y firma/verificación. """

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from database import _get_user_row  # para obtener keys de la db
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from recursos.constantes import KDF_ITERATIONS, SALT_SIZE, print_and_log, print_in_log

# ------------ Autenticación del usuario ------------
# Algoritmo: SHA-256 + KDF (Key Derivation Function)
def hash_password(password: str):
    """ Hashea una contraseña usando PBKDF2 con SHA-256.
    Devuelve el salt y la clave derivada.
    :param password: contraseña del usuario
    :return: (salt, clave derivada) """
    salt = os.urandom(SALT_SIZE)
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, KDF_ITERATIONS)
    key = kdf.derive(password.encode())
    print_and_log("\n[PBKDF2]   ✅ Contraseña hasheada con SHA-256 y clave derivada")
    return salt, key

def verify_password(stored_salt, stored_key, password_attempt: str) -> bool:
    """ Verifica si la contraseña introducida coincide con la almacenada.
    :param stored_salt: salt almacenado (bytes)
    :param stored_key: clave derivada almacenada (bytes)
    :param password_attempt: contraseña introducida por el usuario
    :return: True si coincide, False si no """
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, stored_salt, KDF_ITERATIONS)
    try:
        kdf.verify(password_attempt.encode(), stored_key)
        return True
    except Exception:
        return False


# ---------------- Cifrado simétrico ----------------
# Algoritmo: AES-128, modo de operación: GCM
def generate_aes_key() -> bytes:
    """ Genera una clave AES de 128 bits   
    :return: clave AES (bytes) """
    key = AESGCM.generate_key(128)
    print_and_log("[AES128]   ✅ Clave generada (longitud 128 bits)")
    return key

def encrypt_message(key: bytes, message: str, aad: bytes = b"") -> dict:
    """ Cifra un mensaje usando AES-128-GCM.
    :param key: clave AES (bytes)
    :param message: mensaje a cifrar (str)
    :param aad: datos adicionales autenticados (bytes)
    :return: diccionario con 'ciphertext', 'nonce' y 'aad' """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, message.encode(), aad)
    print_and_log("[AES128-GCM] ✅ Mensaje cifrado: ", ct)
    return {"ciphertext": ct, "nonce": nonce, "aad": aad}

def decrypt_message(key: bytes, enc: dict) -> str:
    """ Descifra un mensaje cifrado con AES-128-GCM.
    :param key: clave AES (bytes)
    :param enc: diccionario con 'ciphertext', 'nonce' y 'aad'
    :return: mensaje descifrado (str) """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(enc["nonce"], enc["ciphertext"], enc["aad"]).decode()


# --------------- Cifrado asimétrico ----------------
# Algoritmo: RSA-2048, padding: OAEP
def generate_rsa_keypair():
    """ Genera un par de claves RSA (privada y pública) de 2048 bits.
    :return: (clave privada, clave pública) """
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    print_and_log(f"[RSA2048]  ✅ Claves privada y pública generadas")
    return priv, priv.public_key()

def serialize_keys(priv, pub):
    """ Serializa las claves RSA a formato PEM.
    :param priv: objeto de clave privada RSA
    :param pub: objeto de clave pública RSA
    :return: (clave privada en bytes, clave pública en bytes) """
    priv_bytes = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_bytes, pub_bytes

def rsa_encrypt_for_user(recipient_username: str, data: bytes) -> bytes:
    """ Cifra datos para un usuario específico usando su clave pública RSA.
    :param recipient_username: nombre de usuario del destinatario
    :param data: datos a cifrar (bytes)
    :return: datos cifrados (bytes) """
    row = _get_user_row(recipient_username)
    pub_bytes = row[2]
    pub = serialization.load_pem_public_key(pub_bytes)
    print_and_log(f"[RSA2048]  ✅ Datos cifrados para usuario '{recipient_username}'")
    return pub.encrypt(data, asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA256()),
                                               algorithm=hashes.SHA256(), label=None))

def rsa_decrypt_for_user(username: str, encrypted_data: bytes) -> bytes:
    """ Descifra datos para un usuario específico usando su clave privada RSA almacenada en la base de datos.
    :param username: nombre de usuario
    :param encrypted_data: datos cifrados (bytes)
    :return: datos descifrados (bytes) """
    row = _get_user_row(username)
    priv_bytes = row[1]
    try:
        priv = serialization.load_pem_private_key(priv_bytes, password=None)
        return priv.decrypt(encrypted_data, asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA256()),
                                                              algorithm=hashes.SHA256(), label=None))
    except Exception:
        raise RuntimeError("La clave privada en la BD está cifrada. Desbloquea la clave y usa rsa_decrypt_with_privatekey(priv_obj, ...)")


# --- Des/cifrado de clave privada con contraseña ---
# Algoritmos: KDF (Key Derivation Function), AES-GCM
def _derive_key_from_password(password: str, salt: bytes, length: int = 32) -> bytes:
    """ Deriva una clave simétrica a partir de una contraseña usando PBKDF2 con SHA-256 
    :param password: contraseña del usuario
    :param salt: salt aleatorio (bytes)
    :param length: longitud de la clave derivada en bytes (16, 24, 32)
    :return: clave derivada (bytes) """
    kdf = PBKDF2HMAC(hashes.SHA256(), length, salt, KDF_ITERATIONS)
    return kdf.derive(password.encode())

def encrypt_private_key_with_password(priv_bytes: bytes, password: str) -> bytes:
    """ Cifra la clave privada (en bytes) con una contraseña usando AES-GCM.
    Devuelve un blob que contiene: salt (16 bytes) + nonce (12 bytes) + ciphertext.
    :param priv_bytes: clave privada en bytes (PEM)
    :param password: contraseña del usuario
    :return: blob cifrado (bytes) """
    salt = os.urandom(SALT_SIZE)
    key = _derive_key_from_password(password, salt, length=32)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, priv_bytes, None)
    print_and_log("[AESGCM]   ✅ Clave privada cifrada para almacenamiento seguro")
    return salt + nonce + ct

def decrypt_private_key_with_password(enc_blob: bytes, password: str) -> bytes:
    """ Descifra la clave privada usando la contraseña. 
    :param enc_blob: blob cifrado (salt + nonce + ciphertext)
    :param password: contraseña del usuario
    :return: clave privada en bytes (PEM) """
    if len(enc_blob) < SALT_SIZE + 12 + 16:
        raise ValueError("Enc_blob demasiado corto o corrupto")
    salt = enc_blob[:SALT_SIZE]
    nonce = enc_blob[SALT_SIZE:SALT_SIZE + 12]
    ct = enc_blob[SALT_SIZE + 12:]
    key = _derive_key_from_password(password, salt, length=32)
    aesgcm = AESGCM(key)
    priv_bytes = aesgcm.decrypt(nonce, ct, None)
    print_and_log("[AESGCM]   ✅ Clave privada descifrada correctamente")
    return priv_bytes


# -------- Cifrado RSA con objeto private_key -------
# Algoritmo: RSA-2048, padding: OAEP

def rsa_decrypt_with_privatekey(priv_obj, encrypted_data: bytes) -> bytes:
    """ Descifra datos usando un objeto de clave privada RSA.
    :param priv_obj: objeto de clave privada RSA (cryptography)
    :param encrypted_data: datos cifrados (bytes)
    :return: datos descifrados (bytes) """
    return priv_obj.decrypt(
        encrypted_data,
        asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA256()),
                          algorithm=hashes.SHA256(),
                          label=None)
    )


# ----------------- Firma digital  ------------------
# Algoritmo: RSA-PSS con SHA-256 
def sign_with_private_key_obj(priv_obj, message: bytes) -> bytes:
    """ Firma un mensaje usando un objeto de clave privada RSA.
    :param priv_obj: objeto de clave privada RSA (cryptography)
    :param message: mensaje a firmar (bytes)
    :return: firma (bytes) """
    sig = priv_obj.sign(
        message,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print_and_log("[FIRMA]      ✅ Mensaje firmado (RSA-PSS SHA-256).")
    return sig

def verify_signature_with_public_bytes(pub_bytes: bytes, message: bytes, signature: bytes, log: bool = True) -> bool:
    """ Verifica firma dada la clave pública en PEM.
    :param pub_bytes: clave pública en bytes (PEM)
    :param message: mensaje original (bytes)
    :param signature: firma a verificar (bytes)
    :param log: si se debe registrar el resultado en logs.txt
    :return: True si la firma es válida, False si no """
    pub = serialization.load_pem_public_key(pub_bytes)
    try:
        pub.verify(
            signature,
            message,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        if log:
            print_in_log("[FIRMA] ✅ Verificación de firma correcta.")
        return True
    except Exception:
        if log:
            print_and_log("[FIRMA] ❌ Verificación de firma fallida.")
        return False
