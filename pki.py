""" Módulo PKI que gestiona AC1 (raíz) y AC2 (sub) para emitir certificados de usuario y
y verificar sus cadenas, con claves privadas cifradas y certificados en formato PEM. """

import os
import datetime
import keyring  # keyring para gestión segura de contraseñas
import secrets
from datetime import timezone
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cripto import encrypt_private_key_with_password, decrypt_private_key_with_password
from database import _get_user_row, add_certificate
from recursos.constantes import print_and_log, OUTPUT_DIR, AC1_CERT_FILE, AC2_CERT_FILE

# ----------------- Generadores internos -----------------
def _generate_rsa_key(key_size=2048):
    """ Genera una clave privada RSA.
    :return: Clave privada RSA. """
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)

def _save_cert(path, cert_obj):
    """ Guarda el certificado en disco
    :param path: Ruta del archivo
    :param cert_obj: Objeto x509.Certificate
    :return: None """
    with open(path, "wb") as f:
        f.write(cert_obj.public_bytes(serialization.Encoding.PEM))

def _save_encrypted_key(path, key_obj, password):
    """ Guarda la clave privada cifrada en disco 
    :param path: Ruta del archivo
    :param key_obj: Objeto de clave privada
    :param password: Contraseña para cifrado
    :return: None """
    blob = encrypt_private_key_with_password(
        key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ),
        password
    )
    with open(path, "wb") as f:
        f.write(blob)

def _load_encrypted_key(path, password):
    """ Carga la clave privada cifrada desde archivo PEM cifrado.
    :param path: Ruta del archivo
    :param password: Contraseña para descifrado
    :return: Objeto de clave privada """
    with open(path, "rb") as f:
        blob = f.read()
    pem = decrypt_private_key_with_password(blob, password)
    return serialization.load_pem_private_key(pem, password=None)

def _load_cert(path):
    """ Carga un certificado X.509 desde archivo PEM.
    :param path: Ruta del archivo.
    :return: Certificado cargado. """
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


# ----------------- Certificados -----------------
def _create_root_ca(name="AC1 Root CA"):
    """ Crea el certificado autofirmado para la AC Raíz.
    :return: Tupla (clave privada, certificado) """
    priv = _generate_rsa_key()
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(priv, hashes.SHA256())
    )
    return priv, cert

def _create_sub_ca(issuer_priv, issuer_cert, name="AC2 Sub CA"):
    """ Crea el certificado de la AC Subordinada firmado por la AC Raíz.
    :param issuer_priv: Clave privada de la AC1. 
    :param issuer_cert: Certificado de la AC1. 
    :return: Clave privada y certificado de la AC2. """
    priv = _generate_rsa_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(issuer_priv, hashes.SHA256())
    )
    return priv, cert

def _create_user_cert(user_pub_key, issuer_priv, issuer_cert, username):
    """ Crea un certificado de usuario final firmado por la AC Subordinada.
    :param user_pub_key: Clave pública del usuario.
    :param issuer_priv: Clave privada de la AC2. """
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, username)])
    now = datetime.datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(user_pub_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False
        )
        .sign(issuer_priv, hashes.SHA256())
    )
    return cert


# ----------------- PKI pública -----------------
def init_pki():
    """ Inicializa la estructura de la PKI.
    Si no existen los archivos de AC1 y AC2, los crea.
    :return: None """
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Contraseña en keyring
    ac1_pass = keyring.get_password("pki_app", "AC1_KEY_PASSWORD")
    ac2_pass = keyring.get_password("pki_app", "AC2_KEY_PASSWORD")

    # Verificar y crear AC1 (Raíz)
    if not (ac1_pass and os.path.exists(AC1_CERT_FILE) and os.path.exists(os.path.join(OUTPUT_DIR,"AC1_key.pem.enc"))):
        print_and_log("[CERT-PKI] ⚙️ Generando AC1 (Raíz)...")
        ac1_priv, ac1_cert = _create_root_ca("AC1 Root CA")

        keyring.set_password("pki_app", "AC1_KEY_PASSWORD", secrets.token_urlsafe(32))
        _save_encrypted_key(os.path.join(OUTPUT_DIR,"AC1_key.pem.enc"), ac1_priv,
                            password=keyring.get_password("pki_app", "AC1_KEY_PASSWORD"))
        _save_cert(AC1_CERT_FILE, ac1_cert)
        print_and_log("[CERT-PKI] ✅ AC1 creada correctamente.")

    else:
        ac1_priv = _load_encrypted_key(os.path.join(OUTPUT_DIR,"AC1_key.pem.enc"), ac1_pass)
        print_and_log("[CERT-PKI] ℹ️  AC1 ya existe.")

    # Verificar y crear AC2 (Subordinada)
    if not (ac2_pass and os.path.exists(AC2_CERT_FILE) and os.path.exists(os.path.join(OUTPUT_DIR,"AC2_key.pem.enc"))):
        print_and_log("[CERT-PKI] ⚙️ Generando AC2 (Subordinada)...")
        ac2_priv, ac2_cert = _create_sub_ca(ac1_priv, _load_cert(AC1_CERT_FILE), "AC2 Sub CA")
        
        keyring.set_password("pki_app", "AC2_KEY_PASSWORD", secrets.token_urlsafe(32))
        _save_encrypted_key(os.path.join(OUTPUT_DIR,"AC2_key.pem.enc"), ac2_priv,
                            password=keyring.get_password("pki_app", "AC2_KEY_PASSWORD"))
        _save_cert(AC2_CERT_FILE, ac2_cert)
        print_and_log("[CERT-PKI] ✅ AC2 creada correctamente.")
    else:
        ac2_priv = _load_encrypted_key(os.path.join(OUTPUT_DIR,"AC2_key.pem.enc"), ac2_pass)
        print_and_log("[CERT-PKI] ℹ️  AC2 ya existe.")

    print_and_log("[CERT-PKI] 🔄 PKI inicializada y lista.")

def issue_certificate_for_user(username: str):
    """ Emite un certificado para un usuario existente en la BD, firmado por AC2.
    Guarda el certificado en la base de datos.
    :param username: Nombre del usuario.
    :return: Certificado emitido. """
    row = _get_user_row(username)
    if not row:
        raise ValueError(f"Usuario '{username}' no encontrado en BD.")

    user_pub_bytes = row[2]
    user_pub_key = serialization.load_pem_public_key(user_pub_bytes)

    ac2_pass = keyring.get_password("pki_app", "AC2_KEY_PASSWORD")
    ac2_priv = _load_encrypted_key(os.path.join(OUTPUT_DIR,"AC2_key.pem.enc"), ac2_pass)
    ac2_cert = _load_cert(AC2_CERT_FILE)

    user_cert = _create_user_cert(user_pub_key, ac2_priv, ac2_cert, username)
    cert_pem = user_cert.public_bytes(serialization.Encoding.PEM)

    add_certificate(username, cert_pem)
    print_and_log(f"[CERT-PKI] 🟢 Certificado emitido y guardado para '{username}'.")
    return user_cert

def verify_certificate_chain(cert_pem: bytes) -> bool:
    """ Verifica criptográficamente la cadena: Usuario -> AC2 -> AC1.
    Devuelve True si es válida.
    :param cert_pem: Certificado del usuario en formato PEM.
    :return: True si la cadena es válida, False en caso contrario. """
    try:
        user_cert = x509.load_pem_x509_certificate(cert_pem)
        ac2_cert = _load_cert(AC2_CERT_FILE)
        ac1_cert = _load_cert(AC1_CERT_FILE)

        # Verificar firmas
        ac2_cert.public_key().verify(
            user_cert.signature,
            user_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            user_cert.signature_hash_algorithm
        )
        ac1_cert.public_key().verify(
            ac2_cert.signature,
            ac2_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            ac2_cert.signature_hash_algorithm
        )

        # Verificar fechas y usar las propiedades _utc del certificado
        now = datetime.datetime.now(timezone.utc)
        if not (user_cert.not_valid_before_utc <= now <= user_cert.not_valid_after_utc):
            raise ValueError("Certificado expirado o aún no válido.")

        print_and_log("[CERT-PKI] 🔐 Cadena de certificación verificada correctamente.")
        return True
    except Exception as e:
        print_and_log(f"[CERT-PKI] ❌ Fallo en verificación de cadena: {e}")
        return False
